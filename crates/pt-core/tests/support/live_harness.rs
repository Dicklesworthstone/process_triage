//! Live system test harness for no-mock integration tests.
//!
//! This harness keeps real OS resources open (files, sockets, pipes) to enable
//! collectors to observe `/proc` data without mocks or fixtures.

#![allow(dead_code)]
// Test support intentionally provides more helpers than any single test uses.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

static HARNESS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static HARNESS_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Run an exact permission-sensitive test under an owned unprivileged process
/// when its caller is root. Returns true only after the complete child test
/// passes; ordinary nonroot callers execute their original body directly.
#[cfg(target_os = "linux")]
pub fn run_owned_unprivileged_case(test_name: &str) -> bool {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    const MARKER: &str = "PT_TEST_UNPRIVILEGED_PRECHECK_CASE";
    const UID: libc::uid_t = 65534;
    const GID: libc::gid_t = 65534;
    if let Some(marker) = std::env::var_os(MARKER) {
        assert_eq!(marker, test_name, "exact dropped-privilege test selector");
        let status = fs::read_to_string("/proc/thread-self/status")
            .expect("read actual dropped test thread credentials");
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap_or_else(|| panic!("missing credential field {name}: {status}"))
                .trim()
        };
        for (name, expected) in [("Uid:", UID), ("Gid:", GID)] {
            let ids: Vec<u32> = field(name)
                .split_whitespace()
                .map(|id| id.parse().expect("numeric actual credential"))
                .collect();
            assert_eq!(
                ids,
                vec![expected; 4],
                "real/effective/saved/filesystem {name}"
            );
        }
        assert!(
            field("Groups:").is_empty(),
            "supplementary groups must be cleared: {status}"
        );
        for name in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            assert_eq!(
                u64::from_str_radix(field(name), 16).expect("actual capability mask"),
                0,
                "retained privilege in {name}: {status}"
            );
        }
        assert_eq!(field("NoNewPrivs:"), "1", "exec must not regain privileges");
        // SAFETY: these calls only observe this test thread's credentials.
        assert_eq!(unsafe { libc::getuid() }, UID);
        assert_eq!(unsafe { libc::geteuid() }, UID);
        assert_eq!(unsafe { libc::getgid() }, GID);
        assert_eq!(unsafe { libc::getegid() }, GID);
        eprintln!("owned unprivileged case={test_name} credentials={status}");
        println!("PT_UNPRIVILEGED_PRECHECKS_READY {test_name}");
        return false;
    }
    // SAFETY: observing the caller cannot change the multithreaded runner.
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    struct OwnedRunner(Child);
    impl Drop for OwnedRunner {
        fn drop(&mut self) {
            match self.0.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(error) = self.0.kill() {
                        eprintln!("owned privilege runner cleanup kill: {error}");
                    }
                    if let Err(error) = self.0.wait() {
                        eprintln!("owned privilege runner cleanup wait: {error}");
                    }
                }
                Err(error) => {
                    eprintln!("owned privilege runner status unknown; no signal sent: {error}")
                }
            }
        }
    }

    // Only this newly created, retained directory changes ownership. Existing
    // checkout paths and permissions are never changed for the dropped caller.
    let artifacts =
        std::env::temp_dir().join(format!("pt-unprivileged-case-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&artifacts)
        .expect("create a fresh retained unprivileged work directory");
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&artifacts)
        .expect("open only the new owned directory");
    // SAFETY: the descriptor pins the freshly created directory, not an
    // existing repository path or a symlink supplied by another process.
    assert_eq!(
        unsafe { libc::fchown(directory.as_raw_fd(), UID, GID) },
        0,
        "set new work directory owner: {}",
        io::Error::last_os_error()
    );
    let metadata = directory.metadata().expect("actual new directory metadata");
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), UID);
    assert_eq!(metadata.gid(), GID);
    assert_eq!(metadata.mode() & 0o777, 0o700);
    let stdout_path = artifacts.join("stdout.log");
    let stderr_path = artifacts.join("stderr.log");
    let stdout = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stdout_path)
        .expect("create retained privilege-run stdout");
    let stderr = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stderr_path)
        .expect("create retained privilege-run stderr");
    let mut command = Command::new(std::env::current_exe().expect("current libtest executable"));
    command
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(MARKER, test_name)
        .env("PT_TEST_UNPRIVILEGED_ARTIFACT_DIR", &artifacts)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: only the newly forked, owned child changes credentials. Before
    // exec this closure uses kernel interfaces and stack storage, and returns
    // OS errors without allocating, logging or touching environment/mutexes.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::prctl(
                    libc::PR_SET_KEEPCAPS,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                || libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                || libc::setresgid(GID, GID, GID) != 0
                || libc::setresuid(UID, UID, UID) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Linux UAPI v3 is one header plus two 32-bit capability records.
            let header = CapHeader {
                version: 0x2008_0522,
                pid: 0,
            };
            let data = [
                CapData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                CapData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    eprintln!(
        "root-owned unprivileged case={test_name} executable={:?} argv={:?} artifacts={}",
        command.get_program(),
        command.get_args().collect::<Vec<_>>(),
        artifacts.display()
    );
    let mut child = OwnedRunner(
        command
            .spawn()
            .expect("spawn genuinely unprivileged exact test"),
    );
    let status = child.0.wait().expect("wait for complete unprivileged test");
    let stdout = fs::read_to_string(&stdout_path).expect("read retained test stdout");
    let stderr = fs::read_to_string(&stderr_path).expect("read retained test stderr");
    eprintln!("unprivileged case={test_name} status={status} stdout={stdout} stderr={stderr}");
    assert!(
        status.success(),
        "exact unprivileged case failed; artifacts={}",
        artifacts.display()
    );
    assert!(
        stdout.contains(&format!("PT_UNPRIVILEGED_PRECHECKS_READY {test_name}")),
        "actual privilege validation must execute"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "the selected test must run and pass exactly once: {stdout}"
    );
    true
}

/// Live resource harness scoped to a test.
///
/// The harness holds open files and sockets in the current process so that
/// `/proc/self/*` reflects these resources for collector validation.
#[derive(Debug)]
pub struct LiveHarness {
    _guard: MutexGuard<'static, ()>,
    temp_dir: PathBuf,
    files: Vec<File>,
    tcp_listener: Option<TcpListener>,
    tcp_streams: Vec<TcpStream>,
    udp_socket: Option<UdpSocket>,
    #[cfg(unix)]
    unix_listener: Option<UnixListener>,
    #[cfg(unix)]
    unix_streams: Vec<UnixStream>,
    child: Option<Child>,
}

impl LiveHarness {
    /// Create a new harness and a unique temp directory.
    pub fn new() -> io::Result<Self> {
        let guard = HARNESS_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("harness lock poisoned");

        let suffix = HARNESS_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir =
            std::env::temp_dir().join(format!("pt_live_harness_{}_{}", std::process::id(), suffix));
        fs::create_dir_all(&temp_dir)?;

        Ok(Self {
            _guard: guard,
            temp_dir,
            files: Vec::new(),
            tcp_listener: None,
            tcp_streams: Vec::new(),
            udp_socket: None,
            #[cfg(unix)]
            unix_listener: None,
            #[cfg(unix)]
            unix_streams: Vec::new(),
            child: None,
        })
    }

    /// Return the PID for the current process.
    pub fn pid(&self) -> u32 {
        std::process::id()
    }

    /// Return the harness temp directory.
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Open a read/write temp file and keep it open.
    pub fn open_rw_file(&mut self) -> io::Result<PathBuf> {
        let path = self.temp_dir.join(format!("rw_{}.txt", self.files.len()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        self.files.push(file);
        Ok(path)
    }

    /// Open a read-only temp file and keep it open.
    pub fn open_ro_file(&mut self) -> io::Result<PathBuf> {
        let path = self.temp_dir.join(format!("ro_{}.txt", self.files.len()));
        if !path.exists() {
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)?;
        }
        let file = OpenOptions::new().read(true).open(&path)?;
        self.files.push(file);
        Ok(path)
    }

    /// Open an anonymous pipe and keep both ends open.
    #[cfg(unix)]
    pub fn open_pipe(&mut self) -> io::Result<()> {
        let mut fds = [0; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let read_end = unsafe { File::from_raw_fd(fds[0]) };
        let write_end = unsafe { File::from_raw_fd(fds[1]) };
        self.files.push(read_end);
        self.files.push(write_end);
        Ok(())
    }

    /// Open a TCP listener and an established client/server connection.
    pub fn open_tcp_connection(&mut self) -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;

        self.tcp_listener = Some(listener);
        self.tcp_streams.push(client);
        self.tcp_streams.push(server);
        Ok(addr.port())
    }

    /// Open a UDP socket bound to localhost.
    pub fn open_udp_socket(&mut self) -> io::Result<u16> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        self.udp_socket = Some(socket);
        Ok(port)
    }

    /// Open a Unix domain socket listener + connection (Linux/Unix only).
    #[cfg(unix)]
    pub fn open_unix_socket(&mut self) -> io::Result<PathBuf> {
        let path = self
            .temp_dir
            .join(format!("unix_{}.sock", self.unix_streams.len()));
        let listener = UnixListener::bind(&path)?;
        let client = UnixStream::connect(&path)?;
        let (server, _) = listener.accept()?;

        self.unix_listener = Some(listener);
        self.unix_streams.push(client);
        self.unix_streams.push(server);
        Ok(path)
    }

    /// Spawn a long-lived child process for signal/action tests.
    ///
    /// This does not delete any files or directories, and the child is
    /// terminated on drop if still running.
    pub fn spawn_sleep_child(&mut self, duration: Duration) -> io::Result<u32> {
        let secs = duration.as_secs().max(1);
        let child = Command::new("sleep").arg(secs.to_string()).spawn()?;
        let pid = child.id();
        self.child = Some(child);
        Ok(pid)
    }

    /// Attempt to terminate the child process if present.
    pub fn terminate_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for LiveHarness {
    fn drop(&mut self) {
        self.terminate_child();
        for stream in &self.tcp_streams {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        #[cfg(unix)]
        for stream in &self.unix_streams {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}
