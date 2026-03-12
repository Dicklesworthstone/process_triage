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
