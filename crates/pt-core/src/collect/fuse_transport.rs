//! Linux SSH subsystem transports can survive sshfs daemonization as PID 1's
//! children. Their socketpair has two different inode numbers. A transport
//! need not hold /dev/fuse or remain a descendant of the mount server.

use super::{proc_parsers::read_required_proc_stat, procfs::read_bounded};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

const RULE: &str = "builtin.sftp_transport";

/// Only an OpenSSH subsystem invocation qualifies. Read the real NUL-delimited
/// argv: a remote shell command or a quoted ProxyCommand can contain "-s sftp".
fn is_sftp_subsystem(cmdline: &[u8]) -> Option<bool> {
    let mut argv = cmdline.strip_suffix(&[0])?.split(|&byte| byte == 0);
    if argv.next()?.is_empty() {
        return None;
    }
    let mut destination = false;
    let mut subsystem = false;
    let mut options = true;
    while let Some(arg) = argv.next() {
        if options && arg == b"--" {
            options = false;
            continue;
        }
        if options && arg.len() > 1 && arg[0] == b'-' {
            for (i, &flag) in arg[1..].iter().enumerate() {
                // Options accepting a value consume the rest of this word or
                // the next argv entry, including a value starting with "-".
                if b"BbcDEeFIiJLlmOoPpQRSWw".contains(&flag) {
                    let value = if i + 2 == arg.len() {
                        argv.next()?
                    } else {
                        &arg[i + 2..]
                    };
                    if flag == b'o' {
                        let mut option = value
                            .split(|byte| *byte == b'=' || byte.is_ascii_whitespace())
                            .filter(|word| !word.is_empty());
                        if option
                            .next()
                            .is_some_and(|word| word.eq_ignore_ascii_case(b"SessionType"))
                            && option
                                .next()
                                .is_some_and(|word| word.eq_ignore_ascii_case(b"subsystem"))
                        {
                            subsystem = true;
                        }
                    }
                    break;
                }
                subsystem |= flag == b's';
            }
        } else if destination {
            return Some(subsystem && arg == b"sftp" && argv.next().is_none());
        } else {
            destination = true;
        }
    }
    destination.then_some(false)
}

fn socket_inode(pid: u32, fd: u32) -> Option<u64> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .ok()?
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
        .filter(|&inode| inode != 0)
}

#[derive(Debug, PartialEq)]
struct Peer {
    target_inode: u64,
    server_inode: u64,
    pid: u32,
    fd: u32,
}

/// Read the reverse socket row: the local endpoint belongs to a server FD,
/// and the opposite endpoint must match a descriptor of this very transport.
type PeerTable = HashMap<u64, Vec<Peer>>;

fn index_peers(table: &str) -> PeerTable {
    let mut peers = PeerTable::new();
    for row in table.lines() {
        let mut fields = row.split_ascii_whitespace();
        if fields.next() != Some("u_str") || fields.next() != Some("ESTAB") {
            continue;
        }
        if fields.nth(2) != Some("*") {
            continue;
        }
        let Some(local) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        if fields.next() != Some("*") {
            continue;
        }
        let Some(remote) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        if local == 0 || remote == 0 || local == remote {
            continue;
        }
        for owner in row.split(",pid=").skip(1) {
            let Some((pid, rest)) = owner.split_once(",fd=") else {
                continue;
            };
            let Some((fd, _)) = rest.split_once(')') else {
                continue;
            };
            if let (Ok(pid), Ok(fd)) = (pid.parse::<u32>(), fd.parse::<u32>()) {
                if pid != 0 {
                    let owners = peers.entry(remote).or_default();
                    if owners.len() >= 16 {
                        break;
                    }
                    owners.push(Peer {
                        target_inode: remote,
                        server_inode: local,
                        pid,
                        fd,
                    });
                }
            }
        }
    }
    peers
}

fn read_peer_table() -> Option<PeerTable> {
    use super::tool_runner::{ToolConfig, ToolRunner};
    let ss = ["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"]
        .into_iter()
        .find(|path| Path::new(path).is_file())?;
    let runner = ToolRunner::new(ToolConfig {
        use_nice: false,
        default_timeout: std::time::Duration::from_millis(300),
        max_output_bytes: 512 * 1024,
        ..Default::default()
    });
    let table = runner.run_tool(ss, &["-H", "-x", "-n", "-p"], None).ok()?;
    if !table.success() || table.truncated || !table.stderr.is_empty() {
        return None;
    }
    Some(index_peers(std::str::from_utf8(&table.stdout).ok()?))
}

/// One bounded owner census per planning pass. A missing or truncated table
/// is cached for that pass as well. Execution constructs its own observation.
#[derive(Default)]
pub(crate) struct FusePeerLookup {
    table: OnceLock<Option<PeerTable>>,
}

impl FusePeerLookup {
    pub(crate) fn refusal(&self, pid: u32, comm: &str) -> Option<String> {
        self.refusal_with(pid, comm, read_peer_table, |server| {
            (super::protected::holds_fuse_device(server) == Some(true))
                .then(|| super::protected::fuse_mountpoints(server))
        })
    }

    fn refusal_with(
        &self,
        pid: u32,
        comm: &str,
        read: impl FnOnce() -> Option<PeerTable>,
        server_mounts: impl Fn(u32) -> Option<Vec<String>>,
    ) -> Option<String> {
        let mut stdio: Vec<_> = (0..=2).filter_map(|fd| socket_inode(pid, fd)).collect();
        stdio.sort_unstable();
        stdio.dedup();
        if !stdio.is_empty() {
            let birth = read_required_proc_stat(pid).ok().map(|s| s.starttime);
            if let (Some(birth), Some(table)) = (birth, self.table.get_or_init(read).as_ref()) {
                let start = std::time::Instant::now();
                for peer in stdio.iter().filter_map(|inode| table.get(inode)).flatten() {
                    if start.elapsed() >= std::time::Duration::from_millis(300) {
                        break;
                    }
                    if let Some(description) = confirm_peer(pid, peer, &server_mounts) {
                        if read_required_proc_stat(pid).is_ok_and(|s| s.starttime == birth) {
                            return Some(format!("builtin.fuse_transport: {description}; inspect the mount and transport before taking action"));
                        }
                    }
                }
            }
        }
        unresolved_ssh_refusal(pid, comm)
    }
}

/// Verify that the reported owner still holds the exact peer endpoint, the
/// server is protected, and the target still has the observed stdio endpoint.
fn confirm_peer(
    pid: u32,
    peer: &Peer,
    server_mounts: impl FnOnce(u32) -> Option<Vec<String>>,
) -> Option<String> {
    let before = read_required_proc_stat(peer.pid).ok()?;
    if pid == peer.pid || socket_inode(peer.pid, peer.fd) != Some(peer.server_inode) {
        return None;
    }
    let mounts = server_mounts(peer.pid)?;
    if read_required_proc_stat(peer.pid).ok()?.starttime != before.starttime
        || socket_inode(peer.pid, peer.fd) != Some(peer.server_inode)
        || !(0..=2).any(|fd| socket_inode(pid, fd) == Some(peer.target_inode))
    {
        return None;
    }
    let mount = if mounts.is_empty() {
        String::new()
    } else {
        format!(" for mount(s) {mounts:?}")
    };
    Some(format!(
        "Unix socket peer held by FUSE server PID {}{mount}",
        peer.pid
    ))
}

/// Absence of owner attribution cannot release an SFTP subsystem transport.
fn unresolved_ssh_refusal(pid: u32, comm: &str) -> Option<String> {
    if comm.trim_end() != "ssh" {
        return None;
    }
    let path = format!("/proc/{pid}/cmdline");
    match read_bounded(Path::new(&path), 128 * 1024)
        .ok().and_then(|cmdline| is_sftp_subsystem(&cmdline))
    {
        Some(false) => None,
        None => Some(format!("{RULE}: SSH subsystem arguments unavailable; cannot exclude a live filesystem transport")),
        Some(true) => Some(format!("{RULE}: mount ownership is unresolved; an orphaned SSH SFTP subsystem can still carry live filesystem traffic; inspect the mount and transport before taking action")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_parser_respects_argument_and_command_boundaries() {
        let classify = |args: &[&str]| is_sftp_subsystem((args.join("\0") + "\0").as_bytes());
        for args in [
            vec![
                "ssh",
                "-x",
                "-a",
                "-oClearAllForwardings=yes",
                "-oBatchMode=yes",
                "user@host",
                "-s",
                "sftp",
            ],
            vec!["ssh", "-Ts", "-p", "2222", "host", "sftp"],
            vec![
                "/usr/bin/ssh",
                "-o",
                "sessionTYPE=subsystem",
                "host",
                "sftp",
            ],
        ] {
            assert_eq!(classify(&args), Some(true), "{args:?}");
        }
        for args in [
            vec!["ssh", "host", "echo", "-s", "sftp"],
            vec!["ssh", "host", "sftp"],
            vec!["ssh", "-s", "host", "custom-subsystem"],
            vec!["ssh", "-S", "-s", "host", "sftp"],
            vec![
                "ssh",
                "-o",
                "ProxyCommand=ssh other -s sftp",
                "host",
                "sftp",
            ],
        ] {
            assert_eq!(classify(&args), Some(false), "{args:?}");
        }
        assert_eq!(is_sftp_subsystem(b"ssh\0-s\0host\0sftp"), None);
        assert_eq!(is_sftp_subsystem(b""), None);
        assert_eq!(is_sftp_subsystem(b"ssh: rewritten title\0"), None);
    }

    #[test]
    fn only_reverse_connected_unix_socket_owner_rows_establish_peer_evidence() {
        let rows = concat!(
            "u_str ESTAB 0 0 * 200 * 100 users:((\"sshfs\",pid=42,fd=4))\n",
            "u_str ESTAB 0 0 * 100 * 200 users:((\"ssh\",pid=43,fd=0))\n",
            "u_str ESTAB 0 0 * 100 * 100 users:((\"wrong\",pid=44,fd=5))\n",
            "u_str ESTAB 0 0 * 401 * 0 users:((\"missing\",pid=45,fd=6))\n",
            "u_str LISTEN 0 0 * 500 * 100 users:((\"wrong\",pid=46,fd=0))\n",
        );
        assert_eq!(
            index_peers(rows).remove(&100).unwrap(),
            [Peer {
                target_inode: 100,
                server_inode: 200,
                pid: 42,
                fd: 4
            }]
        );
    }

    #[test]
    fn confirmed_unix_peer_protects_any_stdio_helper_and_rechecks_reused_fds() {
        use std::cell::Cell;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::{net::UnixStream, process::CommandExt};
        use std::process::{Command, Stdio};

        let (peer, transport) = UnixStream::pair().unwrap();
        let owner_pid = std::process::id();
        let fd = peer.as_raw_fd();
        let keep_peer = peer.try_clone().unwrap();
        let mut child = Command::new("/bin/sh")
            .arg0("ssh")
            .args(["-c", "read -r line", "host", "/usr/libexec/sftp-server"])
            .stdin(Stdio::from(OwnedFd::from(transport)))
            .spawn()
            .unwrap();
        let pid = child.id();
        let local = socket_inode(owner_pid, fd as u32).unwrap();
        let remote = socket_inode(pid, 0).unwrap();
        let rows = format!(
            "u_str ESTAB 0 0 * {local} * {remote} users:((\"server\",pid={owner_pid},fd={fd}))"
        );
        let calls = Cell::new(0);
        let read = || {
            calls.set(calls.get() + 1);
            Some(index_peers(&rows))
        };
        let mount = |server| (server == owner_pid).then(|| vec!["/owned".to_owned()]);
        let lookup = FusePeerLookup::default();
        for name in ["custom-helper", "ssh"] {
            assert!(lookup
                .refusal_with(pid, name, read, mount)
                .unwrap()
                .contains("/owned"));
            assert!(
                lookup.refusal_with(pid, name, read, |_| None).is_none(),
                "an unrelated ordinary peer does not establish mount protection"
            );
        }
        assert_eq!(calls.get(), 1);

        // Replace the server's numeric FD while retaining the original endpoint
        // through another descriptor. The old ss entry must no longer match.
        let (unrelated, _other) = UnixStream::pair().unwrap();
        // SAFETY: both FDs refer to socket endpoints owned by this test.
        assert_eq!(unsafe { libc::dup2(unrelated.as_raw_fd(), fd) }, fd);
        assert!(lookup.refusal_with(pid, "ssh", read, mount).is_none());
        assert!(lookup
            .refusal_with(pid, "other-helper", read, mount)
            .is_none());
        assert_eq!(calls.get(), 1);
        let fresh = FusePeerLookup::default();
        assert!(fresh
            .refusal_with(pid, "other-helper", || None, mount)
            .is_none());
        drop(keep_peer);
        child.wait().unwrap();
    }

    #[test]
    fn live_subsystem_with_socketpair_is_refused_without_mount_or_owner_visibility() {
        use crate::action::prechecks::{fuse_target_precheck, PreCheckResult};
        use crate::decision::Action;
        use std::io::{BufRead, BufReader, Write};
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::{net::UnixStream, process::CommandExt};
        use std::process::{Command, Stdio};

        let (mut peer, stdio) = UnixStream::pair().unwrap();
        let mut child = Command::new("/bin/sh")
            .arg0("ssh")
            .args(["-s", "host", "sftp"])
            .stdin(Stdio::from(OwnedFd::from(stdio)))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        peer.write_all(b"printf ssh >/proc/self/comm; printf 'ready\\n'; read -r finish\n")
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let pid = child.id();
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
        assert_eq!(ready.trim(), "ready");
        assert_eq!(comm.trim(), "ssh");
        // Stand-in protected owner, genuine Unix socketpair, process births
        // and procfs FD links. A stale/wrong fd must not be attributed.
        let mut owner = Peer {
            pid: std::process::id(),
            fd: peer.as_raw_fd() as u32,
            server_inode: socket_inode(std::process::id(), peer.as_raw_fd() as u32).unwrap(),
            target_inode: socket_inode(pid, 0).unwrap(),
        };
        let mount = |server| (server == std::process::id()).then(|| vec!["/stand-in".to_string()]);
        let description = confirm_peer(pid, &owner, mount).unwrap();
        assert!(description.contains("/stand-in"));
        assert!(description.contains(&format!("PID {}", owner.pid)));
        owner.server_inode = owner.target_inode;
        assert!(confirm_peer(pid, &owner, mount).is_none());
        let evidence = super::super::protected::holds_fuse_device(pid);
        assert_eq!(evidence, Some(false));
        for action in [
            Action::Pause,
            Action::Freeze,
            Action::Kill,
            Action::Restart,
            Action::Renice,
            Action::Throttle,
            Action::CapMemory,
            Action::Quarantine,
        ] {
            let result = fuse_target_precheck(pid, &comm, evidence, action);
            assert!(
                matches!(result, PreCheckResult::Blocked { ref reason, .. } if reason.contains(RULE)),
                "{action:?}: {result:?}"
            );
        }
        for action in [
            Action::Keep,
            Action::Resume,
            Action::Unfreeze,
            Action::Unquarantine,
        ] {
            assert!(fuse_target_precheck(pid, &comm, evidence, action).is_passed());
        }
        drop(peer);
        child.wait().unwrap();
    }
}
