//! Live-system integration tests for network collectors.
//!
//! These tests are Linux-only and do not use mocks. They validate that
//! network collectors can observe real sockets created by the harness.

#![cfg(target_os = "linux")]

use pt_core::collect::{collect_network_info, NetworkSnapshot};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

mod support;
use support::live_harness::LiveHarness;

fn skip_if_proc_unavailable() -> bool {
    if !std::path::Path::new("/proc").exists() {
        eprintln!("skipping: /proc not available on this system");
        return true;
    }
    false
}

#[test]
fn live_network_collects_tcp_udp_unix() {
    if skip_if_proc_unavailable() {
        return;
    }

    let mut harness = LiveHarness::new().expect("harness init");
    let _tcp_port = harness.open_tcp_connection().expect("open tcp");
    let _udp_port = harness.open_udp_socket().expect("open udp");

    #[cfg(unix)]
    {
        let _unix_path = harness.open_unix_socket().expect("open unix socket");
    }

    let pid = harness.pid();
    let network = collect_network_info(pid).expect("collect_network_info");

    let tcp_listen = network
        .listen_ports
        .iter()
        .any(|p| p.protocol == "tcp" || p.protocol == "tcp6");
    assert!(tcp_listen, "expected at least one tcp listen port");

    let tcp_established = network.tcp_connections.iter().any(|c| c.state.is_active());
    assert!(tcp_established, "expected an active tcp connection");

    let udp_present = network.udp_sockets.iter().any(|s| s.local_port > 0);
    assert!(udp_present, "expected at least one udp socket");

    #[cfg(unix)]
    {
        let unix_present = network.unix_sockets.iter().any(|s| s.inode > 0);
        assert!(unix_present, "expected at least one unix socket");
    }
}

struct NamespaceListener {
    child: Child,
    pid: u32,
    port: u16,
}

impl NamespaceListener {
    fn spawn(isolated: bool, port: u16) -> Self {
        let executable = std::env::current_exe().expect("current test executable");
        let mut command = if isolated {
            let mut command = Command::new("unshare");
            command
                .args(["--user", "--map-root-user", "--net"])
                .arg(&executable);
            command
        } else {
            Command::new(executable)
        };
        let child = command
            .args([
                "--exact",
                "namespace_listener_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PT_NETWORK_NAMESPACE_LISTENER", port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start an owned namespace listener");
        let mut owned = Self {
            child,
            pid: 0,
            port: 0,
        };
        let stdout = owned.child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(ready) = line.strip_prefix("PT_NETWORK_READY ") {
                    let _ = send.send(ready.to_string());
                    break;
                }
            }
        });
        let ready = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("owned listener becomes ready within a bounded interval");
        let mut fields = ready.split_whitespace();
        owned.pid = fields.next().unwrap().parse().unwrap();
        owned.port = fields.next().unwrap().parse().unwrap();
        assert!(fields.next().is_none());
        owned
    }
}

impl Drop for NamespaceListener {
    fn drop(&mut self) {
        // Only the child created by this test is signaled and reaped. Killing
        // also bounds cleanup when an assertion fails before its stdin closes.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn namespace_listener_child() {
    let Ok(port) = std::env::var("PT_NETWORK_NAMESPACE_LISTENER") else {
        return;
    };
    let listener = std::net::TcpListener::bind(("0.0.0.0", port.parse::<u16>().unwrap()))
        .expect("listen inside the selected network namespace");
    println!(
        "\nPT_NETWORK_READY {} {}",
        std::process::id(),
        listener.local_addr().unwrap().port()
    );
    std::io::stdout().flush().unwrap();
    let mut release = String::new();
    std::io::stdin().read_line(&mut release).unwrap();
    drop(listener);
}

#[test]
fn live_snapshot_observes_private_namespaces_without_false_port_conflicts() {
    let capability = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .output();
    match capability {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!(
                "skipping private namespace integration: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        Err(error) => {
            eprintln!("skipping private namespace integration: {error}");
            return;
        }
    }
    let host = NamespaceListener::spawn(false, 0);
    let private = NamespaceListener::spawn(true, host.port);
    let snapshot = NetworkSnapshot::collect();
    let host_info = snapshot
        .get_process_info_checked(host.pid)
        .expect("host listener observation");
    let private_info = snapshot
        .get_process_info_checked(private.pid)
        .expect("private listener observation");
    assert_ne!(host_info.namespace, private_info.namespace);
    assert!(host_info
        .listen_ports
        .iter()
        .any(|socket| socket.port == host.port));
    assert!(private_info
        .listen_ports
        .iter()
        .any(|socket| socket.port == host.port));

    let mut resources =
        pt_core::collect::network_resource_collector::collect_listener_resources_from_checked(
            host.pid, &snapshot,
        )
        .unwrap();
    resources.extend(
        pt_core::collect::network_resource_collector::collect_listener_resources_from_checked(
            private.pid,
            &snapshot,
        )
        .unwrap(),
    );
    assert_eq!(
        resources
            .iter()
            .filter(|resource| resource.kind == pt_common::ResourceKind::Listener)
            .count(),
        2
    );
    assert!(pt_core::collect::detect_listener_conflicts(&resources).is_empty());
}
