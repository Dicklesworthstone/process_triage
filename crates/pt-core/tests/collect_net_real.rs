// Reads /proc/net/*: nothing to check on other platforms.
#![cfg(all(feature = "test-utils", target_os = "linux"))]

use pt_core::collect;
use pt_core::test_utils::ProcessHarness;

#[test]
fn test_proc_net_tcp_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness;

    // Bind to high port
    let port = 19345;
    // Use exec so the shell becomes the python process, keeping the PID
    let cmd = format!("exec python3 -c \"import socket, time; s=socket.socket(); s.bind(('127.0.0.1', {})); s.listen(); time.sleep(5)\"", port);

    let proc = harness.spawn_shell(&cmd).expect("spawn python listener");

    std::thread::sleep(std::time::Duration::from_millis(500));

    #[cfg(target_os = "linux")]
    {
        // Verify process is running
        if std::fs::read_to_string(format!("/proc/{}/stat", proc.pid())).is_err() {
            println!("Process {} exited early", proc.pid());
            return; // Python might not be installed
        }

        // Check /proc/net/tcp
        let tcp = collect::parse_proc_net_tcp("/proc/net/tcp", false).expect("read tcp");
        let found = tcp
            .iter()
            .any(|c| c.local_port == port && c.state.is_listen());

        assert!(found, "Port {} not found in /proc/net/tcp", port);

        // Check per-process correlation (inode matching)
        // This requires permission to read /proc/<pid>/fd/
        let info = collect::collect_network_info(proc.pid());

        if let Some(info) = info {
            let matched = info.listen_ports.iter().any(|p| p.port == port);
            assert!(
                matched,
                "Port {} not attributed to process {}",
                port,
                proc.pid()
            );
        }
    }
}

#[test]
fn test_proc_net_udp_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness;
    let port = 19346;
    // Python UDP
    let cmd = format!("exec python3 -c \"import socket, time; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', {})); time.sleep(5)\"", port);

    let _proc = harness.spawn_shell(&cmd).expect("spawn python udp");
    std::thread::sleep(std::time::Duration::from_millis(500));

    #[cfg(target_os = "linux")]
    {
        let udp = collect::parse_proc_net_udp("/proc/net/udp", false).expect("read udp");
        let found = udp.iter().any(|c| c.local_port == port);
        assert!(found, "Port {} not found in /proc/net/udp", port);
    }
}
