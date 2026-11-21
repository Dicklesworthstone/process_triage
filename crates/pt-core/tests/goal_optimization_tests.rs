use pt_core::decision::goal_optimizer::{
    optimize_dp, optimize_greedy, optimize_greedy_with_preferences, optimize_ilp,
    reoptimize_on_change, AlternativePlan, GoalAchievement, OptCandidate, PreferenceModel,
    ResourceGoal,
};
use pt_core::decision::goal_parser::{parse_goal, Goal};
use pt_core::decision::goal_plan::{optimize_goal_plan, PlanCandidate, PlanConstraints};

#[cfg(target_os = "linux")]
mod live_descriptor_goals {
    use super::parse_goal;
    use pt_core::decision::goal_contribution::GoalResourceSnapshot;
    use std::io::{BufRead, Write};
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    struct SocketHolder {
        child: Child,
        events: Receiver<std::io::Result<String>>,
        reader: Option<std::thread::JoinHandle<()>>,
        tid: u32,
    }

    impl Drop for SocketHolder {
        fn drop(&mut self) {
            // This child remains owned and unreaped, so the PID cannot refer to
            // another process. Killing it also terminates its fixture thread.
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    impl SocketHolder {
        fn spawn(listener: &TcpListener, private_table: bool) -> Option<Self> {
            const SCRIPT: &str = r#"
import ctypes, os, queue, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int
private_table = sys.argv[1] == 'private'
ready = queue.Queue()
close_socket = threading.Event()
socket_closed = threading.Event()
finish = threading.Event()
def worker():
    if private_table and libc.unshare(0x400) != 0:
        ready.put(('unsupported', ctypes.get_errno()))
        return
    ready.put(('ready', threading.get_native_id()))
    close_socket.wait()
    os.close(2)
    socket_closed.set()
    finish.wait()
thread = threading.Thread(target=worker)
thread.start()
event = ready.get(timeout=5)
if event[0] == 'unsupported':
    print(*event, flush=True)
    thread.join()
    sys.exit(0)
if private_table:
    os.close(2)
print(*event, flush=True)
try:
    for line in sys.stdin:
        if line.strip() == 'close-socket':
            close_socket.set()
            if not socket_closed.wait(5):
                raise RuntimeError('worker failed to close owned socket')
            print('closed', flush=True)
finally:
    close_socket.set()
    finish.set()
    thread.join()
"#;
            let socket: OwnedFd = listener
                .try_clone()
                .expect("duplicate owned listener")
                .into();
            let mut command = Command::new("python3");
            command
                .args(["-u", "-c", SCRIPT])
                .arg(if private_table { "private" } else { "shared" })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::from(socket));
            let child = match command.spawn() {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("SKIP live descriptor goals: python3 is unavailable");
                    return None;
                }
                Err(error) => panic!("spawn owned socket holder: {error}"),
            };
            // Do not leave an extra listener reference in the parent command.
            drop(command);
            let (sender, events) = mpsc::channel();
            let mut holder = Self {
                child,
                events,
                reader: None,
                tid: 0,
            };
            let stdout = holder.child.stdout.take().expect("fixture stdout");
            holder.reader = Some(std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }));
            let ready = holder.event();
            if let Some(errno) = ready.strip_prefix("unsupported ") {
                let errno = errno.parse::<i32>().expect("numeric unshare error");
                assert!(
                    matches!(errno, libc::EPERM | libc::EACCES | libc::ENOSYS),
                    "unexpected unshare(CLONE_FILES) failure: {errno}"
                );
                eprintln!(
                    "SKIP private descriptor table: unshare(CLONE_FILES) unavailable: {}",
                    std::io::Error::from_raw_os_error(errno)
                );
                return None;
            }
            holder.tid = ready
                .strip_prefix("ready ")
                .expect("owned worker readiness")
                .parse()
                .expect("numeric worker identity");
            assert_ne!(holder.tid, holder.child.id());
            Some(holder)
        }

        fn event(&self) -> String {
            self.events
                .recv_timeout(Duration::from_secs(10))
                .expect("bounded owned socket-holder response")
                .expect("read owned socket-holder response")
        }

        fn close_socket(&mut self) {
            writeln!(
                self.child.stdin.as_mut().expect("fixture stdin"),
                "close-socket"
            )
            .expect("request owned socket close");
            assert_eq!(self.event(), "closed");
        }

        fn worker_descriptor(&self) -> std::path::PathBuf {
            format!("/proc/{}/task/{}/fd/2", self.child.id(), self.tid).into()
        }
    }

    fn assert_observed_holders(snapshot: &GoalResourceSnapshot, port: u16, pids: &[u32]) {
        let observed = &snapshot.ports[&port];
        assert!(observed.bound_socket_count.is_some_and(|count| count > 0));
        if let Some(holders) = &observed.holders {
            for pid in pids {
                assert!(
                    holders.iter().any(|holder| holder.pid.0 == *pid),
                    "port {port} remains held by pid {pid}: {observed:?}"
                );
            }
        } else {
            // CI may prohibit inspecting unrelated users' processes. Such an
            // incomplete census must be explicit and cannot become A-only
            // ownership. Deterministic sampler tests cover that regression
            // independently of these host permissions.
            assert!(snapshot
                .warnings
                .contains(&format!("port_{port}_ownership_incomplete")));
            eprintln!("live port census remains unknown: {:?}", snapshot.warnings);
        }
    }

    #[test]
    fn port_census_retains_private_worker_holder_of_another_process_socket() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind owned listener");
        let address = listener.local_addr().expect("owned listener address");
        let expected_socket = std::fs::read_link(format!("/proc/self/fd/{}", listener.as_raw_fd()))
            .expect("owned socket inode");
        let Some(mut holder) = SocketHolder::spawn(&listener, true) else {
            return;
        };
        assert_eq!(
            std::fs::read_link(holder.worker_descriptor()).expect("private worker socket"),
            expected_socket
        );
        assert_eq!(
            std::fs::read_link(format!("/proc/{}/fd/2", holder.child.id()))
                .expect_err("leader closed its copy")
                .kind(),
            std::io::ErrorKind::NotFound
        );

        let goal = parse_goal(&format!("free port {}", address.port())).unwrap();
        // Passing no candidates must not hide either process from ownership.
        let observed = GoalResourceSnapshot::collect(&goal, &[]);
        assert_observed_holders(
            &observed,
            address.port(),
            &[std::process::id(), holder.child.id()],
        );

        // Releasing the visible owner's copy does not release the port: the
        // non-leader's private table still owns this exact socket inode.
        drop(listener);
        assert_eq!(
            TcpListener::bind(address)
                .expect_err("private worker still retains the listener")
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        assert_eq!(
            std::fs::read_link(holder.worker_descriptor()).unwrap(),
            expected_socket
        );

        // An owned negative control proves that the worker reference, rather
        // than a leaked parent descriptor, was what kept the port occupied.
        holder.close_socket();
        let _rebound = TcpListener::bind(address).expect("port freed after last owner closes");
    }

    #[test]
    fn fd_goal_does_not_count_a_shared_thread_descriptor_table_twice() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind owned listener");
        let Some(holder) = SocketHolder::spawn(&listener, false) else {
            return;
        };
        let population = pt_core::collect::quick_scan(&pt_core::collect::QuickScanOptions {
            pids: vec![holder.child.id()],
            ..Default::default()
        })
        .expect("observe owned multithreaded process")
        .processes;
        let process = population
            .iter()
            .find(|process| process.pid.0 == holder.child.id())
            .expect("owned process in census");
        let identity =
            pt_common::ProcessIdentity::new(process.pid.0, process.start_id.clone(), process.uid);
        let count = std::fs::read_dir(format!("/proc/{}/fd", holder.child.id()))
            .expect("owned leader descriptor table")
            .collect::<Result<Vec<_>, _>>()
            .expect("complete owned descriptor entries")
            .len() as u64;
        assert!(count >= 3, "stdio descriptors are held by both threads");
        let observed =
            GoalResourceSnapshot::collect(&parse_goal("free 1 fd").unwrap(), &population);
        assert_eq!(observed.fd_count(&identity), Some(count));
    }
}

#[test]
fn memory_pressure_risk_budget_prefers_low_risk_set() {
    let candidates = vec![
        PlanCandidate {
            pid: 1,
            expected_contribution: 5.0,
            confidence: 0.95,
            risk: 1.0,
            is_protected: false,
            uid: 1000,
            label: "A".to_string(),
        },
        PlanCandidate {
            pid: 2,
            expected_contribution: 3.0,
            confidence: 0.9,
            risk: 1.0,
            is_protected: false,
            uid: 1000,
            label: "B".to_string(),
        },
        PlanCandidate {
            pid: 3,
            expected_contribution: 8.0,
            confidence: 0.6,
            risk: 10.0,
            is_protected: false,
            uid: 1000,
            label: "C".to_string(),
        },
    ];

    let constraints = PlanConstraints {
        goal_target: 10.0,
        max_total_risk: 3.0,
        ..Default::default()
    };

    let plans = optimize_goal_plan(&candidates, &constraints);
    assert!(!plans.is_empty());

    let matched = plans.iter().any(|plan| {
        let pids: Vec<u32> = plan.actions.iter().map(|a| a.pid).collect();
        pids.contains(&1) && pids.contains(&2) && !pids.contains(&3) && !plan.goal_achievable
    });
    assert!(
        matched,
        "expected a plan that picks A+B and reports shortfall"
    );
}

#[test]
fn dp_minimize_kills_prefers_single_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 1.5,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_dp(&candidates, &goals, 1.0);
    assert!(result.feasible);
    assert_eq!(result.selected.len(), 1);
    assert_eq!(result.selected[0].id, "C");
}

#[test]
fn ilp_minimize_kills_prefers_single_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 1.5,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert_eq!(result.algorithm, "ilp_branch_bound");
    assert!(result.feasible);
    assert_eq!(result.selected.len(), 1);
    assert_eq!(result.selected[0].id, "C");
}

#[test]
fn ilp_infeasible_falls_back() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert!(result.algorithm.contains("infeasible"));
    assert!(!result.feasible);
    assert!(result.goal_achievement[0].shortfall > 0.0);
}

#[test]
fn confidence_threshold_filters_candidates() {
    let candidates = vec![
        PlanCandidate {
            pid: 10,
            expected_contribution: 2.0,
            confidence: 0.99,
            risk: 0.5,
            is_protected: false,
            uid: 1000,
            label: "high".to_string(),
        },
        PlanCandidate {
            pid: 11,
            expected_contribution: 10.0,
            confidence: 0.8,
            risk: 0.5,
            is_protected: false,
            uid: 1000,
            label: "low".to_string(),
        },
    ];

    let constraints = PlanConstraints {
        goal_target: 2.0,
        min_confidence: 0.95,
        ..Default::default()
    };

    let plans = optimize_goal_plan(&candidates, &constraints);
    assert!(!plans.is_empty());
    for plan in plans {
        assert!(plan.actions.iter().all(|a| a.pid == 10));
    }
}

#[test]
fn greedy_prefers_higher_efficiency_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 5.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 0.5,
            contributions: vec![1.98],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 1.5,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.selected.is_empty());
    assert_eq!(result.selected[0].id, "B");
}

#[test]
fn infeasible_goal_reports_shortfall() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.feasible);
    assert_eq!(result.goal_achievement.len(), 1);
    assert!(result.goal_achievement[0].shortfall > 0.0);
}

#[test]
fn composite_goal_parser_accepts_and() {
    let goal = parse_goal("free 4GB RAM AND release port 3000").unwrap();
    assert!(matches!(goal, Goal::And(ref parts) if parts.len() == 2));
}

#[test]
fn alternatives_include_tradeoff_variants() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 0.2,
            contributions: vec![150.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 0.4,
            contributions: vec![120.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 0.6,
            contributions: vec![110.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 200.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.alternatives.is_empty());
    assert!(result
        .alternatives
        .iter()
        .any(|alt| alt.action_count != result.selected.len()));
}

#[test]
fn pareto_frontier_excludes_dominated_sets() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 3.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 1.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    let pareto: Vec<_> = result
        .alternatives
        .iter()
        .filter(|alt| alt.description.starts_with("Pareto:"))
        .collect();

    assert!(!pareto.is_empty(), "expected Pareto alternatives");

    let losses: Vec<f64> = pareto.iter().map(|alt| alt.total_loss).collect();
    let mut sorted = losses.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    assert_eq!(
        losses, sorted,
        "Pareto alternatives should be sorted by loss"
    );

    let dominated_c = pareto.iter().any(|alt| {
        alt.action_count == 1
            && (alt.total_loss - 3.0).abs() < 1e-6
            && alt.goal_achievement[0].achieved >= 6.0 - 1e-6
    });
    assert!(
        !dominated_c,
        "dominated set should not be on Pareto frontier"
    );
}

#[test]
fn telemetry_emits_objective_and_convergence() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(result
        .log_events
        .iter()
        .any(|e| { e.event == "objective_eval" && e.candidate_id.is_some() && e.loss.is_some() }));
    assert!(result
        .log_events
        .iter()
        .any(|e| { e.event == "converged" && e.total_loss.is_some() }));
}

#[test]
fn telemetry_emits_pareto_points() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 0.5,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 2.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(result.log_events.iter().any(|e| e.event == "pareto_point"));
}

#[test]
fn telemetry_emits_constraint_prune() {
    let candidates = vec![OptCandidate {
        id: "A".to_string(),
        expected_loss: 1.0,
        contributions: vec![1.0],
        blocked: false,
        block_reason: None,
    }];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert!(result
        .log_events
        .iter()
        .any(|e| e.event == "constraint_prune"));
}

#[test]
fn weighted_multi_goal_priority_changes_selection_order() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 2.0,
            contributions: vec![10.0, 0.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0, 5.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let memory_heavy_goals = vec![
        ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 8.0,
            weight: 10.0,
        },
        ResourceGoal {
            resource: "cpu_pct".to_string(),
            target: 1.0,
            weight: 1.0,
        },
    ];
    let cpu_heavy_goals = vec![
        ResourceGoal {
            resource: "memory_mb".to_string(),
            target: 1.0,
            weight: 1.0,
        },
        ResourceGoal {
            resource: "cpu_pct".to_string(),
            target: 1.0,
            weight: 10.0,
        },
    ];

    let memory_first = optimize_greedy(&candidates, &memory_heavy_goals);
    let cpu_first = optimize_greedy(&candidates, &cpu_heavy_goals);

    assert_eq!(memory_first.selected[0].id, "A");
    assert_eq!(cpu_first.selected[0].id, "B");
}

#[test]
fn blocked_candidates_are_excluded_and_logged() {
    let candidates = vec![
        OptCandidate {
            id: "blocked".to_string(),
            expected_loss: 0.1,
            contributions: vec![100.0],
            blocked: true,
            block_reason: Some("protected".to_string()),
        },
        OptCandidate {
            id: "allowed".to_string(),
            expected_loss: 1.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(result.selected.iter().all(|s| s.id != "blocked"));
    assert!(result
        .log_events
        .iter()
        .any(|e| e.event == "constraint_violation"
            && e.note.as_deref() == Some("blocked_candidates=1")));
}

#[test]
fn ilp_constraint_prune_event_has_diagnostics() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![1.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![1.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    let prune_event = result
        .log_events
        .iter()
        .find(|e| e.event == "constraint_prune")
        .expect("expected constraint_prune event");
    assert!(prune_event.current_contribution.is_some());
    assert!(prune_event.remaining_max.is_some());
    assert_eq!(prune_event.target, Some(5.0));
}

#[test]
fn reoptimize_skips_when_no_change() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&candidates, &goals);
    let decision = reoptimize_on_change(&previous, &candidates, &candidates, &goals);
    assert!(!decision.reoptimized);
    assert_eq!(decision.reason, "no_change");
}

#[test]
fn reoptimize_when_selected_missing() {
    let prev_candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&prev_candidates, &goals);
    let new_candidates = vec![OptCandidate {
        id: "B".to_string(),
        expected_loss: 2.0,
        contributions: vec![4.0],
        blocked: false,
        block_reason: None,
    }];
    let decision = reoptimize_on_change(&previous, &prev_candidates, &new_candidates, &goals);
    assert!(decision.reoptimized);
    assert_eq!(decision.reason, "selected_missing");
}

#[test]
fn reoptimize_on_churn_threshold() {
    let prev_candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 3.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "D".to_string(),
            expected_loss: 4.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "E".to_string(),
            expected_loss: 5.0,
            contributions: vec![7.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&prev_candidates, &goals);
    let mut new_candidates = prev_candidates.clone();
    new_candidates.push(OptCandidate {
        id: "F".to_string(),
        expected_loss: 6.0,
        contributions: vec![8.0],
        blocked: false,
        block_reason: None,
    });
    new_candidates.push(OptCandidate {
        id: "G".to_string(),
        expected_loss: 7.0,
        contributions: vec![9.0],
        blocked: false,
        block_reason: None,
    });
    let decision = reoptimize_on_change(&previous, &prev_candidates, &new_candidates, &goals);
    assert!(decision.reoptimized);
    assert_eq!(decision.reason, "churn_threshold");
}

#[test]
fn preference_update_moves_toward_choice() {
    let mut model = PreferenceModel {
        risk_tolerance: 0.1,
        learning_rate: 0.5,
    };
    let alternatives = vec![
        AlternativePlan {
            description: "low".to_string(),
            action_count: 1,
            total_loss: 1.0,
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 1.0,
                achieved: 1.0,
                shortfall: 0.0,
                met: true,
            }],
        },
        AlternativePlan {
            description: "high".to_string(),
            action_count: 1,
            total_loss: 3.0,
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 1.0,
                achieved: 1.0,
                shortfall: 0.0,
                met: true,
            }],
        },
    ];

    let update = model.update_from_choice(&alternatives[1], &alternatives);
    assert!(update.updated > update.prior);
}

#[test]
fn preference_influences_selection() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 5.0,
            contributions: vec![15.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 20.0,
        weight: 1.0,
    }];
    let aggressive = PreferenceModel {
        risk_tolerance: 1.0,
        learning_rate: 0.2,
    };
    let conservative = PreferenceModel {
        risk_tolerance: 0.0,
        learning_rate: 0.2,
    };

    let result_aggressive = optimize_greedy_with_preferences(&candidates, &goals, &aggressive);
    let result_conservative = optimize_greedy_with_preferences(&candidates, &goals, &conservative);

    assert_eq!(result_aggressive.selected[0].id, "A");
    assert_eq!(result_conservative.selected[0].id, "B");
}
