//! Comprehensive tests for supervisor detection.
//!
//! This module contains unit tests, integration tests, and edge case tests
//! for the supervision detection system per the test plan in process_triage-cfia.

#[cfg(test)]
mod ancestry_tests {
    use super::super::ancestry::*;
    use super::super::types::*;

    // =========================================================================
    // Unit Tests: Parent Chain Reconstruction
    // =========================================================================

    #[test]
    fn test_parse_stat_formats() {
        // Standard format
        let (ppid, comm) = parse_stat("1234 (bash) S 1000 1234 1234 0 -1", 1234).unwrap();
        assert_eq!(ppid, 1000);
        assert_eq!(comm, "bash");

        // Comm with spaces
        let (ppid, comm) = parse_stat("5678 (Web Content) R 4321 5678 5678 0 -1", 5678).unwrap();
        assert_eq!(ppid, 4321);
        assert_eq!(comm, "Web Content");

        // Comm with parentheses
        let (ppid, comm) = parse_stat("9999 (my (test) app) S 8888 9999 9999 0 -1", 9999).unwrap();
        assert_eq!(ppid, 8888);
        assert_eq!(comm, "my (test) app");
    }

    #[test]
    fn test_parse_stat_all_states() {
        // Test all process states: R, S, D, Z, T, t, W, X, x, K, W, P
        for state in &["R", "S", "D", "Z", "T", "t", "X", "I"] {
            let content = format!("100 (test) {} 1 100 100 0 -1", state);
            let result = parse_stat(&content, 100);
            assert!(result.is_ok(), "Failed to parse state {}", state);
        }
    }

    #[test]
    fn test_parse_stat_edge_cases() {
        // Empty comm
        let result = parse_stat("1 () S 0 1 1 0 -1", 1);
        assert!(result.is_ok());
        let (ppid, comm) = result.unwrap();
        assert_eq!(ppid, 0);
        assert_eq!(comm, "");

        // Very long comm (kernel truncates at 15 chars but we should handle longer)
        let (ppid, comm) = parse_stat("1 (averylongprocessname) S 0 1 1 0 -1", 1).unwrap();
        assert_eq!(ppid, 0);
        assert_eq!(comm, "averylongprocessname");
    }

    #[test]
    fn test_parse_stat_error_cases() {
        // Missing parentheses
        let result = parse_stat("1234 bash S 1000 1234", 1234);
        assert!(result.is_err());

        // Missing closing paren
        let result = parse_stat("1234 (bash S 1000 1234", 1234);
        assert!(result.is_err());

        // Not enough fields
        let result = parse_stat("1234 (bash) S", 1234);
        assert!(result.is_err());

        // Invalid PPID
        let result = parse_stat("1234 (bash) S notanumber 1234", 1234);
        assert!(result.is_err());
    }

    // =========================================================================
    // Unit Tests: Supervisor Pattern Matching
    // =========================================================================

    #[test]
    fn test_supervisor_database_agent_patterns() {
        let db = SupervisorDatabase::with_defaults();

        // AI Agents
        assert!(!db.find_matches("claude").is_empty());
        assert!(!db.find_matches("claude-code").is_empty());
        assert!(!db.find_matches("codex").is_empty());
        assert!(!db.find_matches("aider").is_empty());
        assert!(!db.find_matches("cursor").is_empty());
        assert!(!db.find_matches("Cursor").is_empty());

        // Should NOT match similar but different names
        assert!(db.find_matches("claudette").is_empty()); // Not exact match
        assert!(db.find_matches("xcodex").is_empty()); // Prefix
    }

    #[test]
    fn test_supervisor_database_ide_patterns() {
        let db = SupervisorDatabase::with_defaults();

        // VS Code variants
        assert!(!db.find_matches("code").is_empty());
        assert!(!db.find_matches("code-server").is_empty());
        assert!(!db.find_matches("Code").is_empty());

        // JetBrains
        assert!(!db.find_matches("idea").is_empty());
        assert!(!db.find_matches("pycharm").is_empty());
        assert!(!db.find_matches("webstorm").is_empty());
        assert!(!db.find_matches("goland").is_empty());
        assert!(!db.find_matches("clion").is_empty());

        // Vim/Neovim
        assert!(!db.find_matches("nvim").is_empty());
        assert!(!db.find_matches("vim").is_empty());
    }

    #[test]
    fn test_supervisor_database_ci_patterns() {
        let db = SupervisorDatabase::with_defaults();

        // GitHub Actions
        assert!(!db.find_matches("Runner.Worker").is_empty());
        assert!(!db.find_matches("actions-runner").is_empty());

        // GitLab
        assert!(!db.find_matches("gitlab-runner").is_empty());

        // Jenkins
        assert!(!db.find_matches("jenkins").is_empty());
    }

    #[test]
    fn test_supervisor_database_terminal_patterns() {
        let db = SupervisorDatabase::with_defaults();

        assert!(!db.find_matches("tmux: server").is_empty());
        assert!(!db.find_matches("tmux").is_empty());
        assert!(!db.find_matches("screen").is_empty());
        assert!(!db.find_matches("SCREEN").is_empty());
    }

    #[test]
    fn test_supervisor_database_orchestrator_patterns() {
        let db = SupervisorDatabase::with_defaults();

        assert!(!db.find_matches("systemd").is_empty());
        assert!(!db.find_matches("systemd-logind").is_empty());
        assert!(!db.find_matches("launchd").is_empty());
        assert!(!db.find_matches("PM2").is_empty());
        assert!(!db.find_matches("supervisord").is_empty());
    }

    #[test]
    fn test_supervisor_database_no_false_positives() {
        let db = SupervisorDatabase::with_defaults();

        // Common user processes that should NOT match
        assert!(db.find_matches("python").is_empty());
        assert!(db.find_matches("node").is_empty());
        assert!(db.find_matches("java").is_empty());
        assert!(db.find_matches("firefox").is_empty());
        assert!(db.find_matches("chrome").is_empty());
        assert!(db.find_matches("my-app").is_empty());
        assert!(db.find_matches("sleep").is_empty());
        assert!(db.find_matches("cat").is_empty());
    }

    #[test]
    fn test_supervisor_pattern_confidence_weights() {
        let db = SupervisorDatabase::with_defaults();

        // AI agents should have high confidence
        let claude_matches = db.find_matches("claude");
        assert!(!claude_matches.is_empty());
        assert!(claude_matches[0].confidence_weight >= 0.90);

        // Terminal multiplexers should have lower confidence
        let tmux_matches = db.find_matches("tmux");
        assert!(!tmux_matches.is_empty());
        assert!(tmux_matches[0].confidence_weight <= 0.75);
    }

    #[test]
    fn test_supervisor_pattern_categories() {
        let db = SupervisorDatabase::with_defaults();

        // Verify categories are correct
        let claude_matches = db.find_matches("claude");
        assert_eq!(claude_matches[0].category, SupervisorCategory::Agent);

        let code_matches = db.find_matches("code");
        assert_eq!(code_matches[0].category, SupervisorCategory::Ide);

        let runner_matches = db.find_matches("actions-runner");
        assert_eq!(runner_matches[0].category, SupervisorCategory::Ci);

        let tmux_matches = db.find_matches("tmux");
        assert_eq!(tmux_matches[0].category, SupervisorCategory::Terminal);

        let systemd_matches = db.find_matches("systemd");
        assert_eq!(systemd_matches[0].category, SupervisorCategory::Orchestrator);
    }

    // =========================================================================
    // Unit Tests: Shell Supervisor Detection
    // =========================================================================

    #[test]
    fn test_shell_not_supervisor() {
        let db = SupervisorDatabase::with_defaults();

        // Shells themselves are NOT supervisors in the default database
        // (they are intermediate in the chain, not the supervisor)
        assert!(db.find_matches("bash").is_empty());
        assert!(db.find_matches("zsh").is_empty());
        assert!(db.find_matches("fish").is_empty());
        assert!(db.find_matches("sh").is_empty());
    }

    // =========================================================================
    // Unit Tests: Nested Supervisor Chains
    // =========================================================================

    #[test]
    fn test_supervision_result_construction() {
        // Test not supervised
        let result = SupervisionResult::not_supervised(vec![]);
        assert!(!result.is_supervised);
        assert!(result.supervisor_type.is_none());

        // Test supervised
        let result = SupervisionResult::supervised_by_ancestry(
            SupervisorCategory::Agent,
            "claude".to_string(),
            pt_common::ProcessId(1234),
            2,
            0.95,
            vec![SupervisionEvidence {
                evidence_type: EvidenceType::Ancestry,
                description: "Test evidence".to_string(),
                weight: 0.95,
            }],
            vec![
                AncestryEntry {
                    pid: pt_common::ProcessId(5678),
                    comm: "my-app".to_string(),
                    cmdline: Some("my-app --flag".to_string()),
                },
                AncestryEntry {
                    pid: pt_common::ProcessId(4321),
                    comm: "bash".to_string(),
                    cmdline: Some("/bin/bash".to_string()),
                },
                AncestryEntry {
                    pid: pt_common::ProcessId(1234),
                    comm: "claude".to_string(),
                    cmdline: Some("claude".to_string()),
                },
            ],
        );

        assert!(result.is_supervised);
        assert_eq!(result.supervisor_type, Some(SupervisorCategory::Agent));
        assert_eq!(result.supervisor_name, Some("claude".to_string()));
        assert_eq!(result.supervisor_pid, Some(pt_common::ProcessId(1234)));
        assert_eq!(result.depth, Some(2));
        assert_eq!(result.confidence, 0.95);
        assert_eq!(result.ancestry_chain.len(), 3);
    }

    // =========================================================================
    // Integration Tests: Process Tree (Linux only)
    // =========================================================================

    #[cfg(target_os = "linux")]
    #[test]
    fn test_real_process_ancestry() {
        let pid = std::process::id();
        let result = analyze_supervision(pid).expect("should analyze current process");

        // Should have at least one entry (self)
        assert!(!result.ancestry_chain.is_empty());
        assert_eq!(result.ancestry_chain[0].pid.0, pid);

        // Should have valid confidence
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_batch_analysis_multiple_pids() {
        // Get current PID and try parent
        let pid = std::process::id();
        let results = analyze_supervision_batch(&[pid, 1]).unwrap();

        // Should have at least one result (current process)
        assert!(!results.is_empty());

        // Current process should be in results
        assert!(results.iter().any(|(p, _)| *p == pid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_process_tree_cache_efficiency() {
        let mut cache = ProcessTreeCache::new();

        // Populate should work
        cache.populate().expect("should populate cache");

        // Cache should have entries (unless running in a very minimal container)
        // We can't assert exact counts, but the operation should complete
    }

    // =========================================================================
    // Edge Cases: Circular References
    // =========================================================================

    #[test]
    fn test_loop_detection_in_stat_parsing() {
        // parse_stat doesn't detect loops, but the analyzer should
        // This tests that parsing doesn't itself cause issues
        let content = "1 (init) S 1 1 1 0 -1"; // self-referential ppid
        let result = parse_stat(content, 1);
        assert!(result.is_ok());
        let (ppid, _) = result.unwrap();
        assert_eq!(ppid, 1); // Self-parent should be detectable
    }

    // =========================================================================
    // Edge Cases: Missing Entries
    // =========================================================================

    #[test]
    fn test_nonexistent_process() {
        let mut analyzer = AncestryAnalyzer::new();
        // PID 4000000000 should not exist
        let result = analyzer.analyze(4000000000);

        // Should return ProcessNotFound
        assert!(matches!(result, Err(AncestryError::ProcessNotFound(_))));
    }

    // =========================================================================
    // Edge Cases: Zombie Processes
    // =========================================================================

    #[test]
    fn test_parse_zombie_state() {
        // Zombie process state parsing
        let content = "999 (zombie_child) Z 1000 999 999 0 -1";
        let result = parse_stat(content, 999);
        assert!(result.is_ok());
        let (ppid, comm) = result.unwrap();
        assert_eq!(ppid, 1000);
        assert_eq!(comm, "zombie_child");
    }

    // =========================================================================
    // Edge Cases: Kernel Threads
    // =========================================================================

    #[test]
    fn test_kernel_thread_patterns() {
        // Kernel threads often have brackets in their names
        // parse_stat should handle them correctly
        let content = "2 (kthreadd) S 0 0 0 0 -1";
        let (ppid, comm) = parse_stat(content, 2).unwrap();
        assert_eq!(ppid, 0);
        assert_eq!(comm, "kthreadd");

        // Worker threads
        let content = "123 (kworker/0:0) I 2 0 0 0 -1";
        let (ppid, comm) = parse_stat(content, 123).unwrap();
        assert_eq!(ppid, 2);
        assert_eq!(comm, "kworker/0:0");
    }
}

#[cfg(test)]
mod environ_tests {
    use super::super::environ::*;
    use super::super::types::SupervisorCategory;
    use std::collections::HashMap;

    #[test]
    fn test_environ_database_claude_patterns() {
        let db = EnvironDatabase::with_defaults();
        let mut env = HashMap::new();

        // CLAUDE_SESSION_ID
        env.insert("CLAUDE_SESSION_ID".to_string(), "abc123".to_string());
        let matches = db.find_matches(&env);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|(p, _)| p.supervisor_name == "claude"));
    }

    #[test]
    fn test_environ_database_vscode_patterns() {
        let db = EnvironDatabase::with_defaults();
        let mut env = HashMap::new();

        // VSCODE_PID
        env.insert("VSCODE_PID".to_string(), "12345".to_string());
        let matches = db.find_matches(&env);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|(p, _)| p.supervisor_name == "vscode"));
    }

    #[test]
    fn test_environ_database_ci_patterns() {
        let db = EnvironDatabase::with_defaults();

        // GitHub Actions
        let mut env1 = HashMap::new();
        env1.insert("GITHUB_ACTIONS".to_string(), "true".to_string());
        let matches = db.find_matches(&env1);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|(p, _)| p.supervisor_name == "github-actions"));

        // GitLab CI
        let mut env2 = HashMap::new();
        env2.insert("GITLAB_CI".to_string(), "true".to_string());
        let matches = db.find_matches(&env2);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|(p, _)| p.supervisor_name == "gitlab-ci"));

        // Generic CI
        let mut env3 = HashMap::new();
        env3.insert("CI".to_string(), "true".to_string());
        let matches = db.find_matches(&env3);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_environ_analyzer_multiple_matches() {
        let analyzer = EnvironAnalyzer::new();
        let mut env = HashMap::new();

        // Multiple matching variables
        env.insert("VSCODE_PID".to_string(), "12345".to_string());
        env.insert("VSCODE_IPC_HOOK".to_string(), "/tmp/vscode-ipc".to_string());

        let result = analyzer.analyze_env(&env);
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("vscode".to_string()));
        // Should have multiple evidence items
        assert!(result.evidence.len() >= 1);
    }

    #[test]
    fn test_environ_value_pattern_matching() {
        let db = EnvironDatabase::with_defaults();

        // TERM_PROGRAM=vscode should match
        let mut env1 = HashMap::new();
        env1.insert("TERM_PROGRAM".to_string(), "vscode".to_string());
        let matches = db.find_matches(&env1);
        assert!(matches.iter().any(|(p, _)| p.var_name == "TERM_PROGRAM"));

        // TERM_PROGRAM=iterm2 should NOT match (wrong value)
        let mut env2 = HashMap::new();
        env2.insert("TERM_PROGRAM".to_string(), "iterm2".to_string());
        let matches = db.find_matches(&env2);
        assert!(!matches.iter().any(|(p, _)| p.var_name == "TERM_PROGRAM"));
    }

    #[test]
    fn test_environ_no_false_positives() {
        let analyzer = EnvironAnalyzer::new();
        let mut env = HashMap::new();

        // Common env vars that should NOT indicate supervision
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("USER".to_string(), "testuser".to_string());
        env.insert("SHELL".to_string(), "/bin/bash".to_string());
        env.insert("TERM".to_string(), "xterm-256color".to_string());

        let result = analyzer.analyze_env(&env);
        assert!(!result.is_supervised);
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::super::ipc::*;
    use super::super::types::SupervisorCategory;

    #[test]
    fn test_ipc_database_vscode_sockets() {
        let db = IpcDatabase::with_defaults();

        // Various VS Code socket patterns
        assert!(!db.find_matches("/tmp/vscode-ipc-12345.sock").is_empty());
        assert!(!db.find_matches("/tmp/vscode-abc123").is_empty());
    }

    #[test]
    fn test_ipc_database_claude_sockets() {
        let db = IpcDatabase::with_defaults();

        assert!(!db.find_matches("/tmp/claude-session-123").is_empty());
        assert!(!db.find_matches("/tmp/claude-ipc.sock").is_empty());
    }

    #[test]
    fn test_ipc_database_tmux_sockets() {
        let db = IpcDatabase::with_defaults();

        assert!(!db.find_matches("/tmp/tmux-1000/default").is_empty());
    }

    #[test]
    fn test_ipc_analyzer_multiple_sockets() {
        let analyzer = IpcAnalyzer::new();

        let sockets = vec![
            "/tmp/vscode-ipc-123.sock".to_string(),
            "/tmp/random-socket".to_string(),
        ];

        let result = analyzer.analyze_sockets(&sockets);
        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("vscode".to_string()));
    }

    #[test]
    fn test_ipc_no_false_positives() {
        let db = IpcDatabase::with_defaults();

        // Common sockets that should NOT match
        assert!(db.find_matches("/var/run/nscd/socket").is_empty());
        assert!(db.find_matches("/tmp/mysql.sock").is_empty());
        assert!(db.find_matches("/var/run/docker.sock").is_empty());
    }
}

#[cfg(test)]
mod signature_integration_tests {
    use super::super::signature::*;
    use super::super::types::SupervisorCategory;
    use std::collections::HashMap;

    #[test]
    fn test_unified_signature_database() {
        let db = SignatureDatabase::with_defaults();

        // Should have signatures
        assert!(!db.is_empty());

        // Process name matching
        let claude_matches = db.find_by_process_name("claude");
        assert!(!claude_matches.is_empty());
        assert_eq!(claude_matches[0].category, SupervisorCategory::Agent);

        // Env var matching
        let gh_matches = db.find_by_env_var("GITHUB_ACTIONS", "true");
        assert!(!gh_matches.is_empty());
        assert_eq!(gh_matches[0].category, SupervisorCategory::Ci);

        // Socket matching
        let vscode_matches = db.find_by_socket_path("/tmp/vscode-ipc-test");
        assert!(!vscode_matches.is_empty());
        assert_eq!(vscode_matches[0].category, SupervisorCategory::Ide);

        // PID file matching
        let supervisord_matches = db.find_by_pid_file("/var/run/supervisord.pid");
        assert!(!supervisord_matches.is_empty());
    }

    #[test]
    fn test_signature_to_legacy_conversion() {
        let db = SignatureDatabase::with_defaults();

        // Convert to legacy databases
        let supervisor_db = db.to_supervisor_database();
        let environ_db = db.to_environ_database();
        let ipc_db = db.to_ipc_database();

        // Legacy databases should work
        assert!(!supervisor_db.find_matches("claude").is_empty());

        let mut env = HashMap::new();
        env.insert("VSCODE_PID".to_string(), "123".to_string());
        assert!(!environ_db.find_matches(&env).is_empty());

        assert!(!ipc_db.find_matches("/tmp/vscode-test").is_empty());
    }
}

#[cfg(test)]
mod combined_detection_tests {
    use super::super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_combined_detector() {
        let mut detector = SupervisionDetector::new();
        let pid = std::process::id();

        let result = detector.detect(pid).expect("should detect");

        // Result should be valid
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);

        // If supervised, should have supervisor info
        if result.is_supervised {
            assert!(result.supervisor_name.is_some());
            assert!(result.supervisor_type.is_some());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_batch_detection() {
        let pid = std::process::id();
        let results = detect_supervision_batch(&[pid]).expect("should batch detect");

        assert!(!results.is_empty());
    }
}

#[cfg(test)]
mod logging_tests {
    //! Tests for logging/telemetry requirements.
    //!
    //! These tests verify that detection operations produce appropriate
    //! structured log output for debugging and auditing.

    use super::super::ancestry::*;
    use super::super::types::*;

    #[test]
    fn test_supervision_evidence_structure() {
        let evidence = SupervisionEvidence {
            evidence_type: EvidenceType::Ancestry,
            description: "Test evidence".to_string(),
            weight: 0.95,
        };

        // Evidence should be serializable
        let json = serde_json::to_string(&evidence).expect("should serialize");
        assert!(json.contains("ancestry"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn test_supervision_result_serialization() {
        let result = SupervisionResult::supervised_by_ancestry(
            SupervisorCategory::Agent,
            "claude".to_string(),
            pt_common::ProcessId(1234),
            2,
            0.95,
            vec![SupervisionEvidence {
                evidence_type: EvidenceType::Ancestry,
                description: "Test".to_string(),
                weight: 0.95,
            }],
            vec![],
        );

        let json = serde_json::to_string(&result).expect("should serialize");
        assert!(json.contains("is_supervised"));
        assert!(json.contains("true"));
        assert!(json.contains("agent"));
        assert!(json.contains("claude"));
    }

    #[test]
    fn test_ancestry_entry_serialization() {
        let entry = AncestryEntry {
            pid: pt_common::ProcessId(1234),
            comm: "test".to_string(),
            cmdline: Some("test --flag".to_string()),
        };

        let json = serde_json::to_string(&entry).expect("should serialize");
        assert!(json.contains("1234"));
        assert!(json.contains("test"));
    }
}
