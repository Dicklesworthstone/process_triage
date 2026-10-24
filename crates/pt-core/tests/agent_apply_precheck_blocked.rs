//! Agent apply precheck-blocked tests.
//!
//! Ensures agent apply returns PolicyBlocked when a live precheck blocks an action.
//! Live prechecks and action execution are Linux-only.

#![cfg(target_os = "linux")]

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, QuickScanOptions};
use pt_core::config::policy::{PatternEntry, PatternKind};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::exit_codes::ExitCode;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction, PreCheck,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::Duration;
use tempfile::TempDir;

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn with_temp_dirs<T>(f: impl FnOnce(&Path, &Path) -> T) -> T {
    let data_dir = TempDir::new().expect("create temp data dir").keep();
    let config_dir = TempDir::new().expect("create temp config dir").keep();
    f(&data_dir, &config_dir)
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

#[test]
#[cfg(target_os = "linux")]
fn agent_apply_returns_policy_blocked_for_precheck_block() {
    with_temp_dirs(|data_dir, config_dir| {
        let mut policy = Policy::default();
        policy.robot_mode.enabled = true;
        policy.robot_mode.min_posterior = 0.0;
        policy.robot_mode.require_human_for_supervised = false;
        policy.guardrails.min_process_age_seconds = 0;
        policy.guardrails.protected_patterns.push(PatternEntry {
            pattern: "^sleep$".to_string(),
            kind: PatternKind::Regex,
            case_insensitive: true,
            notes: Some("test-only protected pattern".to_string()),
        });

        fs::write(
            config_dir.join("policy.json"),
            serde_json::to_string_pretty(&policy).expect("serialize policy"),
        )
        .expect("write policy.json");

        let store = SessionStore::at_data_dir(data_dir);
        let session_id = SessionId::new();
        let manifest = SessionManifest::new(&session_id, None, SessionMode::RobotPlan, None);
        let handle = store.create(&manifest).expect("create session");
        let ctx = SessionContext::new(
            &session_id,
            "host-test".to_string(),
            "run-test".to_string(),
            None,
        );
        handle.write_context(&ctx).expect("write context");

        let child = ProcessCommand::new("sleep")
            .arg("900")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep process");
        let mut guard = ChildGuard { child };
        let pid = guard.child.id();

        let scan = quick_scan(&QuickScanOptions {
            pids: vec![pid],
            ..QuickScanOptions::default()
        })
        .expect("scan owned target");
        let target = scan.processes.iter().find(|p| p.pid.0 == pid).unwrap();
        assert_eq!(
            target.comm, "sleep",
            "protected fixture must really be sleep"
        );
        let identity = ProcessIdentity::full(
            pid,
            target.start_id.clone(),
            target.uid,
            target.pgid,
            target.sid,
            IdentityQuality::Full,
        );

        let plan = Plan {
            plan_id: "plan-test".to_string(),
            session_id: session_id.0.clone(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            policy_id: None,
            policy_version: "1.0.0".to_string(),
            actions: vec![PlanAction {
                action_id: "action-1".to_string(),
                target: identity.clone(),
                action: Action::Kill,
                order: 0,
                stage: 0,
                timeouts: ActionTimeouts::default(),
                pre_checks: vec![PreCheck::CheckNotProtected],
                rationale: ActionRationale {
                    expected_loss: None,
                    expected_recovery: None,
                    expected_recovery_stddev: None,
                    posterior_odds_abandoned_vs_useful: None,
                    sprt_boundary: None,
                    posterior: None,
                    memory_mb: None,
                    has_known_signature: None,
                    category: None,
                },
                on_success: Vec::<ActionHook>::new(),
                on_failure: Vec::<ActionHook>::new(),
                blocked: false,
                routing: ActionRouting::Direct,
                confidence: ActionConfidence::Normal,
                original_zombie_target: None,
                d_state_diagnostics: None,
            }],
            pre_toggled: Vec::new(),
            gates_summary: GatesSummary {
                total_candidates: 1,
                blocked_candidates: 0,
                pre_toggled_actions: 0,
            },
        };

        let decision_dir = handle.dir.join("decision");
        fs::create_dir_all(&decision_dir).expect("create decision dir");
        let plan_path = decision_dir.join("plan.json");
        fs::write(
            &plan_path,
            serde_json::to_string_pretty(&plan).expect("serialize plan"),
        )
        .expect("write plan");

        let result = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir)
            .env("PROCESS_TRIAGE_CONFIG", config_dir)
            .args([
                "--format",
                "json",
                "--dry-run",
                "agent",
                "apply",
                "--session",
                &session_id.0,
                "--pids",
                &pid.to_string(),
            ])
            .assert()
            .code(ExitCode::PolicyBlocked.as_i32())
            .get_output()
            .clone();
        let logs = Path::new("target/test-logs/e2e/agent_apply")
            .join(&session_id.0)
            .join("protected-precheck");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("stdout.json"), &result.stdout).unwrap();
        fs::write(logs.join("stderr.log"), &result.stderr).unwrap();
        fs::write(
            logs.join("identity.json"),
            serde_json::to_vec_pretty(&identity).unwrap(),
        )
        .unwrap();
        let output = result.stdout;

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let summary = json
            .get("summary")
            .expect("Missing summary in agent apply output");
        assert_eq!(
            summary.get("blocked_by_prechecks").and_then(|v| v.as_u64()),
            Some(1),
            "Expected blocked_by_prechecks to be 1"
        );

        let outcomes = json
            .get("outcomes")
            .and_then(|v| v.as_array())
            .expect("Missing outcomes array");
        assert_eq!(outcomes.len(), 1, "Expected exactly one outcome");
        assert_eq!(
            outcomes[0].get("status").and_then(|v| v.as_str()),
            Some("precheck_blocked"),
            "Expected precheck_blocked status"
        );
        assert_eq!(
            outcomes[0].get("check").and_then(|v| v.as_str()),
            Some("check_not_protected"),
            "Expected check_not_protected in outcome"
        );
        assert!(
            guard.child.try_wait().unwrap().is_none(),
            "protected target died"
        );
        let current = quick_scan(&QuickScanOptions {
            pids: vec![pid],
            ..QuickScanOptions::default()
        })
        .unwrap();
        let survivor = current.processes.iter().find(|p| p.pid.0 == pid).unwrap();
        assert_eq!(survivor.start_id, identity.start_id);
        assert_eq!(survivor.uid, identity.uid);
    });
}
