//! Agent apply precheck-blocked tests.
//!
//! Ensures agent apply returns PolicyBlocked when a live precheck blocks an action.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};
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
use std::env;
use std::fs;
use std::process::{Child, Command as ProcessCommand};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn with_temp_dirs<T>(f: impl FnOnce(&TempDir, &TempDir) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned");

    let old_data = env::var("PROCESS_TRIAGE_DATA").ok();
    let old_config = env::var("PROCESS_TRIAGE_CONFIG").ok();

    let data_dir = TempDir::new().expect("create temp data dir");
    let config_dir = TempDir::new().expect("create temp config dir");

    env::set_var("PROCESS_TRIAGE_DATA", data_dir.path());
    env::set_var("PROCESS_TRIAGE_CONFIG", config_dir.path());

    let result = f(&data_dir, &config_dir);

    match old_data {
        Some(val) => env::set_var("PROCESS_TRIAGE_DATA", val),
        None => env::remove_var("PROCESS_TRIAGE_DATA"),
    }
    match old_config {
        Some(val) => env::set_var("PROCESS_TRIAGE_CONFIG", val),
        None => env::remove_var("PROCESS_TRIAGE_CONFIG"),
    }

    result
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
        policy.guardrails.protected_patterns.push(PatternEntry {
            pattern: "^sleep$".to_string(),
            kind: PatternKind::Regex,
            case_insensitive: true,
            notes: Some("test-only protected pattern".to_string()),
        });

        fs::write(
            config_dir.path().join("policy.json"),
            serde_json::to_string_pretty(&policy).expect("serialize policy"),
        )
        .expect("write policy.json");

        let store = SessionStore::from_env().expect("session store from env");
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
            .arg("30")
            .spawn()
            .expect("spawn sleep process");
        let guard = ChildGuard { child };
        let pid = guard.child.id();

        let identity = ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId("boot:1:424242".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };

        let plan = Plan {
            plan_id: "plan-test".to_string(),
            session_id: session_id.0.clone(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            policy_id: None,
            policy_version: "1.0.0".to_string(),
            actions: vec![PlanAction {
                action_id: "action-1".to_string(),
                target: identity,
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

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
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
            .stdout
            .clone();

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
    });
}
