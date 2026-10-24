//! Agent apply confirmation gate tests.
//!
//! Ensures agent apply requires --yes when not in dry-run/shadow.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::exit_codes::ExitCode;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::Duration;
use tempfile::TempDir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn with_temp_data_dir<T>(f: impl FnOnce(&Path, &Path) -> T) -> T {
    let data = TempDir::new().expect("create temp data dir").keep();
    let config = TempDir::new().expect("create temp config dir").keep();
    let mut policy = Policy::default();
    // Eligibility is isolated to this fresh target; confirmation remains mandatory.
    policy.guardrails.min_process_age_seconds = 0;
    fs::write(
        config.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize policy"),
    )
    .expect("write isolated policy");
    f(&data, &config)
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

#[test]
fn agent_apply_requires_yes_flag() {
    with_temp_data_dir(|dir, config| {
        let store = SessionStore::at_data_dir(dir);
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

        let mut child = ChildGuard(
            ProcessCommand::new("sleep")
                .arg("900")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn owned target"),
        );
        let pid = child.0.id();
        let scan = quick_scan(&QuickScanOptions {
            pids: vec![pid],
            ..QuickScanOptions::default()
        })
        .expect("scan owned target");
        let target = scan.processes.iter().find(|p| p.pid.0 == pid).unwrap();
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
                pre_checks: vec![],
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
            .env("PROCESS_TRIAGE_DATA", dir)
            .env("PROCESS_TRIAGE_CONFIG", config)
            .args([
                "--format",
                "json",
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
            .join("requires-yes");
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
        assert_eq!(
            json.get("error").and_then(|v| v.as_str()),
            Some("confirmation_required"),
            "Expected confirmation_required error"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "unconfirmed target died"
        );
        let current = quick_scan(&QuickScanOptions {
            pids: vec![pid],
            ..QuickScanOptions::default()
        })
        .unwrap();
        let survivor = current.processes.iter().find(|p| p.pid.0 == pid).unwrap();
        assert_eq!(survivor.start_id, identity.start_id);
        assert_eq!(survivor.uid, identity.uid);
        assert!(
            matches!(
                fs::read(handle.dir.join("action/outcomes.jsonl")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "confirmation refusal must leave outcomes genuinely absent"
        );
        assert!(
            matches!(
                fs::read(dir.join("rate_limit.json")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "confirmation refusal must leave budget genuinely absent"
        );
    });
}
