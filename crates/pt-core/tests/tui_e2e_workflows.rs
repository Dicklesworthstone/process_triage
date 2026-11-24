#![cfg(feature = "ui")]
//! E2E TUI workflow tests using ftui message-based testing.
//!
//! All interactions use ftui `Msg` types sent through `Model::update()`.

use ftui::{
    Cmd as FtuiCmd, KeyCode as FtuiKeyCode, KeyEvent as FtuiKeyEvent, Model as FtuiModel,
    Modifiers as FtuiModifiers,
};
use pt_core::tui::widgets::{DetailView, ProcessRow};
use pt_core::tui::{
    App, AppState, Msg, PressureOverview, PressureUnit, RefreshOutcome, UndoBatch, UndoOverview,
    UndoRestoreOutcome,
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Send a Msg through the ftui Model::update loop, discarding the Cmd.
fn send_msg(app: &mut App, msg: Msg) {
    let _cmd = <App as FtuiModel>::update(app, msg);
}

fn deferred_task(command: FtuiCmd<Msg>) -> Box<dyn FnOnce() -> Msg + Send> {
    let FtuiCmd::Sequence(commands) = command else {
        panic!("expected a logged asynchronous task");
    };
    let mut task = None;
    for command in commands {
        match command {
            FtuiCmd::Log(_) => {}
            FtuiCmd::Task(_, run) => {
                assert!(task.is_none(), "one request must schedule one task");
                task = Some(run);
            }
            other => panic!("unexpected task command: {other:?}"),
        }
    }
    task.expect("the production update must schedule a task")
}

fn confirmed_request(app: &mut App) -> Msg {
    send_msg(app, ftui_char('e'));
    assert_eq!(app.state, AppState::Confirming);
    let FtuiCmd::Msg(request @ Msg::RequestExecute { .. }) =
        <App as FtuiModel>::update(app, Msg::ConfirmExecute)
    else {
        panic!("a fresh confirmation must create a bound request");
    };
    request
}

fn pressure_overview() -> PressureOverview {
    PressureOverview {
        header: vec![
            "Host load 3.0 / 8 online CPUs | PSI CPU some avg10 1.2%".into(),
            "Available memory 2 GiB | Swap unknown | Regime cpu_contention [P details]".into(),
        ],
        details: vec![
            "Observed host pressure from this scan".into(),
            "Cgroup kernel accounting unavailable; process-tree grouping only".into(),
        ],
        units: vec![
            PressureUnit {
                id: "tree-alpha".into(),
                label: "Alpha workload".into(),
                member_pids: vec![1001, 1002],
                summary: "CPU observed subtotal 0.5 cores, measured 1/2 members".into(),
                details: vec!["RSS sums may count shared pages more than once".into()],
            },
            PressureUnit {
                id: "tree-empty".into(),
                label: "Protected workload".into(),
                summary: "4 observed members; 0 candidate rows".into(),
                ..PressureUnit::default()
            },
        ],
    }
}

fn app_with_pressure() -> App {
    let mut app = App::new();
    app.replace_processes(RefreshOutcome {
        rows: sample_rows(),
        pressure: Some(pressure_overview()),
        ..RefreshOutcome::default()
    });
    app
}

fn pressure_filter_first_unit(app: &mut App) {
    send_msg(app, ftui_char('P'));
    send_msg(app, Msg::CursorHome);
    send_msg(app, ftui_char('j'));
    send_msg(app, ftui_key(FtuiKeyCode::Enter));
    assert_eq!(app.state, AppState::Normal);
    assert_eq!(app.process_table.visible_rows().len(), 2);
    assert_eq!(app.process_table.selected_count(), 0);
}

fn rendered_app(app: &App, width: u16, height: u16) -> String {
    let mut pool = ftui::GraphemePool::new();
    let mut frame = ftui::Frame::new(width, height, &mut pool);
    <App as FtuiModel>::view(app, &mut frame);
    ftui_harness::buffer_to_text(&frame.buffer)
}

#[test]
fn pressure_header_and_scrollable_host_and_unit_details_render_without_a_goal() {
    for (width, height) in [(80, 24), (120, 30), (200, 40)] {
        let mut overview = pressure_overview();
        overview
            .details
            .extend((1..=40).map(|n| format!("Host observation {n:02}")));
        overview.units[0]
            .details
            .extend((1..=40).map(|n| format!("Unit observation {n:02}")));
        let mut app = App::new();
        app.replace_processes(RefreshOutcome {
            rows: sample_rows(),
            pressure: Some(overview),
            ..RefreshOutcome::default()
        });
        send_msg(&mut app, Msg::Resized { width, height });
        let text = rendered_app(&app, width, height);
        assert!(text.contains("Host load 3.0 / 8 online CPUs"), "{text}");
        assert!(text.contains("Swap unknown"), "{text}");
        send_msg(&mut app, ftui_char('P'));
        assert_eq!(app.state, AppState::Pressure);
        assert!(app.selected_pressure_unit().is_none());
        let text = rendered_app(&app, width, height);
        assert!(
            text.contains("Cgroup kernel accounting unavailable"),
            "{text}"
        );
        for _ in 0..20 {
            send_msg(&mut app, ftui_char(']'));
        }
        assert!(rendered_app(&app, width, height).contains("Host observation 40"));
        send_msg(&mut app, ftui_char('j'));
        let text = rendered_app(&app, width, height);
        assert!(text.contains("measured 1/2 members"), "{text}");
        assert!(text.contains("RSS sums may count shared pages"), "{text}");
        for _ in 0..20 {
            send_msg(&mut app, ftui_char(']'));
        }
        assert!(rendered_app(&app, width, height).contains("Unit observation 40"));
        for _ in 0..20 {
            send_msg(&mut app, ftui_char('['));
        }
        assert!(rendered_app(&app, width, height).contains("measured 1/2 members"));
        assert_eq!(app.selected_pressure_unit().unwrap().id, "tree-alpha");
        assert_eq!(app.process_table.selected_count(), 0);
    }
}

#[test]
fn pressure_filter_preserves_search_and_expires_process_confirmations_without_selecting() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&calls);
    let mut app = app_with_pressure();
    app.set_execute_op(Arc::new(move |_, _, _| {
        recorded.fetch_add(1, Ordering::SeqCst);
        Ok(pt_core::tui::ExecutionOutcome::default())
    }));
    send_msg(&mut app, Msg::SelectAll);
    let old = confirmed_request(&mut app);
    pressure_filter_first_unit(&mut app);
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, old),
        FtuiCmd::None
    ));
    assert!(app.process_table.get_explicitly_spared().is_empty());
    assert!(app.process_table.get_explicitly_selected().is_empty());
    assert_eq!(
        app.process_table.rows.len(),
        5,
        "filtering retains canonical candidate rows"
    );
    app.search.set_value("node");
    send_msg(&mut app, Msg::SearchCommit);
    assert_eq!(app.process_table.visible_rows()[0].pid, 1001);
    assert_eq!(app.process_table.visible_rows().len(), 1);
    send_msg(&mut app, Msg::SelectAll);
    let filtered = confirmed_request(&mut app);
    send_msg(&mut app, ftui_char('c'));
    assert_eq!(app.process_table.filter.as_deref(), Some("node"));
    assert_eq!(app.process_table.visible_rows().len(), 1);
    assert_eq!(app.process_table.selected_count(), 0);
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, filtered),
        FtuiCmd::None
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    app.search.set_value("");
    send_msg(&mut app, Msg::SearchCommit);
    assert_eq!(app.process_table.visible_rows().len(), 5);
    send_msg(&mut app, Msg::OpenPressure);
    send_msg(&mut app, Msg::SelectAll);
    send_msg(&mut app, ftui_char('e'));
    send_msg(&mut app, Msg::ConfirmExecute);
    assert_eq!(app.state, AppState::Pressure);
    assert_eq!(app.process_table.selected_count(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn pressure_refresh_replaces_observations_with_rows_and_discards_membership_filters() {
    use std::sync::Arc;
    let mut app = app_with_pressure();
    let old_overview = app.pressure_overview().cloned();
    pressure_filter_first_unit(&mut app);
    send_msg(&mut app, Msg::SelectAll);
    let old_request = confirmed_request(&mut app);
    let mut new_overview = pressure_overview();
    new_overview.header[0] = "New host pressure observation".into();
    new_overview.units[0].member_pids = vec![1005];
    new_overview.units[0].label = "New workload".into();
    let expected = new_overview.clone();
    app.set_refresh_op(Arc::new(move || {
        Ok(RefreshOutcome {
            rows: sample_rows()
                .into_iter()
                .filter(|row| row.pid == 1001 || row.pid == 1005)
                .collect(),
            pressure: Some(new_overview.clone()),
            ..RefreshOutcome::default()
        })
    }));
    let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
    assert_eq!(
        app.process_table.visible_rows().len(),
        5,
        "refresh immediately clears the old filter"
    );
    let completed = refresh();
    assert_eq!(
        app.pressure_overview(),
        old_overview.as_ref(),
        "callback alone cannot update display"
    );
    for message in [
        Msg::OpenPressure,
        Msg::FilterPressureUnit,
        Msg::ClearPressureFilter,
        old_request,
    ] {
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, message),
            FtuiCmd::None
        ));
    }
    assert_eq!(app.state, AppState::Normal);
    send_msg(
        &mut app,
        Msg::RefreshComplete {
            ticket: u64::MAX,
            result: Ok(RefreshOutcome::default()),
        },
    );
    assert_eq!(app.pressure_overview(), old_overview.as_ref());
    send_msg(&mut app, completed.clone());
    assert_eq!(app.pressure_overview(), Some(&expected));
    assert_eq!(app.process_table.visible_rows().len(), 2);
    assert_eq!(app.process_table.selected_count(), 0);
    send_msg(&mut app, completed);
    send_msg(&mut app, ftui_char('P'));
    assert!(app.selected_pressure_unit().is_none());
    send_msg(&mut app, ftui_char('j'));
    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    assert_eq!(app.process_table.visible_rows().len(), 1);
    assert_eq!(app.process_table.visible_rows()[0].pid, 1005);
}

#[test]
fn pressure_unknown_and_unrepresented_units_never_widen_an_existing_filter() {
    let mut app = app_with_rows();
    send_msg(&mut app, ftui_char('P'));
    assert!(rendered_app(&app, 80, 24).contains("Host pressure observations are unavailable"));
    send_msg(&mut app, Msg::FilterPressureUnit);
    assert_eq!(app.state, AppState::Pressure);
    assert_eq!(app.process_table.visible_rows().len(), 5);
    let mut overview = pressure_overview();
    overview.units.push(PressureUnit {
        id: "foreign".into(),
        label: "No matching candidate".into(),
        member_pids: vec![9999],
        ..PressureUnit::default()
    });
    app.replace_processes(RefreshOutcome {
        rows: sample_rows(),
        pressure: Some(overview),
        ..RefreshOutcome::default()
    });
    pressure_filter_first_unit(&mut app);
    send_msg(&mut app, ftui_char('P'));
    for expected in ["tree-empty", "foreign"] {
        send_msg(&mut app, ftui_char('j'));
        assert_eq!(app.selected_pressure_unit().unwrap().id, expected);
        send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
        assert_eq!(app.state, AppState::Pressure);
        assert_eq!(app.process_table.visible_rows().len(), 2);
        assert_eq!(app.process_table.selected_count(), 0);
    }
    send_msg(&mut app, ftui_char('c'));
    assert_eq!(app.process_table.visible_rows().len(), 5);
    send_msg(&mut app, Msg::ProcessesScanned(sample_rows()));
    assert!(app.pressure_overview().is_none());
    assert_eq!(app.state, AppState::Normal);
    assert_eq!(app.process_table.visible_rows().len(), 5);
}

#[test]
fn pressure_browsing_and_filter_changes_wait_for_execution_and_restoration() {
    use std::sync::Arc;
    let mut app = app_with_pressure();
    app.set_execute_op(Arc::new(|_, _, _| {
        Ok(pt_core::tui::ExecutionOutcome::default())
    }));
    pressure_filter_first_unit(&mut app);
    send_msg(&mut app, Msg::SelectAll);
    let request = confirmed_request(&mut app);
    let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
    for message in [
        Msg::OpenPressure,
        Msg::FilterPressureUnit,
        Msg::ClearPressureFilter,
    ] {
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, message),
            FtuiCmd::None
        ));
        assert_eq!(app.state, AppState::Normal);
        assert_eq!(app.process_table.visible_rows().len(), 2);
    }
    send_msg(&mut app, execute());
    app.set_undo_ops(
        Arc::new(|| {
            Ok(UndoOverview {
                batches: vec![undo_batch("aaaa", 1)],
                ..UndoOverview::default()
            })
        }),
        Arc::new(|batch| {
            Ok(UndoRestoreOutcome {
                session_id: batch.session_id,
                restored: 1,
                ..UndoRestoreOutcome::default()
            })
        }),
    );
    load_undo(&mut app);
    let request = confirmed_undo_request(&mut app);
    let restore = deferred_task(<App as FtuiModel>::update(&mut app, request));
    for message in [
        Msg::OpenPressure,
        Msg::FilterPressureUnit,
        Msg::ClearPressureFilter,
    ] {
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, message),
            FtuiCmd::None
        ));
        assert_eq!(app.state, AppState::Undo);
        assert_eq!(app.process_table.visible_rows().len(), 2);
    }
    send_msg(&mut app, restore());
    send_msg(&mut app, Msg::OpenPressure);
    assert_eq!(app.state, AppState::Pressure);
}

fn undo_batch(suffix: &str, pending: usize) -> UndoBatch {
    UndoBatch {
        session_id: format!("pt-20261124-010000-{suffix}"),
        plan_sha256: "a".repeat(64),
        receipt_fingerprint: format!("reviewed-{suffix}"),
        created_at: "2026-11-24T01:00:00Z".into(),
        pending,
        details: vec![format!("pause PID 42: {pending} pending receipt(s)")],
        ..UndoBatch::default()
    }
}

fn load_undo(app: &mut App) {
    let inspect = deferred_task(<App as FtuiModel>::update(app, Msg::OpenUndo));
    assert_eq!(app.state, AppState::Undo);
    let completed = inspect();
    send_msg(app, completed);
}

fn confirmed_undo_request(app: &mut App) -> Msg {
    send_msg(app, Msg::ShowUndoConfirmation);
    assert_eq!(app.state, AppState::ConfirmingUndo);
    assert_eq!(
        app.confirm_dialog.selected,
        pt_core::tui::widgets::ConfirmChoice::No
    );
    send_msg(app, ftui_key(FtuiKeyCode::Left));
    let FtuiCmd::Msg(request @ Msg::RequestUndo { .. }) =
        <App as FtuiModel>::update(app, ftui_key(FtuiKeyCode::Enter))
    else {
        panic!("explicit undo confirmation must create a bound request");
    };
    request
}

#[test]
fn undo_panel_selects_one_saved_batch_and_never_replays_settled_authority() {
    use std::sync::{Arc, Mutex};

    let first = undo_batch("aaaa", 1);
    let second = undo_batch("aaab", 2);
    let saved = Arc::new(Mutex::new(UndoOverview {
        batches: vec![first.clone(), second.clone()],
        ..UndoOverview::default()
    }));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut app = app_with_rows();
    let inspected = Arc::clone(&saved);
    let restored = Arc::clone(&saved);
    let observed = Arc::clone(&calls);
    app.set_undo_ops(
        Arc::new(move || Ok(inspected.lock().unwrap().clone())),
        Arc::new(move |selection| {
            let mut saved = restored.lock().unwrap();
            let batch = saved
                .batches
                .iter_mut()
                .find(|batch| batch.session_id == selection.session_id)
                .unwrap();
            assert_eq!(
                *batch, selection,
                "restore must receive exactly the displayed batch"
            );
            observed.lock().unwrap().push(selection.clone());
            batch.settled += batch.pending;
            batch.pending = 0;
            batch.receipt_fingerprint = "settled".to_string();
            Ok(UndoRestoreOutcome {
                overview: saved.clone(),
                session_id: selection.session_id,
                restored: selection.pending,
                remaining: 0,
                summary: "Recorded original values restored".into(),
                error: None,
            })
        }),
    );
    load_undo(&mut app);
    assert_eq!(app.selected_undo_batch(), Some(&first));
    send_msg(&mut app, ftui_char('j'));
    assert_eq!(app.selected_undo_batch(), Some(&second));
    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    assert_eq!(app.state, AppState::ConfirmingUndo);
    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    assert_eq!(app.state, AppState::Undo);
    assert!(
        calls.lock().unwrap().is_empty(),
        "Enter defaults to cancellation"
    );

    let request = confirmed_undo_request(&mut app);
    let restore = deferred_task(<App as FtuiModel>::update(&mut app, request.clone()));
    assert!(
        calls.lock().unwrap().is_empty(),
        "model update must defer the callback"
    );
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, request.clone()),
        FtuiCmd::None
    ));
    let completed = restore();
    assert_eq!(
        app.selected_undo_batch().unwrap().pending,
        2,
        "display waits for its own completion"
    );
    send_msg(&mut app, completed.clone());
    assert_eq!(
        app.selected_undo_batch().unwrap().session_id,
        second.session_id
    );
    assert_eq!(app.selected_undo_batch().unwrap().pending, 0);
    assert_eq!(app.selected_undo_batch().unwrap().settled, 2);
    assert_eq!(app.undo_overview().unwrap().batches[0].pending, 1);
    assert_eq!(*calls.lock().unwrap(), vec![second]);
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, request),
        FtuiCmd::None
    ));
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, completed),
        FtuiCmd::None
    ));
    send_msg(&mut app, Msg::ShowUndoConfirmation);
    assert_eq!(
        app.state,
        AppState::Undo,
        "settled batch cannot be confirmed again"
    );
    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn undo_refresh_consumes_old_confirmation_and_serializes_all_mutating_operations() {
    use std::sync::{Arc, Mutex};

    let saved = Arc::new(Mutex::new(UndoOverview {
        batches: vec![undo_batch("aaaa", 1)],
        ..UndoOverview::default()
    }));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut app = app_with_rows();
    let inspected = Arc::clone(&saved);
    let observed = Arc::clone(&calls);
    app.set_undo_ops(
        Arc::new(move || Ok(inspected.lock().unwrap().clone())),
        Arc::new(move |batch| {
            observed.lock().unwrap().push(batch);
            Err("receipt changed before restoration".into())
        }),
    );
    load_undo(&mut app);
    let stale = confirmed_undo_request(&mut app);
    saved.lock().unwrap().batches[0].receipt_fingerprint = "a later reviewed receipt".into();
    let inspect = deferred_task(<App as FtuiModel>::update(
        &mut app,
        Msg::RequestUndoRefresh,
    ));
    let completed = inspect();
    assert_eq!(
        app.selected_undo_batch().unwrap().receipt_fingerprint,
        "reviewed-aaaa"
    );
    for message in [
        stale.clone(),
        Msg::ConfirmUndo,
        Msg::ShowUndoConfirmation,
        Msg::RequestRefresh,
        Msg::RequestUndoRefresh,
        Msg::SelectAll,
        Msg::ConfirmExecute,
        Msg::CursorDown,
        Msg::ProcessesScanned(vec![]),
        Msg::UndoLoaded {
            ticket: 0,
            result: Ok(UndoOverview::default()),
        },
    ] {
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, message),
            FtuiCmd::None
        ));
    }
    assert!(calls.lock().unwrap().is_empty());
    send_msg(&mut app, completed);
    assert_eq!(
        app.selected_undo_batch().unwrap().receipt_fingerprint,
        "a later reviewed receipt"
    );
    let fresh = confirmed_undo_request(&mut app);
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, stale.clone()),
        FtuiCmd::None
    ));
    let restore = deferred_task(<App as FtuiModel>::update(&mut app, fresh.clone()));
    for message in [
        stale,
        fresh,
        Msg::OpenUndo,
        Msg::CloseUndo,
        Msg::RequestRefresh,
        Msg::RequestUndoRefresh,
        Msg::ShowUndoConfirmation,
        Msg::ConfirmUndo,
        Msg::ConfirmExecute,
        Msg::SelectAll,
        Msg::ProcessesScanned(vec![]),
        Msg::Quit,
        Msg::UndoComplete {
            ticket: 0,
            result: Ok(UndoRestoreOutcome::default()),
        },
    ] {
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, message),
            FtuiCmd::None
        ));
    }
    assert!(!app.should_quit());
    send_msg(&mut app, restore());
    assert_eq!(calls.lock().unwrap().len(), 1);
    send_msg(&mut app, Msg::ShowUndoConfirmation);
    assert_eq!(
        app.state,
        AppState::Undo,
        "callback failure requires a fresh inspection"
    );
    let inspect = deferred_task(<App as FtuiModel>::update(
        &mut app,
        Msg::RequestUndoRefresh,
    ));
    send_msg(&mut app, inspect());
    send_msg(&mut app, Msg::ShowUndoConfirmation);
    assert_eq!(app.state, AppState::ConfirmingUndo);
    send_msg(&mut app, Msg::CancelUndo);
}

#[test]
fn undo_read_only_blocked_missing_and_unsupported_batches_remain_inspectable() {
    use std::sync::Arc;

    for variant in [
        "read_only",
        "blocked",
        "settled",
        "unsupported",
        "unrecorded",
        "missing_binding",
    ] {
        let mut batch = undo_batch("aaaa", 1);
        let mut overview = UndoOverview::default();
        match variant {
            "read_only" => overview.read_only_reason = Some("shadow mode".into()),
            "blocked" => batch.blocked_reason = Some("saved child plan changed".into()),
            "settled" => {
                batch.pending = 0;
                batch.settled = 1;
            }
            "unsupported" => {
                batch.pending = 0;
                batch.unsupported = 1;
            }
            "unrecorded" => {
                batch.pending = 0;
                batch.unrecorded = 1;
            }
            "missing_binding" => batch.receipt_fingerprint.clear(),
            _ => unreachable!(),
        }
        overview.batches.push(batch.clone());
        let mut app = app_with_rows();
        app.set_undo_ops(
            Arc::new(move || Ok(overview.clone())),
            Arc::new(|_| panic!("non-restorable batch must not reach the backend")),
        );
        load_undo(&mut app);
        assert_eq!(app.selected_undo_batch(), Some(&batch), "{variant}");
        send_msg(&mut app, Msg::ShowUndoConfirmation);
        assert_eq!(app.state, AppState::Undo, "{variant}");
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, Msg::ConfirmUndo),
            FtuiCmd::None
        ));
        assert!(matches!(
            <App as FtuiModel>::update(&mut app, Msg::RequestUndo { ticket: 1 }),
            FtuiCmd::None
        ));
    }
}

#[test]
fn undo_partial_results_keep_completed_and_pending_controls_visible() {
    use std::sync::Arc;

    let original = UndoOverview {
        batches: vec![undo_batch("aaaa", 2)],
        ..UndoOverview::default()
    };
    let mut after = original.clone();
    after.batches[0].pending = 1;
    after.batches[0].settled = 1;
    after.batches[0].receipt_fingerprint = "partial-result".into();
    after.batches[0].details = vec![
        "pause PID 42: restored".into(),
        "pause PID 43: refused; still pending".into(),
    ];
    let displayed = after.clone();
    let mut app = app_with_rows();
    app.set_undo_ops(
        Arc::new(move || Ok(original.clone())),
        Arc::new(move |selection| {
            Ok(UndoRestoreOutcome {
                overview: after.clone(),
                session_id: selection.session_id,
                restored: 1,
                remaining: 1,
                summary: "Stopped after a refusal".into(),
                error: Some("PID 43 identity changed".into()),
            })
        }),
    );
    load_undo(&mut app);
    let request = confirmed_undo_request(&mut app);
    let restore = deferred_task(<App as FtuiModel>::update(&mut app, request));
    send_msg(&mut app, restore());
    assert_eq!(app.undo_overview(), Some(&displayed));
    assert_eq!(app.state, AppState::Undo);
    for (width, height) in [(80, 24), (120, 30), (200, 40)] {
        let mut pool = ftui::GraphemePool::new();
        let mut frame = ftui::Frame::new(width, height, &mut pool);
        <App as FtuiModel>::view(&app, &mut frame);
        let text = ftui_harness::buffer_to_text(&frame.buffer);
        for expected in [
            "Undo recorded controls",
            "1 restored; 1 pending",
            "PID 43 identity changed",
            "pause PID 42: restored",
            "pause PID 43: refused; still pending",
        ] {
            assert!(
                text.contains(expected),
                "{width}x{height} is missing {expected}:\n{text}"
            );
        }
        assert!(
            !text.contains("partial-result"),
            "receipt bindings are not user-facing text"
        );
    }
}

#[test]
fn undo_confirmation_expires_on_selection_close_and_process_replacement() {
    use std::sync::Arc;

    for invalidation in ["cursor", "close", "processes"] {
        let overview = UndoOverview {
            batches: vec![undo_batch("aaaa", 1), undo_batch("aaab", 1)],
            ..UndoOverview::default()
        };
        let mut app = app_with_rows();
        app.set_undo_ops(
            Arc::new(move || Ok(overview.clone())),
            Arc::new(|_| panic!("expired selection cannot restore")),
        );
        load_undo(&mut app);
        let request = confirmed_undo_request(&mut app);
        send_msg(
            &mut app,
            match invalidation {
                "cursor" => Msg::CursorDown,
                "close" => Msg::CloseUndo,
                "processes" => Msg::ProcessesScanned(vec![]),
                _ => unreachable!(),
            },
        );
        assert!(
            matches!(<App as FtuiModel>::update(&mut app, request), FtuiCmd::None),
            "{invalidation}"
        );
    }
}

#[test]
fn undo_details_scroll_without_changing_the_reviewed_batch() {
    use std::sync::Arc;

    let mut batch = undo_batch("aaaa", 40);
    batch.details = (1..=40)
        .map(|pid| format!("pause PID {pid}: pending recorded original job-control state"))
        .collect();
    let expected = batch.clone();
    let overview = UndoOverview {
        batches: vec![batch],
        ..UndoOverview::default()
    };
    let mut app = app_with_rows();
    app.set_undo_ops(
        Arc::new(move || Ok(overview.clone())),
        Arc::new(|_| panic!("detail navigation must not restore a control")),
    );
    load_undo(&mut app);
    for (width, height) in [(80, 24), (120, 30), (200, 40)] {
        send_msg(&mut app, Msg::Resized { width, height });
        for _ in 0..12 {
            send_msg(&mut app, ftui_char(']'));
        }
        let mut pool = ftui::GraphemePool::new();
        let mut frame = ftui::Frame::new(width, height, &mut pool);
        <App as FtuiModel>::view(&app, &mut frame);
        let text = ftui_harness::buffer_to_text(&frame.buffer);
        assert!(
            text.contains("pause PID 40: pending"),
            "last receipt must be reachable at {width}x{height}:\n{text}"
        );
        assert_eq!(app.selected_undo_batch(), Some(&expected));
        for _ in 0..12 {
            send_msg(&mut app, ftui_char('['));
        }
        let mut frame = ftui::Frame::new(width, height, &mut pool);
        <App as FtuiModel>::view(&app, &mut frame);
        let text = ftui_harness::buffer_to_text(&frame.buffer);
        assert!(
            text.contains("pause PID 1: pending"),
            "first receipt must remain reachable:\n{text}"
        );
    }
}

#[test]
fn undo_failed_inspection_cannot_reuse_an_old_review_token() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let inspected = Arc::clone(&calls);
    let overview = UndoOverview {
        batches: vec![undo_batch("aaaa", 1)],
        ..UndoOverview::default()
    };
    let mut app = app_with_rows();
    app.set_undo_ops(
        Arc::new(move || match inspected.fetch_add(1, Ordering::SeqCst) {
            1 => Err("child control reference unavailable".into()),
            _ => Ok(overview.clone()),
        }),
        Arc::new(|_| panic!("failed inspection must not authorize restoration")),
    );
    let first = deferred_task(<App as FtuiModel>::update(&mut app, Msg::OpenUndo));
    let old_completed = first();
    send_msg(&mut app, old_completed.clone());
    let stale_request = confirmed_undo_request(&mut app);
    let reload = deferred_task(<App as FtuiModel>::update(
        &mut app,
        Msg::RequestUndoRefresh,
    ));
    send_msg(&mut app, reload());
    assert!(
        app.selected_undo_batch().is_some(),
        "last observed records stay visible"
    );
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, old_completed),
        FtuiCmd::None
    ));
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, stale_request),
        FtuiCmd::None
    ));
    send_msg(&mut app, Msg::ShowUndoConfirmation);
    assert_eq!(app.state, AppState::Undo);
    let reload = deferred_task(<App as FtuiModel>::update(
        &mut app,
        Msg::RequestUndoRefresh,
    ));
    send_msg(&mut app, reload());
    send_msg(&mut app, Msg::ShowUndoConfirmation);
    assert_eq!(app.state, AppState::ConfirmingUndo);
    send_msg(&mut app, Msg::CancelUndo);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn undo_open_expires_an_already_confirmed_process_execution() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut app = app_with_rows();
    app.set_execute_op(Arc::new(move |_, _, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(pt_core::tui::ExecutionOutcome::default())
    }));
    app.set_undo_ops(
        Arc::new(|| {
            Ok(UndoOverview {
                batches: vec![undo_batch("aaaa", 1)],
                ..UndoOverview::default()
            })
        }),
        Arc::new(|_| panic!("opening a panel never restores controls")),
    );
    send_msg(&mut app, Msg::SelectAll);
    let stale = confirmed_request(&mut app);
    let inspect = deferred_task(<App as FtuiModel>::update(&mut app, Msg::OpenUndo));
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, stale.clone()),
        FtuiCmd::None
    ));
    send_msg(&mut app, inspect());
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, stale.clone()),
        FtuiCmd::None
    ));
    send_msg(&mut app, Msg::ConfirmExecute);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    send_msg(&mut app, Msg::CloseUndo);
    send_msg(&mut app, Msg::SelectAll);
    let fresh = confirmed_request(&mut app);
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, stale),
        FtuiCmd::None
    ));
    let execute = deferred_task(<App as FtuiModel>::update(&mut app, fresh));
    send_msg(&mut app, execute());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Send multiple Msgs sequentially.
fn send_msgs(app: &mut App, msgs: &[Msg]) {
    for msg in msgs {
        send_msg(app, msg.clone());
    }
}

/// Create a KeyPressed Msg from a key code.
fn ftui_key(code: FtuiKeyCode) -> Msg {
    Msg::KeyPressed(FtuiKeyEvent::new(code))
}

/// Create a KeyPressed Msg for a character key.
fn ftui_char(c: char) -> Msg {
    ftui_key(FtuiKeyCode::Char(c))
}

/// Create a KeyPressed Msg with Ctrl modifier.
fn ftui_key_ctrl(c: char) -> Msg {
    Msg::KeyPressed(FtuiKeyEvent::new(FtuiKeyCode::Char(c)).with_modifiers(FtuiModifiers::CTRL))
}

fn make_row(
    pid: u32,
    score: u32,
    classification: &str,
    runtime: &str,
    memory: &str,
    command: &str,
    galaxy_brain: Option<&str>,
) -> ProcessRow {
    ProcessRow {
        pid,
        score,
        classification: classification.to_string(),
        runtime: runtime.to_string(),
        memory: memory.to_string(),
        command: command.to_string(),
        selected: false,
        galaxy_brain: galaxy_brain.map(|s| s.to_string()),
        why_summary: None,
        top_evidence: vec![],
        confidence: None,
        plan_preview: vec![],
        provenance_headline: None,
        provenance_sections: Vec::new(),
        provenance_caveats: Vec::new(),
        blast_radius_risk: None,
    }
}

fn sample_rows() -> Vec<ProcessRow> {
    vec![
        make_row(
            1001,
            95,
            "KILL",
            "3d 2h",
            "2.1 GB",
            "node dev-server --watch",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.95"),
        ),
        make_row(
            1002,
            72,
            "REVIEW",
            "12h 30m",
            "512 MB",
            "python train.py --epochs 100",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.72"),
        ),
        make_row(1003, 15, "SPARE", "5m", "64 MB", "vim session.rs", None),
        make_row(
            1004,
            88,
            "KILL",
            "7d 4h",
            "4.0 GB",
            "jupyter notebook --port 8888",
            Some("Galaxy-Brain Mode\nPosterior: P(abandoned)=0.88"),
        ),
        make_row(
            1005,
            45,
            "REVIEW",
            "1h 15m",
            "256 MB",
            "cargo test --workspace",
            None,
        ),
    ]
}

fn app_with_rows() -> App {
    let mut app = App::new();
    app.process_table.set_rows(sample_rows());
    app
}

// ===========================================================================
// 1. Navigation Workflows (key bindings: j/Down, k/Up, Home, End, etc.)
// ===========================================================================

#[test]
fn nav_cursor_down_moves_selection() {
    let mut app = app_with_rows();
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, ftui_char('j'));
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Down));
    assert_eq!(app.process_table.cursor, 2);
}

#[test]
fn nav_cursor_up_moves_selection() {
    let mut app = app_with_rows();

    // Move down first, then back up
    send_msgs(&mut app, &[ftui_char('j'), ftui_char('j'), ftui_char('k')]);
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Up));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_cursor_wraps_at_boundaries() {
    let mut app = app_with_rows();

    // At top, going up shouldn't crash
    send_msg(&mut app, ftui_char('k'));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_home_end_jumps() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key(FtuiKeyCode::End));
    assert_eq!(app.process_table.cursor, 4); // last row

    send_msg(&mut app, ftui_key(FtuiKeyCode::Home));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_page_down_up() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key(FtuiKeyCode::PageDown));
    // With 5 rows and page size 10, should be at last row
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, ftui_key(FtuiKeyCode::PageUp));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_ctrl_d_ctrl_u_page() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key_ctrl('d'));
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, ftui_key_ctrl('u'));
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn nav_cursor_via_semantic_msgs() {
    // Test semantic navigation messages directly (no key binding involved)
    let mut app = app_with_rows();

    send_msgs(&mut app, &[Msg::CursorDown, Msg::CursorDown]);
    assert_eq!(app.process_table.cursor, 2);

    send_msg(&mut app, Msg::CursorUp);
    assert_eq!(app.process_table.cursor, 1);

    send_msg(&mut app, Msg::CursorHome);
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, Msg::CursorEnd);
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, Msg::PageUp);
    assert_eq!(app.process_table.cursor, 0);

    send_msg(&mut app, Msg::PageDown);
    assert_eq!(app.process_table.cursor, 4);

    send_msg(&mut app, Msg::HalfPageUp);
    assert_eq!(app.process_table.cursor, 0);
}

// ===========================================================================
// 2. Search/Filter Workflows
// ===========================================================================

#[test]
fn search_enter_and_exit() {
    let mut app = app_with_rows();
    assert_eq!(app.state, AppState::Normal);

    send_msg(&mut app, ftui_char('/'));
    assert_eq!(app.state, AppState::Searching);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_type_and_filter() {
    let mut app = app_with_rows();

    // Enter search mode and type "node"
    send_msg(&mut app, ftui_char('/'));
    send_msgs(
        &mut app,
        &[
            ftui_char('n'),
            ftui_char('o'),
            ftui_char('d'),
            ftui_char('e'),
        ],
    );

    // Search query should be populated
    assert_eq!(app.search.value, "node");
}

#[test]
fn search_backspace_deletes() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('/'));
    send_msgs(
        &mut app,
        &[
            ftui_char('a'),
            ftui_char('b'),
            ftui_key(FtuiKeyCode::Backspace),
        ],
    );

    assert_eq!(app.search.value, "a");
}

#[test]
fn search_enter_confirms_and_returns_to_normal() {
    let mut app = app_with_rows();

    send_msgs(
        &mut app,
        &[ftui_char('/'), ftui_char('k'), ftui_key(FtuiKeyCode::Enter)],
    );

    assert_eq!(app.state, AppState::Normal);
    // Search should have been committed
    assert!(!app.search.value.is_empty());
}

#[test]
fn search_via_semantic_msgs() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::EnterSearchMode);
    assert_eq!(app.state, AppState::Searching);

    send_msgs(
        &mut app,
        &[
            Msg::SearchInput('t'),
            Msg::SearchInput('e'),
            Msg::SearchInput('s'),
            Msg::SearchInput('t'),
        ],
    );
    assert_eq!(app.search.value, "test");

    send_msg(&mut app, Msg::SearchBackspace);
    assert_eq!(app.search.value, "tes");

    send_msg(&mut app, Msg::SearchCommit);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_cancel_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('x'));
    send_msg(&mut app, Msg::SearchCancel);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn search_history_via_msg() {
    let mut app = app_with_rows();

    // First search
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('a'));
    send_msg(&mut app, Msg::SearchCommit);

    // Second search
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchInput('b'));
    send_msg(&mut app, Msg::SearchCommit);

    // Navigate history
    send_msg(&mut app, Msg::EnterSearchMode);
    send_msg(&mut app, Msg::SearchHistoryUp);
    // Should not crash
    send_msg(&mut app, Msg::SearchHistoryDown);
    send_msg(&mut app, Msg::SearchCancel);
}

// ===========================================================================
// 3. Selection/Toggle Workflows
// ===========================================================================

#[test]
fn toggle_selection_on_current_row() {
    let mut app = app_with_rows();

    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 1);

    // Toggle again to deselect
    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn select_all_and_deselect_all() {
    let mut app = app_with_rows();

    // Select all with 'A' key binding
    send_msg(&mut app, ftui_char('A'));
    assert_eq!(app.process_table.selected_count(), 5);

    // Deselect all with 'u' key binding
    send_msg(&mut app, ftui_char('u'));
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn select_recommended_selects_kill_only() {
    let mut app = app_with_rows();

    // 'a' selects recommended (KILL classification)
    send_msg(&mut app, ftui_char('a'));
    let count = app.process_table.selected_count();
    // We have 2 KILL rows (1001, 1004)
    assert_eq!(count, 2, "Should select 2 KILL-classified rows");
}

#[test]
fn invert_selection_with_x_key() {
    let mut app = app_with_rows();

    // Select first row
    send_msg(&mut app, ftui_char(' '));
    assert_eq!(app.process_table.selected_count(), 1);

    // Invert with 'x' key
    send_msg(&mut app, ftui_char('x'));
    assert_eq!(app.process_table.selected_count(), 4);
}

#[test]
fn invert_selection_via_msg() {
    let mut app = app_with_rows();

    // Select first row
    send_msg(&mut app, Msg::ToggleSelection);
    assert_eq!(app.process_table.selected_count(), 1);

    // Invert via semantic message
    send_msg(&mut app, Msg::InvertSelection);
    assert_eq!(app.process_table.selected_count(), 4);
}

#[test]
fn navigate_and_toggle_multiple() {
    let mut app = app_with_rows();

    // Select rows 0, 2, 4 by navigating and toggling
    send_msgs(
        &mut app,
        &[
            ftui_char(' '), // select row 0
            ftui_char('j'), // move to row 1
            ftui_char('j'), // move to row 2
            ftui_char(' '), // select row 2
            ftui_char('j'), // move to row 3
            ftui_char('j'), // move to row 4
            ftui_char(' '), // select row 4
        ],
    );
    assert_eq!(app.process_table.selected_count(), 3);
}

#[test]
fn selection_via_semantic_msgs() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::SelectAll);
    assert_eq!(app.process_table.selected_count(), 5);

    send_msg(&mut app, Msg::DeselectAll);
    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, Msg::SelectRecommended);
    assert_eq!(app.process_table.selected_count(), 2);

    send_msg(&mut app, Msg::InvertSelection);
    assert_eq!(app.process_table.selected_count(), 3);
}

// ===========================================================================
// 4. Drilldown / Detail View Workflows
// ===========================================================================

#[test]
fn detail_view_toggle_visibility() {
    let mut app = app_with_rows();

    let initial = app.is_detail_visible();
    // Enter toggles detail visibility
    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    assert_ne!(app.is_detail_visible(), initial);
}

#[test]
fn detail_view_switch_to_genealogy() {
    let mut app = app_with_rows();

    // 't' switches to genealogy view
    send_msg(&mut app, ftui_char('t'));
    assert_eq!(app.current_detail_view(), DetailView::Genealogy);
}

// ===========================================================================
// 5. Execute / Abort Workflows
// ===========================================================================

#[test]
fn execute_shows_confirmation_dialog() {
    let mut app = app_with_rows();

    // Select a process and press 'e' (ftui execute binding) to execute
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);

    // Should show confirmation dialog
    assert!(
        app.confirm_dialog.visible,
        "Confirmation dialog should be visible"
    );
}

#[test]
fn execute_abort_with_escape() {
    let mut app = app_with_rows();

    // Select, execute, then abort
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert!(!app.confirm_dialog.visible);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn execute_confirm_with_enter() {
    let mut app = app_with_rows();

    // Select, execute, then confirm
    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Enter));
    // After confirmation, dialog should close
    assert!(!app.confirm_dialog.visible);
}

#[test]
fn execute_with_no_selection_shows_status() {
    let mut app = app_with_rows();
    assert_eq!(app.process_table.selected_count(), 0);

    // Try to execute with nothing selected (ftui 'e' binding)
    send_msg(&mut app, ftui_char('e'));

    // Should not show confirmation (nothing selected)
    assert!(!app.confirm_dialog.visible);
}

#[test]
fn confirmation_dialog_tab_toggles() {
    let mut app = app_with_rows();

    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    // Tab should toggle between options
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    // No crash
}

#[test]
fn confirmation_dialog_left_right() {
    let mut app = app_with_rows();

    send_msgs(&mut app, &[ftui_char(' '), ftui_char('e')]);
    assert!(app.confirm_dialog.visible);

    // Navigate left/right
    send_msgs(
        &mut app,
        &[
            ftui_char('l'), // right
            ftui_char('h'), // left
        ],
    );
}

// ===========================================================================
// 6. Help Overlay Workflow
// ===========================================================================

#[test]
fn help_opens_and_closes() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn help_question_mark_toggles() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn help_toggle_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::ToggleHelp);
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, Msg::ToggleHelp);
    assert_eq!(app.state, AppState::Normal);
}

// ===========================================================================
// 7. Quit Workflow
// ===========================================================================

#[test]
fn quit_with_q() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('q'));
    assert!(app.should_quit());
}

#[test]
fn quit_with_ctrl_c() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_key_ctrl('c'));
    assert!(app.should_quit());
}

#[test]
fn quit_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::Quit);
    assert!(app.should_quit());
}

#[test]
fn quit_from_help_returns_to_normal() {
    let mut app = app_with_rows();

    // Enter help, then quit help
    send_msg(&mut app, ftui_char('?'));
    assert_eq!(app.state, AppState::Help);

    send_msg(&mut app, ftui_char('q'));
    assert_eq!(app.state, AppState::Normal);

    // Now quit from normal
    send_msg(&mut app, ftui_char('q'));
    assert!(app.should_quit());
}

// ===========================================================================
// 8. Focus Cycling
// ===========================================================================

#[test]
fn tab_cycles_focus() {
    let mut app = app_with_rows();

    // Tab should cycle through focus targets
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    send_msg(&mut app, ftui_key(FtuiKeyCode::Tab));
    // No crash
}

#[test]
fn focus_cycle_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::FocusNext);
    send_msg(&mut app, Msg::FocusPrev);
    // No crash
}

// ===========================================================================
// 9. Resize Handling
// ===========================================================================

#[test]
fn resize_updates_layout() {
    let mut app = app_with_rows();

    // Simulate resize via ftui Msg
    send_msg(
        &mut app,
        Msg::Resized {
            width: 200,
            height: 60,
        },
    );

    // Simulate resize to compact
    send_msg(
        &mut app,
        Msg::Resized {
            width: 80,
            height: 24,
        },
    );
}

#[test]
fn minimal_terminal_renders_without_crash() {
    let mut app = app_with_rows();

    // Very small terminal
    send_msg(
        &mut app,
        Msg::Resized {
            width: 40,
            height: 10,
        },
    );
    // No crash
}

// ===========================================================================
// 10. Full Workflow Sequences
// ===========================================================================

#[test]
fn workflow_search_filter_select_abort() {
    let mut app = app_with_rows();

    // 1. Search for "python"
    send_msgs(
        &mut app,
        &[
            ftui_char('/'),
            ftui_char('p'),
            ftui_char('y'),
            ftui_char('t'),
            ftui_char('h'),
            ftui_char('o'),
            ftui_char('n'),
            ftui_key(FtuiKeyCode::Enter),
        ],
    );
    assert_eq!(app.state, AppState::Normal);

    // 2. Select all visible
    send_msg(&mut app, ftui_char('A'));

    // 3. Execute (ftui binding: 'e')
    send_msg(&mut app, ftui_char('e'));

    // 4. Abort
    send_msg(&mut app, ftui_key(FtuiKeyCode::Escape));
    assert!(!app.confirm_dialog.visible);
    assert_eq!(app.state, AppState::Normal);

    // 5. Deselect all
    send_msg(&mut app, ftui_char('u'));
    assert_eq!(app.process_table.selected_count(), 0);
}

// ===========================================================================
// 12. Status Messages & Refresh
// ===========================================================================

#[test]
fn refresh_sets_status_message() {
    let mut app = app_with_rows();

    send_msg(&mut app, ftui_char('r'));
    // The key enters the guarded refresh transition before returning its task.
    // This test observes the request without executing the skeleton task.
}

#[test]
fn refresh_via_msg() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::RequestRefresh);
    // Should not crash; in skeleton mode, returns a task that resolves to empty rows
}

// ===========================================================================
// 13. Async Result Messages
// ===========================================================================

#[test]
fn processes_scanned_updates_rows() {
    let mut app = App::new();
    assert_eq!(app.process_table.selected_count(), 0);

    send_msg(&mut app, Msg::ProcessesScanned(sample_rows()));
    assert_eq!(app.process_table.rows.len(), 5);
}

#[test]
fn refresh_complete_updates_rows() {
    let mut app = app_with_rows();

    let new_rows = vec![make_row(
        9999,
        50,
        "REVIEW",
        "1h",
        "128 MB",
        "test-process",
        None,
    )];
    app.set_refresh_op(std::sync::Arc::new(move || {
        Ok(pt_core::tui::RefreshOutcome {
            rows: new_rows.clone(),
            ..Default::default()
        })
    }));
    let refresh = deferred_task(<App as FtuiModel>::update(&mut app, Msg::RequestRefresh));
    send_msg(&mut app, refresh());
    assert_eq!(app.process_table.rows.len(), 1);
    assert_eq!(app.process_table.rows[0].pid, 9999);
}

#[test]
fn execution_complete_ok() {
    use pt_core::tui::ExecutionOutcome;
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::SelectAll);
    app.set_execute_op(std::sync::Arc::new(|pids, explicit, spares| {
        assert_eq!(pids.len(), 5);
        assert!(explicit.is_empty());
        assert!(spares.is_empty());
        Ok(ExecutionOutcome {
            mode: None,
            attempted: 3,
            succeeded: 2,
            failed: 1,
        })
    }));
    let request = confirmed_request(&mut app);
    let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
    send_msg(&mut app, execute());
    assert_eq!(app.state, AppState::Normal);
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn execution_complete_err() {
    let mut app = app_with_rows();

    send_msg(&mut app, Msg::SelectAll);
    app.set_execute_op(std::sync::Arc::new(|pids, explicit, spares| {
        assert_eq!(pids.len(), 5);
        assert!(explicit.is_empty());
        assert!(spares.is_empty());
        Err("test error".to_string())
    }));
    let request = confirmed_request(&mut app);
    let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
    send_msg(&mut app, execute());
    assert_eq!(app.state, AppState::Normal);
    assert_eq!(app.process_table.selected_count(), 0);
}

// ===========================================================================
// 14. Empty State
// ===========================================================================

#[test]
fn empty_process_list_navigation_safe() {
    let mut app = App::new();

    // Navigation on empty list should not crash
    send_msgs(
        &mut app,
        &[
            ftui_char('j'),
            ftui_char('k'),
            ftui_key(FtuiKeyCode::Home),
            ftui_key(FtuiKeyCode::End),
            ftui_char(' '),
            ftui_char('A'),
            ftui_char('u'),
        ],
    );
}

#[test]
fn empty_process_list_semantic_msgs_safe() {
    let mut app = App::new();

    send_msgs(
        &mut app,
        &[
            Msg::CursorDown,
            Msg::CursorUp,
            Msg::CursorHome,
            Msg::CursorEnd,
            Msg::PageDown,
            Msg::PageUp,
            Msg::HalfPageDown,
            Msg::HalfPageUp,
            Msg::ToggleSelection,
            Msg::SelectAll,
            Msg::DeselectAll,
            Msg::InvertSelection,
            Msg::SelectRecommended,
        ],
    );
    // No crash
}

// ===========================================================================
// 15. Rapid Event Sequences (Stress Tests)
// ===========================================================================

#[test]
fn rapid_navigation_stress() {
    let mut app = app_with_rows();

    // 100 rapid key presses
    for _ in 0..100 {
        send_msg(&mut app, ftui_char('j'));
    }
    // Cursor should be clamped to valid range
    assert!(app.process_table.cursor < 5);

    for _ in 0..100 {
        send_msg(&mut app, ftui_char('k'));
    }
    assert_eq!(app.process_table.cursor, 0);
}

#[test]
fn rapid_toggle_stress() {
    let mut app = app_with_rows();

    // Rapidly toggle selection 200 times
    for _ in 0..200 {
        send_msg(&mut app, ftui_char(' '));
    }

    // Even number of toggles -> should be back to 0
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn rapid_search_enter_exit_stress() {
    let mut app = app_with_rows();

    // Enter and exit search 50 times
    for _ in 0..50 {
        send_msgs(&mut app, &[ftui_char('/'), ftui_key(FtuiKeyCode::Escape)]);
    }
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn rapid_semantic_msg_stress() {
    let mut app = app_with_rows();

    for _ in 0..50 {
        send_msgs(
            &mut app,
            &[
                Msg::CursorDown,
                Msg::ToggleSelection,
                Msg::CursorDown,
                Msg::CursorUp,
            ],
        );
    }
    // Should not crash
}

// ===========================================================================
// 16. Misc ftui-Specific Messages
// ===========================================================================

#[test]
fn tick_msg_is_noop() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::Tick);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn noop_msg_is_noop() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::Noop);
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn focus_changed_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::FocusChanged(false));
    send_msg(&mut app, Msg::FocusChanged(true));
    assert_eq!(app.state, AppState::Normal);
}

#[test]
fn paste_received_enters_search() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::PasteReceived {
            text: "pasted-text".to_string(),
            bracketed: true,
        },
    );
    assert_eq!(app.state, AppState::Searching);
    assert_eq!(app.search.value, "pasted-text");
}

#[test]
fn clipboard_received_sets_search_value() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::ClipboardReceived("clipboard-content".to_string()),
    );
    assert_eq!(app.search.value, "clipboard-content");
}

#[test]
fn export_evidence_ledger_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::ExportEvidenceLedger);
    // Should not crash; sets status about not being wired
}

#[test]
fn ledger_exported_ok() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::LedgerExported(Ok(std::path::PathBuf::from("/tmp/ledger.json"))),
    );
    // Should not crash
}

#[test]
fn ledger_exported_err() {
    let mut app = app_with_rows();
    send_msg(
        &mut app,
        Msg::LedgerExported(Err("export failed".to_string())),
    );
    // Should not crash
}

#[test]
fn confirm_execute_via_msg() {
    let mut app = app_with_rows();
    assert!(matches!(
        <App as FtuiModel>::update(&mut app, Msg::ConfirmExecute),
        FtuiCmd::None
    ));
    send_msg(&mut app, Msg::SelectAll);
    let request = confirmed_request(&mut app);
    let execute = deferred_task(<App as FtuiModel>::update(&mut app, request));
    send_msg(&mut app, execute());
    assert_eq!(app.process_table.selected_count(), 0);
}

#[test]
fn cancel_execute_via_msg() {
    let mut app = app_with_rows();
    send_msg(&mut app, Msg::CancelExecute);
    // Directly triggers cancel handling
}

#[test]
fn goal_view_toggle_msg() {
    let mut app = app_with_rows();
    // No goal order set, should report unavailable
    send_msg(&mut app, Msg::ToggleGoalView);
    // Should not crash
}
