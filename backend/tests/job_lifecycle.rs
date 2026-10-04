//! Phase 1 lifecycle tests: every valid transition and every invalid one.
//!
//! Spec chain: QUEUED -> FETCHING -> SCANNING -> NORMALIZING -> REPORTING
//! -> DELIVERING -> COMPLETED, with FAILED reachable from any non-terminal,
//! CANCELLED reachable from any non-terminal, and PARTIAL reachable from any
//! post-fetch work phase. Terminal states transition nowhere.
//!
//! Job-level mirror: QUEUED -> RUNNING -> {COMPLETED, PARTIAL, FAILED,
//! CANCELLED, ENGINE_UNAVAILABLE}, plus QUEUED -> {FAILED, CANCELLED} direct.
//! Runs without a database.

use firecrow_backend::models::JobStatus;
use firecrow_backend::schemas::scan_contract::PipelineState;

#[test]
fn pipeline_linear_chain_advances_one_step() {
    use PipelineState as S;
    for (from, to) in [
        (S::Queued, S::Fetching),
        (S::Fetching, S::Scanning),
        (S::Scanning, S::Normalizing),
        (S::Normalizing, S::Reporting),
        (S::Reporting, S::Delivering),
        (S::Delivering, S::Completed),
    ] {
        assert!(from.can_transition(&to), "{from:?} -> {to:?} must be legal");
    }
}

#[test]
fn pipeline_failure_reachable_from_every_non_terminal() {
    use PipelineState as S;
    for from in [
        S::Queued,
        S::Fetching,
        S::Scanning,
        S::Normalizing,
        S::Reporting,
        S::Delivering,
    ] {
        assert!(
            from.can_transition(&S::Failed),
            "{from:?} -> Failed must be legal"
        );
    }
}

#[test]
fn pipeline_cancellation_reachable_from_every_non_terminal() {
    use PipelineState as S;
    for from in [
        S::Queued,
        S::Fetching,
        S::Scanning,
        S::Normalizing,
        S::Reporting,
        S::Delivering,
    ] {
        assert!(
            from.can_transition(&S::Cancelled),
            "{from:?} -> Cancelled must be legal"
        );
    }
}

#[test]
fn pipeline_partial_reachable_from_post_fetch_work_phases_only() {
    use PipelineState as S;
    for from in [S::Scanning, S::Normalizing, S::Reporting, S::Delivering] {
        assert!(
            from.can_transition(&S::Partial),
            "{from:?} -> Partial must be legal"
        );
    }
    for from in [S::Queued, S::Fetching] {
        assert!(
            !from.can_transition(&S::Partial),
            "{from:?} -> Partial must be illegal (nothing ran yet)"
        );
    }
}

#[test]
fn pipeline_terminal_states_transition_nowhere() {
    use PipelineState as S;
    let terminals = [S::Completed, S::Partial, S::Failed, S::Cancelled];
    let all = [
        S::Queued,
        S::Fetching,
        S::Scanning,
        S::Normalizing,
        S::Reporting,
        S::Delivering,
        S::Completed,
        S::Partial,
        S::Failed,
        S::Cancelled,
    ];
    for from in terminals {
        assert!(from.is_terminal(), "{from:?} must be terminal");
        for to in all {
            assert!(
                !from.can_transition(&to),
                "{from:?} -> {to:?} must be illegal (terminal)"
            );
        }
    }
}

#[test]
fn pipeline_skips_backwards_and_self_loops_are_illegal() {
    use PipelineState as S;
    let all = [
        S::Queued,
        S::Fetching,
        S::Scanning,
        S::Normalizing,
        S::Reporting,
        S::Delivering,
        S::Completed,
        S::Partial,
        S::Failed,
        S::Cancelled,
    ];
    // Self-loops are illegal: no phase re-enters itself.
    for s in all {
        if !s.is_terminal() {
            assert!(!s.can_transition(&s), "{s:?} -> itself must be illegal");
        }
    }
    // Backwards and skip-ahead jumps along the chain.
    let illegal = [
        (S::Fetching, S::Queued),
        (S::Scanning, S::Fetching),
        (S::Scanning, S::Queued),
        (S::Queued, S::Scanning),
        (S::Fetching, S::Completed),
        (S::Queued, S::Queued),
        (S::Normalizing, S::Scanning),
        (S::Reporting, S::Scanning),
        (S::Delivering, S::Fetching),
        (S::Completed, S::Queued),
        // Terminal states are never valid *targets* from non-terminals
        // (except via the legal Failed/Cancelled/Partial/Completed edges).
        (S::Queued, S::Completed),
        (S::Scanning, S::Completed),
        (S::Reporting, S::Completed),
        (S::Normalizing, S::Completed),
    ];
    for (from, to) in illegal {
        assert!(
            !from.can_transition(&to),
            "{from:?} -> {to:?} must be illegal"
        );
    }
    // Non-terminal states are never re-entered from later phases.
    assert!(!S::Delivering.can_transition(&S::Fetching));
    assert!(!S::Reporting.can_transition(&S::Queued));
}

// Helper removed: the illegal-pair table now names its targets directly.

#[test]
fn job_status_terminals_and_transitions() {
    // Terminal set.
    for s in [
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ] {
        assert!(s.is_terminal(), "{s:?} must be terminal");
    }
    assert!(!JobStatus::Queued.is_terminal());
    assert!(!JobStatus::Running.is_terminal());

    // Valid: claim, direct fail/cancel from queue, fan-out from running.
    assert!(JobStatus::Queued.can_transition(&JobStatus::Running));
    assert!(JobStatus::Queued.can_transition(&JobStatus::Failed));
    assert!(JobStatus::Queued.can_transition(&JobStatus::Cancelled));
    for to in [
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ] {
        assert!(
            JobStatus::Running.can_transition(&to),
            "Running -> {to:?} must be legal"
        );
    }

    // Invalid: everything out of a terminal, backwards, and queue re-entry.
    let all = [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ];
    for from in [
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ] {
        for to in all {
            assert!(
                !from.can_transition(&to),
                "{from:?} -> {to:?} must be illegal (terminal)"
            );
        }
    }
    for to in [
        JobStatus::Queued,
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::EngineUnavailable,
    ] {
        assert!(
            !JobStatus::Queued.can_transition(&to),
            "Queued -> {to:?} must be illegal (only Running/Failed/Cancelled)"
        );
    }
    assert!(!JobStatus::Running.can_transition(&JobStatus::Queued));
    assert!(!JobStatus::Running.can_transition(&JobStatus::Running));
    assert!(!JobStatus::Queued.can_transition(&JobStatus::Queued));
}
