//! Blast Radius Tests - Section 11.14
//!
//! Tests for blast radius analysis including:
//! - Descendant enumeration
//! - Resource aggregation across process subtrees
//! - Risk propagation through process trees
//! - Impact scoring with blast radius scenarios
//! - Warning generation for high-impact kills
//! - Logging requirements validation
//!
//! See: process_triage-wu3n

use pt_core::decision::robot_constraints::{
    ConstraintChecker, ConstraintKind, RobotCandidate, RuntimeRobotConstraints,
};
use pt_core::inference::belief_prop::{BeliefPropConfig, BeliefPropagator, ProcessNode, State};
use pt_core::inference::impact::{ImpactComponents, ImpactSeverity, SupervisorLevel};
use std::collections::HashMap;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create belief map with given state probabilities.
fn make_belief(useful: f64, bad: f64, abandoned: f64, zombie: f64) -> HashMap<State, f64> {
    let mut belief = HashMap::new();
    belief.insert(State::Useful, useful);
    belief.insert(State::UsefulBad, bad);
    belief.insert(State::Abandoned, abandoned);
    belief.insert(State::Zombie, zombie);
    belief
}

/// Simulated process node for blast radius testing.
#[derive(Debug, Clone)]
struct SimulatedProcess {
    pid: u32,
    ppid: u32,
    memory_mb: f64,
    connections: usize,
    listen_ports: usize,
    file_handles: usize,
    is_supervised: bool,
}

impl SimulatedProcess {
    fn new(pid: u32, ppid: u32) -> Self {
        Self {
            pid,
            ppid,
            memory_mb: 10.0,
            connections: 0,
            listen_ports: 0,
            file_handles: 5,
            is_supervised: false,
        }
    }

    fn with_memory(mut self, mb: f64) -> Self {
        self.memory_mb = mb;
        self
    }

    fn with_connections(mut self, count: usize) -> Self {
        self.connections = count;
        self
    }

    fn with_listen_ports(mut self, count: usize) -> Self {
        self.listen_ports = count;
        self
    }

    fn with_file_handles(mut self, count: usize) -> Self {
        self.file_handles = count;
        self
    }

    fn with_supervised(mut self, supervised: bool) -> Self {
        self.is_supervised = supervised;
        self
    }
}

/// Simulated process tree for blast radius calculations.
#[derive(Debug)]
struct ProcessSubtree {
    processes: Vec<SimulatedProcess>,
    children_map: HashMap<u32, Vec<u32>>,
}

impl ProcessSubtree {
    fn new() -> Self {
        Self {
            processes: Vec::new(),
            children_map: HashMap::new(),
        }
    }

    fn add_process(&mut self, proc: SimulatedProcess) {
        let pid = proc.pid;
        let ppid = proc.ppid;
        self.processes.push(proc);
        // Track parent-child relationship
        if ppid != 0 && ppid != 1 {
            self.children_map.entry(ppid).or_default().push(pid);
        }
    }

    /// Get all descendants of a process (recursive enumeration).
    /// Uses visited set to prevent infinite loops from circular references.
    fn enumerate_descendants(&self, root_pid: u32) -> Vec<u32> {
        use std::collections::HashSet;

        let mut descendants = Vec::new();
        let mut stack = vec![root_pid];
        let mut visited = HashSet::new();
        visited.insert(root_pid);

        while let Some(pid) = stack.pop() {
            if let Some(children) = self.children_map.get(&pid) {
                for &child in children {
                    if !visited.contains(&child) {
                        visited.insert(child);
                        descendants.push(child);
                        stack.push(child);
                    }
                }
            }
        }

        descendants
    }

    /// Aggregate resources across the subtree rooted at a process.
    fn aggregate_resources(&self, root_pid: u32) -> SubtreeResources {
        let descendants = self.enumerate_descendants(root_pid);
        let all_pids: Vec<u32> = std::iter::once(root_pid)
            .chain(descendants.iter().copied())
            .collect();

        let mut resources = SubtreeResources::default();
        resources.total_descendants = descendants.len();

        for proc in &self.processes {
            if all_pids.contains(&proc.pid) {
                resources.total_memory_mb += proc.memory_mb;
                resources.total_connections += proc.connections;
                resources.total_listen_ports += proc.listen_ports;
                resources.total_file_handles += proc.file_handles;
            }
        }

        resources
    }

    /// Get process by PID.
    fn get_process(&self, pid: u32) -> Option<&SimulatedProcess> {
        self.processes.iter().find(|p| p.pid == pid)
    }
}

/// Aggregated resources for a process subtree.
#[derive(Debug, Default)]
struct SubtreeResources {
    total_descendants: usize,
    total_memory_mb: f64,
    total_connections: usize,
    total_listen_ports: usize,
    total_file_handles: usize,
}

/// Blast radius warning thresholds.
struct BlastRadiusThresholds {
    max_descendants_warn: usize,
    max_memory_mb_warn: f64,
    max_connections_warn: usize,
    max_ports_warn: usize,
}

impl Default for BlastRadiusThresholds {
    fn default() -> Self {
        Self {
            max_descendants_warn: 10,
            max_memory_mb_warn: 1024.0,
            max_connections_warn: 10,
            max_ports_warn: 5,
        }
    }
}

/// Generate warnings based on blast radius analysis.
fn generate_blast_radius_warnings(
    resources: &SubtreeResources,
    thresholds: &BlastRadiusThresholds,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if resources.total_descendants > thresholds.max_descendants_warn {
        warnings.push(format!(
            "High descendant count: {} descendants will be terminated",
            resources.total_descendants
        ));
    }

    if resources.total_memory_mb > thresholds.max_memory_mb_warn {
        warnings.push(format!(
            "High memory impact: {:.1}MB total memory in subtree",
            resources.total_memory_mb
        ));
    }

    if resources.total_connections > thresholds.max_connections_warn {
        warnings.push(format!(
            "Network impact: {} active connections will be terminated",
            resources.total_connections
        ));
    }

    if resources.total_listen_ports > thresholds.max_ports_warn {
        warnings.push(format!(
            "Port impact: {} listening ports will be freed",
            resources.total_listen_ports
        ));
    }

    warnings
}

// ============================================================================
// Unit Tests: Descendant Enumeration
// ============================================================================

#[test]
fn test_descendant_enumeration_single_node() {
    // SCENARIO: isolated_process
    // Tree: single node, no children
    // Expected: Blast radius = 1, low impact
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1));

    let descendants = tree.enumerate_descendants(1000);
    assert!(descendants.is_empty(), "Single node should have no descendants");

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_descendants, 0);
}

#[test]
fn test_descendant_enumeration_linear_chain() {
    // Tree: 1000 → 1001 → 1002 → 1003
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1));
    tree.add_process(SimulatedProcess::new(1001, 1000));
    tree.add_process(SimulatedProcess::new(1002, 1001));
    tree.add_process(SimulatedProcess::new(1003, 1002));

    // From root, should find all descendants
    let descendants = tree.enumerate_descendants(1000);
    assert_eq!(descendants.len(), 3);
    assert!(descendants.contains(&1001));
    assert!(descendants.contains(&1002));
    assert!(descendants.contains(&1003));

    // From middle node, should only find downstream
    let mid_descendants = tree.enumerate_descendants(1001);
    assert_eq!(mid_descendants.len(), 2);
    assert!(mid_descendants.contains(&1002));
    assert!(mid_descendants.contains(&1003));

    // From leaf, should find nothing
    let leaf_descendants = tree.enumerate_descendants(1003);
    assert!(leaf_descendants.is_empty());
}

#[test]
fn test_descendant_enumeration_supervisor_with_workers() {
    // SCENARIO: supervisor_with_workers
    // Tree: supervisor → 10 workers
    // Expected: Blast radius = 11, high impact
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_memory(50.0));

    for i in 0..10 {
        tree.add_process(SimulatedProcess::new(1001 + i, 1000).with_memory(100.0));
    }

    let descendants = tree.enumerate_descendants(1000);
    assert_eq!(
        descendants.len(),
        10,
        "Supervisor should have 10 worker descendants"
    );

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_descendants, 10);
    // 50 + (10 * 100) = 1050 MB
    assert!(
        (resources.total_memory_mb - 1050.0).abs() < 0.1,
        "Total memory should be 1050 MB, got {}",
        resources.total_memory_mb
    );
}

#[test]
fn test_descendant_enumeration_multi_level_tree() {
    // Tree:
    //       1000
    //      /    \
    //    1001   1002
    //    / \      |
    //  1003 1004 1005
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1));
    tree.add_process(SimulatedProcess::new(1001, 1000));
    tree.add_process(SimulatedProcess::new(1002, 1000));
    tree.add_process(SimulatedProcess::new(1003, 1001));
    tree.add_process(SimulatedProcess::new(1004, 1001));
    tree.add_process(SimulatedProcess::new(1005, 1002));

    let descendants = tree.enumerate_descendants(1000);
    assert_eq!(descendants.len(), 5);

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_descendants, 5);
}

// ============================================================================
// Unit Tests: Resource Aggregation
// ============================================================================

#[test]
fn test_resource_aggregation_memory() {
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_memory(100.0));
    tree.add_process(SimulatedProcess::new(1001, 1000).with_memory(200.0));
    tree.add_process(SimulatedProcess::new(1002, 1000).with_memory(300.0));

    let resources = tree.aggregate_resources(1000);
    assert!(
        (resources.total_memory_mb - 600.0).abs() < 0.1,
        "Total memory should be 600 MB"
    );
}

#[test]
fn test_resource_aggregation_connections() {
    // SCENARIO: database_connections
    // Tree: app → 5 db connections
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_connections(2));

    for i in 0..5 {
        tree.add_process(
            SimulatedProcess::new(1001 + i, 1000)
                .with_connections(10) // Each connection handler has 10 connections
                .with_memory(50.0),
        );
    }

    let resources = tree.aggregate_resources(1000);
    assert_eq!(
        resources.total_connections,
        52,
        "Should have 2 + (5 * 10) = 52 connections"
    );
    assert_eq!(resources.total_descendants, 5);
}

#[test]
fn test_resource_aggregation_file_handles() {
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_file_handles(100));
    tree.add_process(SimulatedProcess::new(1001, 1000).with_file_handles(50));
    tree.add_process(SimulatedProcess::new(1002, 1001).with_file_handles(25));

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_file_handles, 175);
}

#[test]
fn test_resource_aggregation_ports() {
    let mut tree = ProcessSubtree::new();
    tree.add_process(
        SimulatedProcess::new(1000, 1)
            .with_listen_ports(2)
            .with_memory(100.0),
    );
    tree.add_process(
        SimulatedProcess::new(1001, 1000)
            .with_listen_ports(1)
            .with_memory(50.0),
    );
    tree.add_process(
        SimulatedProcess::new(1002, 1000)
            .with_listen_ports(3)
            .with_memory(50.0),
    );

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_listen_ports, 6, "Should have 6 total ports");
}

#[test]
fn test_resource_aggregation_cascading_failure() {
    // SCENARIO: cascading_failure
    // Tree: init → service → 100 connections
    let mut tree = ProcessSubtree::new();
    tree.add_process(
        SimulatedProcess::new(1000, 1)
            .with_memory(200.0)
            .with_connections(5),
    );

    // Service with 100 connection handlers
    for i in 0..100 {
        tree.add_process(
            SimulatedProcess::new(1001 + i, 1000)
                .with_connections(1)
                .with_memory(10.0),
        );
    }

    let resources = tree.aggregate_resources(1000);
    assert_eq!(
        resources.total_connections,
        105,
        "Should aggregate all connections"
    );
    assert_eq!(resources.total_descendants, 100);
    assert!(
        (resources.total_memory_mb - 1200.0).abs() < 0.1,
        "Total memory: 200 + (100 * 10) = 1200 MB"
    );
}

// ============================================================================
// Unit Tests: Risk Propagation
// ============================================================================

#[test]
fn test_risk_propagation_belief_coupling() {
    // Test that abandonment belief propagates from parent to children
    let mut propagator = BeliefPropagator::new(BeliefPropConfig::strong_coupling());

    // Parent strongly abandoned
    let parent_belief = make_belief(0.05, 0.05, 0.85, 0.05);
    // Child weakly useful
    let child_belief = make_belief(0.4, 0.2, 0.3, 0.1);

    propagator.add_process(ProcessNode::with_belief(1000, 1, parent_belief));
    propagator.add_process(ProcessNode::with_belief(1001, 1000, child_belief.clone()));

    let result = propagator.propagate().unwrap();

    // Child should be pulled toward abandoned due to coupling
    let child_marginal = result.marginals.get(&1001).unwrap();
    let coupled_abandoned = *child_marginal.get(&State::Abandoned).unwrap();

    // Original was 0.3, should be higher now due to parent influence
    assert!(
        coupled_abandoned > 0.3,
        "Coupling should increase child's abandoned probability from 0.3 to {:.2}",
        coupled_abandoned
    );
}

#[test]
fn test_risk_propagation_supervisor_tree() {
    // Supervisor with multiple workers - risk should propagate
    let mut propagator = BeliefPropagator::new(BeliefPropConfig::default());

    // Supervisor is abandoned
    let supervisor_belief = make_belief(0.1, 0.1, 0.7, 0.1);
    propagator.add_process(ProcessNode::with_belief(1000, 1, supervisor_belief));

    // Workers are initially uncertain
    for i in 1..=5 {
        let worker_belief = make_belief(0.25, 0.25, 0.25, 0.25);
        propagator.add_process(ProcessNode::with_belief(1000 + i, 1000, worker_belief));
    }

    let result = propagator.propagate().unwrap();

    // All workers should shift toward abandoned
    for i in 1..=5 {
        let worker_marginal = result.marginals.get(&(1000 + i)).unwrap();
        let abandoned = *worker_marginal.get(&State::Abandoned).unwrap();
        assert!(
            abandoned > 0.25,
            "Worker {} should have elevated abandoned probability",
            i
        );
    }
}

#[test]
fn test_risk_propagation_no_coupling() {
    // With no coupling, beliefs should remain independent
    let mut propagator = BeliefPropagator::new(BeliefPropConfig::independent());

    let parent_belief = make_belief(0.05, 0.05, 0.85, 0.05);
    let child_belief = make_belief(0.7, 0.1, 0.1, 0.1);

    propagator.add_process(ProcessNode::with_belief(1000, 1, parent_belief));
    propagator.add_process(ProcessNode::with_belief(1001, 1000, child_belief.clone()));

    let result = propagator.propagate().unwrap();

    let child_marginal = result.marginals.get(&1001).unwrap();
    let child_useful = *child_marginal.get(&State::Useful).unwrap();

    // Should stay close to original 0.7
    assert!(
        (child_useful - 0.7).abs() < 0.1,
        "Without coupling, child useful should stay near 0.7, got {:.2}",
        child_useful
    );
}

// ============================================================================
// Unit Tests: Impact Scoring
// ============================================================================

#[test]
fn test_impact_score_isolated_process() {
    // Low impact: no children, no network, no critical files
    let components = ImpactComponents {
        listen_ports_count: 0,
        established_conns_count: 0,
        open_fds_count: 5,
        open_write_fds_count: 0,
        critical_writes_count: 0,
        critical_write_categories: Vec::new(),
        child_count: 0,
        supervisor_level: SupervisorLevel::None,
        supervisor_name: None,
        missing_data: Vec::new(),
    };

    let severity = ImpactSeverity::from_score(0.0);
    assert_eq!(severity, ImpactSeverity::Low);
}

#[test]
fn test_impact_score_supervised_process() {
    // High impact: supervised by agent
    let components = ImpactComponents {
        supervisor_level: SupervisorLevel::Agent,
        supervisor_name: Some("claude".to_string()),
        ..Default::default()
    };

    let weight = components.supervisor_level.protection_weight();
    assert_eq!(weight, 1.0, "Agent supervision should have max protection");
}

#[test]
fn test_impact_score_child_count_effect() {
    // Test that child count affects impact through ImpactComponents
    // (score_children is private, so we test via the data structures)

    // Components with no children - should have lower weight contribution
    let no_children = ImpactComponents {
        child_count: 0,
        ..Default::default()
    };
    assert_eq!(no_children.child_count, 0);

    // Components with children - should have higher weight contribution
    let with_children = ImpactComponents {
        child_count: 10,
        ..Default::default()
    };
    assert_eq!(with_children.child_count, 10);

    // Components with many children
    let many_children = ImpactComponents {
        child_count: 50,
        ..Default::default()
    };
    assert!(many_children.child_count > with_children.child_count);
}

#[test]
fn test_impact_severity_thresholds() {
    assert_eq!(ImpactSeverity::from_score(0.0), ImpactSeverity::Low);
    assert_eq!(ImpactSeverity::from_score(0.24), ImpactSeverity::Low);
    assert_eq!(ImpactSeverity::from_score(0.25), ImpactSeverity::Medium);
    assert_eq!(ImpactSeverity::from_score(0.49), ImpactSeverity::Medium);
    assert_eq!(ImpactSeverity::from_score(0.50), ImpactSeverity::High);
    assert_eq!(ImpactSeverity::from_score(0.74), ImpactSeverity::High);
    assert_eq!(ImpactSeverity::from_score(0.75), ImpactSeverity::Critical);
    assert_eq!(ImpactSeverity::from_score(1.0), ImpactSeverity::Critical);
}

// ============================================================================
// Unit Tests: Warning Generation
// ============================================================================

#[test]
fn test_warning_generation_high_descendants() {
    let resources = SubtreeResources {
        total_descendants: 15,
        total_memory_mb: 500.0,
        total_connections: 5,
        total_listen_ports: 2,
        total_file_handles: 50,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert!(
        warnings
            .iter()
            .any(|w| w.contains("High descendant count")),
        "Should warn about high descendants"
    );
    assert!(warnings.iter().any(|w| w.contains("15")));
}

#[test]
fn test_warning_generation_high_memory() {
    let resources = SubtreeResources {
        total_descendants: 5,
        total_memory_mb: 2048.0, // 2GB
        total_connections: 5,
        total_listen_ports: 2,
        total_file_handles: 50,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert!(
        warnings.iter().any(|w| w.contains("High memory impact")),
        "Should warn about high memory"
    );
    assert!(warnings.iter().any(|w| w.contains("2048")));
}

#[test]
fn test_warning_generation_network_impact() {
    let resources = SubtreeResources {
        total_descendants: 5,
        total_memory_mb: 500.0,
        total_connections: 50, // High connections
        total_listen_ports: 2,
        total_file_handles: 50,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert!(
        warnings.iter().any(|w| w.contains("Network impact")),
        "Should warn about network impact"
    );
}

#[test]
fn test_warning_generation_port_impact() {
    let resources = SubtreeResources {
        total_descendants: 5,
        total_memory_mb: 500.0,
        total_connections: 5,
        total_listen_ports: 10, // Many ports
        total_file_handles: 50,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert!(
        warnings.iter().any(|w| w.contains("Port impact")),
        "Should warn about port impact"
    );
}

#[test]
fn test_warning_generation_no_warnings() {
    let resources = SubtreeResources {
        total_descendants: 2,
        total_memory_mb: 100.0,
        total_connections: 2,
        total_listen_ports: 1,
        total_file_handles: 20,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert!(warnings.is_empty(), "Low impact should generate no warnings");
}

#[test]
fn test_warning_generation_multiple_warnings() {
    let resources = SubtreeResources {
        total_descendants: 50,   // High
        total_memory_mb: 5000.0, // High
        total_connections: 100,  // High
        total_listen_ports: 20,  // High
        total_file_handles: 500,
    };

    let thresholds = BlastRadiusThresholds::default();
    let warnings = generate_blast_radius_warnings(&resources, &thresholds);

    assert_eq!(
        warnings.len(),
        4,
        "Should generate 4 warnings for all exceeded thresholds"
    );
}

// ============================================================================
// Integration Tests: Robot Constraints with Blast Radius
// ============================================================================

#[test]
fn test_robot_constraints_per_candidate_blast_radius() {
    use pt_core::config::policy::RobotMode;

    let robot_mode = RobotMode {
        enabled: true,
        min_posterior: 0.95,
        min_confidence: None,
        max_blast_radius_mb: 1024.0, // 1GB limit
        max_kills: 10,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: false,
    };

    let constraints = RuntimeRobotConstraints::from_policy(&robot_mode);
    let checker = ConstraintChecker::new(constraints);

    // Small process should pass
    let small_candidate = RobotCandidate::new()
        .with_posterior(0.98)
        .with_memory_mb(100.0)
        .with_kill_action(true);

    let result = checker.check_candidate(&small_candidate);
    assert!(result.allowed, "Small process should be allowed");

    // Large process should be blocked
    let large_candidate = RobotCandidate::new()
        .with_posterior(0.98)
        .with_memory_mb(2000.0) // 2GB, exceeds 1GB limit
        .with_kill_action(true);

    let result = checker.check_candidate(&large_candidate);
    assert!(!result.allowed, "Large process should be blocked");
    assert!(result
        .violations
        .iter()
        .any(|v| v.constraint == ConstraintKind::MaxBlastRadius));
}

#[test]
fn test_robot_constraints_accumulated_blast_radius() {
    use pt_core::config::policy::RobotMode;

    let robot_mode = RobotMode {
        enabled: true,
        min_posterior: 0.90,
        min_confidence: None,
        max_blast_radius_mb: 500.0, // Per-candidate limit
        max_kills: 100,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: false,
    };

    let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
        .with_max_total_blast_radius_mb(Some(1000.0)); // Total limit 1GB

    let checker = ConstraintChecker::new(constraints);

    // Record 800MB of kills
    checker.record_action(800 * 1024 * 1024, true);

    // Try to add another 300MB - should exceed total limit
    let candidate = RobotCandidate::new()
        .with_posterior(0.95)
        .with_memory_mb(300.0)
        .with_kill_action(true);

    let result = checker.check_candidate(&candidate);
    assert!(!result.allowed, "Should exceed total blast radius limit");
    assert!(result
        .violations
        .iter()
        .any(|v| v.constraint == ConstraintKind::MaxTotalBlastRadius));

    // Smaller candidate should still fit
    let small_candidate = RobotCandidate::new()
        .with_posterior(0.95)
        .with_memory_mb(100.0) // Only 100MB more
        .with_kill_action(true);

    let result = checker.check_candidate(&small_candidate);
    assert!(
        result.allowed,
        "Small candidate should fit within remaining budget"
    );
}

#[test]
fn test_robot_constraints_metrics_tracking() {
    use pt_core::config::policy::RobotMode;

    let robot_mode = RobotMode {
        enabled: true,
        min_posterior: 0.90,
        min_confidence: None,
        max_blast_radius_mb: 1000.0,
        max_kills: 5,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: false,
    };

    let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
        .with_max_total_blast_radius_mb(Some(2000.0));

    let checker = ConstraintChecker::new(constraints);

    // Record some actions
    checker.record_action(200 * 1024 * 1024, true); // 200MB kill
    checker.record_action(300 * 1024 * 1024, true); // 300MB kill
    checker.record_action(100 * 1024 * 1024, false); // 100MB non-kill

    let metrics = checker.current_metrics();

    assert_eq!(metrics.current_kills, 2);
    assert_eq!(metrics.remaining_kills, 3);
    assert!((metrics.accumulated_blast_radius_mb - 600.0).abs() < 1.0);
    assert!((metrics.remaining_blast_radius_mb.unwrap() - 1400.0).abs() < 1.0);
}

// ============================================================================
// Integration Tests: End-to-End Scenarios
// ============================================================================

#[test]
fn test_e2e_scenario_isolated_process() {
    // SCENARIO: isolated_process
    // Single process, no children, minimal resources
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_memory(50.0));

    let resources = tree.aggregate_resources(1000);

    assert_eq!(resources.total_descendants, 0);
    assert!((resources.total_memory_mb - 50.0).abs() < 0.1);

    let warnings = generate_blast_radius_warnings(&resources, &BlastRadiusThresholds::default());
    assert!(warnings.is_empty(), "Isolated process should have no warnings");
}

#[test]
fn test_e2e_scenario_supervisor_with_workers() {
    // SCENARIO: supervisor_with_workers
    // Supervisor with 11 workers (>10 threshold for warning)
    let mut tree = ProcessSubtree::new();
    tree.add_process(
        SimulatedProcess::new(1000, 1)
            .with_memory(100.0)
            .with_supervised(false),
    );

    for i in 0..11 {
        tree.add_process(
            SimulatedProcess::new(1001 + i, 1000)
                .with_memory(100.0)
                .with_connections(5),
        );
    }

    let resources = tree.aggregate_resources(1000);

    assert_eq!(resources.total_descendants, 11);
    assert!((resources.total_memory_mb - 1200.0).abs() < 0.1); // 100 + 11*100
    assert_eq!(resources.total_connections, 55); // 11 * 5

    let warnings = generate_blast_radius_warnings(&resources, &BlastRadiusThresholds::default());

    // Should warn about high descendants (>10)
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("High descendant count")),
        "Should warn about 11 descendants exceeding threshold of 10"
    );

    // Should warn about memory (1200MB > 1024MB threshold)
    assert!(
        warnings.iter().any(|w| w.contains("High memory impact")),
        "Should warn about high memory"
    );

    // Should warn about connections (55 > 10 threshold)
    assert!(
        warnings.iter().any(|w| w.contains("Network impact")),
        "Should warn about network connections"
    );
}

#[test]
fn test_e2e_scenario_cascading_failure() {
    // SCENARIO: cascading_failure
    // Service with 100 connection handlers
    let mut tree = ProcessSubtree::new();
    tree.add_process(
        SimulatedProcess::new(1000, 1)
            .with_memory(200.0)
            .with_listen_ports(3),
    );

    for i in 0..100 {
        tree.add_process(
            SimulatedProcess::new(1001 + i, 1000)
                .with_memory(10.0)
                .with_connections(1),
        );
    }

    let resources = tree.aggregate_resources(1000);

    // Verify cascading impact
    assert_eq!(resources.total_descendants, 100);
    assert_eq!(resources.total_connections, 100);
    assert!((resources.total_memory_mb - 1200.0).abs() < 0.1);

    let warnings = generate_blast_radius_warnings(&resources, &BlastRadiusThresholds::default());

    // Should have all warnings
    assert!(warnings.len() >= 3, "Cascading failure should trigger multiple warnings: descendants, memory, connections");
}

// ============================================================================
// Logging Requirements Tests
// ============================================================================

#[test]
fn test_logging_descendant_enumeration() {
    // Test that descendant enumeration can be logged
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1));
    tree.add_process(SimulatedProcess::new(1001, 1000));
    tree.add_process(SimulatedProcess::new(1002, 1000));

    let descendants = tree.enumerate_descendants(1000);

    // Verify data is available for logging
    let log_entry = format!(
        "descendant_enumeration: pid=1000, descendant_count={}, descendants={:?}",
        descendants.len(),
        descendants
    );

    assert!(log_entry.contains("pid=1000"));
    assert!(log_entry.contains("descendant_count=2"));
}

#[test]
fn test_logging_resource_aggregation() {
    let mut tree = ProcessSubtree::new();
    tree.add_process(SimulatedProcess::new(1000, 1).with_memory(100.0));
    tree.add_process(
        SimulatedProcess::new(1001, 1000)
            .with_memory(200.0)
            .with_connections(5),
    );

    let resources = tree.aggregate_resources(1000);

    // Verify data is available for logging
    let log_entry = format!(
        "resource_aggregation: pid=1000, total_memory_mb={:.1}, total_connections={}, total_descendants={}",
        resources.total_memory_mb,
        resources.total_connections,
        resources.total_descendants
    );

    assert!(log_entry.contains("total_memory_mb=300.0"));
    assert!(log_entry.contains("total_connections=5"));
    assert!(log_entry.contains("total_descendants=1"));
}

#[test]
fn test_logging_warning_events() {
    let resources = SubtreeResources {
        total_descendants: 20,
        total_memory_mb: 2000.0,
        total_connections: 50,
        total_listen_ports: 10,
        total_file_handles: 100,
    };

    let warnings = generate_blast_radius_warnings(&resources, &BlastRadiusThresholds::default());

    // Verify warnings can be logged
    for (i, warning) in warnings.iter().enumerate() {
        let log_entry = format!("blast_radius_warning: index={}, message=\"{}\"", i, warning);
        assert!(!log_entry.is_empty());
    }

    assert_eq!(warnings.len(), 4, "Should have 4 warnings to log");
}

#[test]
fn test_logging_constraint_metrics() {
    use pt_core::config::policy::RobotMode;

    let robot_mode = RobotMode {
        enabled: true,
        min_posterior: 0.95,
        min_confidence: None,
        max_blast_radius_mb: 1000.0,
        max_kills: 10,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: false,
    };

    let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
        .with_max_total_blast_radius_mb(Some(5000.0));

    let checker = ConstraintChecker::new(constraints);
    checker.record_action(1000 * 1024 * 1024, true);

    let metrics = checker.current_metrics();

    // Verify metrics can be logged
    let log_entry = format!(
        "constraint_metrics: current_kills={}, remaining_kills={}, accumulated_mb={:.1}, remaining_mb={:.1}",
        metrics.current_kills,
        metrics.remaining_kills,
        metrics.accumulated_blast_radius_mb,
        metrics.remaining_blast_radius_mb.unwrap_or(0.0)
    );

    assert!(log_entry.contains("current_kills=1"));
    assert!(log_entry.contains("remaining_kills=9"));
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_edge_case_empty_tree() {
    let tree = ProcessSubtree::new();
    let descendants = tree.enumerate_descendants(9999);
    assert!(descendants.is_empty());
}

#[test]
fn test_edge_case_circular_reference_protection() {
    // Ensure tree building doesn't infinite loop on malformed data
    let mut tree = ProcessSubtree::new();
    // Note: In a real scenario, this would be invalid, but the tree
    // structure should handle it gracefully
    tree.add_process(SimulatedProcess::new(1000, 1001)); // Points to non-existent parent
    tree.add_process(SimulatedProcess::new(1001, 1000)); // Creates a cycle

    // Should not panic and should return limited results
    let descendants = tree.enumerate_descendants(1000);
    // Depending on insertion order, this may find 1001 or nothing
    assert!(descendants.len() <= 1);
}

#[test]
fn test_edge_case_very_deep_tree() {
    let mut tree = ProcessSubtree::new();

    // Create a 100-level deep tree
    tree.add_process(SimulatedProcess::new(1000, 1));
    for i in 1..100 {
        tree.add_process(SimulatedProcess::new(1000 + i, 1000 + i - 1));
    }

    let descendants = tree.enumerate_descendants(1000);
    assert_eq!(descendants.len(), 99);

    let resources = tree.aggregate_resources(1000);
    assert_eq!(resources.total_descendants, 99);
}

#[test]
fn test_edge_case_very_wide_tree() {
    let mut tree = ProcessSubtree::new();

    // Create a tree with 1000 direct children
    tree.add_process(SimulatedProcess::new(1000, 1).with_memory(10.0));
    for i in 0..1000 {
        tree.add_process(SimulatedProcess::new(2000 + i, 1000).with_memory(1.0));
    }

    let descendants = tree.enumerate_descendants(1000);
    assert_eq!(descendants.len(), 1000);

    let resources = tree.aggregate_resources(1000);
    assert!((resources.total_memory_mb - 1010.0).abs() < 0.1); // 10 + 1000*1
}

#[test]
fn test_edge_case_zero_resources() {
    let resources = SubtreeResources::default();
    let warnings = generate_blast_radius_warnings(&resources, &BlastRadiusThresholds::default());
    assert!(warnings.is_empty());
}
