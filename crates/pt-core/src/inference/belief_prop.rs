//! Belief propagation on PPID trees for coupled process inference.
//!
//! This module implements exact sum-product belief propagation on process trees
//! formed by PPID relationships. It enables coupled inference where adjacent
//! processes in the tree can share state correlations.
//!
//! # Background
//!
//! Process parent-child relationships form a forest (collection of trees rooted
//! at init descendants). When processes are related, their states may be correlated:
//! - Parent stuck → children likely stuck
//! - Worker pool processes likely share fate
//!
//! # Coupled Prior
//!
//! The pairwise potential between adjacent processes:
//!
//! ```text
//! ψ(S_u, S_v) ∝ exp(J × 1{S_u = S_v})
//! ```
//!
//! When J > 0, adjacent processes prefer the same state.
//!
//! # Algorithm
//!
//! 1. Build PPID forest from process list
//! 2. Root each tree at the topmost process (closest to init)
//! 3. Pass messages from leaves to roots (upward)
//! 4. Pass messages from roots to leaves (downward)
//! 5. Compute marginals from product of incoming messages
//!
//! # Example
//!
//! ```rust
//! use pt_core::inference::belief_prop::{
//!     BeliefPropagator, BeliefPropConfig, ProcessNode, State
//! };
//! use std::collections::HashMap;
//!
//! let config = BeliefPropConfig::default();
//! let mut propagator = BeliefPropagator::new(config);
//!
//! // Add processes with their local beliefs (from individual posterior computation)
//! let mut beliefs = HashMap::new();
//! beliefs.insert(State::Useful, 0.3);
//! beliefs.insert(State::Abandoned, 0.7);
//!
//! propagator.add_process(ProcessNode {
//!     pid: 1000,
//!     ppid: 1,
//!     local_belief: beliefs.clone(),
//! });
//!
//! propagator.add_process(ProcessNode {
//!     pid: 1001,
//!     ppid: 1000,
//!     local_belief: beliefs.clone(),
//! });
//!
//! // Run belief propagation
//! let result = propagator.propagate().unwrap();
//!
//! // Get coupled posteriors
//! for (pid, posterior) in &result.marginals {
//!     println!("PID {}: {:?}", pid, posterior);
//! }
//! ```

use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

/// Process states for the 4-class model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Useful,
    UsefulBad,
    Abandoned,
    Zombie,
}

impl State {
    /// All possible states.
    pub fn all() -> &'static [State] {
        &[State::Useful, State::UsefulBad, State::Abandoned, State::Zombie]
    }

    /// Index for array access (0-3).
    pub fn index(&self) -> usize {
        match self {
            State::Useful => 0,
            State::UsefulBad => 1,
            State::Abandoned => 2,
            State::Zombie => 3,
        }
    }

    /// Create from index.
    pub fn from_index(i: usize) -> Option<State> {
        match i {
            0 => Some(State::Useful),
            1 => Some(State::UsefulBad),
            2 => Some(State::Abandoned),
            3 => Some(State::Zombie),
            _ => None,
        }
    }
}

/// Configuration for belief propagation.
#[derive(Debug, Clone)]
pub struct BeliefPropConfig {
    /// Coupling strength J. Higher values = stronger state correlation.
    /// J > 0 means adjacent nodes prefer same state.
    pub coupling_strength: f64,
    /// Maximum iterations for loopy BP (not used in tree case).
    pub max_iterations: usize,
    /// Convergence threshold for message changes.
    pub convergence_threshold: f64,
    /// Whether to normalize messages (recommended for stability).
    pub normalize_messages: bool,
    /// Damping factor for message updates (0 = no damping, 1 = full damping).
    pub damping: f64,
}

impl Default for BeliefPropConfig {
    fn default() -> Self {
        Self {
            coupling_strength: 1.0,
            max_iterations: 100,
            convergence_threshold: 1e-6,
            normalize_messages: true,
            damping: 0.0,
        }
    }
}

impl BeliefPropConfig {
    /// Strong coupling configuration.
    pub fn strong_coupling() -> Self {
        Self {
            coupling_strength: 2.0,
            ..Default::default()
        }
    }

    /// Weak coupling configuration.
    pub fn weak_coupling() -> Self {
        Self {
            coupling_strength: 0.5,
            ..Default::default()
        }
    }

    /// No coupling (independent inference).
    pub fn independent() -> Self {
        Self {
            coupling_strength: 0.0,
            ..Default::default()
        }
    }
}

/// A process node with its local belief.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Local belief (from individual posterior computation).
    /// Maps State → probability.
    pub local_belief: HashMap<State, f64>,
}

impl ProcessNode {
    /// Create a new process node with uniform belief.
    pub fn new(pid: u32, ppid: u32) -> Self {
        let mut local_belief = HashMap::new();
        for state in State::all() {
            local_belief.insert(*state, 0.25);
        }
        Self {
            pid,
            ppid,
            local_belief,
        }
    }

    /// Create with specific beliefs.
    pub fn with_belief(pid: u32, ppid: u32, belief: HashMap<State, f64>) -> Self {
        Self {
            pid,
            ppid,
            local_belief: belief,
        }
    }

    /// Get log-belief for a state (with small epsilon for numerical stability).
    fn log_belief(&self, state: State) -> f64 {
        let prob = self.local_belief.get(&state).copied().unwrap_or(0.25);
        (prob.max(1e-10)).ln()
    }
}

/// A tree in the process forest.
#[derive(Debug, Clone)]
pub struct ProcessTree {
    /// Root PID of this tree.
    pub root: u32,
    /// All PIDs in this tree.
    pub nodes: Vec<u32>,
    /// Parent mapping (child → parent).
    pub parents: HashMap<u32, u32>,
    /// Children mapping (parent → children).
    pub children: HashMap<u32, Vec<u32>>,
    /// Depth of each node (root = 0).
    pub depths: HashMap<u32, usize>,
}

impl ProcessTree {
    /// Get leaves (nodes with no children).
    pub fn leaves(&self) -> Vec<u32> {
        self.nodes
            .iter()
            .filter(|&pid| self.children.get(pid).map_or(true, |c| c.is_empty()))
            .copied()
            .collect()
    }

    /// Get nodes in order from leaves to root (for upward pass).
    pub fn upward_order(&self) -> Vec<u32> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<u32> = self.leaves().into_iter().collect();

        while let Some(pid) = queue.pop_front() {
            if visited.contains(&pid) {
                continue;
            }

            // Check if all children have been processed
            let children = self.children.get(&pid).map_or(&[] as &[u32], |c| c.as_slice());
            if children.iter().all(|c| visited.contains(c)) {
                visited.insert(pid);
                order.push(pid);

                // Add parent to queue
                if let Some(&parent) = self.parents.get(&pid) {
                    if !visited.contains(&parent) {
                        queue.push_back(parent);
                    }
                }
            } else {
                // Defer this node
                queue.push_back(pid);
            }
        }

        order
    }

    /// Get nodes in order from root to leaves (for downward pass).
    pub fn downward_order(&self) -> Vec<u32> {
        let mut order = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.root);

        while let Some(pid) = queue.pop_front() {
            order.push(pid);
            if let Some(children) = self.children.get(&pid) {
                for child in children {
                    queue.push_back(*child);
                }
            }
        }

        order
    }
}

/// Message from node u to node v.
#[derive(Debug, Clone)]
struct Message {
    /// Log-probabilities for each state.
    log_probs: [f64; 4],
}

impl Message {
    /// Create a uniform message.
    fn uniform() -> Self {
        Self {
            log_probs: [0.0; 4],
        }
    }

    /// Normalize log-probabilities (for numerical stability).
    fn normalize(&mut self) {
        let max = self.log_probs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        if max.is_finite() {
            for p in &mut self.log_probs {
                *p -= max;
            }
        }
    }

    /// Get probability for a state.
    fn prob(&self, state: State) -> f64 {
        self.log_probs[state.index()]
    }
}

/// Result of belief propagation.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefPropResult {
    /// Number of trees in the forest.
    pub num_trees: usize,
    /// Tree structures.
    pub trees: Vec<TreeSummary>,
    /// Coupled marginal posteriors for each process.
    pub marginals: HashMap<u32, HashMap<State, f64>>,
    /// Change in beliefs compared to local priors.
    pub belief_changes: HashMap<u32, f64>,
    /// Total message passing iterations used.
    pub iterations: usize,
    /// Whether propagation converged.
    pub converged: bool,
}

/// Summary of a single tree.
#[derive(Debug, Clone, Serialize)]
pub struct TreeSummary {
    /// Root PID.
    pub root: u32,
    /// Number of nodes.
    pub size: usize,
    /// Maximum depth.
    pub max_depth: usize,
    /// PIDs of all nodes.
    pub node_pids: Vec<u32>,
}

/// Evidence for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefPropEvidence {
    /// Number of trees analyzed.
    pub num_trees: usize,
    /// Number of processes with coupled inference.
    pub num_coupled_processes: usize,
    /// Average belief change from local to coupled.
    pub avg_belief_change: f64,
    /// Maximum belief change.
    pub max_belief_change: f64,
    /// PIDs that changed classification due to coupling.
    pub classification_changes: Vec<u32>,
}

impl From<&BeliefPropResult> for BeliefPropEvidence {
    fn from(result: &BeliefPropResult) -> Self {
        let changes: Vec<f64> = result.belief_changes.values().copied().collect();
        let avg_change = if changes.is_empty() {
            0.0
        } else {
            changes.iter().sum::<f64>() / changes.len() as f64
        };
        let max_change = changes.iter().cloned().fold(0.0, f64::max);

        // Find processes with significant classification change
        let classification_changes: Vec<u32> = result
            .belief_changes
            .iter()
            .filter(|(_, &change)| change > 0.1)
            .map(|(&pid, _)| pid)
            .collect();

        Self {
            num_trees: result.num_trees,
            num_coupled_processes: result.marginals.len(),
            avg_belief_change: avg_change,
            max_belief_change: max_change,
            classification_changes,
        }
    }
}

/// Errors from belief propagation.
#[derive(Debug, Error)]
pub enum BeliefPropError {
    #[error("no processes to analyze")]
    EmptyForest,

    #[error("cycle detected in process tree at PID {0}")]
    CycleDetected(u32),

    #[error("invalid belief for PID {pid}: {message}")]
    InvalidBelief { pid: u32, message: String },
}

/// Belief propagator for PPID trees.
pub struct BeliefPropagator {
    config: BeliefPropConfig,
    processes: HashMap<u32, ProcessNode>,
}

impl BeliefPropagator {
    /// Create a new belief propagator.
    pub fn new(config: BeliefPropConfig) -> Self {
        Self {
            config,
            processes: HashMap::new(),
        }
    }

    /// Add a process to the forest.
    pub fn add_process(&mut self, node: ProcessNode) {
        self.processes.insert(node.pid, node);
    }

    /// Add multiple processes.
    pub fn add_processes(&mut self, nodes: impl IntoIterator<Item = ProcessNode>) {
        for node in nodes {
            self.add_process(node);
        }
    }

    /// Clear all processes.
    pub fn clear(&mut self) {
        self.processes.clear();
    }

    /// Build the process forest from PPID relationships.
    fn build_forest(&self) -> Result<Vec<ProcessTree>, BeliefPropError> {
        if self.processes.is_empty() {
            return Err(BeliefPropError::EmptyForest);
        }

        let pids: HashSet<u32> = self.processes.keys().copied().collect();
        let mut assigned: HashSet<u32> = HashSet::new();
        let mut trees = Vec::new();

        // Find roots: processes whose parent is not in our set (or PID 1)
        let mut roots: Vec<u32> = self
            .processes
            .values()
            .filter(|p| p.ppid == 1 || !pids.contains(&p.ppid))
            .map(|p| p.pid)
            .collect();

        // Sort for deterministic ordering
        roots.sort();

        // Build tree for each root
        for root in roots {
            if assigned.contains(&root) {
                continue;
            }

            let tree = self.build_tree(root, &pids, &mut assigned)?;
            trees.push(tree);
        }

        // Handle orphans (processes not reachable from any root)
        for &pid in &pids {
            if !assigned.contains(&pid) {
                let tree = self.build_tree(pid, &pids, &mut assigned)?;
                trees.push(tree);
            }
        }

        Ok(trees)
    }

    /// Build a single tree starting from root.
    fn build_tree(
        &self,
        root: u32,
        all_pids: &HashSet<u32>,
        assigned: &mut HashSet<u32>,
    ) -> Result<ProcessTree, BeliefPropError> {
        let mut nodes = Vec::new();
        let mut parents = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut depths = HashMap::new();

        let mut queue = VecDeque::new();
        queue.push_back((root, 0usize));
        let mut visited = HashSet::new();

        while let Some((pid, depth)) = queue.pop_front() {
            if visited.contains(&pid) {
                continue;
            }

            visited.insert(pid);
            assigned.insert(pid);
            nodes.push(pid);
            depths.insert(pid, depth);

            // Find children
            for (&child_pid, process) in &self.processes {
                if process.ppid == pid && all_pids.contains(&child_pid) && !visited.contains(&child_pid)
                {
                    children.entry(pid).or_default().push(child_pid);
                    parents.insert(child_pid, pid);
                    queue.push_back((child_pid, depth + 1));
                }
            }
        }

        Ok(ProcessTree {
            root,
            nodes,
            parents,
            children,
            depths,
        })
    }

    /// Compute pairwise potential ψ(s_u, s_v).
    fn pairwise_potential(&self, state_u: State, state_v: State) -> f64 {
        if state_u == state_v {
            self.config.coupling_strength
        } else {
            0.0
        }
    }

    /// Run belief propagation on a single tree.
    fn propagate_tree(&self, tree: &ProcessTree) -> HashMap<u32, HashMap<State, f64>> {
        let n = tree.nodes.len();

        if n == 0 {
            return HashMap::new();
        }

        if n == 1 {
            // Single node: marginal = local belief
            let pid = tree.root;
            if let Some(process) = self.processes.get(&pid) {
                let mut marginal = HashMap::new();
                for state in State::all() {
                    marginal.insert(*state, process.local_belief.get(state).copied().unwrap_or(0.25));
                }
                let mut result = HashMap::new();
                result.insert(pid, marginal);
                return result;
            }
        }

        // Initialize messages
        let mut messages: HashMap<(u32, u32), Message> = HashMap::new();

        // Upward pass: leaves to root
        let upward = tree.upward_order();
        for &pid in &upward {
            if pid == tree.root {
                continue;
            }

            if let Some(&parent) = tree.parents.get(&pid) {
                let msg = self.compute_message(pid, parent, tree, &messages);
                messages.insert((pid, parent), msg);
            }
        }

        // Downward pass: root to leaves
        let downward = tree.downward_order();
        for &pid in &downward {
            if let Some(children) = tree.children.get(&pid) {
                for &child in children {
                    let msg = self.compute_message(pid, child, tree, &messages);
                    messages.insert((pid, child), msg);
                }
            }
        }

        // Compute marginals
        self.compute_marginals(tree, &messages)
    }

    /// Compute message from node u to node v.
    fn compute_message(
        &self,
        from: u32,
        to: u32,
        tree: &ProcessTree,
        messages: &HashMap<(u32, u32), Message>,
    ) -> Message {
        let process = match self.processes.get(&from) {
            Some(p) => p,
            None => return Message::uniform(),
        };

        let mut msg = Message::uniform();

        // For each state of the target node
        for state_v in State::all() {
            let mut log_sum = f64::NEG_INFINITY;

            // Sum over states of the source node
            for state_u in State::all() {
                // Log of local belief
                let log_local = process.log_belief(*state_u);

                // Log of pairwise potential
                let log_psi = self.pairwise_potential(*state_u, *state_v);

                // Collect messages from other neighbors (not the target)
                let mut log_neighbor_product = 0.0;

                // From parent (if not the target)
                if let Some(&parent) = tree.parents.get(&from) {
                    if parent != to {
                        if let Some(parent_msg) = messages.get(&(parent, from)) {
                            log_neighbor_product += parent_msg.prob(*state_u);
                        }
                    }
                }

                // From children (if not the target)
                if let Some(children) = tree.children.get(&from) {
                    for &child in children {
                        if child != to {
                            if let Some(child_msg) = messages.get(&(child, from)) {
                                log_neighbor_product += child_msg.prob(*state_u);
                            }
                        }
                    }
                }

                let log_term = log_local + log_psi + log_neighbor_product;
                log_sum = log_sum_exp(log_sum, log_term);
            }

            msg.log_probs[state_v.index()] = log_sum;
        }

        if self.config.normalize_messages {
            msg.normalize();
        }

        msg
    }

    /// Compute marginals from messages.
    fn compute_marginals(
        &self,
        tree: &ProcessTree,
        messages: &HashMap<(u32, u32), Message>,
    ) -> HashMap<u32, HashMap<State, f64>> {
        let mut marginals = HashMap::new();

        for &pid in &tree.nodes {
            let process = match self.processes.get(&pid) {
                Some(p) => p,
                None => continue,
            };

            let mut log_marginal = [0.0f64; 4];

            // Start with local belief
            for state in State::all() {
                log_marginal[state.index()] = process.log_belief(*state);
            }

            // Multiply by incoming messages
            if let Some(&parent) = tree.parents.get(&pid) {
                if let Some(msg) = messages.get(&(parent, pid)) {
                    for state in State::all() {
                        log_marginal[state.index()] += msg.prob(*state);
                    }
                }
            }

            if let Some(children) = tree.children.get(&pid) {
                for &child in children {
                    if let Some(msg) = messages.get(&(child, pid)) {
                        for state in State::all() {
                            log_marginal[state.index()] += msg.prob(*state);
                        }
                    }
                }
            }

            // Normalize to probabilities
            let log_sum = log_marginal.iter().cloned().fold(f64::NEG_INFINITY, |a, b| log_sum_exp(a, b));
            let mut state_probs = HashMap::new();

            for state in State::all() {
                let log_prob = log_marginal[state.index()] - log_sum;
                state_probs.insert(*state, log_prob.exp());
            }

            marginals.insert(pid, state_probs);
        }

        marginals
    }

    /// Run belief propagation on all trees.
    pub fn propagate(&self) -> Result<BeliefPropResult, BeliefPropError> {
        let forest = self.build_forest()?;

        let mut all_marginals = HashMap::new();
        let mut belief_changes = HashMap::new();
        let mut tree_summaries = Vec::new();

        for tree in &forest {
            let marginals = self.propagate_tree(tree);

            // Compute belief changes
            for (&pid, coupled_belief) in &marginals {
                if let Some(process) = self.processes.get(&pid) {
                    let change = compute_belief_change(&process.local_belief, coupled_belief);
                    belief_changes.insert(pid, change);
                }
            }

            all_marginals.extend(marginals);

            // Create tree summary
            let max_depth = tree.depths.values().copied().max().unwrap_or(0);
            tree_summaries.push(TreeSummary {
                root: tree.root,
                size: tree.nodes.len(),
                max_depth,
                node_pids: tree.nodes.clone(),
            });
        }

        Ok(BeliefPropResult {
            num_trees: forest.len(),
            trees: tree_summaries,
            marginals: all_marginals,
            belief_changes,
            iterations: 1, // Exact BP on trees converges in one pass
            converged: true,
        })
    }
}

impl Default for BeliefPropagator {
    fn default() -> Self {
        Self::new(BeliefPropConfig::default())
    }
}

/// Log-sum-exp for numerical stability.
fn log_sum_exp(a: f64, b: f64) -> f64 {
    if a == f64::NEG_INFINITY {
        return b;
    }
    if b == f64::NEG_INFINITY {
        return a;
    }

    let max = a.max(b);
    max + ((a - max).exp() + (b - max).exp()).ln()
}

/// Compute total variation distance between two belief distributions.
fn compute_belief_change(
    local: &HashMap<State, f64>,
    coupled: &HashMap<State, f64>,
) -> f64 {
    let mut total = 0.0;
    for state in State::all() {
        let p1 = local.get(state).copied().unwrap_or(0.25);
        let p2 = coupled.get(state).copied().unwrap_or(0.25);
        total += (p1 - p2).abs();
    }
    total / 2.0 // TV distance = 0.5 * L1 distance
}

/// Convenience function to run belief propagation.
pub fn propagate_beliefs(
    processes: Vec<ProcessNode>,
    coupling_strength: f64,
) -> Result<BeliefPropResult, BeliefPropError> {
    let config = BeliefPropConfig {
        coupling_strength,
        ..Default::default()
    };

    let mut propagator = BeliefPropagator::new(config);
    propagator.add_processes(processes);
    propagator.propagate()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_belief(useful: f64, bad: f64, abandoned: f64, zombie: f64) -> HashMap<State, f64> {
        let mut belief = HashMap::new();
        belief.insert(State::Useful, useful);
        belief.insert(State::UsefulBad, bad);
        belief.insert(State::Abandoned, abandoned);
        belief.insert(State::Zombie, zombie);
        belief
    }

    #[test]
    fn test_state_all() {
        let states = State::all();
        assert_eq!(states.len(), 4);
    }

    #[test]
    fn test_state_index_roundtrip() {
        for state in State::all() {
            let idx = state.index();
            let recovered = State::from_index(idx).unwrap();
            assert_eq!(*state, recovered);
        }
    }

    #[test]
    fn test_config_default() {
        let config = BeliefPropConfig::default();
        assert_eq!(config.coupling_strength, 1.0);
        assert!(config.normalize_messages);
    }

    #[test]
    fn test_config_presets() {
        let strong = BeliefPropConfig::strong_coupling();
        assert_eq!(strong.coupling_strength, 2.0);

        let weak = BeliefPropConfig::weak_coupling();
        assert_eq!(weak.coupling_strength, 0.5);

        let independent = BeliefPropConfig::independent();
        assert_eq!(independent.coupling_strength, 0.0);
    }

    #[test]
    fn test_process_node_new() {
        let node = ProcessNode::new(1000, 1);
        assert_eq!(node.pid, 1000);
        assert_eq!(node.ppid, 1);
        assert_eq!(node.local_belief.len(), 4);
    }

    #[test]
    fn test_empty_forest() {
        let propagator = BeliefPropagator::default();
        let result = propagator.propagate();
        assert!(matches!(result, Err(BeliefPropError::EmptyForest)));
    }

    #[test]
    fn test_single_node() {
        let mut propagator = BeliefPropagator::default();

        let belief = make_belief(0.1, 0.1, 0.7, 0.1);
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));

        let result = propagator.propagate().unwrap();

        assert_eq!(result.num_trees, 1);
        assert_eq!(result.marginals.len(), 1);

        // Single node should have marginal = local belief
        let marginal = result.marginals.get(&1000).unwrap();
        assert!((marginal.get(&State::Abandoned).unwrap() - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_two_nodes_same_belief() {
        let mut propagator = BeliefPropagator::new(BeliefPropConfig::strong_coupling());

        let belief = make_belief(0.1, 0.1, 0.7, 0.1);
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, belief.clone()));

        let result = propagator.propagate().unwrap();

        assert_eq!(result.num_trees, 1);
        assert_eq!(result.marginals.len(), 2);

        // Both should still be high abandoned
        let m1 = result.marginals.get(&1000).unwrap();
        let m2 = result.marginals.get(&1001).unwrap();

        assert!(*m1.get(&State::Abandoned).unwrap() > 0.5);
        assert!(*m2.get(&State::Abandoned).unwrap() > 0.5);
    }

    #[test]
    fn test_coupling_effect() {
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

        // Original was 0.3, should be higher now
        assert!(
            coupled_abandoned > 0.3,
            "Coupling should increase child's abandoned probability"
        );
    }

    #[test]
    fn test_independent_inference() {
        let mut propagator = BeliefPropagator::new(BeliefPropConfig::independent());

        let parent_belief = make_belief(0.05, 0.05, 0.85, 0.05);
        let child_belief = make_belief(0.4, 0.2, 0.3, 0.1);

        propagator.add_process(ProcessNode::with_belief(1000, 1, parent_belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, child_belief.clone()));

        let result = propagator.propagate().unwrap();

        // With no coupling, marginals should match local beliefs
        let child_marginal = result.marginals.get(&1001).unwrap();
        let child_abandoned = *child_marginal.get(&State::Abandoned).unwrap();

        // Should be close to original 0.3
        assert!((child_abandoned - 0.3).abs() < 0.1);
    }

    #[test]
    fn test_three_node_chain() {
        let mut propagator = BeliefPropagator::new(BeliefPropConfig::default());

        let belief = make_belief(0.25, 0.25, 0.25, 0.25);
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1002, 1001, belief.clone()));

        let result = propagator.propagate().unwrap();

        assert_eq!(result.num_trees, 1);
        assert_eq!(result.trees[0].size, 3);
        assert_eq!(result.trees[0].max_depth, 2);
    }

    #[test]
    fn test_multiple_trees() {
        let mut propagator = BeliefPropagator::default();

        let belief = make_belief(0.25, 0.25, 0.25, 0.25);

        // Tree 1
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, belief.clone()));

        // Tree 2
        propagator.add_process(ProcessNode::with_belief(2000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(2001, 2000, belief.clone()));

        let result = propagator.propagate().unwrap();

        assert_eq!(result.num_trees, 2);
        assert_eq!(result.marginals.len(), 4);
    }

    #[test]
    fn test_tree_leaves() {
        let mut propagator = BeliefPropagator::default();

        let belief = make_belief(0.25, 0.25, 0.25, 0.25);

        // Parent with two children
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1002, 1000, belief.clone()));

        let result = propagator.propagate().unwrap();

        assert_eq!(result.num_trees, 1);
        assert_eq!(result.trees[0].size, 3);
    }

    #[test]
    fn test_belief_change_computation() {
        let local = make_belief(0.8, 0.1, 0.05, 0.05);
        let coupled = make_belief(0.4, 0.3, 0.2, 0.1);

        let change = compute_belief_change(&local, &coupled);

        // TV distance should be meaningful
        assert!(change > 0.0);
        assert!(change <= 1.0);
    }

    #[test]
    fn test_log_sum_exp() {
        // Basic cases
        assert!((log_sum_exp(0.0, 0.0) - 2.0_f64.ln()).abs() < 1e-10);

        // Edge cases
        assert_eq!(log_sum_exp(f64::NEG_INFINITY, 0.0), 0.0);
        assert_eq!(log_sum_exp(0.0, f64::NEG_INFINITY), 0.0);

        // Large difference (should handle without overflow)
        let result = log_sum_exp(100.0, 0.0);
        assert!((result - 100.0).abs() < 1e-10);
    }

    #[test]
    fn test_evidence_conversion() {
        let result = BeliefPropResult {
            num_trees: 2,
            trees: vec![],
            marginals: {
                let mut m = HashMap::new();
                m.insert(1000, make_belief(0.5, 0.2, 0.2, 0.1));
                m.insert(1001, make_belief(0.3, 0.3, 0.3, 0.1));
                m
            },
            belief_changes: {
                let mut c = HashMap::new();
                c.insert(1000, 0.15);
                c.insert(1001, 0.05);
                c
            },
            iterations: 1,
            converged: true,
        };

        let evidence = BeliefPropEvidence::from(&result);

        assert_eq!(evidence.num_trees, 2);
        assert_eq!(evidence.num_coupled_processes, 2);
        assert!((evidence.avg_belief_change - 0.1).abs() < 1e-10);
        assert!((evidence.max_belief_change - 0.15).abs() < 1e-10);
        assert_eq!(evidence.classification_changes.len(), 1);
    }

    #[test]
    fn test_convenience_function() {
        let processes = vec![
            ProcessNode::with_belief(1000, 1, make_belief(0.1, 0.1, 0.7, 0.1)),
            ProcessNode::with_belief(1001, 1000, make_belief(0.3, 0.2, 0.4, 0.1)),
        ];

        let result = propagate_beliefs(processes, 1.0).unwrap();
        assert_eq!(result.num_trees, 1);
        assert_eq!(result.marginals.len(), 2);
    }

    #[test]
    fn test_message_normalize() {
        let mut msg = Message {
            log_probs: [100.0, 101.0, 99.0, 98.0],
        };

        msg.normalize();

        // After normalization, max should be around 0
        let max = msg.log_probs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        assert!((max - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_tree_upward_downward_order() {
        let mut propagator = BeliefPropagator::default();

        let belief = make_belief(0.25, 0.25, 0.25, 0.25);

        // Build a small tree: 1000 → 1001 → 1002
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1001, 1000, belief.clone()));
        propagator.add_process(ProcessNode::with_belief(1002, 1001, belief.clone()));

        let forest = propagator.build_forest().unwrap();
        let tree = &forest[0];

        let upward = tree.upward_order();
        let downward = tree.downward_order();

        // Upward should start with leaf (1002)
        assert_eq!(upward[0], 1002);
        assert_eq!(upward[2], 1000);

        // Downward should start with root (1000)
        assert_eq!(downward[0], 1000);
        assert_eq!(downward[2], 1002);
    }

    #[test]
    fn test_pairwise_potential() {
        let propagator = BeliefPropagator::new(BeliefPropConfig {
            coupling_strength: 2.0,
            ..Default::default()
        });

        // Same state → coupling strength
        assert_eq!(
            propagator.pairwise_potential(State::Abandoned, State::Abandoned),
            2.0
        );

        // Different states → 0
        assert_eq!(
            propagator.pairwise_potential(State::Useful, State::Abandoned),
            0.0
        );
    }

    #[test]
    fn test_propagation_converges() {
        let mut propagator = BeliefPropagator::default();

        // Create a larger tree
        let belief = make_belief(0.25, 0.25, 0.25, 0.25);
        propagator.add_process(ProcessNode::with_belief(1000, 1, belief.clone()));
        for i in 1..10 {
            propagator.add_process(ProcessNode::with_belief(1000 + i, 1000 + i - 1, belief.clone()));
        }

        let result = propagator.propagate().unwrap();

        assert!(result.converged);
        assert_eq!(result.iterations, 1); // Trees converge in one pass
    }
}
