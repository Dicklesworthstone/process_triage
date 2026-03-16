//! Blast-radius output contract, confidence tiers, and evidence accounting.
//!
//! Defines the machine-readable schema for reasoning about what happens when
//! a process is killed: direct impact (memory freed, children terminated),
//! indirect impact (shared resources, dependent processes), and unknowns
//! (insufficient evidence to determine impact).
//!
//! Every blast-radius conclusion cites the provenance edges that support it,
//! and uncertainty is surfaced explicitly rather than hidden behind a number.

use serde::{Deserialize, Serialize};

use crate::ProvenanceConfidence;

/// Schema version for the blast-radius contract.
pub const BLAST_RADIUS_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Blast-radius assessment
// ---------------------------------------------------------------------------

/// A complete blast-radius assessment for a process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusAssessment {
    /// The process this assessment is for.
    pub pid: u32,
    /// Overall risk level.
    pub risk_level: RiskLevel,
    /// Overall confidence in this assessment.
    pub confidence: BlastRadiusConfidence,
    /// Direct impact of killing this process.
    pub direct: DirectImpact,
    /// Indirect impact on other processes and resources.
    pub indirect: IndirectImpact,
    /// What we couldn't determine.
    pub unknowns: Vec<Unknown>,
    /// Human-readable summary.
    pub summary: String,
    /// Provenance edges that support this assessment.
    pub supporting_evidence: Vec<EvidenceCitation>,
}

/// Overall risk level for display and gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Killing is safe; minimal impact expected.
    Low,
    /// Some impact possible; worth reviewing.
    Medium,
    /// Significant impact; requires confirmation.
    High,
    /// Critical impact; should not proceed without explicit authorization.
    Critical,
}

impl RiskLevel {
    /// Whether automated kill should be blocked at this risk level.
    pub fn blocks_automation(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// Confidence in the blast-radius assessment itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadiusConfidence {
    /// Overall confidence tier.
    pub tier: ConfidenceTier,
    /// What percentage of the process's provenance graph was observable.
    pub evidence_coverage: EvidenceCoverage,
    /// Reasons for confidence downgrades.
    pub downgrade_reasons: Vec<String>,
}

/// Confidence tiers for blast-radius conclusions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    /// Full provenance graph available; all impacts accounted for.
    Comprehensive,
    /// Most evidence available; minor gaps don't change the conclusion.
    Adequate,
    /// Significant gaps; conclusion may miss important impacts.
    Partial,
    /// Insufficient evidence; blast radius is essentially unknown.
    Insufficient,
}

impl ConfidenceTier {
    /// Convert from the general provenance confidence.
    pub fn from_provenance(c: ProvenanceConfidence) -> Self {
        match c {
            ProvenanceConfidence::High => Self::Comprehensive,
            ProvenanceConfidence::Medium => Self::Adequate,
            ProvenanceConfidence::Low => Self::Partial,
            ProvenanceConfidence::Unknown => Self::Insufficient,
        }
    }
}

/// How much of the evidence space was covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCoverage {
    /// Number of provenance edges examined.
    pub edges_examined: usize,
    /// Number of edges that had sufficient evidence.
    pub edges_resolved: usize,
    /// Number of edges with missing or ambiguous evidence.
    pub edges_unresolved: usize,
    /// Whether deep-scan probes were available.
    pub deep_scan_available: bool,
}

impl EvidenceCoverage {
    /// Coverage ratio (0.0 to 1.0).
    pub fn ratio(&self) -> f64 {
        if self.edges_examined == 0 {
            return 0.0;
        }
        self.edges_resolved as f64 / self.edges_examined as f64
    }
}

// ---------------------------------------------------------------------------
// Direct impact
// ---------------------------------------------------------------------------

/// Direct, immediate consequences of killing the process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectImpact {
    /// Memory that would be freed (in bytes).
    pub memory_bytes: u64,
    /// CPU percentage that would be freed.
    pub cpu_pct: f64,
    /// Number of child processes that would be terminated.
    pub child_count: u32,
    /// Open file descriptors that would be closed.
    pub fd_count: u32,
    /// Network listeners that would stop.
    pub listener_count: u32,
    /// Lockfiles that would become stale.
    pub lockfile_count: u32,
}

impl DirectImpact {
    /// An empty/zero direct impact.
    pub fn none() -> Self {
        Self {
            memory_bytes: 0,
            cpu_pct: 0.0,
            child_count: 0,
            fd_count: 0,
            listener_count: 0,
            lockfile_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Indirect impact
// ---------------------------------------------------------------------------

/// Indirect consequences: effects on other processes, services, and resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectImpact {
    /// Processes that depend on this one (via shared resources, supervisor, etc.).
    pub dependent_processes: Vec<DependentProcess>,
    /// Shared resources that would be affected.
    pub affected_resources: Vec<AffectedResource>,
    /// Services that may need restart or notification.
    pub affected_services: Vec<AffectedService>,
}

impl IndirectImpact {
    /// An empty indirect impact.
    pub fn none() -> Self {
        Self {
            dependent_processes: Vec::new(),
            affected_resources: Vec::new(),
            affected_services: Vec::new(),
        }
    }

    /// Whether there are any indirect impacts.
    pub fn has_impact(&self) -> bool {
        !self.dependent_processes.is_empty()
            || !self.affected_resources.is_empty()
            || !self.affected_services.is_empty()
    }
}

/// A process that depends on the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentProcess {
    pub pid: u32,
    pub comm: String,
    /// How this process depends on the target.
    pub dependency_kind: DependencyKind,
    /// Confidence that this dependency exists.
    pub confidence: ProvenanceConfidence,
}

/// How one process depends on another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Child process (will receive SIGHUP/SIGTERM).
    Child,
    /// Shares a resource (port, socket, lock).
    SharedResource,
    /// Communicates via pipe or socket.
    IpcPeer,
    /// Same supervisor group.
    SupervisorPeer,
    /// Same workspace/project.
    WorkspacePeer,
}

/// A resource that would be affected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedResource {
    /// The resource identifier.
    pub resource_id: String,
    /// Human-readable label.
    pub label: String,
    /// What happens to this resource.
    pub impact: ResourceImpactKind,
    /// Other PIDs that also use this resource.
    pub shared_with_pids: Vec<u32>,
}

/// What happens to a resource when its owner is killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceImpactKind {
    /// Resource becomes unavailable (e.g., listener stops).
    Unavailable,
    /// Resource becomes stale (e.g., lockfile left behind).
    Stale,
    /// Resource is released cleanly (e.g., advisory lock).
    Released,
    /// Impact is unknown.
    Unknown,
}

/// A service that would be affected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedService {
    /// The service name (e.g., systemd unit).
    pub name: String,
    /// Whether the service will auto-restart.
    pub auto_restart: Option<bool>,
    /// Confidence in service impact.
    pub confidence: ProvenanceConfidence,
}

// ---------------------------------------------------------------------------
// Unknowns
// ---------------------------------------------------------------------------

/// Something we couldn't determine about the blast radius.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unknown {
    /// What we couldn't determine.
    pub description: String,
    /// Why we couldn't determine it.
    pub reason: UnknownReason,
    /// Whether this gap could change the risk level.
    pub could_affect_risk: bool,
}

/// Why something is unknown in the blast-radius assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// Evidence was redacted by privacy policy.
    Redacted,
    /// Collector couldn't access the required data.
    CollectionFailed,
    /// Deep-scan probes weren't available.
    NoDeepScan,
    /// The evidence was contradictory.
    Contradictory,
    /// Platform doesn't support this evidence type.
    PlatformUnsupported,
}

// ---------------------------------------------------------------------------
// Evidence citations
// ---------------------------------------------------------------------------

/// A citation linking a blast-radius conclusion to provenance evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCitation {
    /// What conclusion this evidence supports.
    pub claim: String,
    /// The provenance edge or node ID supporting it.
    pub provenance_id: String,
    /// Confidence in this specific piece of evidence.
    pub confidence: ProvenanceConfidence,
}

// ---------------------------------------------------------------------------
// Risk computation helpers
// ---------------------------------------------------------------------------

/// Compute the overall risk level from impact metrics.
pub fn compute_risk_level(
    direct: &DirectImpact,
    indirect: &IndirectImpact,
    confidence: &BlastRadiusConfidence,
) -> RiskLevel {
    // Critical: listeners + dependents, or very high memory
    if direct.listener_count > 0 && !indirect.dependent_processes.is_empty() {
        return RiskLevel::Critical;
    }
    if direct.memory_bytes > 4 * 1024 * 1024 * 1024 {
        return RiskLevel::Critical;
    }

    // High: any indirect impact with dependents or affected services
    if !indirect.affected_services.is_empty() {
        return RiskLevel::High;
    }
    if indirect.dependent_processes.len() > 2 {
        return RiskLevel::High;
    }

    // If confidence is insufficient, bump up the risk
    if confidence.tier == ConfidenceTier::Insufficient {
        return RiskLevel::High;
    }

    // Medium: some indirect impact or significant direct impact
    if indirect.has_impact() {
        return RiskLevel::Medium;
    }
    if direct.child_count > 3 || direct.lockfile_count > 0 {
        return RiskLevel::Medium;
    }
    if direct.memory_bytes > 1024 * 1024 * 1024 {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

/// Generate a human-readable summary from a blast-radius assessment.
pub fn summarize_blast_radius(assessment: &BlastRadiusAssessment) -> String {
    let mut parts = Vec::new();

    let mem_mb = assessment.direct.memory_bytes / (1024 * 1024);
    if mem_mb > 0 {
        parts.push(format!("frees {mem_mb}MB RAM"));
    }

    if assessment.direct.child_count > 0 {
        parts.push(format!(
            "terminates {} child{}",
            assessment.direct.child_count,
            if assessment.direct.child_count == 1 {
                ""
            } else {
                "ren"
            }
        ));
    }

    if assessment.direct.listener_count > 0 {
        parts.push(format!(
            "stops {} listener{}",
            assessment.direct.listener_count,
            if assessment.direct.listener_count == 1 {
                ""
            } else {
                "s"
            }
        ));
    }

    if !assessment.indirect.dependent_processes.is_empty() {
        parts.push(format!(
            "affects {} dependent process{}",
            assessment.indirect.dependent_processes.len(),
            if assessment.indirect.dependent_processes.len() == 1 {
                ""
            } else {
                "es"
            }
        ));
    }

    if !assessment.unknowns.is_empty() {
        let risky = assessment
            .unknowns
            .iter()
            .filter(|u| u.could_affect_risk)
            .count();
        if risky > 0 {
            parts.push(format!(
                "{risky} unknown risk factor{}",
                if risky == 1 { "" } else { "s" }
            ));
        }
    }

    if parts.is_empty() {
        "minimal impact expected".to_string()
    } else {
        parts.join("; ")
    }
}

/// Canonical debug event names.
pub const BLAST_RADIUS_COMPUTED: &str = "provenance_blast_radius_computed";
pub const BLAST_RADIUS_EVIDENCE_GAP: &str = "provenance_blast_radius_evidence_gap";

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_assessment() -> BlastRadiusAssessment {
        BlastRadiusAssessment {
            pid: 100,
            risk_level: RiskLevel::Low,
            confidence: BlastRadiusConfidence {
                tier: ConfidenceTier::Comprehensive,
                evidence_coverage: EvidenceCoverage {
                    edges_examined: 5,
                    edges_resolved: 5,
                    edges_unresolved: 0,
                    deep_scan_available: true,
                },
                downgrade_reasons: Vec::new(),
            },
            direct: DirectImpact::none(),
            indirect: IndirectImpact::none(),
            unknowns: Vec::new(),
            summary: String::new(),
            supporting_evidence: Vec::new(),
        }
    }

    #[test]
    fn risk_level_low_for_minimal_impact() {
        let a = minimal_assessment();
        let risk = compute_risk_level(&a.direct, &a.indirect, &a.confidence);
        assert_eq!(risk, RiskLevel::Low);
    }

    #[test]
    fn risk_level_critical_for_listener_with_dependents() {
        let direct = DirectImpact {
            listener_count: 1,
            ..DirectImpact::none()
        };
        let indirect = IndirectImpact {
            dependent_processes: vec![DependentProcess {
                pid: 200,
                comm: "worker".to_string(),
                dependency_kind: DependencyKind::SharedResource,
                confidence: ProvenanceConfidence::High,
            }],
            ..IndirectImpact::none()
        };
        let confidence = BlastRadiusConfidence {
            tier: ConfidenceTier::Comprehensive,
            evidence_coverage: EvidenceCoverage {
                edges_examined: 3,
                edges_resolved: 3,
                edges_unresolved: 0,
                deep_scan_available: true,
            },
            downgrade_reasons: Vec::new(),
        };

        let risk = compute_risk_level(&direct, &indirect, &confidence);
        assert_eq!(risk, RiskLevel::Critical);
    }

    #[test]
    fn risk_level_critical_for_huge_memory() {
        let direct = DirectImpact {
            memory_bytes: 5 * 1024 * 1024 * 1024,
            ..DirectImpact::none()
        };
        let risk = compute_risk_level(
            &direct,
            &IndirectImpact::none(),
            &minimal_assessment().confidence,
        );
        assert_eq!(risk, RiskLevel::Critical);
    }

    #[test]
    fn risk_level_high_for_insufficient_confidence() {
        let confidence = BlastRadiusConfidence {
            tier: ConfidenceTier::Insufficient,
            evidence_coverage: EvidenceCoverage {
                edges_examined: 1,
                edges_resolved: 0,
                edges_unresolved: 1,
                deep_scan_available: false,
            },
            downgrade_reasons: vec!["no deep scan".to_string()],
        };

        let risk = compute_risk_level(&DirectImpact::none(), &IndirectImpact::none(), &confidence);
        assert_eq!(risk, RiskLevel::High);
    }

    #[test]
    fn risk_level_medium_for_lockfiles() {
        let direct = DirectImpact {
            lockfile_count: 2,
            ..DirectImpact::none()
        };
        let risk = compute_risk_level(
            &direct,
            &IndirectImpact::none(),
            &minimal_assessment().confidence,
        );
        assert_eq!(risk, RiskLevel::Medium);
    }

    #[test]
    fn automation_blocking() {
        assert!(!RiskLevel::Low.blocks_automation());
        assert!(!RiskLevel::Medium.blocks_automation());
        assert!(RiskLevel::High.blocks_automation());
        assert!(RiskLevel::Critical.blocks_automation());
    }

    #[test]
    fn evidence_coverage_ratio() {
        let cov = EvidenceCoverage {
            edges_examined: 10,
            edges_resolved: 7,
            edges_unresolved: 3,
            deep_scan_available: true,
        };
        assert!((cov.ratio() - 0.7).abs() < f64::EPSILON);

        let empty = EvidenceCoverage {
            edges_examined: 0,
            edges_resolved: 0,
            edges_unresolved: 0,
            deep_scan_available: false,
        };
        assert!((empty.ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_generation() {
        let mut a = minimal_assessment();
        a.direct.memory_bytes = 500 * 1024 * 1024;
        a.direct.child_count = 2;
        a.direct.listener_count = 1;

        let summary = summarize_blast_radius(&a);
        assert!(summary.contains("500MB"));
        assert!(summary.contains("2 children"));
        assert!(summary.contains("1 listener"));
    }

    #[test]
    fn summary_minimal_impact() {
        let a = minimal_assessment();
        let summary = summarize_blast_radius(&a);
        assert_eq!(summary, "minimal impact expected");
    }

    #[test]
    fn confidence_tier_from_provenance() {
        assert_eq!(
            ConfidenceTier::from_provenance(ProvenanceConfidence::High),
            ConfidenceTier::Comprehensive
        );
        assert_eq!(
            ConfidenceTier::from_provenance(ProvenanceConfidence::Unknown),
            ConfidenceTier::Insufficient
        );
    }

    #[test]
    fn indirect_impact_has_impact() {
        assert!(!IndirectImpact::none().has_impact());

        let with_dep = IndirectImpact {
            dependent_processes: vec![DependentProcess {
                pid: 1,
                comm: "x".to_string(),
                dependency_kind: DependencyKind::Child,
                confidence: ProvenanceConfidence::High,
            }],
            ..IndirectImpact::none()
        };
        assert!(with_dep.has_impact());
    }

    #[test]
    fn json_round_trip() {
        let a = minimal_assessment();
        let json = serde_json::to_string(&a).expect("serialize");
        let parsed: BlastRadiusAssessment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.pid, a.pid);
        assert_eq!(parsed.risk_level, a.risk_level);
    }
}
