//! Fleet-wide pattern correlation and alerting.
//!
//! Detects process patterns that appear across multiple hosts, correlates
//! temporal/behavioral/outcome similarities, and generates fleet-level alerts
//! for coordinated action (e.g., fleet-wide kill after a bad deploy).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A process pattern observation from a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternObservation {
    /// Host identifier.
    pub host_id: String,
    /// Pattern key (e.g., command hash, signature).
    pub pattern_key: String,
    /// Number of instances on this host.
    pub instance_count: usize,
    /// Average CPU fraction across instances.
    pub avg_cpu: f64,
    /// Average RSS bytes across instances.
    pub avg_rss_bytes: u64,
    /// Timestamp of earliest instance spawn (epoch seconds).
    pub earliest_spawn_ts: f64,
    /// Timestamp of latest instance spawn (epoch seconds).
    pub latest_spawn_ts: f64,
    /// Whether instances are classified as abandoned/zombie on this host.
    pub abandoned_fraction: f64,
    /// Optional deploy SHA associated with these instances.
    pub deploy_sha: Option<String>,
}

/// Configuration for fleet pattern correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPatternConfig {
    /// Minimum fraction of hosts with a pattern to flag as fleet-wide.
    pub min_host_fraction: f64,
    /// Minimum absolute number of hosts.
    pub min_hosts: usize,
    /// Maximum time window (seconds) for temporal correlation.
    pub temporal_window_secs: f64,
    /// Minimum abandoned fraction across fleet to trigger alert.
    pub min_abandoned_fraction: f64,
}

impl Default for FleetPatternConfig {
    fn default() -> Self {
        Self {
            min_host_fraction: 0.5,
            min_hosts: 2,
            temporal_window_secs: 3600.0,
            min_abandoned_fraction: 0.5,
        }
    }
}

/// Types of correlation detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorrelationType {
    /// Processes spawned within a tight time window.
    Temporal,
    /// Similar resource usage patterns.
    Behavioral,
    /// Similar abandonment outcomes.
    Outcome,
    /// Linked to the same deploy SHA.
    Deploy,
}

impl std::fmt::Display for CorrelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Temporal => write!(f, "temporal"),
            Self::Behavioral => write!(f, "behavioral"),
            Self::Outcome => write!(f, "outcome"),
            Self::Deploy => write!(f, "deploy"),
        }
    }
}

/// A fleet-wide alert for a correlated pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAlert {
    /// Pattern key that triggered the alert.
    pub pattern_key: String,
    /// Number of hosts affected.
    pub affected_hosts: usize,
    /// Total fleet size.
    pub fleet_size: usize,
    /// Fraction of fleet affected.
    pub host_fraction: f64,
    /// Total instances across fleet.
    pub total_instances: usize,
    /// Fleet-wide abandoned fraction.
    pub fleet_abandoned_fraction: f64,
    /// Types of correlation detected.
    pub correlations: Vec<CorrelationType>,
    /// Deploy SHA if linked.
    pub deploy_sha: Option<String>,
    /// Recommended action.
    pub recommendation: FleetRecommendation,
    /// Human-readable summary.
    pub summary: String,
}

/// Recommended action for a fleet alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetRecommendation {
    /// Monitor only, no action needed.
    Monitor,
    /// Investigate the pattern.
    Investigate,
    /// Kill all instances fleet-wide.
    FleetKill,
    /// Roll back the associated deploy.
    RollbackDeploy,
}

impl std::fmt::Display for FleetRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "monitor"),
            Self::Investigate => write!(f, "investigate"),
            Self::FleetKill => write!(f, "fleet_kill"),
            Self::RollbackDeploy => write!(f, "rollback_deploy"),
        }
    }
}

/// Correlate patterns across fleet observations and generate alerts.
pub fn correlate_fleet_patterns(
    observations: &[PatternObservation],
    config: &FleetPatternConfig,
) -> Vec<FleetAlert> {
    if observations.is_empty() {
        return vec![];
    }

    // Group by pattern_key.
    let mut by_pattern: HashMap<&str, Vec<&PatternObservation>> = HashMap::new();
    for obs in observations {
        by_pattern.entry(&obs.pattern_key).or_default().push(obs);
    }

    // Count total unique hosts.
    let all_hosts: HashSet<&str> = observations.iter().map(|o| o.host_id.as_str()).collect();
    let fleet_size = all_hosts.len();

    let mut alerts = Vec::new();

    for (pattern_key, obs_list) in &by_pattern {
        let hosts: HashSet<&str> = obs_list.iter().map(|o| o.host_id.as_str()).collect();
        let affected = hosts.len();
        let host_frac = affected as f64 / fleet_size as f64;

        if host_frac < config.min_host_fraction || affected < config.min_hosts {
            continue;
        }

        let total_instances: usize = obs_list.iter().map(|o| o.instance_count).sum();

        // Detect correlation types.
        let mut correlations = Vec::new();

        // Temporal: are spawn times clustered?
        let spawn_times: Vec<f64> = obs_list.iter().map(|o| o.earliest_spawn_ts).collect();
        if let (Some(&min_t), Some(&max_t)) = (
            spawn_times.iter().reduce(|a, b| if a < b { a } else { b }),
            spawn_times.iter().reduce(|a, b| if a > b { a } else { b }),
        ) {
            if (max_t - min_t) <= config.temporal_window_secs {
                correlations.push(CorrelationType::Temporal);
            }
        }

        // Behavioral: similar resource usage (low CV of CPU across hosts).
        let cpus: Vec<f64> = obs_list.iter().map(|o| o.avg_cpu).collect();
        if cpus.len() >= 2 {
            let mean_cpu = cpus.iter().sum::<f64>() / cpus.len() as f64;
            let var = cpus.iter().map(|c| (c - mean_cpu).powi(2)).sum::<f64>() / cpus.len() as f64;
            let cv = if mean_cpu > 1e-6 {
                var.sqrt() / mean_cpu
            } else {
                0.0
            };
            if cv < 0.5 {
                correlations.push(CorrelationType::Behavioral);
            }
        }

        // Outcome: high abandoned fraction across fleet.
        let total_abandoned_weighted: f64 = obs_list
            .iter()
            .map(|o| o.abandoned_fraction * o.instance_count as f64)
            .sum();
        let fleet_abandoned = if total_instances > 0 {
            total_abandoned_weighted / total_instances as f64
        } else {
            0.0
        };
        if fleet_abandoned >= config.min_abandoned_fraction {
            correlations.push(CorrelationType::Outcome);
        }

        // Deploy: all observations share the same deploy SHA.
        let deploy_shas: HashSet<&str> = obs_list
            .iter()
            .filter_map(|o| o.deploy_sha.as_deref())
            .collect();
        let common_deploy = if deploy_shas.len() == 1 {
            deploy_shas.into_iter().next().map(String::from)
        } else {
            None
        };
        if common_deploy.is_some() {
            correlations.push(CorrelationType::Deploy);
        }

        if correlations.is_empty() {
            continue; // No meaningful correlation found.
        }

        let recommendation =
            determine_recommendation(&correlations, fleet_abandoned, common_deploy.is_some());

        let summary = format!(
            "Pattern \"{}\" affects {}/{} hosts ({:.0}%), {} instances, {:.0}% abandoned{}",
            pattern_key,
            affected,
            fleet_size,
            host_frac * 100.0,
            total_instances,
            fleet_abandoned * 100.0,
            if let Some(ref sha) = common_deploy {
                format!(", deploy {}", &sha[..sha.len().min(8)])
            } else {
                String::new()
            },
        );

        alerts.push(FleetAlert {
            pattern_key: pattern_key.to_string(),
            affected_hosts: affected,
            fleet_size,
            host_fraction: host_frac,
            total_instances,
            fleet_abandoned_fraction: fleet_abandoned,
            correlations,
            deploy_sha: common_deploy,
            recommendation,
            summary,
        });
    }

    // Sort by severity (most hosts affected first).
    alerts.sort_by(|a, b| {
        b.affected_hosts
            .cmp(&a.affected_hosts)
            .then_with(|| b.total_instances.cmp(&a.total_instances))
    });

    alerts
}

fn determine_recommendation(
    correlations: &[CorrelationType],
    abandoned_frac: f64,
    has_deploy: bool,
) -> FleetRecommendation {
    let has_outcome = correlations.contains(&CorrelationType::Outcome);

    if has_deploy && has_outcome && abandoned_frac > 0.7 {
        FleetRecommendation::RollbackDeploy
    } else if has_outcome && abandoned_frac > 0.7 {
        FleetRecommendation::FleetKill
    } else if has_outcome {
        FleetRecommendation::Investigate
    } else {
        FleetRecommendation::Monitor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obs(
        host: &str,
        pattern: &str,
        count: usize,
        abandoned: f64,
        deploy: Option<&str>,
    ) -> PatternObservation {
        PatternObservation {
            host_id: host.to_string(),
            pattern_key: pattern.to_string(),
            instance_count: count,
            avg_cpu: 0.0,
            avg_rss_bytes: 100_000_000,
            earliest_spawn_ts: 1000.0,
            latest_spawn_ts: 1010.0,
            abandoned_fraction: abandoned,
            deploy_sha: deploy.map(String::from),
        }
    }

    #[test]
    fn test_empty_observations() {
        let alerts = correlate_fleet_patterns(&[], &FleetPatternConfig::default());
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_single_host_no_alert() {
        let obs = vec![make_obs("host-1", "nginx", 5, 0.8, None)];
        let config = FleetPatternConfig {
            min_hosts: 2,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_fleet_wide_alert() {
        let obs = vec![
            make_obs("host-1", "bun-test", 3, 0.9, None),
            make_obs("host-2", "bun-test", 3, 0.8, None),
            make_obs("host-3", "bun-test", 2, 1.0, None),
            make_obs("host-3", "nginx", 1, 0.0, None), // Different pattern
        ];
        let config = FleetPatternConfig {
            min_host_fraction: 0.5,
            min_hosts: 2,
            min_abandoned_fraction: 0.5,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        // Only bun-test should alert (3/3 hosts, >50%).
        // nginx is only on 1/3 hosts.
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].pattern_key, "bun-test");
        assert_eq!(alerts[0].affected_hosts, 3);
        assert_eq!(alerts[0].total_instances, 8);
        assert!(alerts[0].fleet_abandoned_fraction > 0.8);
        assert!(alerts[0].correlations.contains(&CorrelationType::Outcome));
    }

    #[test]
    fn test_deploy_correlation() {
        let sha = "abc123def456";
        let obs = vec![
            make_obs("host-1", "worker", 2, 0.9, Some(sha)),
            make_obs("host-2", "worker", 3, 0.8, Some(sha)),
        ];
        let config = FleetPatternConfig::default();
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].correlations.contains(&CorrelationType::Deploy));
        assert_eq!(alerts[0].deploy_sha, Some(sha.to_string()));
        assert_eq!(
            alerts[0].recommendation,
            FleetRecommendation::RollbackDeploy
        );
    }

    #[test]
    fn test_temporal_correlation() {
        let obs = vec![
            PatternObservation {
                earliest_spawn_ts: 1000.0,
                latest_spawn_ts: 1010.0,
                ..make_obs("host-1", "cron-job", 1, 0.0, None)
            },
            PatternObservation {
                earliest_spawn_ts: 1005.0,
                latest_spawn_ts: 1015.0,
                ..make_obs("host-2", "cron-job", 1, 0.0, None)
            },
        ];
        let config = FleetPatternConfig {
            temporal_window_secs: 60.0,
            min_abandoned_fraction: 0.0,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].correlations.contains(&CorrelationType::Temporal));
    }

    #[test]
    fn test_behavioral_correlation() {
        let obs = vec![
            PatternObservation {
                avg_cpu: 0.50,
                ..make_obs("host-1", "compute", 2, 0.0, None)
            },
            PatternObservation {
                avg_cpu: 0.52,
                ..make_obs("host-2", "compute", 2, 0.0, None)
            },
        ];
        let config = FleetPatternConfig {
            min_abandoned_fraction: 0.0,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0]
            .correlations
            .contains(&CorrelationType::Behavioral));
    }

    #[test]
    fn test_fleet_kill_recommendation() {
        let obs = vec![
            make_obs("host-1", "leak", 5, 1.0, None),
            make_obs("host-2", "leak", 3, 0.9, None),
        ];
        let config = FleetPatternConfig::default();
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].recommendation, FleetRecommendation::FleetKill);
    }

    #[test]
    fn test_below_threshold_no_alert() {
        let obs = vec![
            make_obs("host-1", "rare", 1, 0.5, None),
            make_obs("host-2", "common", 1, 0.0, None),
            make_obs("host-3", "common", 1, 0.0, None),
            make_obs("host-4", "common", 1, 0.0, None),
        ];
        let config = FleetPatternConfig {
            min_host_fraction: 0.5,
            min_hosts: 2,
            min_abandoned_fraction: 0.5,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        // "rare" only on 1/4 hosts (25% < 50%).
        // "common" on 3/4 hosts but abandoned_fraction=0.
        // Common has temporal+behavioral but no outcome → should still alert with Monitor.
        let rare_alerts: Vec<_> = alerts.iter().filter(|a| a.pattern_key == "rare").collect();
        assert!(rare_alerts.is_empty());
    }

    #[test]
    fn test_summary_format() {
        let obs = vec![
            make_obs("h1", "test-runner", 2, 0.8, Some("deadbeef")),
            make_obs("h2", "test-runner", 3, 0.9, Some("deadbeef")),
        ];
        let alerts = correlate_fleet_patterns(&obs, &FleetPatternConfig::default());
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].summary.contains("test-runner"));
        assert!(alerts[0].summary.contains("2/2"));
        assert!(alerts[0].summary.contains("deadbeef"));
    }

    #[test]
    fn test_sorted_by_severity() {
        let obs = vec![
            make_obs("h1", "minor", 1, 0.9, None),
            make_obs("h2", "minor", 1, 0.8, None),
            make_obs("h1", "major", 5, 1.0, None),
            make_obs("h2", "major", 5, 1.0, None),
            make_obs("h3", "major", 3, 0.9, None),
        ];
        let config = FleetPatternConfig {
            min_host_fraction: 0.3,
            min_hosts: 2,
            ..Default::default()
        };
        let alerts = correlate_fleet_patterns(&obs, &config);
        assert!(alerts.len() >= 2);
        assert_eq!(alerts[0].pattern_key, "major"); // More hosts.
    }
}
