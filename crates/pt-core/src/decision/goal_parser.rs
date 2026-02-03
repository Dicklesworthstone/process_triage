//! Goal parser for resource targets.
//!
//! Parses human-readable goal strings like "free 4GB RAM" or "release port 3000"
//! into structured goal ASTs for the goal-oriented optimizer.

use serde::{Deserialize, Serialize};

/// A parsed resource goal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Goal {
    /// A single resource target.
    Target(ResourceTarget),
    /// Conjunction: all sub-goals must be met.
    And(Vec<Goal>),
    /// Disjunction: at least one sub-goal must be met.
    Or(Vec<Goal>),
}

impl Goal {
    /// Canonical string representation for telemetry/caching.
    pub fn canonical(&self) -> String {
        match self {
            Goal::Target(t) => t.canonical(),
            Goal::And(goals) => {
                let parts: Vec<String> = goals.iter().map(|g| g.canonical()).collect();
                format!("({})", parts.join(" AND "))
            }
            Goal::Or(goals) => {
                let parts: Vec<String> = goals.iter().map(|g| g.canonical()).collect();
                format!("({})", parts.join(" OR "))
            }
        }
    }
}

/// A single resource target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceTarget {
    /// Type of resource.
    pub metric: Metric,
    /// Target value (in canonical units: bytes, fraction, count).
    pub value: f64,
    /// Comparator (direction of the goal).
    pub comparator: Comparator,
    /// Optional: specific port number for port goals.
    pub port: Option<u16>,
}

impl ResourceTarget {
    pub fn canonical(&self) -> String {
        match self.metric {
            Metric::Memory => format!("memory {} {:.0} bytes", self.comparator, self.value),
            Metric::Cpu => format!("cpu {} {:.2}%", self.comparator, self.value * 100.0),
            Metric::Port => format!("release port {}", self.port.unwrap_or(0)),
            Metric::FileDescriptors => format!("fds {} {:.0}", self.comparator, self.value),
        }
    }
}

/// Resource metric type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Metric {
    Memory,
    Cpu,
    Port,
    FileDescriptors,
}

/// Goal comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparator {
    /// Free at least this amount (>=).
    FreeAtLeast,
    /// Reduce below this amount (<=).
    ReduceBelow,
    /// Release (exact match, for ports).
    Release,
}

impl std::fmt::Display for Comparator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FreeAtLeast => write!(f, "free>="),
            Self::ReduceBelow => write!(f, "<="),
            Self::Release => write!(f, "release"),
        }
    }
}

/// Error from goal parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalParseError {
    /// Empty input.
    EmptyInput,
    /// Unrecognized goal format.
    UnrecognizedFormat(String),
    /// Invalid unit.
    InvalidUnit(String),
    /// Invalid number.
    InvalidNumber(String),
    /// Invalid port number.
    InvalidPort(String),
    /// Ambiguous input.
    Ambiguous(String),
}

impl std::fmt::Display for GoalParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "Empty goal string"),
            Self::UnrecognizedFormat(s) => {
                write!(f, "Unrecognized goal format: \"{}\". Try: \"free 4GB RAM\", \"reduce CPU below 50%\", \"release port 3000\", \"free 100 FDs\"", s)
            }
            Self::InvalidUnit(u) => write!(f, "Invalid unit: \"{}\". Use: B, KB, MB, GB, TB", u),
            Self::InvalidNumber(n) => write!(f, "Invalid number: \"{}\"", n),
            Self::InvalidPort(p) => write!(f, "Invalid port: \"{}\" (must be 1-65535)", p),
            Self::Ambiguous(s) => write!(f, "Ambiguous goal: \"{}\"", s),
        }
    }
}

/// Parse a goal string into a structured Goal.
///
/// Supported formats:
/// - "free 4GB RAM"
/// - "free 500MB memory"
/// - "reduce CPU below 50%"
/// - "free 20% CPU"
/// - "release port 3000"
/// - "free 100 FDs"
/// - "free 50 file descriptors"
/// - Composition: "free 4GB RAM AND release port 3000"
pub fn parse_goal(input: &str) -> Result<Goal, GoalParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(GoalParseError::EmptyInput);
    }

    // Check for composition.
    // Split on " AND " or " OR " (case insensitive).
    let upper = trimmed.to_uppercase();

    if upper.contains(" AND ") {
        let parts = split_preserving_case(trimmed, " AND ");
        let goals: Result<Vec<Goal>, GoalParseError> = parts
            .iter()
            .map(|p| parse_single_goal(p.trim()).map(Goal::Target))
            .collect();
        return Ok(Goal::And(goals?));
    }

    if upper.contains(" OR ") {
        let parts = split_preserving_case(trimmed, " OR ");
        let goals: Result<Vec<Goal>, GoalParseError> = parts
            .iter()
            .map(|p| parse_single_goal(p.trim()).map(Goal::Target))
            .collect();
        return Ok(Goal::Or(goals?));
    }

    parse_single_goal(trimmed).map(Goal::Target)
}

/// Split a string on a separator (case-insensitive) but preserve original case.
fn split_preserving_case<'a>(input: &'a str, sep: &str) -> Vec<&'a str> {
    let upper_input = input.to_uppercase();
    let upper_sep = sep.to_uppercase();
    let mut parts = Vec::new();
    let mut start = 0;

    while let Some(pos) = upper_input[start..].find(&upper_sep) {
        parts.push(&input[start..start + pos]);
        start += pos + sep.len();
    }
    parts.push(&input[start..]);
    parts
}

fn parse_single_goal(input: &str) -> Result<ResourceTarget, GoalParseError> {
    let lower = input.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();

    if tokens.is_empty() {
        return Err(GoalParseError::EmptyInput);
    }

    // "release port <N>"
    if tokens.len() >= 3 && tokens[0] == "release" && tokens[1] == "port" {
        let port_str = tokens[2];
        let port: u16 = port_str
            .parse()
            .map_err(|_| GoalParseError::InvalidPort(port_str.to_string()))?;
        if port == 0 {
            return Err(GoalParseError::InvalidPort(port_str.to_string()));
        }
        return Ok(ResourceTarget {
            metric: Metric::Port,
            value: port as f64,
            comparator: Comparator::Release,
            port: Some(port),
        });
    }

    // "reduce CPU below <N>%"
    if tokens.len() >= 4 && tokens[0] == "reduce" && tokens[1] == "cpu" && tokens[2] == "below" {
        let pct_str = tokens[3].trim_end_matches('%');
        let pct: f64 = pct_str
            .parse()
            .map_err(|_| GoalParseError::InvalidNumber(pct_str.to_string()))?;
        return Ok(ResourceTarget {
            metric: Metric::Cpu,
            value: pct / 100.0,
            comparator: Comparator::ReduceBelow,
            port: None,
        });
    }

    // "free <N><unit> RAM/memory" or "free <N>% CPU" or "free <N> FDs"
    if tokens.len() >= 3 && tokens[0] == "free" {
        let amount_str = tokens[1];

        // CPU percentage: "free 20% CPU"
        if amount_str.ends_with('%') && (tokens[2] == "cpu") {
            let pct_str = amount_str.trim_end_matches('%');
            let pct: f64 = pct_str
                .parse()
                .map_err(|_| GoalParseError::InvalidNumber(pct_str.to_string()))?;
            return Ok(ResourceTarget {
                metric: Metric::Cpu,
                value: pct / 100.0,
                comparator: Comparator::FreeAtLeast,
                port: None,
            });
        }

        // FDs: "free 100 FDs" or "free 100 file descriptors"
        if tokens[2] == "fds"
            || tokens[2] == "fd"
            || (tokens.len() >= 4 && tokens[2] == "file" && tokens[3] == "descriptors")
        {
            let n: f64 = amount_str
                .parse()
                .map_err(|_| GoalParseError::InvalidNumber(amount_str.to_string()))?;
            return Ok(ResourceTarget {
                metric: Metric::FileDescriptors,
                value: n,
                comparator: Comparator::FreeAtLeast,
                port: None,
            });
        }

        // Memory: "free 4GB RAM" or "free 500MB memory"
        if tokens[2] == "ram" || tokens[2] == "memory" || tokens[2] == "mem" {
            let bytes = parse_memory_amount(amount_str)?;
            return Ok(ResourceTarget {
                metric: Metric::Memory,
                value: bytes,
                comparator: Comparator::FreeAtLeast,
                port: None,
            });
        }

        // Try to parse as memory with unit embedded: "free 4gb" (no resource word)
        if let Ok(_bytes) = parse_memory_amount(amount_str) {
            // Ambiguous without resource qualifier — check if there's a trailing qualifier
            return Err(GoalParseError::Ambiguous(format!(
                "\"free {}\" - did you mean \"free {} RAM\" or \"free {} FDs\"?",
                amount_str, amount_str, amount_str
            )));
        }
    }

    Err(GoalParseError::UnrecognizedFormat(input.to_string()))
}

/// Parse a memory amount string like "4GB", "500MB", "1024B" into bytes.
fn parse_memory_amount(s: &str) -> Result<f64, GoalParseError> {
    let s = s.to_lowercase();

    // Find the boundary between number and unit.
    let num_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());

    if num_end == 0 {
        return Err(GoalParseError::InvalidNumber(s.to_string()));
    }

    let num_str = &s[..num_end];
    let unit_str = s[num_end..].trim();

    let num: f64 = num_str
        .parse()
        .map_err(|_| GoalParseError::InvalidNumber(num_str.to_string()))?;

    let multiplier = match unit_str {
        "" | "b" | "bytes" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(GoalParseError::InvalidUnit(unit_str.to_string())),
    };

    Ok(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_memory() {
        let goal = parse_goal("free 4GB RAM").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::Memory);
            assert_eq!(t.comparator, Comparator::FreeAtLeast);
            assert!((t.value - 4.0 * 1024.0 * 1024.0 * 1024.0).abs() < 1.0);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_free_memory_mb() {
        let goal = parse_goal("free 500MB memory").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::Memory);
            assert!((t.value - 500.0 * 1024.0 * 1024.0).abs() < 1.0);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_reduce_cpu() {
        let goal = parse_goal("reduce CPU below 50%").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::Cpu);
            assert_eq!(t.comparator, Comparator::ReduceBelow);
            assert!((t.value - 0.5).abs() < 0.01);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_free_cpu() {
        let goal = parse_goal("free 20% CPU").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::Cpu);
            assert_eq!(t.comparator, Comparator::FreeAtLeast);
            assert!((t.value - 0.2).abs() < 0.01);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_release_port() {
        let goal = parse_goal("release port 3000").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::Port);
            assert_eq!(t.port, Some(3000));
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_free_fds() {
        let goal = parse_goal("free 100 FDs").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::FileDescriptors);
            assert!((t.value - 100.0).abs() < 0.01);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_free_file_descriptors() {
        let goal = parse_goal("free 50 file descriptors").unwrap();
        if let Goal::Target(t) = goal {
            assert_eq!(t.metric, Metric::FileDescriptors);
            assert!((t.value - 50.0).abs() < 0.01);
        } else {
            panic!("Expected Target");
        }
    }

    #[test]
    fn test_and_composition() {
        let goal = parse_goal("free 4GB RAM AND release port 3000").unwrap();
        if let Goal::And(goals) = goal {
            assert_eq!(goals.len(), 2);
        } else {
            panic!("Expected And");
        }
    }

    #[test]
    fn test_or_composition() {
        let goal = parse_goal("free 2GB RAM OR free 20% CPU").unwrap();
        if let Goal::Or(goals) = goal {
            assert_eq!(goals.len(), 2);
        } else {
            panic!("Expected Or");
        }
    }

    #[test]
    fn test_invalid_port() {
        let err = parse_goal("release port 0").unwrap_err();
        match err {
            GoalParseError::InvalidPort(_) => {}
            _ => panic!("Expected InvalidPort, got {:?}", err),
        }
    }

    #[test]
    fn test_invalid_unit() {
        let err = parse_goal("free 4XB RAM").unwrap_err();
        match err {
            GoalParseError::InvalidUnit(_) => {}
            _ => panic!("Expected InvalidUnit, got {:?}", err),
        }
    }

    #[test]
    fn test_empty_input() {
        let err = parse_goal("").unwrap_err();
        assert_eq!(err, GoalParseError::EmptyInput);
    }

    #[test]
    fn test_unrecognized_format() {
        let err = parse_goal("do something weird").unwrap_err();
        match err {
            GoalParseError::UnrecognizedFormat(_) => {}
            _ => panic!("Expected UnrecognizedFormat, got {:?}", err),
        }
    }

    #[test]
    fn test_canonical_roundtrip() {
        let goal = parse_goal("free 4GB RAM AND release port 8080").unwrap();
        let canonical = goal.canonical();
        assert!(canonical.contains("AND"));
        assert!(canonical.contains("memory"));
        assert!(canonical.contains("port 8080"));
    }

    #[test]
    fn test_deterministic_parsing() {
        let input = "free 2GB RAM AND reduce CPU below 70%";
        let g1 = parse_goal(input).unwrap();
        let g2 = parse_goal(input).unwrap();
        assert_eq!(g1.canonical(), g2.canonical());
    }

    #[test]
    fn test_case_insensitive() {
        let g1 = parse_goal("Free 4GB RAM").unwrap();
        let g2 = parse_goal("free 4gb ram").unwrap();
        assert_eq!(g1, g2);
    }
}
