//! Goal parser for resource targets.
//!
//! Parses human-readable goal strings like "free 4GB RAM" or "release port 3000"
//! into structured goal ASTs for the goal-oriented optimizer.

use super::relief::ReliefGoal;
use serde::{Deserialize, Serialize};

/// A parsed resource goal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Goal {
    /// Choose the least disruptive available tier of pressure remedies.
    /// This is an observed-pressure request, not a quantitative resource target.
    Relieve(ReliefGoal),
    /// A single resource target.
    Target(ResourceTarget),
    /// Conjunction: all sub-goals must be met.
    And(Vec<Goal>),
    /// Disjunction: at least one sub-goal must be met.
    Or(Vec<Goal>),
}

impl Goal {
    /// Disk recovery and verification use one explicitly resolved filesystem.
    /// Validate typed/deserialized goals too, not just the command parser.
    pub fn disk_target(&self) -> Result<Option<&ResourceTarget>, GoalParseError> {
        match self {
            Self::Target(target) => Ok((target.metric == Metric::Disk).then_some(target)),
            Self::Relieve(_) => Ok(None),
            Self::And(parts) | Self::Or(parts) => disk_target_in(parts),
        }
    }

    /// Canonical string representation for telemetry/caching.
    pub fn canonical(&self) -> String {
        match self {
            Goal::Relieve(scope) => scope.canonical().to_string(),
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
    /// A directory on the filesystem to reclaim. None selects the filesystem
    /// containing the caller's current directory, resolved during observation.
    /// Omit absent fields so older saved goals retain their canonical hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_path: Option<String>,
}

impl ResourceTarget {
    pub fn canonical(&self) -> String {
        match self.metric {
            Metric::Memory => format!("memory {} {:.0} bytes", self.comparator, self.value),
            Metric::Cpu => format!("cpu {} {:.2}%", self.comparator, self.value * 100.0),
            Metric::Port => format!("release port {}", self.port.unwrap_or(0)),
            Metric::FileDescriptors => format!("fds {} {:.0}", self.comparator, self.value),
            Metric::Disk => {
                let scope = self.disk_path.as_ref().map_or_else(String::new, |path| {
                    format!(" on {}", serde_json::Value::String(path.clone()))
                });
                format!("free-disk {:.0}B{scope}", self.value)
            }
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
    Disk,
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
    /// Disk scope is not a valid absolute directory path.
    InvalidDiskPath(String),
    /// Ambiguous input.
    Ambiguous(String),
}

impl std::fmt::Display for GoalParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "Empty goal string"),
            Self::UnrecognizedFormat(s) => {
                write!(f, "Unrecognized goal format: \"{}\". Try: \"relieve\", \"cpu-pressure\", \"mem-pressure\", \"io-pressure\", \"free 4GB RAM\", \"free-disk 4GB on /data\", \"reduce CPU below 50%\", \"release port 3000\", \"free 100 FDs\"", s)
            }
            Self::InvalidUnit(u) => write!(f, "Invalid unit: \"{}\". Use: B, KB, MB, GB, TB", u),
            Self::InvalidNumber(n) => write!(f, "Invalid number: \"{}\"", n),
            Self::InvalidPort(p) => write!(f, "Invalid port: \"{}\" (must be 1-65535)", p),
            Self::InvalidDiskPath(path) => write!(
                f,
                "Invalid disk path: {path:?}; use an absolute directory path, optionally JSON-quoted"
            ),
            Self::Ambiguous(s) => write!(f, "Ambiguous goal: \"{}\"", s),
        }
    }
}

/// Parse a goal string into a structured Goal.
///
/// Supported formats:
/// - "relieve", "cpu-pressure", "mem-pressure", "io-pressure"
/// - "free 4GB RAM"
/// - "free 500MB memory"
/// - "reduce CPU below 50%"
/// - "CPU < 50%" or "CPU <= 50%" (whole-host capacity)
/// - "free 20% CPU"
/// - "release port 3000"
/// - "free port 3000"
/// - "free 100 FDs"
/// - "free 50 file descriptors"
/// - "free-disk 4GB" (filesystem containing the current directory)
/// - "free-disk 4 GB on /data" (one filesystem per goal request)
/// - Composition: "free 4GB RAM AND release port 3000"
pub fn parse_goal(input: &str) -> Result<Goal, GoalParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(GoalParseError::EmptyInput);
    }

    let relief = match trimmed.to_ascii_lowercase().as_str() {
        "relieve" => Some(ReliefGoal::All),
        "cpu-pressure" => Some(ReliefGoal::Cpu),
        "mem-pressure" => Some(ReliefGoal::Memory),
        "io-pressure" => Some(ReliefGoal::Io),
        _ => None,
    };
    if let Some(scope) = relief {
        return Ok(Goal::Relieve(scope));
    }

    // Check for composition.
    // Split on " AND " or " OR " (case insensitive).
    let parts = split_preserving_case(trimmed, " AND ");
    if parts.len() > 1 {
        let goals: Result<Vec<Goal>, GoalParseError> = parts
            .iter()
            .map(|p| parse_single_goal(p.trim()).map(Goal::Target))
            .collect();
        let goals = goals?;
        validate_disk_target_count(&goals)?;
        return Ok(Goal::And(goals));
    }

    let parts = split_preserving_case(trimmed, " OR ");
    if parts.len() > 1 {
        let goals: Result<Vec<Goal>, GoalParseError> = parts
            .iter()
            .map(|p| parse_single_goal(p.trim()).map(Goal::Target))
            .collect();
        let goals = goals?;
        validate_disk_target_count(&goals)?;
        return Ok(Goal::Or(goals));
    }

    parse_single_goal(trimmed).map(Goal::Target)
}

fn validate_disk_target_count(goals: &[Goal]) -> Result<(), GoalParseError> {
    disk_target_in(goals).map(|_| ())
}

fn disk_target_in(goals: &[Goal]) -> Result<Option<&ResourceTarget>, GoalParseError> {
    let mut found = None;
    for goal in goals {
        if let Some(target) = goal.disk_target()? {
            if found.is_some() {
                return Err(GoalParseError::Ambiguous(
                    "Use one disk target per request so planned and measured recovery share one filesystem"
                        .to_string(),
                ));
            }
            found = Some(target);
        }
    }
    Ok(found)
}

/// Split a string on a separator (case-insensitive) but preserve original case.
fn split_preserving_case<'a>(input: &'a str, sep: &str) -> Vec<&'a str> {
    // Preserve byte offsets into the original string. Unicode case folding can
    // change its length (for example, the ligature ﬃ becomes three letters).
    let upper_input = input.to_ascii_uppercase();
    let upper_sep = sep.to_ascii_uppercase();
    let mut parts = Vec::new();
    let mut start = 0;

    let mut quoted = false;
    let mut escaped = false;
    for (pos, byte) in input.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            quoted = !quoted;
            continue;
        }
        if !quoted
            && pos >= start
            && upper_input.as_bytes().get(pos..pos + upper_sep.len())
                == Some(upper_sep.as_bytes())
        {
            parts.push(&input[start..pos]);
            start = pos + sep.len();
        }
    }
    parts.push(&input[start..]);
    parts
}

fn parse_single_goal(input: &str) -> Result<ResourceTarget, GoalParseError> {
    if input
        .split_whitespace()
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("free-disk"))
    {
        return parse_disk_goal(input);
    }
    let lower = input.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();

    if tokens.is_empty() {
        return Err(GoalParseError::EmptyInput);
    }

    // "release port <N>" / "free port <N>"
    if tokens.len() == 3 && matches!(tokens[0], "release" | "free") && tokens[1] == "port" {
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
            disk_path: None,
        });
    }

    // "CPU < <N>%" / "CPU <= <N>%", including compact forms.
    if let Some(rest) = lower.strip_prefix("cpu") {
        let rest = rest.trim_start();
        if let Some(amount) = rest.strip_prefix("<=").or_else(|| rest.strip_prefix('<')) {
            return Ok(ResourceTarget {
                metric: Metric::Cpu,
                value: parse_cpu_fraction(amount.trim())?,
                comparator: Comparator::ReduceBelow,
                port: None,
                disk_path: None,
            });
        }
    }

    // "reduce CPU below <N>%"
    if tokens.len() == 4 && tokens[0] == "reduce" && tokens[1] == "cpu" && tokens[2] == "below" {
        return Ok(ResourceTarget {
            metric: Metric::Cpu,
            value: parse_cpu_fraction(tokens[3])?,
            comparator: Comparator::ReduceBelow,
            port: None,
            disk_path: None,
        });
    }

    // "free <N><unit> RAM/memory" or "free <N>% CPU" or "free <N> FDs"
    if tokens.len() >= 3 && tokens[0] == "free" {
        let amount_str = tokens[1];

        // CPU percentage: "free 20% CPU"
        if tokens.len() == 3 && amount_str.ends_with('%') && tokens[2] == "cpu" {
            return Ok(ResourceTarget {
                metric: Metric::Cpu,
                value: parse_cpu_fraction(amount_str)?,
                comparator: Comparator::FreeAtLeast,
                port: None,
                disk_path: None,
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
                disk_path: None,
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
                disk_path: None,
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

fn parse_disk_goal(input: &str) -> Result<ResourceTarget, GoalParseError> {
    let rest = input
        .split_once(char::is_whitespace)
        .map(|(_, rest)| rest.trim())
        .ok_or_else(|| GoalParseError::UnrecognizedFormat(input.to_string()))?;
    let lower = rest.to_ascii_lowercase();
    let (amount, path) = match lower.find(" on ") {
        Some(at) => (&rest[..at], Some(rest[at + 4..].trim())),
        None => (rest, None),
    };
    let words: Vec<_> = amount.split_whitespace().collect();
    if words.is_empty() || words.len() > 2 {
        return Err(GoalParseError::UnrecognizedFormat(input.to_string()));
    }
    if words.len() == 2 && !words[1].bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(GoalParseError::InvalidUnit(words[1].to_string()));
    }
    let amount = words.join("");
    let bytes = parse_memory_amount(&amount)?;
    if !bytes.is_finite() || bytes < 0.0 || bytes >= u64::MAX as f64 {
        return Err(GoalParseError::InvalidNumber(amount));
    }
    let disk_path = path
        .map(|path| {
            let decoded = if path.starts_with('"') {
                serde_json::from_str::<String>(path)
                    .map_err(|_| GoalParseError::InvalidDiskPath(path.to_string()))?
            } else {
                path.to_string()
            };
            if !decoded.starts_with('/')
                || decoded.chars().any(char::is_control)
                || decoded.len() > 4096
            {
                return Err(GoalParseError::InvalidDiskPath(decoded));
            }
            Ok(decoded)
        })
        .transpose()?;
    Ok(ResourceTarget {
        metric: Metric::Disk,
        value: bytes.ceil(),
        comparator: Comparator::FreeAtLeast,
        port: None,
        disk_path,
    })
}

/// CPU goals are fractions of the whole host, not percentages of one core.
fn parse_cpu_fraction(amount: &str) -> Result<f64, GoalParseError> {
    let number = amount.strip_suffix('%').unwrap_or(amount);
    let percent = number
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
        .ok_or_else(|| GoalParseError::InvalidNumber(amount.to_string()))?;
    Ok(percent / 100.0)
}

/// Parse a memory amount string like "4GB", "500MB", "1024B" into bytes.
fn parse_memory_amount(s: &str) -> Result<f64, GoalParseError> {
    let s = s.to_lowercase();

    // Find the boundary between number and unit.
    let num_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());

    if num_end == 0 {
        return Err(GoalParseError::InvalidNumber(s));
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
    fn disk_goals_bind_one_preserved_path_and_roundtrip() {
        for (input, expected_bytes, path) in [
            ("free-disk 1.5GB", 1_610_612_736.0, None),
            ("FREE-DISK 2 GiB on /Data/Builds", 2_147_483_648.0, Some("/Data/Builds")),
            ("free-disk 0B on /", 0.0, Some("/")),
            (r#"free-disk 1MB on "/dåta/Build AND Cache""#, 1_048_576.0, Some("/dåta/Build AND Cache")),
        ] {
            let goal = parse_goal(input).unwrap();
            let target = goal.disk_target().unwrap().unwrap();
            assert_eq!(target.metric, Metric::Disk);
            assert_eq!(target.value, expected_bytes);
            assert_eq!(target.disk_path.as_deref(), path);
            assert_eq!(target.port, None);
            assert_eq!(parse_goal(&goal.canonical()).unwrap(), goal);
            assert_eq!(serde_json::from_str::<Goal>(&serde_json::to_string(&goal).unwrap()).unwrap(), goal);
        }
    }

    #[test]
    fn disk_composition_keeps_filesystem_scope_unambiguous() {
        let goal = parse_goal(r#"free-disk 1GB on "/Build AND Cache" AND free 2GB RAM"#).unwrap();
        assert_eq!(goal.disk_target().unwrap().unwrap().disk_path.as_deref(), Some("/Build AND Cache"));
        for input in [
            "free-disk 1GB on /data AND free-disk 2GB on /other",
            "free-disk 1GB OR free-disk 2GB",
            "free-disk -1GB",
            "free-disk NaNGB",
            "free-disk 18446744073709551616B",
            "free-disk 1 2GB",
            "free-disk 1GB on relative",
            "free-disk 1GB on",
            r#"free-disk 1GB on "/data" trailing"#,
            "free-disk 1GB on /bad\npath",
        ] {
            assert!(parse_goal(input).is_err(), "accepted {input:?}");
        }
        let typed = Goal::And(vec![parse_goal("free-disk 1GB").unwrap(), parse_goal("free-disk 2GB").unwrap()]);
        assert!(typed.disk_target().is_err());
    }

    #[test]
    fn older_goal_json_does_not_gain_an_empty_disk_scope() {
        let original = serde_json::json!({
            "metric": "Memory", "value": 4096.0,
            "comparator": "FreeAtLeast", "port": null,
        });
        let target: ResourceTarget = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(target.disk_path, None);
        assert_eq!(serde_json::to_value(target).unwrap(), original);
    }

    #[test]
    fn pressure_goals_round_trip_without_implying_resource_targets() {
        for (input, scope) in [
            ("relieve", ReliefGoal::All),
            ("cpu-pressure", ReliefGoal::Cpu),
            ("mem-pressure", ReliefGoal::Memory),
            ("io-pressure", ReliefGoal::Io),
        ] {
            let goal = Goal::Relieve(scope);
            assert_eq!(
                parse_goal(&format!("  {}  ", input.to_ascii_uppercase())),
                Ok(goal.clone())
            );
            assert_eq!(parse_goal(&goal.canonical()), Ok(goal.clone()));
            let encoded = serde_json::to_string(&goal).unwrap();
            assert_eq!(serde_json::from_str::<Goal>(&encoded).unwrap(), goal);
        }
        for input in [
            "relieve AND free 4GB RAM",
            "cpu-pressure OR free 10% CPU",
            "relieve extra",
            "io-pressure 10%",
        ] {
            assert!(parse_goal(input).is_err(), "{input}");
        }
    }

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
    fn cpu_threshold_aliases_and_canonical_form_round_trip() {
        let expected = parse_goal("reduce CPU below 50%").unwrap();
        for input in ["CPU < 50%", "cpu<=50%", "CpU <= 50%"] {
            assert_eq!(parse_goal(input).unwrap(), expected, "{input}");
        }
        assert_eq!(parse_goal(&expected.canonical()).unwrap(), expected);
        let combined = parse_goal("CPU < 80% AND free 4GB RAM").unwrap();
        assert!(matches!(combined, Goal::And(parts) if parts.len() == 2));
    }

    #[test]
    fn cpu_targets_are_finite_whole_host_percentages() {
        for amount in ["-1", "100.1", "NaN", "inf", "1e309", "20%", "20 extra"] {
            for input in [
                format!("CPU < {amount}%"),
                format!("reduce CPU below {amount}%"),
                format!("free {amount}% CPU"),
            ] {
                assert!(parse_goal(&input).is_err(), "{input}");
            }
        }
        assert!(parse_goal("CPU <= 0%").is_ok());
        assert!(parse_goal("CPU <= 100%").is_ok());
        assert!(parse_goal("reduce CPU below 50% extra").is_err());
        assert!(parse_goal("free 20% CPU extra").is_err());
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
    fn free_port_is_the_same_goal_as_release_port() {
        for port in [1, 3000, 65535] {
            assert_eq!(
                parse_goal(&format!("FrEe PoRt {port}")),
                parse_goal(&format!("release port {port}")),
            );
        }
        assert!(parse_goal("free port 0").is_err());
        assert!(parse_goal("free port 65536").is_err());
        assert!(parse_goal("free port 3000 extra").is_err());
        let goal = parse_goal("free 10 FDs AND free port 3000").unwrap();
        assert!(matches!(goal, Goal::And(parts) if parts.len() == 2));
    }

    #[test]
    fn composite_invalid_unicode_does_not_corrupt_byte_offsets() {
        for input in ["ﬃ AND free port 3000", "ſ OR free port 3000"] {
            assert!(parse_goal(input).is_err());
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
