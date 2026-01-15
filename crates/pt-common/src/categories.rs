//! Command and CWD category taxonomies for process classification.
//!
//! This module defines the taxonomies for categorizing processes by:
//! - Command type (test runner, dev server, agent, daemon, etc.)
//! - Working directory (project, system, temp, home)
//!
//! Categories feed into the Bayesian inference as Dirichlet-Categorical evidence.
//! The categorization affects prior probabilities for each process class.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Schema version for category taxonomy.
pub const CATEGORIES_SCHEMA_VERSION: &str = "1.0.0";

/// Command categories for process classification.
///
/// These categories affect the prior probability of a process being
/// useful, abandoned, or zombie based on command type patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    /// Test runners: bun test, jest, pytest, mocha, cargo test, go test
    Test,
    /// Development servers: next dev, vite, webpack-dev-server, nodemon
    DevServer,
    /// AI/coding agents: claude, codex, copilot, gemini, cursor
    Agent,
    /// Production servers: gunicorn, nginx, apache, uvicorn, node server
    Server,
    /// System daemons: systemd services, cron, docker, supervisord
    Daemon,
    /// Build tools: webpack, esbuild, tsc, cargo build, make, gradle
    Build,
    /// Editors/IDEs: code, vim, nvim, emacs, nano, cursor
    Editor,
    /// Interactive shells: bash, zsh, fish, sh, pwsh
    Shell,
    /// Database clients: psql, mysql, mongo, redis-cli
    Database,
    /// Version control: git operations (not just git command)
    Vcs,
    /// Package managers: npm, yarn, pip, cargo, brew
    PackageManager,
    /// Container tools: docker, podman, kubectl, docker-compose
    Container,
    /// Unknown/other - default category
    Unknown,
}

impl CommandCategory {
    /// Get all category variants in order (matches Dirichlet parameter order).
    pub fn all() -> &'static [CommandCategory] {
        &[
            CommandCategory::Test,
            CommandCategory::DevServer,
            CommandCategory::Agent,
            CommandCategory::Server,
            CommandCategory::Daemon,
            CommandCategory::Build,
            CommandCategory::Editor,
            CommandCategory::Shell,
            CommandCategory::Database,
            CommandCategory::Vcs,
            CommandCategory::PackageManager,
            CommandCategory::Container,
            CommandCategory::Unknown,
        ]
    }

    /// Get the index of this category (for Dirichlet parameters).
    pub fn index(&self) -> usize {
        Self::all().iter().position(|c| c == self).unwrap_or(12)
    }

    /// Get category from index.
    pub fn from_index(idx: usize) -> Self {
        Self::all().get(idx).copied().unwrap_or(CommandCategory::Unknown)
    }

    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            CommandCategory::Test => "test",
            CommandCategory::DevServer => "devserver",
            CommandCategory::Agent => "agent",
            CommandCategory::Server => "server",
            CommandCategory::Daemon => "daemon",
            CommandCategory::Build => "build",
            CommandCategory::Editor => "editor",
            CommandCategory::Shell => "shell",
            CommandCategory::Database => "database",
            CommandCategory::Vcs => "vcs",
            CommandCategory::PackageManager => "package_manager",
            CommandCategory::Container => "container",
            CommandCategory::Unknown => "unknown",
        }
    }
}

impl Default for CommandCategory {
    fn default() -> Self {
        CommandCategory::Unknown
    }
}

/// CWD (Current Working Directory) categories.
///
/// Working directory context affects interpretation of process behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwdCategory {
    /// User project directories: ~/projects/*, ~/code/*, ~/repos/*
    Project,
    /// System directories: /usr, /var, /etc, /opt
    System,
    /// Temporary directories: /tmp, /var/tmp, /private/tmp
    Temp,
    /// Home directory root: ~, /home/user
    Home,
    /// Application data: ~/.config/*, ~/.local/*
    AppData,
    /// Runtime directories: /run, /var/run
    Runtime,
    /// Root filesystem: /
    Root,
    /// Unknown/other
    Unknown,
}

impl CwdCategory {
    /// Get all category variants in order.
    pub fn all() -> &'static [CwdCategory] {
        &[
            CwdCategory::Project,
            CwdCategory::System,
            CwdCategory::Temp,
            CwdCategory::Home,
            CwdCategory::AppData,
            CwdCategory::Runtime,
            CwdCategory::Root,
            CwdCategory::Unknown,
        ]
    }

    /// Get the index of this category.
    pub fn index(&self) -> usize {
        Self::all().iter().position(|c| c == self).unwrap_or(7)
    }

    /// Get category from index.
    pub fn from_index(idx: usize) -> Self {
        Self::all().get(idx).copied().unwrap_or(CwdCategory::Unknown)
    }

    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            CwdCategory::Project => "project",
            CwdCategory::System => "system",
            CwdCategory::Temp => "temp",
            CwdCategory::Home => "home",
            CwdCategory::AppData => "appdata",
            CwdCategory::Runtime => "runtime",
            CwdCategory::Root => "root",
            CwdCategory::Unknown => "unknown",
        }
    }
}

impl Default for CwdCategory {
    fn default() -> Self {
        CwdCategory::Unknown
    }
}

/// Pattern rule for matching commands to categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPattern {
    /// The category this pattern matches.
    pub category: CommandCategory,
    /// Regex pattern to match against command.
    pub pattern: String,
    /// Human-readable description of what this matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Example commands that match this pattern.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
}

/// Pattern rule for matching CWD paths to categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwdPattern {
    /// The category this pattern matches.
    pub category: CwdCategory,
    /// Glob or regex pattern to match against path.
    pub pattern: String,
    /// Whether this is a glob pattern (else regex).
    #[serde(default)]
    pub is_glob: bool,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Compiled category matcher for efficient categorization.
pub struct CategoryMatcher {
    command_patterns: Vec<(CommandCategory, Regex)>,
    cwd_patterns: Vec<(CwdCategory, Regex)>,
    /// Retained for debugging/future use; patterns are already compiled.
    #[allow(dead_code)]
    home_dir: Option<String>,
}

impl CategoryMatcher {
    /// Create a new category matcher with default patterns.
    pub fn new() -> Self {
        Self::with_home_dir(std::env::var("HOME").ok())
    }

    /// Create a matcher with a specific home directory.
    pub fn with_home_dir(home_dir: Option<String>) -> Self {
        let command_patterns = Self::default_command_patterns();
        let cwd_patterns = Self::default_cwd_patterns(&home_dir);

        Self {
            command_patterns,
            cwd_patterns,
            home_dir,
        }
    }

    /// Categorize a command string.
    pub fn categorize_command(&self, command: &str) -> CommandCategory {
        let command_lower = command.to_lowercase();

        for (category, regex) in &self.command_patterns {
            if regex.is_match(&command_lower) {
                return *category;
            }
        }

        CommandCategory::Unknown
    }

    /// Categorize a working directory path.
    pub fn categorize_cwd(&self, path: &str) -> CwdCategory {
        // Normalize path separators
        let path_normalized = path.replace('\\', "/");

        for (category, regex) in &self.cwd_patterns {
            if regex.is_match(&path_normalized) {
                return *category;
            }
        }

        CwdCategory::Unknown
    }

    /// Get command category index for Dirichlet parameters.
    pub fn command_index(&self, command: &str) -> usize {
        self.categorize_command(command).index()
    }

    /// Get CWD category index.
    pub fn cwd_index(&self, path: &str) -> usize {
        self.categorize_cwd(path).index()
    }

    /// Build default command patterns.
    fn default_command_patterns() -> Vec<(CommandCategory, Regex)> {
        let patterns = vec![
            // Test runners (highest priority - specific patterns)
            (CommandCategory::Test, r"(^|[/\s])(bun\s+test|jest|pytest|mocha|vitest|cargo\s+test|go\s+test|npm\s+test|yarn\s+test|phpunit|rspec|minitest)(\s|$)"),
            (CommandCategory::Test, r"--test|--spec|\.test\.|\.spec\."),

            // AI/coding agents
            (CommandCategory::Agent, r"(^|[/\s])(claude|codex|copilot|gemini|cursor|aider|continue|cody)(\s|$|-|_)"),
            (CommandCategory::Agent, r"anthropic|openai.*agent|ai.*assistant"),

            // Development servers
            (CommandCategory::DevServer, r"(^|[/\s])(next\s+dev|vite|webpack.*dev|nodemon|ts-node-dev|vue-cli-service\s+serve)(\s|$)"),
            (CommandCategory::DevServer, r"--hot|--watch|--hmr|dev.*server|serve.*dev"),
            (CommandCategory::DevServer, r"(^|[/\s])npm\s+run\s+dev"),

            // Build tools
            (CommandCategory::Build, r"(^|[/\s])(webpack|esbuild|rollup|parcel|vite\s+build|tsc|cargo\s+build|make|gradle|maven|cmake)(\s|$)"),
            (CommandCategory::Build, r"npm\s+run\s+build|yarn\s+build"),

            // Editors/IDEs
            (CommandCategory::Editor, r"(^|[/\s])(code|code-server|cursor|vim|nvim|neovim|emacs|nano|subl|sublime|atom|idea|pycharm|webstorm)(\s|$)"),

            // Database clients
            (CommandCategory::Database, r"(^|[/\s])(psql|mysql|mongo|mongosh|redis-cli|sqlite3|pgcli|mycli)(\s|$)"),

            // Container tools
            (CommandCategory::Container, r"(^|[/\s])(docker|podman|kubectl|docker-compose|k9s|helm|minikube|kind)(\s|$)"),

            // Version control
            (CommandCategory::Vcs, r"(^|[/\s])(git|gh|hub|svn|hg|mercurial)(\s|$)"),

            // Package managers
            (CommandCategory::PackageManager, r"(^|[/\s])(npm|yarn|pnpm|pip|pip3|cargo|brew|apt|apt-get|dnf|yum|pacman)(\s|$)"),

            // Production servers
            (CommandCategory::Server, r"(^|[/\s])(gunicorn|uvicorn|nginx|apache|httpd|node\s+server|deno\s+serve|fastify|express)(\s|$)"),
            (CommandCategory::Server, r"--production|NODE_ENV=production"),

            // Daemons (broad patterns)
            (CommandCategory::Daemon, r"(^|[/\s])(systemd|cron|crond|sshd|dockerd|containerd|supervisord|pm2|launchd)(\s|$)"),
            (CommandCategory::Daemon, r"/usr/lib/systemd|/lib/systemd"),

            // Shells (last, as many things run in shells)
            // Match shell with optional path prefix: /bin/bash, /usr/bin/zsh, etc.
            (CommandCategory::Shell, r"(^|/)(bash|zsh|fish|sh|dash|tcsh|csh|ksh|pwsh|powershell)(\s|$)"),
            // Match login shells: -bash, -zsh, etc.
            (CommandCategory::Shell, r"^-(bash|zsh|fish|sh|dash|tcsh|csh|ksh)$"),
        ];

        patterns
            .into_iter()
            .filter_map(|(cat, pat)| {
                Regex::new(pat).ok().map(|r| (cat, r))
            })
            .collect()
    }

    /// Build default CWD patterns.
    fn default_cwd_patterns(home_dir: &Option<String>) -> Vec<(CwdCategory, Regex)> {
        let mut result = Vec::new();

        // Temp directories (highest priority for specific paths)
        if let Ok(r) = Regex::new(r"^(/tmp|/var/tmp|/private/tmp|C:\\Temp)(/|$)") {
            result.push((CwdCategory::Temp, r));
        }

        // Runtime directories
        if let Ok(r) = Regex::new(r"^(/run|/var/run)(/|$)") {
            result.push((CwdCategory::Runtime, r));
        }

        // System directories (/var/tmp is handled by Temp which is checked first)
        if let Ok(r) = Regex::new(r"^(/usr|/var|/etc|/opt|/lib|/sbin|/bin)(/|$)") {
            result.push((CwdCategory::System, r));
        }

        // Root
        if let Ok(r) = Regex::new(r"^/$") {
            result.push((CwdCategory::Root, r));
        }

        // Home-relative patterns
        if let Some(home) = home_dir {
            let home_escaped = regex::escape(home);

            // Project directories (must be before general home)
            let project_pattern = format!(
                r"^{}/(projects?|code|repos?|src|workspace|dev|github|gitlab|work)(/|$)",
                home_escaped
            );
            if let Ok(r) = Regex::new(&project_pattern) {
                result.push((CwdCategory::Project, r));
            }

            // App data directories
            let appdata_pattern = format!(
                r"^{}/(\.(config|local|cache)|Library|AppData)(/|$)",
                home_escaped
            );
            if let Ok(r) = Regex::new(&appdata_pattern) {
                result.push((CwdCategory::AppData, r));
            }

            // Home directory (general, lower priority)
            let home_pattern = format!(r"^{}(/|$)", home_escaped);
            if let Ok(r) = Regex::new(&home_pattern) {
                result.push((CwdCategory::Home, r));
            }
        }

        // Fallback project detection (git repos)
        if let Ok(r) = Regex::new(r"/.git$|/.git/") {
            result.push((CwdCategory::Project, r));
        }

        result
    }
}

impl Default for CategoryMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Category taxonomy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryTaxonomy {
    /// Schema version.
    pub schema_version: String,

    /// Command category definitions.
    pub command_categories: Vec<CommandCategoryDef>,

    /// CWD category definitions.
    pub cwd_categories: Vec<CwdCategoryDef>,

    /// Custom command patterns (in addition to defaults).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_command_patterns: Vec<CommandPattern>,

    /// Custom CWD patterns (in addition to defaults).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_cwd_patterns: Vec<CwdPattern>,
}

/// Command category definition with prior adjustment hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandCategoryDef {
    /// Category identifier.
    pub id: CommandCategory,

    /// Human-readable name.
    pub name: String,

    /// Description.
    pub description: String,

    /// Example commands.
    pub examples: Vec<String>,

    /// Prior probability adjustment hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_hints: Option<PriorHints>,
}

/// CWD category definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwdCategoryDef {
    /// Category identifier.
    pub id: CwdCategory,

    /// Human-readable name.
    pub name: String,

    /// Description.
    pub description: String,

    /// Example paths.
    pub examples: Vec<String>,
}

/// Hints for prior probability adjustments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorHints {
    /// Higher values mean more likely to be abandoned (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandonment_tendency: Option<f64>,

    /// Expected typical runtime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_runtime_secs: Option<u64>,

    /// Whether this category typically runs as daemon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon_like: Option<bool>,
}

impl CategoryTaxonomy {
    /// Create default taxonomy.
    pub fn default_taxonomy() -> Self {
        Self {
            schema_version: CATEGORIES_SCHEMA_VERSION.to_string(),
            command_categories: vec![
                CommandCategoryDef {
                    id: CommandCategory::Test,
                    name: "Test Runner".to_string(),
                    description: "Test execution frameworks and runners".to_string(),
                    examples: vec![
                        "bun test".to_string(),
                        "jest".to_string(),
                        "pytest".to_string(),
                        "cargo test".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.7),
                        expected_runtime_secs: Some(3600),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::DevServer,
                    name: "Development Server".to_string(),
                    description: "Hot-reloading development servers".to_string(),
                    examples: vec![
                        "next dev".to_string(),
                        "vite".to_string(),
                        "webpack-dev-server".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.5),
                        expected_runtime_secs: Some(86400),
                        daemon_like: Some(true),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Agent,
                    name: "AI/Coding Agent".to_string(),
                    description: "AI-powered coding assistants and agents".to_string(),
                    examples: vec![
                        "claude".to_string(),
                        "codex".to_string(),
                        "cursor".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.6),
                        expected_runtime_secs: Some(7200),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Server,
                    name: "Production Server".to_string(),
                    description: "Production application servers".to_string(),
                    examples: vec![
                        "gunicorn".to_string(),
                        "uvicorn".to_string(),
                        "nginx".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.1),
                        expected_runtime_secs: None,
                        daemon_like: Some(true),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Daemon,
                    name: "System Daemon".to_string(),
                    description: "System services and background daemons".to_string(),
                    examples: vec![
                        "systemd".to_string(),
                        "cron".to_string(),
                        "dockerd".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.05),
                        expected_runtime_secs: None,
                        daemon_like: Some(true),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Build,
                    name: "Build Tool".to_string(),
                    description: "Compilation and bundling tools".to_string(),
                    examples: vec![
                        "webpack".to_string(),
                        "cargo build".to_string(),
                        "tsc".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.4),
                        expected_runtime_secs: Some(600),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Editor,
                    name: "Editor/IDE".to_string(),
                    description: "Text editors and integrated development environments".to_string(),
                    examples: vec![
                        "code".to_string(),
                        "vim".to_string(),
                        "cursor".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.2),
                        expected_runtime_secs: Some(28800),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Shell,
                    name: "Interactive Shell".to_string(),
                    description: "Command-line shells".to_string(),
                    examples: vec![
                        "bash".to_string(),
                        "zsh".to_string(),
                        "fish".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.3),
                        expected_runtime_secs: Some(3600),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Database,
                    name: "Database Client".to_string(),
                    description: "Database CLI clients and shells".to_string(),
                    examples: vec![
                        "psql".to_string(),
                        "mysql".to_string(),
                        "mongosh".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.4),
                        expected_runtime_secs: Some(1800),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Vcs,
                    name: "Version Control".to_string(),
                    description: "Version control system commands".to_string(),
                    examples: vec![
                        "git".to_string(),
                        "gh".to_string(),
                        "svn".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.2),
                        expected_runtime_secs: Some(60),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::PackageManager,
                    name: "Package Manager".to_string(),
                    description: "Package and dependency managers".to_string(),
                    examples: vec![
                        "npm".to_string(),
                        "cargo".to_string(),
                        "pip".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.3),
                        expected_runtime_secs: Some(300),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Container,
                    name: "Container Tool".to_string(),
                    description: "Container and orchestration tools".to_string(),
                    examples: vec![
                        "docker".to_string(),
                        "kubectl".to_string(),
                        "podman".to_string(),
                    ],
                    prior_hints: Some(PriorHints {
                        abandonment_tendency: Some(0.2),
                        expected_runtime_secs: Some(120),
                        daemon_like: Some(false),
                    }),
                },
                CommandCategoryDef {
                    id: CommandCategory::Unknown,
                    name: "Unknown".to_string(),
                    description: "Unrecognized command type".to_string(),
                    examples: vec![],
                    prior_hints: None,
                },
            ],
            cwd_categories: vec![
                CwdCategoryDef {
                    id: CwdCategory::Project,
                    name: "Project Directory".to_string(),
                    description: "User project and code directories".to_string(),
                    examples: vec![
                        "~/projects/myapp".to_string(),
                        "~/code/backend".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::System,
                    name: "System Directory".to_string(),
                    description: "System paths (/usr, /var, /etc)".to_string(),
                    examples: vec![
                        "/usr/local/bin".to_string(),
                        "/var/log".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::Temp,
                    name: "Temporary Directory".to_string(),
                    description: "Temporary file storage".to_string(),
                    examples: vec![
                        "/tmp".to_string(),
                        "/var/tmp".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::Home,
                    name: "Home Directory".to_string(),
                    description: "User home directory root".to_string(),
                    examples: vec![
                        "~".to_string(),
                        "/home/user".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::AppData,
                    name: "Application Data".to_string(),
                    description: "User application config and data".to_string(),
                    examples: vec![
                        "~/.config".to_string(),
                        "~/.local/share".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::Runtime,
                    name: "Runtime Directory".to_string(),
                    description: "Runtime state directories".to_string(),
                    examples: vec![
                        "/run".to_string(),
                        "/var/run".to_string(),
                    ],
                },
                CwdCategoryDef {
                    id: CwdCategory::Root,
                    name: "Root".to_string(),
                    description: "Root filesystem".to_string(),
                    examples: vec!["/".to_string()],
                },
                CwdCategoryDef {
                    id: CwdCategory::Unknown,
                    name: "Unknown".to_string(),
                    description: "Unrecognized path".to_string(),
                    examples: vec![],
                },
            ],
            custom_command_patterns: vec![],
            custom_cwd_patterns: vec![],
        }
    }
}

impl Default for CategoryTaxonomy {
    fn default() -> Self {
        Self::default_taxonomy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_category_indexing() {
        assert_eq!(CommandCategory::Test.index(), 0);
        assert_eq!(CommandCategory::Unknown.index(), 12);
        assert_eq!(CommandCategory::from_index(0), CommandCategory::Test);
        assert_eq!(CommandCategory::from_index(100), CommandCategory::Unknown);
    }

    #[test]
    fn test_cwd_category_indexing() {
        assert_eq!(CwdCategory::Project.index(), 0);
        assert_eq!(CwdCategory::Unknown.index(), 7);
        assert_eq!(CwdCategory::from_index(0), CwdCategory::Project);
    }

    #[test]
    fn test_categorize_test_commands() {
        let matcher = CategoryMatcher::new();

        assert_eq!(matcher.categorize_command("bun test"), CommandCategory::Test);
        assert_eq!(matcher.categorize_command("/usr/bin/jest"), CommandCategory::Test);
        assert_eq!(matcher.categorize_command("pytest -v tests/"), CommandCategory::Test);
        assert_eq!(matcher.categorize_command("cargo test --lib"), CommandCategory::Test);
        assert_eq!(matcher.categorize_command("npm test"), CommandCategory::Test);
    }

    #[test]
    fn test_categorize_devserver_commands() {
        let matcher = CategoryMatcher::new();

        assert_eq!(matcher.categorize_command("next dev"), CommandCategory::DevServer);
        assert_eq!(matcher.categorize_command("vite --host"), CommandCategory::DevServer);
        assert_eq!(matcher.categorize_command("nodemon app.js"), CommandCategory::DevServer);
        assert_eq!(matcher.categorize_command("npm run dev"), CommandCategory::DevServer);
    }

    #[test]
    fn test_categorize_agent_commands() {
        let matcher = CategoryMatcher::new();

        assert_eq!(matcher.categorize_command("claude --version"), CommandCategory::Agent);
        assert_eq!(matcher.categorize_command("codex start"), CommandCategory::Agent);
        assert_eq!(matcher.categorize_command("cursor ."), CommandCategory::Agent);
    }

    #[test]
    fn test_categorize_shell_commands() {
        let matcher = CategoryMatcher::new();

        assert_eq!(matcher.categorize_command("bash"), CommandCategory::Shell);
        assert_eq!(matcher.categorize_command("-zsh"), CommandCategory::Shell);
        assert_eq!(matcher.categorize_command("/bin/fish"), CommandCategory::Shell);
    }

    #[test]
    fn test_categorize_unknown() {
        let matcher = CategoryMatcher::new();

        assert_eq!(matcher.categorize_command("some_random_command"), CommandCategory::Unknown);
        assert_eq!(matcher.categorize_command(""), CommandCategory::Unknown);
    }

    #[test]
    fn test_categorize_cwd() {
        let matcher = CategoryMatcher::with_home_dir(Some("/home/user".to_string()));

        assert_eq!(matcher.categorize_cwd("/tmp/test"), CwdCategory::Temp);
        assert_eq!(matcher.categorize_cwd("/var/tmp/session"), CwdCategory::Temp);
        assert_eq!(matcher.categorize_cwd("/usr/local/bin"), CwdCategory::System);
        assert_eq!(matcher.categorize_cwd("/home/user/projects/myapp"), CwdCategory::Project);
        assert_eq!(matcher.categorize_cwd("/home/user/.config/app"), CwdCategory::AppData);
        assert_eq!(matcher.categorize_cwd("/home/user"), CwdCategory::Home);
        assert_eq!(matcher.categorize_cwd("/run/user/1000"), CwdCategory::Runtime);
        assert_eq!(matcher.categorize_cwd("/"), CwdCategory::Root);
    }

    #[test]
    fn test_default_taxonomy() {
        let taxonomy = CategoryTaxonomy::default_taxonomy();

        assert_eq!(taxonomy.schema_version, CATEGORIES_SCHEMA_VERSION);
        assert_eq!(taxonomy.command_categories.len(), 13);
        assert_eq!(taxonomy.cwd_categories.len(), 8);

        // Check that test category has high abandonment tendency
        let test_cat = taxonomy.command_categories
            .iter()
            .find(|c| c.id == CommandCategory::Test)
            .unwrap();
        assert!(test_cat.prior_hints.as_ref().unwrap().abandonment_tendency.unwrap() > 0.5);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let taxonomy = CategoryTaxonomy::default_taxonomy();
        let json = serde_json::to_string_pretty(&taxonomy).unwrap();
        let parsed: CategoryTaxonomy = serde_json::from_str(&json).unwrap();

        assert_eq!(taxonomy.schema_version, parsed.schema_version);
        assert_eq!(taxonomy.command_categories.len(), parsed.command_categories.len());
    }

    #[test]
    fn test_category_names() {
        assert_eq!(CommandCategory::Test.name(), "test");
        assert_eq!(CommandCategory::DevServer.name(), "devserver");
        assert_eq!(CwdCategory::Project.name(), "project");
        assert_eq!(CwdCategory::Temp.name(), "temp");
    }

    #[test]
    fn test_all_categories_covered() {
        // Ensure all() returns all variants
        let all_cmd = CommandCategory::all();
        assert!(all_cmd.contains(&CommandCategory::Test));
        assert!(all_cmd.contains(&CommandCategory::Unknown));
        assert_eq!(all_cmd.len(), 13);

        let all_cwd = CwdCategory::all();
        assert!(all_cwd.contains(&CwdCategory::Project));
        assert!(all_cwd.contains(&CwdCategory::Unknown));
        assert_eq!(all_cwd.len(), 8);
    }
}
