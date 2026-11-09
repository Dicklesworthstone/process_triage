//! Per-user service installation for the dormant, review-only daemon.
//!
//! Definitions are inspectable before installation, never invoke a shell, and
//! always run the daemon with `--dry-run`. Installing does not activate a service
//! unless explicitly requested. A content fingerprint detects local edits so
//! uninstall cannot silently discard an administrator's changes.

use crate::collect::tool_runner::{ToolConfig, ToolRunner, ToolSpec};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const UNIT: &str = "ptd.service";
const LABEL: &str = "com.processtriage.ptd";
const MARKER: &str = "process_triage managed service v1 sha256:";
const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
const MAX_DEFINITION_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePlatform {
    SystemdUser,
    LaunchdAgent,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Invalid(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("refusing service definition {path}: {reason}")]
    Unmanaged { path: PathBuf, reason: String },
    #[error("service manager command {command:?} failed: {reason}")]
    Manager {
        command: ManagerCommand,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagerCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ManagerResult {
    pub command: ManagerCommand,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub truncated: bool,
}

impl ManagerResult {
    fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && !self.truncated
    }

    fn checked(self) -> Result<Self, ServiceError> {
        if self.success() {
            return Ok(self);
        }
        Err(ServiceError::Manager {
            command: self.command,
            reason: format!(
                "exit={:?}, timed_out={}, truncated={}; stdout: {}; stderr: {}",
                self.exit_code, self.timed_out, self.truncated, self.stdout, self.stderr
            ),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ServiceReport {
    pub operation: &'static str,
    pub platform: ServicePlatform,
    pub path: PathBuf,
    pub dry_run: bool,
    pub changed: bool,
    pub installed: bool,
    /// Verified manager registration; `None` means it was not inspected or could not be verified.
    pub manager_loaded: Option<bool>,
    pub review_only: bool,
    pub definition: Option<String>,
    pub commands: Vec<ManagerCommand>,
    pub results: Vec<ManagerResult>,
    pub notes: Vec<String>,
}

impl ServiceReport {
    /// Status preserves manager diagnostics, including a missing user session.
    pub fn manager_succeeded(&self) -> bool {
        self.manager_loaded.is_some()
            && (self.manager_loaded == Some(false)
                || self.results.iter().all(ManagerResult::success))
    }
}

#[derive(Debug)]
pub struct ServiceDefinition {
    platform: ServicePlatform,
    path: PathBuf,
    content: String,
    uid: u32,
}

impl ServiceDefinition {
    pub fn for_current_user(config_dir: &Path) -> Result<Self, ServiceError> {
        let home = dirs::home_dir().ok_or_else(|| {
            ServiceError::Invalid("cannot determine the user's home directory".into())
        })?;
        let (platform, directory) = if cfg!(target_os = "linux") {
            let config_home = std::env::var_os("XDG_CONFIG_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"));
            (ServicePlatform::SystemdUser, config_home.join("systemd/user"))
        } else if cfg!(target_os = "macos") {
            (ServicePlatform::LaunchdAgent, home.join("Library/LaunchAgents"))
        } else {
            return Err(ServiceError::Invalid(
                "daemon services support Linux systemd --user and macOS launch agents".into(),
            ));
        };
        let executable = std::env::current_exe().map_err(|source| ServiceError::Io {
            path: PathBuf::from("current executable"),
            source,
        })?;
        let config_dir = std::path::absolute(config_dir).map_err(|source| ServiceError::Io {
            path: config_dir.to_path_buf(),
            source,
        })?;
        Self::new(platform, &directory, &executable, &config_dir, current_uid())
    }

    /// Build both platform formats without touching the filesystem or a manager.
    pub fn new(
        platform: ServicePlatform,
        directory: &Path,
        executable: &Path,
        config_dir: &Path,
        uid: u32,
    ) -> Result<Self, ServiceError> {
        literal_absolute_path(directory)?;
        let argv = [
            literal_absolute_path(executable)?,
            "--config",
            literal_absolute_path(config_dir)?,
            "--dry-run",
            "daemon",
            "start",
            "--foreground",
        ];
        let (name, body) = match platform {
            ServicePlatform::SystemdUser => {
                let command = argv.map(systemd_argument).join(" ");
                (
                    UNIT.to_string(),
                    format!(
                        "[Unit]\nDescription=Process Triage Dormant Daemon (review only)\n\n\
                         [Service]\nType=simple\nExecStart=:{command}\n\
                         Restart=on-failure\nRestartSec=30\nTimeoutStopSec=30\n\
                         Nice=19\nIOSchedulingClass=idle\n\n\
                         [Install]\nWantedBy=default.target\n"
                    ),
                )
            }
            ServicePlatform::LaunchdAgent => {
                let arguments = argv
                    .iter()
                    .map(|arg| format!("        <string>{}</string>\n", xml_text(arg)))
                    .collect::<String>();
                (
                    format!("{LABEL}.plist"),
                    format!(
                        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                         <plist version=\"1.0\">\n<dict>\n\
                         <key>Label</key><string>{LABEL}</string>\n\
                         <key>ProgramArguments</key>\n<array>\n{arguments}</array>\n\
                         <key>Disabled</key><true/>\n\
                         <key>RunAtLoad</key><true/>\n\
                         <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n\
                         <key>ThrottleInterval</key><integer>30</integer>\n\
                         <key>Nice</key><integer>19</integer>\n\
                         <key>LowPriorityIO</key><true/>\n\
                         <key>ProcessType</key><string>Background</string>\n\
                         </dict>\n</plist>\n"
                    ),
                )
            }
        };
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        let content = match platform {
            ServicePlatform::SystemdUser => format!("# {MARKER}{digest}\n{body}"),
            ServicePlatform::LaunchdAgent => {
                format!("{XML_HEADER}<!-- {MARKER}{digest} -->\n{body}")
            }
        };
        Ok(Self {
            platform,
            path: directory.join(name),
            content,
            uid,
        })
    }

    pub fn install(&self, activate: bool, dry_run: bool) -> Result<ServiceReport, ServiceError> {
        let existing = self.read_managed()?;
        if existing.as_ref().is_some_and(|content| content != &self.content) {
            return Err(self.unmanaged(
                "a different managed definition already exists; inspect it and uninstall before reinstalling",
            ));
        }
        let mut report = self.report("install", dry_run, existing.is_some());
        report.definition = Some(self.content.clone());
        if activate {
            report.commands.push(self.ownership_command());
            report.commands.extend(self.activation_commands(false));
            if self.platform == ServicePlatform::LaunchdAgent {
                report.notes.push(
                    "For an already loaded managed agent, non-force kickstart replaces bootstrap; a running daemon is not restarted.".into(),
                );
            }
        } else {
            report.notes.push(
                "Definition only; run daemon install --activate to enable monitoring. Existing manager enablement is not changed.".into(),
            );
        }
        if dry_run {
            return Ok(report);
        }
        let loaded = if activate {
            self.check_manager_ownership(&mut report)?
        } else {
            false
        };
        if existing.is_none() {
            self.write_new()?;
            report.changed = true;
            report.installed = true;
        }
        if activate {
            report.commands = vec![self.ownership_command()];
            report.commands.extend(self.activation_commands(loaded));
            for command in self.activation_commands(loaded) {
                if command == self.ownership_command() {
                    if !self.check_manager_ownership(&mut report)? {
                        return Err(self.unmanaged(
                            "manager did not load this definition after reload; file retained",
                        ));
                    }
                    continue;
                }
                // A failed activation leaves the inspectable definition intact.
                report.results.push(execute(&command)?.checked()?);
            }
            report.manager_loaded = Some(true);
        }
        Ok(report)
    }

    pub fn status(&self) -> Result<ServiceReport, ServiceError> {
        let existing = self.read_managed()?;
        let mut report = self.report("service-status", false, existing.is_some());
        report.definition = existing;
        let command = self.status_command();
        report.commands.push(command.clone());
        let result = execute(&command)?;
        match self.manager_owns_path(&result) {
            Ok(loaded) => report.manager_loaded = Some(loaded),
            Err(error) => report.notes.push(error.to_string()),
        }
        report.results.push(result);
        Ok(report)
    }

    pub fn uninstall(&self, dry_run: bool) -> Result<ServiceReport, ServiceError> {
        let Some(existing) = self.read_managed()? else {
            return Ok(self.report("uninstall", dry_run, false));
        };
        let mut report = self.report("uninstall", dry_run, true);
        report.definition = Some(existing.clone());
        report.commands.push(self.ownership_command());
        report.commands.extend(self.deactivation_commands(true));
        if self.platform == ServicePlatform::SystemdUser {
            report.commands.push(self.systemctl(&["daemon-reload"]));
        }
        report.notes.push(
            "The definition is removed only after manager deactivation succeeds; launchd bootout is skipped when the job is not loaded.".into(),
        );
        if dry_run {
            return Ok(report);
        }
        let loaded = self.check_manager_ownership(&mut report)?;
        report.commands = vec![self.ownership_command()];
        report.commands.extend(self.deactivation_commands(loaded));
        if self.platform == ServicePlatform::SystemdUser {
            report.commands.push(self.systemctl(&["daemon-reload"]));
        }
        for command in self.deactivation_commands(loaded) {
            report.results.push(execute(&command)?.checked()?);
        }
        if self.read_managed()?.as_deref() != Some(existing.as_str()) {
            return Err(self.unmanaged("definition changed during uninstall; file retained"));
        }
        fs::remove_file(&self.path).map_err(|source| self.io(source))?;
        report.changed = true;
        report.installed = false;
        report.manager_loaded = Some(false);
        if self.platform == ServicePlatform::SystemdUser {
            let command = self.systemctl(&["daemon-reload"]);
            report.results.push(execute(&command)?.checked()?);
        }
        Ok(report)
    }

    fn report(&self, operation: &'static str, dry_run: bool, installed: bool) -> ServiceReport {
        ServiceReport {
            operation,
            platform: self.platform,
            path: self.path.clone(),
            dry_run,
            changed: false,
            installed,
            manager_loaded: None,
            review_only: true,
            definition: None,
            commands: Vec::new(),
            results: Vec::new(),
            notes: vec![
                "The managed daemon generates review plans and never authorizes actions.".into(),
            ],
        }
    }

    fn systemctl(&self, args: &[&str]) -> ManagerCommand {
        ManagerCommand {
            program: "systemctl".into(),
            args: ["--user", "--no-pager", "--no-ask-password"]
                .into_iter()
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect(),
        }
    }

    fn launchctl(&self, args: &[&str]) -> ManagerCommand {
        ManagerCommand {
            program: "/bin/launchctl".into(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    fn service_target(&self) -> String {
        format!("gui/{}/{LABEL}", self.uid)
    }

    fn ownership_command(&self) -> ManagerCommand {
        match self.platform {
            ServicePlatform::SystemdUser => self.systemctl(&[
                "show",
                "--all",
                "--property=FragmentPath,DropInPaths,LoadState",
                UNIT,
            ]),
            ServicePlatform::LaunchdAgent => self.launchctl(&["print", &self.service_target()]),
        }
    }

    fn status_command(&self) -> ManagerCommand {
        match self.platform {
            ServicePlatform::SystemdUser => self.systemctl(&[
                "show",
                "--all",
                "--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
                UNIT,
            ]),
            ServicePlatform::LaunchdAgent => self.ownership_command(),
        }
    }

    fn activation_commands(&self, loaded: bool) -> Vec<ManagerCommand> {
        match self.platform {
            ServicePlatform::SystemdUser => vec![
                self.systemctl(&["daemon-reload"]),
                self.ownership_command(),
                self.systemctl(&["enable", "--now", self.path.to_str().unwrap()]),
            ],
            ServicePlatform::LaunchdAgent => {
                let start = if loaded {
                    self.launchctl(&["kickstart", &self.service_target()])
                } else {
                    self.launchctl(&[
                        "bootstrap",
                        &format!("gui/{}", self.uid),
                        self.path.to_str().unwrap(),
                    ])
                };
                vec![self.launchctl(&["enable", &self.service_target()]), start]
            }
        }
    }

    fn deactivation_commands(&self, loaded: bool) -> Vec<ManagerCommand> {
        match self.platform {
            ServicePlatform::SystemdUser => vec![self.systemctl(&["disable", "--now", UNIT])],
            ServicePlatform::LaunchdAgent => {
                let mut commands = vec![self.launchctl(&["disable", &self.service_target()])];
                if loaded {
                    commands.push(self.launchctl(&["bootout", &self.service_target()]));
                }
                commands
            }
        }
    }

    /// Never stop or replace a manager job whose definition belongs elsewhere.
    fn check_manager_ownership(&self, report: &mut ServiceReport) -> Result<bool, ServiceError> {
        let result = execute(&self.ownership_command())?;
        let loaded = self.manager_owns_path(&result)?;
        report.manager_loaded = Some(loaded);
        report.results.push(result);
        Ok(loaded)
    }

    fn manager_owns_path(&self, result: &ManagerResult) -> Result<bool, ServiceError> {
        if self.platform == ServicePlatform::SystemdUser {
            if result.timed_out
                || result.truncated
                || !matches!(result.exit_code, Some(0 | 1))
            {
                return Err(manager_error(result, "cannot verify service ownership"));
            }
            let property = |name: &str| -> Result<&str, ServiceError> {
                let prefix = format!("{name}=");
                let mut values = result
                    .stdout
                    .lines()
                    .filter_map(|line| line.strip_prefix(&prefix));
                let value = values.next().ok_or_else(|| {
                    manager_error(result, &format!("missing ownership property {name}"))
                })?;
                if values.next().is_some() {
                    return Err(manager_error(
                        result,
                        &format!("duplicate ownership property {name}"),
                    ));
                }
                Ok(value)
            };
            let load_state = property("LoadState")?;
            let path = property("FragmentPath")?;
            let drop_ins = property("DropInPaths")?;
            if !drop_ins.is_empty() {
                return Err(self.unmanaged("the manager has additional unit drop-ins"));
            }
            // systemctl versions differ on whether an absent unit exits 0 or
            // 1. Both require complete, consistent structured absence evidence.
            if load_state == "not-found" && path.is_empty() {
                return Ok(false);
            }
            if !result.success() || load_state != "loaded" {
                return Err(manager_error(result, "unit is not a verified loaded definition"));
            }
            if Some(path) != self.path.to_str() {
                return Err(self.unmanaged(&format!(
                    "manager definition path {path:?} does not match the managed file"
                )));
            }
            return Ok(true);
        }
        if self.platform == ServicePlatform::LaunchdAgent
            && matches!(result.exit_code, Some(3 | 113))
            && !result.timed_out
            && !result.truncated
            && result.stderr.contains("Could not find service")
            && result.stderr.contains(LABEL)
        {
            return Ok(false);
        }
        if !result.success() {
            return Err(manager_error(result, "cannot verify service ownership"));
        }
        let mut paths = result
            .stdout
            .lines()
            .filter_map(|line| line.trim().strip_prefix("path = "));
        let path = paths.next();
        if paths.next().is_none() && path == self.path.to_str() {
            return Ok(true);
        }
        Err(self.unmanaged(&format!(
            "manager definition path {path:?} does not match the managed file"
        )))
    }

    fn read_managed(&self) -> Result<Option<String>, ServiceError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io(source)),
        };
        if !metadata.file_type().is_file() {
            return Err(
                self.unmanaged("existing path is not a regular file (symlinks are refused)")
            );
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&self.path).map_err(|source| self.io(source))?;
        let metadata = file.metadata().map_err(|source| self.io(source))?;
        if !metadata.is_file() || metadata.len() > MAX_DEFINITION_BYTES {
            return Err(self.unmanaged("existing definition is not a bounded regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != current_uid() || metadata.mode() & 0o022 != 0 {
                return Err(self.unmanaged(
                    "definition must belong to this user and not be writable by others",
                ));
            }
        }
        let mut content = String::new();
        file.take(MAX_DEFINITION_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|source| self.io(source))?;
        if content.len() as u64 > MAX_DEFINITION_BYTES
            || !valid_fingerprint(self.platform, &content)
        {
            return Err(self.unmanaged(
                "file is unmanaged or has been edited; inspect and preserve it manually",
            ));
        }
        Ok(Some(content))
    }

    fn write_new(&self) -> Result<(), ServiceError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| self.unmanaged("missing parent directory"))?;
        fs::create_dir_all(parent).map_err(|source| self.io(source))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&self.path).map_err(|source| self.io(source))?;
        file.write_all(self.content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|source| self.io(source))
    }

    fn unmanaged(&self, reason: &str) -> ServiceError {
        ServiceError::Unmanaged {
            path: self.path.clone(),
            reason: reason.into(),
        }
    }

    fn io(&self, source: std::io::Error) -> ServiceError {
        ServiceError::Io {
            path: self.path.clone(),
            source,
        }
    }
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn manager_error(result: &ManagerResult, reason: &str) -> ServiceError {
    ServiceError::Manager {
        command: result.command.clone(),
        reason: format!(
            "{reason}: exit={:?}, timed_out={}, truncated={}; stdout: {}; stderr: {}",
            result.exit_code, result.timed_out, result.truncated, result.stdout, result.stderr
        ),
    }
}

fn literal_absolute_path(path: &Path) -> Result<&str, ServiceError> {
    let text = path.to_str().ok_or_else(|| {
        ServiceError::Invalid(format!("service paths must be UTF-8: {}", path.display()))
    })?;
    if !path.is_absolute() || text.chars().any(char::is_control) {
        return Err(ServiceError::Invalid(format!(
            "service paths must be absolute and contain no control characters: {text:?}"
        )));
    }
    Ok(text)
}

fn systemd_argument(argument: &str) -> String {
    // ':' on ExecStart disables $variable substitution; %% escapes specifiers.
    // Quoting alone does not disable either form of systemd expansion.
    format!(
        "\"{}\"",
        argument
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn valid_fingerprint(platform: ServicePlatform, content: &str) -> bool {
    let (line, body) = match platform {
        ServicePlatform::SystemdUser => content.split_once('\n'),
        ServicePlatform::LaunchdAgent => content
            .strip_prefix(XML_HEADER)
            .and_then(|rest| rest.split_once('\n')),
    }
    .unwrap_or(("", ""));
    let digest = match platform {
        ServicePlatform::SystemdUser => line.strip_prefix(&format!("# {MARKER}")),
        ServicePlatform::LaunchdAgent => line
            .strip_prefix(&format!("<!-- {MARKER}"))
            .and_then(|line| line.strip_suffix(" -->")),
    };
    digest.is_some_and(|digest| digest == hex::encode(Sha256::digest(body.as_bytes())))
}

fn execute(command: &ManagerCommand) -> Result<ManagerResult, ServiceError> {
    let config = ToolConfig {
        default_timeout: Duration::from_secs(15),
        max_output_bytes: 64 * 1024,
        budget_ms: 15_000,
        use_nice: false,
        #[cfg(target_os = "linux")]
        use_ionice: false,
        ..ToolConfig::default()
    };
    let mut spec = ToolSpec::new(&command.program, command.args.clone());
    // ToolRunner intentionally clears inherited environment. User service
    // managers need these discovery variables, but never arbitrary injection
    // variables such as LD_PRELOAD or SYSTEMD_UNIT_PATH.
    let environment_keys: &[&str] = if command.program == "systemctl" {
        &[
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
        ]
    } else {
        &["HOME"]
    };
    for &key in environment_keys {
        match std::env::var(key) {
            Ok(value) if value.is_empty() => {}
            Ok(value) => {
                validate_manager_environment(key, &value)?;
                spec = spec.with_env(key, value);
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(error) => {
                return Err(ServiceError::Invalid(format!(
                    "cannot pass {key} to the user service manager: {error}"
                )));
            }
        }
    }
    let output = ToolRunner::new(config)
        .run(&spec)
        .map_err(|error| ServiceError::Manager {
            command: command.clone(),
            reason: error.to_string(),
        })?;
    Ok(ManagerResult {
        command: command.clone(),
        exit_code: output.exit_code,
        stdout: output.stdout_str(),
        stderr: output.stderr_str(),
        timed_out: output.timed_out,
        truncated: output.truncated,
    })
}

fn validate_manager_environment(key: &str, value: &str) -> Result<(), ServiceError> {
    if value.chars().any(char::is_control)
        || (key != "DBUS_SESSION_BUS_ADDRESS" && !Path::new(value).is_absolute())
    {
        return Err(ServiceError::Invalid(format!(
            "invalid {key} for user service manager: expected a literal {}",
            if key == "DBUS_SESSION_BUS_ADDRESS" {
                "bus address without control characters"
            } else {
                "absolute path without control characters"
            }
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(platform: ServicePlatform, directory: &Path) -> ServiceDefinition {
        ServiceDefinition::new(
            platform,
            directory,
            Path::new("/opt/pt \"quoted\"/%literal/${HOME}/pt-core"),
            Path::new("/home/user/config & <literal>/'quotes'/$HOME/%n"),
            501,
        )
        .unwrap()
    }

    #[test]
    fn systemd_preserves_literal_arguments_and_review_only_foreground_mode() {
        let service = definition(
            ServicePlatform::SystemdUser,
            Path::new("/home/user/.config/systemd/user"),
        );
        assert!(service.content.contains(
            "ExecStart=:\"/opt/pt \\\"quoted\\\"/%%literal/${HOME}/pt-core\""
        ));
        assert!(service
            .content
            .contains("\"/home/user/config & <literal>/'quotes'/$HOME/%%n\""));
        assert!(service
            .content
            .contains("\"--dry-run\" \"daemon\" \"start\" \"--foreground\""));
        assert!(!service.content.contains("WatchdogSec="));
        assert!(valid_fingerprint(service.platform, &service.content));
    }

    #[test]
    fn launchd_escapes_xml_and_is_disabled_until_explicit_activation() {
        let service = definition(
            ServicePlatform::LaunchdAgent,
            Path::new("/Users/user/Library/LaunchAgents"),
        );
        assert!(service.content.contains("&quot;quoted&quot;/%literal/${HOME}"));
        assert!(service
            .content
            .contains("config &amp; &lt;literal&gt;/&apos;quotes&apos;/$HOME/%n"));
        assert!(service.content.contains("<key>Disabled</key><true/>"));
        assert!(service.content.contains("<string>--dry-run</string>"));
        assert!(service.content.contains("<string>--foreground</string>"));
        assert!(valid_fingerprint(service.platform, &service.content));
        assert!(!valid_fingerprint(
            service.platform,
            &service.content.replace("--dry-run", "--yes")
        ));
    }

    #[test]
    fn activation_and_deactivation_are_scoped_to_the_user() {
        let linux = definition(
            ServicePlatform::SystemdUser,
            Path::new("/home/user/.config/systemd/user"),
        );
        assert_eq!(linux.activation_commands(false)[1], linux.ownership_command());
        assert_eq!(
            linux.activation_commands(false)[2].args,
            [
                "--user",
                "--no-pager",
                "--no-ask-password",
                "enable",
                "--now",
                "/home/user/.config/systemd/user/ptd.service"
            ]
        );
        let mac = definition(
            ServicePlatform::LaunchdAgent,
            Path::new("/Users/user/Library/LaunchAgents"),
        );
        assert_eq!(
            mac.activation_commands(false)[0].args,
            ["enable", "gui/501/com.processtriage.ptd"]
        );
        assert_eq!(
            mac.activation_commands(false)[1].args,
            [
                "bootstrap",
                "gui/501",
                "/Users/user/Library/LaunchAgents/com.processtriage.ptd.plist"
            ]
        );
        assert_eq!(
            mac.activation_commands(true)[1].args,
            ["kickstart", "gui/501/com.processtriage.ptd"]
        );
        assert_eq!(mac.deactivation_commands(false).len(), 1);
        assert_eq!(
            mac.deactivation_commands(true)[1].args,
            ["bootout", "gui/501/com.processtriage.ptd"]
        );
    }

    #[test]
    fn preview_never_creates_directories_or_calls_a_manager() {
        let directory = tempfile::tempdir().unwrap().keep();
        let service = definition(ServicePlatform::SystemdUser, &directory.join("not-created"));
        let report = service.install(true, true).unwrap();
        assert!(!report.changed);
        assert!(!report.installed);
        assert_eq!(report.commands.len(), 4);
        assert!(report.results.is_empty());
        assert!(!service.path.parent().unwrap().exists());
    }

    #[test]
    fn installation_is_idempotent_and_refuses_edits_or_other_definitions() {
        let directory = tempfile::tempdir().unwrap().keep();
        let service = definition(ServicePlatform::SystemdUser, &directory);
        assert!(service.install(false, false).unwrap().changed);
        assert!(!service.install(false, false).unwrap().changed);
        let installed = fs::read(&service.path).unwrap();
        assert!(service.uninstall(true).unwrap().dry_run);
        assert_eq!(fs::read(&service.path).unwrap(), installed);
        let changed = ServiceDefinition::new(
            ServicePlatform::SystemdUser,
            &directory,
            Path::new("/opt/other/pt-core"),
            Path::new("/etc/process_triage"),
            current_uid(),
        )
        .unwrap();
        assert!(changed.install(false, false).is_err());
        OpenOptions::new()
            .append(true)
            .open(&service.path)
            .unwrap()
            .write_all(b"# local edit\n")
            .unwrap();
        let edited = fs::read(&service.path).unwrap();
        assert!(service.install(false, false).is_err());
        assert!(service.uninstall(true).is_err());
        assert_eq!(fs::read(&service.path).unwrap(), edited);
    }

    #[cfg(unix)]
    #[test]
    fn foreign_files_and_symlinks_are_preserved() {
        let directory = tempfile::tempdir().unwrap().keep();
        let service = definition(ServicePlatform::SystemdUser, &directory);
        fs::write(&service.path, b"[Service]\nExecStart=/bin/true\n").unwrap();
        assert!(service.install(false, false).is_err());
        assert!(service.uninstall(true).is_err());
        let linked = definition(ServicePlatform::LaunchdAgent, &directory);
        std::os::unix::fs::symlink(&service.path, &linked.path).unwrap();
        assert!(linked.install(false, false).is_err());
        assert!(linked.uninstall(true).is_err());
        assert_eq!(
            fs::read_to_string(&service.path).unwrap(),
            "[Service]\nExecStart=/bin/true\n"
        );
        assert!(fs::symlink_metadata(&linked.path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn manager_ownership_is_checked_without_inventing_success() {
        let service = definition(
            ServicePlatform::SystemdUser,
            Path::new("/home/user/.config/systemd/user"),
        );
        let mut result = ManagerResult {
            command: service.ownership_command(),
            exit_code: Some(0),
            stdout: "LoadState=loaded\nFragmentPath=/etc/systemd/user/ptd.service\nDropInPaths=\n".into(),
            stderr: String::new(),
            timed_out: false,
            truncated: false,
        };
        assert!(service.manager_owns_path(&result).is_err());
        result.stdout = format!(
            "LoadState=loaded\nFragmentPath={}\nDropInPaths=\n",
            service.path.display()
        );
        assert!(service.manager_owns_path(&result).unwrap());
        result.stdout.push_str("DropInPaths=/home/user/override.conf\n");
        assert!(service.manager_owns_path(&result).is_err());
        result.stdout = "LoadState=not-found\nFragmentPath=\nDropInPaths=\n".into();
        assert!(!service.manager_owns_path(&result).unwrap());
        result.exit_code = Some(1);
        assert!(!service.manager_owns_path(&result).unwrap());
        for incomplete in [
            "LoadState=not-found\n",
            "LoadState=not-found\nFragmentPath=/etc/systemd/user/ptd.service\nDropInPaths=\n",
            "LoadState=not-found\nFragmentPath=\nDropInPaths=\nDropInPaths=\n",
        ] {
            result.stdout = incomplete.into();
            assert!(service.manager_owns_path(&result).is_err());
        }
        result.exit_code = Some(0);
        result.stdout = format!("LoadState=loaded\nFragmentPath={}\n", service.path.display());
        assert!(service.manager_owns_path(&result).is_err());
        result.stdout = "LoadState=not-found\nFragmentPath=\nDropInPaths=\n".into();
        result.timed_out = true;
        assert!(service.manager_owns_path(&result).is_err());
    }

    #[test]
    fn launchd_absence_requires_specific_complete_manager_evidence() {
        let service = definition(
            ServicePlatform::LaunchdAgent,
            Path::new("/Users/user/Library/LaunchAgents"),
        );
        let mut result = ManagerResult {
            command: service.ownership_command(),
            exit_code: Some(113),
            stdout: String::new(),
            stderr: "Could not find service \"com.processtriage.ptd\" in domain for user gui: 501".into(),
            timed_out: false,
            truncated: false,
        };
        assert!(!service.manager_owns_path(&result).unwrap());
        result.stderr = "Could not find domain for user gui: 501".into();
        assert!(service.manager_owns_path(&result).is_err());
        result.exit_code = Some(0);
        result.stdout = format!(
            "gui/501/com.processtriage.ptd = {{\n\tpath = {}\n}}",
            service.path.display()
        );
        assert!(service.manager_owns_path(&result).unwrap());
    }

    #[test]
    fn relative_paths_and_control_characters_are_rejected() {
        for executable in [
            "relative/pt-core",
            "/opt/new\nline/pt-core",
            "/opt/nul\0/pt-core",
        ] {
            assert!(ServiceDefinition::new(
                ServicePlatform::SystemdUser,
                Path::new("/tmp/unit"),
                Path::new(executable),
                Path::new("/tmp/config"),
                501
            )
            .is_err());
        }
    }

    #[test]
    fn manager_environment_accepts_literal_session_addresses_and_absolute_paths() {
        assert!(validate_manager_environment("XDG_RUNTIME_DIR", "/run/user/501").is_ok());
        assert!(validate_manager_environment("HOME", "/Users/user with spaces").is_ok());
        assert!(validate_manager_environment(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/run/user/501/bus,guid=literal%value"
        )
        .is_ok());
        assert!(validate_manager_environment("XDG_RUNTIME_DIR", "relative/run").is_err());
        assert!(validate_manager_environment("DBUS_SESSION_BUS_ADDRESS", "bad\naddress").is_err());
    }
}
