# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_pt_core_global_optspecs
    string join \n capabilities= config= f/format= v/verbose q/quiet no-color timeout= robot shadow dry-run standalone fields= compact max-tokens= estimate-tokens h/help V/version
end

function __fish_pt_core_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_pt_core_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_pt_core_using_subcommand
    set -l cmd (__fish_pt_core_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c pt-core -n "__fish_pt_core_needs_command" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_needs_command" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_needs_command" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_needs_command" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_needs_command" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_needs_command" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_needs_command" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_needs_command" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_needs_command" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_needs_command" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_needs_command" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_needs_command" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_needs_command" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_needs_command" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_needs_command" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_needs_command" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "run" -d 'Interactive golden path: scan → infer → plan → TUI approval → staged apply'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "scan" -d 'Scan processes, record observations, or replay recorded scores (no actions)'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "replay" -d 'Review recorded processes and compare scoring configurations without actions'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "deep-scan" -d 'Full deep scan with all available probes'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "__deep-scan-worker"
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "diff" -d 'Compare two sessions and show differences'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "query" -d 'Query telemetry and history'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "bundle" -d 'Create or inspect diagnostic bundles'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "report" -d 'Generate HTML reports'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "check" -d 'Validate configuration and environment'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "doctor" -d 'Read-only host hygiene audit: VM tuning, swap/zram, oomd limits, journald, file-handle/inotify limits, zombie parents (suggests commands, never runs them)'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "learn" -d 'Interactive tutorials and onboarding guidance'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "agent" -d 'Agent/robot subcommands for automated operation'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "robot" -d 'Agent/robot subcommands for automated operation'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "config" -d 'Configuration management'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "daemon" -d 'Background monitoring daemon'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "telemetry" -d 'Telemetry management'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "shadow" -d 'Shadow mode observation management'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "signature" -d 'Signature management (list, add, remove user signatures)'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "schema" -d 'Generate JSON schemas for agent output types'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "update" -d 'Update management: rollback, backup, version history'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "mcp" -d 'MCP server for AI agent integration'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "completions" -d 'Generate shell completion scripts'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "version" -d 'Print version information'
complete -c pt-core -n "__fish_pt_core_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l probe-budget-ms -d 'Maximum deep collection time per refresh in milliseconds (0 skips probes)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l signatures -d 'Load additional signature patterns' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l min-posterior -l threshold -d 'Minimum intervention probability to display (0 includes useful pressure candidates; safety gates still apply)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l goal -d 'Resource goal (e.g. \'free 4GB RAM\') or pressure relief: relieve, cpu-pressure, mem-pressure, io-pressure' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l theme -d 'TUI color theme (overrides environment detection)' -r -f -a "dark\t''
light\t''
high-contrast\t''
no-color\t''"
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l deep -d 'Deep-scan every eligible candidate within the probe budget'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l inline -d 'Render the TUI inline (preserves scrollback) instead of using the alternate screen'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l community-signatures -d 'Include signed community signatures'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l high-contrast -d 'Enable high-contrast mode (WCAG AAA). Shorthand for --theme=high-contrast'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l reduce-motion -d 'Disable animations and use static indicators (accessibility). Also activatable via REDUCE_MOTION or PT_REDUCE_MOTION env vars'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l accessible -d 'Enable screen-reader-friendly mode (text labels, verbose status, no animations). Also activatable via PT_ACCESSIBLE env var'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand run" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l samples -d 'Number of samples to collect' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l interval -d 'Interval between samples (milliseconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l goal -d 'Resource recovery goal (advisory only)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l record-replay -d 'Record this quick scan and scoring observations privately (contains raw commands). The destination must not exist. Redact and review before sharing' -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l record-replay-window-ms -d 'Activity window for replay recording in milliseconds (default: 500; 0 uses lifetime CPU)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l replay-scores -d 'Score a recorded census with current configuration, without inspecting live processes. Requires scoring observations from --record-replay. Never authorizes actions' -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l deep -d 'Force deep scan'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l include-kernel-threads -d 'Include kernel threads in scan output (default: exclude)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand scan" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -f -a "label-template" -d 'Create a private review document with every captured identity left unlabeled'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -f -a "evaluate" -d 'Compare an incumbent and the current --config using the same reviewed capture'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and not __fish_seen_subcommand_from label-template evaluate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l snapshot -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l output -d 'New private destination; existing files and symlinks are refused' -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l host-id -d 'Operator-supplied host identifier for the review cohort' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l split -d 'Declared dataset split; this does not prove a host was held out of training' -r -f -a "training\t''
holdout\t''"
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from label-template" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l snapshot -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l labels -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l baseline-config -d 'Existing configuration directory for the incumbent model' -r -F
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from evaluate" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from help" -f -a "label-template" -d 'Create a private review document with every captured identity left unlabeled'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from help" -f -a "evaluate" -d 'Compare an incumbent and the current --config using the same reviewed capture'
complete -c pt-core -n "__fish_pt_core_using_subcommand replay; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l pids -d 'Target specific PIDs only' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l budget -d 'Wall-clock deadline for deep collection (seconds); incomplete scans fail with exit 22' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l allow-partial -d 'Retain completed records on timeout; requires --budget or --timeout'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand deep-scan" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand __deep-scan-worker" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l category -d 'Filter by category: new, resolved, changed, unchanged, worsened, improved' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l min-score-delta -d 'Minimum score delta to consider a change' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l baseline -d 'Compare current session to the most recent baseline-labeled session'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l last -d 'Compare the latest two sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l changed-only -d 'Only show changes (exclude unchanged)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand diff" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -a "sessions" -d 'Query recent sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -a "actions" -d 'Query action history'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -a "telemetry" -d 'Query recent rows from a persisted Parquet telemetry table'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and not __fish_seen_subcommand_from sessions actions telemetry help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l limit -d 'Maximum sessions to return' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from sessions" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l session -d 'Filter by session ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l limit -d 'Maximum journal records to return (newest sessions, latest entries first)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from actions" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l range -d 'Event-time range (e.g., "1h", "24h", "7d")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l table -d 'Table: runs, proc_samples, proc_features, proc_inference, outcomes, audit, signature_matches' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l session -d 'Filter rows by exact session ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l limit -d 'Maximum rows to return, newest event first' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from telemetry" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from help" -f -a "sessions" -d 'Query recent sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from help" -f -a "actions" -d 'Query action history'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from help" -f -a "telemetry" -d 'Query recent rows from a persisted Parquet telemetry table'
complete -c pt-core -n "__fish_pt_core_using_subcommand query; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -f -a "create" -d 'Create a new diagnostic bundle from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -f -a "inspect" -d 'Inspect an existing bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -f -a "extract" -d 'Extract bundle contents'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and not __fish_seen_subcommand_from create inspect extract help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l session -d 'Session ID to export (default: latest)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s o -l output -d 'Output path for the bundle' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l profile -d 'Export profile: minimal, safe (default), forensic' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l passphrase -d 'Passphrase for bundle encryption/decryption (or use PT_BUNDLE_PASSPHRASE)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l include-telemetry -d 'Include raw telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l include-dumps -d 'Include full process dumps'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l encrypt -d 'Encrypt the bundle with a passphrase (explicit opt-in)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from create" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l passphrase -d 'Passphrase for encrypted bundles (or use PT_BUNDLE_PASSPHRASE)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l verify -d 'Verify file checksums'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from inspect" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s o -l output -d 'Output directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l passphrase -d 'Passphrase for encrypted bundles (or use PT_BUNDLE_PASSPHRASE)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l verify -d 'Verify file checksums before extraction'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from extract" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from help" -f -a "create" -d 'Create a new diagnostic bundle from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from help" -f -a "inspect" -d 'Inspect an existing bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from help" -f -a "extract" -d 'Extract bundle contents'
complete -c pt-core -n "__fish_pt_core_using_subcommand bundle; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l session -d 'Session ID to generate report for (default: latest)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s o -l output -d 'Output path for the HTML report' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l include-ledger -d 'Include detailed math ledger'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l embed-assets -d 'Generate self-contained HTML with built-in styles and readable tables'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand report" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l priors -d 'Check priors.json validity'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l policy -d 'Check policy.json validity'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l check-capabilities -d 'Check system capabilities'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l all -d 'Check all configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand check" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l fix-script -d 'Print the suggested commands as a commented shell script (never executed)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand doctor" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l verify-budget-ms -d 'Per-check verification budget in milliseconds' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l total-budget-ms -d 'Total verification budget in milliseconds' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "list" -d 'List all tutorials with completion status'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "show" -d 'Show one tutorial by id or slug (e.g., 01, first-run)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "verify" -d 'Verify tutorial commands under strict runtime budgets'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "complete" -d 'Mark a tutorial as completed manually'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "reset" -d 'Reset all tutorial progress'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and not __fish_seen_subcommand_from list show verify complete reset help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l all -d 'Verify all tutorials'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l mark-complete -d 'Mark successfully verified tutorials as completed'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from verify" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from complete" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from reset" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all tutorials with completion status'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show one tutorial by id or slug (e.g., 01, first-run)'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Verify tutorial commands under strict runtime budgets'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "complete" -d 'Mark a tutorial as completed manually'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "reset" -d 'Reset all tutorial progress'
complete -c pt-core -n "__fish_pt_core_using_subcommand learn; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "plan" -d 'Generate action plan without execution'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "explain" -d 'Explain reasoning for specific candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "apply" -d 'Execute actions from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "undo" -d 'Inspect or restore the recorded state of a reversible cgroup action'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "verify" -d 'Verify action outcomes'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "diff" -d 'Show changes between sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "snapshot" -d 'Create session snapshot for later comparison'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "capabilities" -d 'Dump current capabilities manifest'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "sessions" -d 'List and manage sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "list-priors" -d 'List current prior configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "label" -d 'Record a human kill/spare verdict so future plans learn from it'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "inbox" -d 'View pending plans and notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "tail" -d 'Stream session progress events (JSONL)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "watch" -d 'Watch for new candidates and emit notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "export-priors" -d 'Export priors to file for transfer between machines'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "import-priors" -d 'Import priors from file (bootstrap from external source)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "report" -d 'Generate HTML report from session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "init" -d 'Initialize pt for installed coding agents'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "export" -d 'Export session bundle (alias for bundle create)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "fleet" -d 'Fleet-wide operations across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l session -d 'Resume existing session' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l label -d 'Label for this plan session (e.g. "baseline" for diff --baseline)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l max-candidates -d 'Maximum candidates to return' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l pids -d 'Restrict inference to selected PIDs (comma-separated); ancestry and safety checks still use the full scan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l min-posterior -l threshold -d 'Minimum posterior probability threshold for candidate selection' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l only -d 'Filter by recommendation (kill, review, all)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l probe-budget-ms -d 'Maximum deep collection time in milliseconds (0 skips automatic and forced probes)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l sample-size -d 'Limit inference to a random sample of N processes (for testing)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l prediction-fields -d 'Select prediction subfields to include (comma-separated) Options: memory,cpu,eta_abandoned,eta_resource_limit,trajectory,diagnostics' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l since -d 'Add an advisory comparison with a prior session to the complete fresh plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l since-time -d 'Compare with the latest same-host snapshot at or before \'2h\' ago or an RFC3339 timestamp; always generate a complete fresh plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l goal -d 'Resource goal (e.g. \'free 4GB RAM\') or pressure relief: relieve, cpu-pressure, mem-pressure, io-pressure' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l yes -d 'Skip safety gate confirmations (use with caution)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l include-kernel-threads -d 'Include kernel threads as candidates (default: exclude)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l deep -d 'Deep-scan every eligible candidate within the probe budget'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l include-predictions -d 'Include trajectory prediction analysis in output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l minimal -d 'Minimal JSON output (PIDs, scores, and recommendations only)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l pretty -d 'Pretty-print JSON output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l brief -d 'Brief output: minimal fields + single-line rationale per candidate'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l narrative -d 'Narrative output: human-readable prose summary'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from plan" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l pids -d 'PIDs whose recorded session decisions should be explained' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l target -d 'Target process with stable identity (format: pid:start_id)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l window-ms -d 'Live activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l include -d 'Include evidence breakdown' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l live -d 'Rescan live processes with current configuration instead of reading saved evidence'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l galaxy-brain -d 'Include galaxy-brain math ledger'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l show-dependencies -d 'Show process dependencies tree'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l show-blast-radius -d 'Show blast radius impact analysis'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l show-history -d 'Show process history/backstory'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l what-if -d 'Show what-if hypotheticals'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from explain" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l pids -d 'PIDs to act on (default: all recommended)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l targets -d 'Specific targets with identity (pid:start_id)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l min-posterior -d 'Minimum posterior probability required (e.g. 0.99)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l max-blast-radius -d 'Max blast radius per action (MB)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l max-total-blast-radius -d 'Max total blast radius for the run (MB)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l max-kills -d 'Max kills per run' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l only-categories -d 'Only act on specific categories' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l exclude-categories -d 'Exclude specific categories' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l settle -d 'Observe host resources after executed actions for this many seconds (0 skips the interval)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l expected-host-id -d 'Refuse if the current host or recorded plan host differs from this ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l expected-plan-sha256 -d 'Refuse if the complete saved plan differs from this approved SHA-256' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l yes -d 'Skip safety gate confirmations'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l recommended -d 'Apply all recommended actions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l require-known-signature -d 'Require known signature match'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l abort-on-unknown -d 'Abort if unknown error/condition'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l resume -d 'Resume interrupted apply (skip already completed actions)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from apply" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l session -d 'Session containing the original action and its durable reversal receipt' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l action-id -d 'Canonical action ID from the saved plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l attempt-id -d 'Select an execution attempt when the action has more than one receipt' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l all -d 'Inspect or restore all pending durable receipts, newest execution first'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l confirm -d 'Restore the recorded state (otherwise inspect receipts without mutation)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from undo" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l wait -d 'Wait for process termination with timeout in seconds (default: 0 = no wait)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l check-respawn -d 'Check if killed processes have respawned'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from verify" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l base -d 'Base session ID (the "before" snapshot)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l compare -d 'Compare session ID (the "after" snapshot, default: current)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l focus -d 'Focus diff output on specific changes: all, new, removed, changed, resources' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from diff" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l label -d 'Label for the snapshot' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l top -d 'Limit to top N processes by resource usage (CPU+memory)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l include-env -d 'Include environment variables in snapshot (redacted by default)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l include-network -d 'Include network connection information'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l minimal -d 'Observe pressure and the top ten responsible units without process inference'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l pretty -d 'Pretty-print JSON output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from snapshot" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l check-action -d 'Check if a specific action type is supported (e.g., "sigterm", "sigkill", "strace")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from capabilities" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l session -d 'Show details for a specific session (consolidates show/status)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l limit -d 'Maximum sessions to return in list mode (default: 10)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l state -d 'Filter by session state' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l older-than -d 'Remove sessions older than duration (e.g., "7d", "30d")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l detail -d 'Include full session detail (plan contents, actions taken)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l cleanup -d 'Remove old sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from sessions" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l class -d 'Filter by class (useful, useful_bad, abandoned, zombie)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l extended -d 'Include all hyperparameters (extended output)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from list-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l pid -d 'Live process whose command pattern to label' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l cmd -d 'Command line to label (instead of a live --pid)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l comm -d 'Process name for --cmd (default: basename of its first word)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l kill -d 'Processes like this should be killed'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l spare -d 'Processes like this should be left alone'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from label" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l ack -d 'Acknowledge/dismiss an item by ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l clear -d 'Clear all acknowledged items'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l clear-all -d 'Clear all items (including unacknowledged)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l unread -d 'Show only unread items'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from inbox" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l session -d 'Session ID to tail' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l follow -d 'Follow the file for new events'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from tail" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l notify-exec -d 'Execute command via shell when watch events are emitted (legacy; prefer --notify-cmd)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l notify-cmd -d 'Execute command directly (no shell) when watch events are emitted' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l notify-arg -d 'Arguments for --notify-cmd (repeatable)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l threshold -d 'Trigger sensitivity (low|medium|high|critical)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l interval -d 'Check interval in seconds' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l goal-memory-available-gb -d 'Goal: minimum memory available (GB) before alerting' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l goal-load-max -d 'Goal: maximum 1-minute load average before alerting' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l once -d 'Run a single iteration and exit'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from watch" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s o -l out -d 'Output file path for exported priors' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l host-profile -d 'Tag priors with host profile name for smart matching' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s i -l from -d 'Input file path for priors to import' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l host-profile -d 'Apply only to specific host profile' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l merge -d 'Merge with existing priors (weighted average)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l replace -d 'Replace existing priors entirely'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l dry-run -d 'Dry run (show what would change without modifying)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l no-backup -d 'Skip backup of existing priors'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from import-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l session -d 'Session ID to generate report for (required unless using --bundle)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l bundle -d 'Path to a .ptb bundle file (alternative to --session)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s o -l out -d 'Output path for the HTML report' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l profile -d 'Redaction profile: minimal, safe (default), forensic' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l report-format -d 'Report output format: html (default), slack, prose' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l prose-style -d 'Prose style: terse, conversational (default), formal, technical' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l title -d 'Custom report title' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l theme -d 'Report theme: light, dark, auto (default)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l galaxy-brain -d 'Include full math ledger in report (galaxy-brain mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l embed-assets -d 'Inline CDN assets for offline viewing (file:// support)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from report" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l agent -d 'Configure specific agent only (claude, codex, copilot, cursor, windsurf)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l yes -d 'Apply defaults without prompts'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l dry-run -d 'Show what would change without modifying files'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l skip-backup -d 'Skip creating backup files'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from init" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l session -d 'Session ID to export (default: latest)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s o -l out -d 'Output path for the bundle' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l profile -d 'Export profile: minimal, safe (default), forensic' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l passphrase -d 'Passphrase for bundle encryption (or use PT_BUNDLE_PASSPHRASE)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l include-telemetry -d 'Include raw telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l include-dumps -d 'Include full process dumps'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l encrypt -d 'Encrypt the bundle with a passphrase'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "inventory" -d 'Preview fleet hosts without connecting (defaults to ~/.ssh/config)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "health" -d 'Inspect current pressure and responsible units on remote hosts (read-only)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "doctor" -d 'Audit remote host hygiene and show suggested remedies (never executed)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "plan" -d 'Generate a fleet-wide plan across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "apply" -d 'Apply a fleet plan for a fleet session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "report" -d 'Generate a fleet report from a fleet session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "status" -d 'Show fleet session status'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "transfer" -d 'Transfer learning data (priors + signatures) between hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from fleet" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Generate action plan without execution'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain reasoning for specific candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "apply" -d 'Execute actions from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "undo" -d 'Inspect or restore the recorded state of a reversible cgroup action'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Verify action outcomes'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "diff" -d 'Show changes between sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "snapshot" -d 'Create session snapshot for later comparison'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "capabilities" -d 'Dump current capabilities manifest'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "sessions" -d 'List and manage sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "list-priors" -d 'List current prior configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "label" -d 'Record a human kill/spare verdict so future plans learn from it'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "inbox" -d 'View pending plans and notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "tail" -d 'Stream session progress events (JSONL)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "watch" -d 'Watch for new candidates and emit notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "export-priors" -d 'Export priors to file for transfer between machines'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "import-priors" -d 'Import priors from file (bootstrap from external source)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "report" -d 'Generate HTML report from session'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "init" -d 'Initialize pt for installed coding agents'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export session bundle (alias for bundle create)'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "fleet" -d 'Fleet-wide operations across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "plan" -d 'Generate action plan without execution'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "explain" -d 'Explain reasoning for specific candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "apply" -d 'Execute actions from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "undo" -d 'Inspect or restore the recorded state of a reversible cgroup action'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "verify" -d 'Verify action outcomes'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "diff" -d 'Show changes between sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "snapshot" -d 'Create session snapshot for later comparison'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "capabilities" -d 'Dump current capabilities manifest'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "sessions" -d 'List and manage sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "list-priors" -d 'List current prior configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "label" -d 'Record a human kill/spare verdict so future plans learn from it'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "inbox" -d 'View pending plans and notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "tail" -d 'Stream session progress events (JSONL)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "watch" -d 'Watch for new candidates and emit notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "export-priors" -d 'Export priors to file for transfer between machines'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "import-priors" -d 'Import priors from file (bootstrap from external source)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "report" -d 'Generate HTML report from session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "init" -d 'Initialize pt for installed coding agents'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "export" -d 'Export session bundle (alias for bundle create)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "fleet" -d 'Fleet-wide operations across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and not __fish_seen_subcommand_from plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l session -d 'Resume existing session' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l label -d 'Label for this plan session (e.g. "baseline" for diff --baseline)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l max-candidates -d 'Maximum candidates to return' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l pids -d 'Restrict inference to selected PIDs (comma-separated); ancestry and safety checks still use the full scan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l min-posterior -l threshold -d 'Minimum posterior probability threshold for candidate selection' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l only -d 'Filter by recommendation (kill, review, all)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l probe-budget-ms -d 'Maximum deep collection time in milliseconds (0 skips automatic and forced probes)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l sample-size -d 'Limit inference to a random sample of N processes (for testing)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l prediction-fields -d 'Select prediction subfields to include (comma-separated) Options: memory,cpu,eta_abandoned,eta_resource_limit,trajectory,diagnostics' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l since -d 'Add an advisory comparison with a prior session to the complete fresh plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l since-time -d 'Compare with the latest same-host snapshot at or before \'2h\' ago or an RFC3339 timestamp; always generate a complete fresh plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l goal -d 'Resource goal (e.g. \'free 4GB RAM\') or pressure relief: relieve, cpu-pressure, mem-pressure, io-pressure' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l yes -d 'Skip safety gate confirmations (use with caution)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l include-kernel-threads -d 'Include kernel threads as candidates (default: exclude)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l deep -d 'Deep-scan every eligible candidate within the probe budget'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l include-predictions -d 'Include trajectory prediction analysis in output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l minimal -d 'Minimal JSON output (PIDs, scores, and recommendations only)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l pretty -d 'Pretty-print JSON output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l brief -d 'Brief output: minimal fields + single-line rationale per candidate'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l narrative -d 'Narrative output: human-readable prose summary'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from plan" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l pids -d 'PIDs whose recorded session decisions should be explained' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l target -d 'Target process with stable identity (format: pid:start_id)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l window-ms -d 'Live activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l include -d 'Include evidence breakdown' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l live -d 'Rescan live processes with current configuration instead of reading saved evidence'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l galaxy-brain -d 'Include galaxy-brain math ledger'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l show-dependencies -d 'Show process dependencies tree'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l show-blast-radius -d 'Show blast radius impact analysis'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l show-history -d 'Show process history/backstory'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l what-if -d 'Show what-if hypotheticals'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from explain" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l pids -d 'PIDs to act on (default: all recommended)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l targets -d 'Specific targets with identity (pid:start_id)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l min-posterior -d 'Minimum posterior probability required (e.g. 0.99)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l max-blast-radius -d 'Max blast radius per action (MB)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l max-total-blast-radius -d 'Max total blast radius for the run (MB)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l max-kills -d 'Max kills per run' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l only-categories -d 'Only act on specific categories' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l exclude-categories -d 'Exclude specific categories' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l settle -d 'Observe host resources after executed actions for this many seconds (0 skips the interval)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l expected-host-id -d 'Refuse if the current host or recorded plan host differs from this ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l expected-plan-sha256 -d 'Refuse if the complete saved plan differs from this approved SHA-256' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l yes -d 'Skip safety gate confirmations'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l recommended -d 'Apply all recommended actions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l require-known-signature -d 'Require known signature match'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l abort-on-unknown -d 'Abort if unknown error/condition'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l resume -d 'Resume interrupted apply (skip already completed actions)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from apply" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l session -d 'Session containing the original action and its durable reversal receipt' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l action-id -d 'Canonical action ID from the saved plan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l attempt-id -d 'Select an execution attempt when the action has more than one receipt' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l all -d 'Inspect or restore all pending durable receipts, newest execution first'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l confirm -d 'Restore the recorded state (otherwise inspect receipts without mutation)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from undo" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l session -d 'Session ID (required)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l wait -d 'Wait for process termination with timeout in seconds (default: 0 = no wait)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l check-respawn -d 'Check if killed processes have respawned'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from verify" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l base -d 'Base session ID (the "before" snapshot)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l compare -d 'Compare session ID (the "after" snapshot, default: current)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l focus -d 'Focus diff output on specific changes: all, new, removed, changed, resources' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from diff" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l label -d 'Label for the snapshot' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l top -d 'Limit to top N processes by resource usage (CPU+memory)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l include-env -d 'Include environment variables in snapshot (redacted by default)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l include-network -d 'Include network connection information'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l minimal -d 'Observe pressure and the top ten responsible units without process inference'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l pretty -d 'Pretty-print JSON output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from snapshot" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l check-action -d 'Check if a specific action type is supported (e.g., "sigterm", "sigkill", "strace")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from capabilities" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l session -d 'Show details for a specific session (consolidates show/status)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l limit -d 'Maximum sessions to return in list mode (default: 10)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l state -d 'Filter by session state' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l older-than -d 'Remove sessions older than duration (e.g., "7d", "30d")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l detail -d 'Include full session detail (plan contents, actions taken)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l cleanup -d 'Remove old sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from sessions" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l class -d 'Filter by class (useful, useful_bad, abandoned, zombie)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l extended -d 'Include all hyperparameters (extended output)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from list-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l pid -d 'Live process whose command pattern to label' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l cmd -d 'Command line to label (instead of a live --pid)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l comm -d 'Process name for --cmd (default: basename of its first word)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l kill -d 'Processes like this should be killed'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l spare -d 'Processes like this should be left alone'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from label" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l ack -d 'Acknowledge/dismiss an item by ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l clear -d 'Clear all acknowledged items'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l clear-all -d 'Clear all items (including unacknowledged)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l unread -d 'Show only unread items'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from inbox" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l session -d 'Session ID to tail' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l follow -d 'Follow the file for new events'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from tail" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l notify-exec -d 'Execute command via shell when watch events are emitted (legacy; prefer --notify-cmd)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l notify-cmd -d 'Execute command directly (no shell) when watch events are emitted' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l notify-arg -d 'Arguments for --notify-cmd (repeatable)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l threshold -d 'Trigger sensitivity (low|medium|high|critical)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l interval -d 'Check interval in seconds' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l window-ms -d 'Activity sampling window in milliseconds (0 uses lifetime CPU averages)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l goal-memory-available-gb -d 'Goal: minimum memory available (GB) before alerting' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l goal-load-max -d 'Goal: maximum 1-minute load average before alerting' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l once -d 'Run a single iteration and exit'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from watch" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s o -l out -d 'Output file path for exported priors' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l host-profile -d 'Tag priors with host profile name for smart matching' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s i -l from -d 'Input file path for priors to import' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l host-profile -d 'Apply only to specific host profile' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l merge -d 'Merge with existing priors (weighted average)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l replace -d 'Replace existing priors entirely'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l dry-run -d 'Dry run (show what would change without modifying)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l no-backup -d 'Skip backup of existing priors'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from import-priors" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l session -d 'Session ID to generate report for (required unless using --bundle)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l bundle -d 'Path to a .ptb bundle file (alternative to --session)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s o -l out -d 'Output path for the HTML report' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l profile -d 'Redaction profile: minimal, safe (default), forensic' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l report-format -d 'Report output format: html (default), slack, prose' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l prose-style -d 'Prose style: terse, conversational (default), formal, technical' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l title -d 'Custom report title' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l theme -d 'Report theme: light, dark, auto (default)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l galaxy-brain -d 'Include full math ledger in report (galaxy-brain mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l embed-assets -d 'Inline CDN assets for offline viewing (file:// support)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from report" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l agent -d 'Configure specific agent only (claude, codex, copilot, cursor, windsurf)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l yes -d 'Apply defaults without prompts'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l dry-run -d 'Show what would change without modifying files'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l skip-backup -d 'Skip creating backup files'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from init" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l session -d 'Session ID to export (default: latest)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s o -l out -d 'Output path for the bundle' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l profile -d 'Export profile: minimal, safe (default), forensic' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l passphrase -d 'Passphrase for bundle encryption (or use PT_BUNDLE_PASSPHRASE)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l include-telemetry -d 'Include raw telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l include-dumps -d 'Include full process dumps'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l encrypt -d 'Encrypt the bundle with a passphrase'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "inventory" -d 'Preview fleet hosts without connecting (defaults to ~/.ssh/config)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "health" -d 'Inspect current pressure and responsible units on remote hosts (read-only)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "doctor" -d 'Audit remote host hygiene and show suggested remedies (never executed)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "plan" -d 'Generate a fleet-wide plan across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "apply" -d 'Apply a fleet plan for a fleet session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "report" -d 'Generate a fleet report from a fleet session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "status" -d 'Show fleet session status'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "transfer" -d 'Transfer learning data (priors + signatures) between hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from fleet" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Generate action plan without execution'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain reasoning for specific candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "apply" -d 'Execute actions from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "undo" -d 'Inspect or restore the recorded state of a reversible cgroup action'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Verify action outcomes'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "diff" -d 'Show changes between sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "snapshot" -d 'Create session snapshot for later comparison'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "capabilities" -d 'Dump current capabilities manifest'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "sessions" -d 'List and manage sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "list-priors" -d 'List current prior configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "label" -d 'Record a human kill/spare verdict so future plans learn from it'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "inbox" -d 'View pending plans and notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "tail" -d 'Stream session progress events (JSONL)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "watch" -d 'Watch for new candidates and emit notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "export-priors" -d 'Export priors to file for transfer between machines'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "import-priors" -d 'Import priors from file (bootstrap from external source)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "report" -d 'Generate HTML report from session'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "init" -d 'Initialize pt for installed coding agents'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export session bundle (alias for bundle create)'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "fleet" -d 'Fleet-wide operations across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand robot; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "show" -d 'Show current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "schema" -d 'Print JSON schema for configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "validate" -d 'Validate configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "list-presets" -d 'List available configuration presets'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "show-preset" -d 'Show configuration values for a preset'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "diff-preset" -d 'Compare a preset with current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "export-preset" -d 'Export a preset to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and not __fish_seen_subcommand_from show schema validate list-presets show-preset diff-preset export-preset help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l file -d 'Show specific config file (priors or policy)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l file -d 'Schema to print (priors or policy)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from schema" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from validate" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from list-presets" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from show-preset" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from diff-preset" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s o -l output -d 'Output file path (stdout if not specified)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from export-preset" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "schema" -d 'Print JSON schema for configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "validate" -d 'Validate configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "list-presets" -d 'List available configuration presets'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "show-preset" -d 'Show configuration values for a preset'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "diff-preset" -d 'Compare a preset with current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "export-preset" -d 'Export a preset to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "start" -d 'Start the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "stop" -d 'Stop the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "status" -d 'Check daemon status'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "install" -d 'Install a per-user monitoring service (use --dry-run to preview)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "service-status" -d 'Inspect the installed service definition and service-manager state'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "uninstall" -d 'Disable, stop, and remove the verified managed service definition'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and not __fish_seen_subcommand_from start stop status install service-status uninstall help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l foreground -d 'Run in foreground'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from start" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from stop" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l activate -d 'Enable and start monitoring; the installed daemon only generates review plans'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from install" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from service-status" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from uninstall" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "start" -d 'Start the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "stop" -d 'Stop the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "status" -d 'Check daemon status'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "install" -d 'Install a per-user monitoring service (use --dry-run to preview)'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "service-status" -d 'Inspect the installed service definition and service-manager state'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "uninstall" -d 'Disable, stop, and remove the verified managed service definition'
complete -c pt-core -n "__fish_pt_core_using_subcommand daemon; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l retention-config -d 'Retention config JSON path (defaults to config dir telemetry_retention.json if present)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -f -a "status" -d 'Show telemetry status'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -f -a "export" -d 'Export one persisted telemetry table without changing its stored redaction'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -f -a "prune" -d 'Prune old telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -f -a "redact" -d 'Create a private redacted copy of all persisted telemetry tables'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and not __fish_seen_subcommand_from status export prune redact help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l retention-config -d 'Retention config JSON path (defaults to config dir telemetry_retention.json if present)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s o -l output -d 'Output path (must not exist, and must be outside the telemetry directory)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l export-format -d 'Export format (separate from the global output format)' -r -f -a "parquet\t''
csv\t''
json\t''
jsonl\t''"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l table -d 'Table: runs, proc_samples, proc_features, proc_inference, outcomes, audit, signature_matches' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l range -d 'Export only this event-time range (default: all stored rows)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l session -d 'Filter rows by exact session ID' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l retention-config -d 'Retention config JSON path (defaults to config dir telemetry_retention.json if present)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l keep -d 'Keep data newer than (e.g., "30d", "90d")' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l retention-config -d 'Retention config JSON path (defaults to config dir telemetry_retention.json if present)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l dry-run -d 'Preview retention actions without deleting files'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l keep-everything -d 'Keep everything (disable pruning)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from prune" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s o -l output -d 'New output directory, outside the source telemetry directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l profile -d 'Sharing profile; one fresh pseudonymization key is used for the entire copy' -r -f -a "safe\t''
minimal\t''"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l telemetry-dir -d 'Telemetry root directory (defaults to XDG data dir)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l retention-config -d 'Retention config JSON path (defaults to config dir telemetry_retention.json if present)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l all -d 'Include all persisted tables (source data is never modified)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from redact" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show telemetry status'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export one persisted telemetry table without changing its stored redaction'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from help" -f -a "prune" -d 'Prune old telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from help" -f -a "redact" -d 'Create a private redacted copy of all persisted telemetry tables'
complete -c pt-core -n "__fish_pt_core_using_subcommand telemetry; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "start" -d 'Start shadow mode observation loop'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "run" -d 'Run a foreground shadow loop (internal)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "stop" -d 'Stop background shadow observer'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "status" -d 'Show shadow observer status and stats'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "export" -d 'Export shadow observations for calibration analysis'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "report" -d 'Generate a calibration/validation report from shadow observations'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and not __fish_seen_subcommand_from start run stop status export report help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l interval -d 'Interval between scans (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l deep-interval -d 'Interval between deep scans (seconds, 0 disables)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l iterations -d 'Number of iterations before exiting (0 = run forever)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l max-candidates -d 'Maximum candidates to return per scan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l min-posterior -d 'Minimum posterior probability threshold' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l only -d 'Filter by recommendation (kill, review, all)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l sample-size -d 'Limit inference to a random sample of N processes' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l background -d 'Run in background (daemon-style)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l include-kernel-threads -d 'Include kernel threads as candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l deep -d 'Force deep scan with all available probes'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from start" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l interval -d 'Interval between scans (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l deep-interval -d 'Interval between deep scans (seconds, 0 disables)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l iterations -d 'Number of iterations before exiting (0 = run forever)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l max-candidates -d 'Maximum candidates to return per scan' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l min-posterior -d 'Minimum posterior probability threshold' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l only -d 'Filter by recommendation (kill, review, all)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l min-age -d 'Only consider processes older than threshold (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l sample-size -d 'Limit inference to a random sample of N processes' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l background -d 'Run in background (daemon-style)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l include-kernel-threads -d 'Include kernel threads as candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l deep -d 'Force deep scan with all available probes'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from run" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from stop" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from status" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s o -l output -d 'Output path (stdout if omitted)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l export-format -d 'Export format (json, jsonl)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l limit -d 'Max observations to export (most recent first)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s o -l output -d 'Output path (stdout if omitted)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l threshold -d 'Classification threshold for kill recommendations' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l limit -d 'Max observations to analyze (most recent first)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from report" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "start" -d 'Start shadow mode observation loop'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "run" -d 'Run a foreground shadow loop (internal)'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "stop" -d 'Stop background shadow observer'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show shadow observer status and stats'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export shadow observations for calibration analysis'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "report" -d 'Generate a calibration/validation report from shadow observations'
complete -c pt-core -n "__fish_pt_core_using_subcommand shadow; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "list" -d 'List all signatures (built-in and user-defined)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "show" -d 'Show details of a specific signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "add" -d 'Add a new user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "remove" -d 'Remove a user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "test" -d 'Test if a process name matches any signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "validate" -d 'Validate user signatures file'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "export" -d 'Export signatures to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "disable" -d 'Disable a signature without deleting it'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "enable" -d 'Re-enable a previously disabled signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "import" -d 'Import signatures from a file or .ptb bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "stats" -d 'Show signature performance statistics'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and not __fish_seen_subcommand_from list show add remove test validate export disable enable import stats help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l category -d 'Filter by category' -r -f -a "agent\t'AI coding agents (Claude, Codex, Aider, Cursor)'
ide\t'IDEs and development tools (VS Code, JetBrains)'
ci\t'CI/CD systems (GitHub Actions, GitLab Runner, Jenkins)'
orchestrator\t'Process orchestrators (systemd, launchd)'
terminal\t'Terminal multiplexers (tmux, screen)'
other\t'Other known supervisors'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l user-only -d 'Only show user-defined signatures'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l builtin-only -d 'Only show built-in signatures'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from list" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from show" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l category -d 'Category' -r -f -a "agent\t'AI coding agents (Claude, Codex, Aider, Cursor)'
ide\t'IDEs and development tools (VS Code, JetBrains)'
ci\t'CI/CD systems (GitHub Actions, GitLab Runner, Jenkins)'
orchestrator\t'Process orchestrators (systemd, launchd)'
terminal\t'Terminal multiplexers (tmux, screen)'
other\t'Other known supervisors'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l pattern -d 'Process name patterns (regex)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l arg-pattern -d 'Command line argument patterns (regex)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l env-var -d 'Environment variable (format: NAME=VALUE_REGEX)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l confidence -d 'Confidence weight (0.0-1.0)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l notes -d 'Optional notes about the signature' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l priority -d 'Priority (higher = checked first)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l prior -d 'What matching processes usually are. Sets the signature\'s class priors, which is what changes their score: `useful` (normal; keep them) or `abandoned` (usually left behind; safe to clean up). Without it the signature only labels matches' -r -f -a "useful\t'Normal, wanted processes (~90% useful prior)'
abandoned\t'Processes that are usually left behind (~80% abandoned prior)'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from add" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l force -d 'Skip confirmation'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from remove" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l cmdline -d 'Optional command line to test' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l all -d 'Show all matches (not just best)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from test" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from validate" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l user-only -d 'Only export user signatures'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from export" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l reason -d 'Optional reason for disabling' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from disable" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from enable" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l passphrase -d 'Bundle passphrase (if encrypted .ptb)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l dry-run -d 'Preview changes without applying'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from import" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l min-matches -d 'Only show signatures with at least this many matches' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l sort -d 'Sort by: matches, accepts, rejects, rate' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from stats" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all signatures (built-in and user-defined)'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show details of a specific signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove a user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "test" -d 'Test if a process name matches any signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "validate" -d 'Validate user signatures file'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export signatures to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable a signature without deleting it'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Re-enable a previously disabled signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "import" -d 'Import signatures from a file or .ptb bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "stats" -d 'Show signature performance statistics'
complete -c pt-core -n "__fish_pt_core_using_subcommand signature; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s l -l list -d 'List all available schema types'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s a -l all -d 'Generate schemas for all types'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l compact -d 'Output compact JSON (no pretty-printing)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand schema" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "rollback" -d 'Rollback to a previous version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "list-backups" -d 'List available backup versions'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "show-backup" -d 'Show backup details'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "verify-backup" -d 'Verify a backup\'s integrity'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "prune-backups" -d 'Remove old backups (keep most recent N)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and not __fish_seen_subcommand_from rollback list-backups show-backup verify-backup prune-backups help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l force -d 'Force rollback without confirmation'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from rollback" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from list-backups" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from show-backup" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from verify-backup" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l keep -d 'Number of backups to keep' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from prune-backups" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "rollback" -d 'Rollback to a previous version'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "list-backups" -d 'List available backup versions'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "show-backup" -d 'Show backup details'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "verify-backup" -d 'Verify a backup\'s integrity'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "prune-backups" -d 'Remove old backups (keep most recent N)'
complete -c pt-core -n "__fish_pt_core_using_subcommand update; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l transport -d 'Transport: stdio (default) for standard MCP integration' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand mcp" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand completions" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l capabilities -d 'Path to capabilities manifest (from pt wrapper)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l config -d 'Override config directory' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -s f -l format -d 'Output format' -r -f -a "json\t'Token-efficient structured JSON (default for machine consumption)'
toon\t'Token-Optimized Object Notation (TOON)'
md\t'Human-readable Markdown'
jsonl\t'Streaming JSON Lines for progress events'
summary\t'One-line summary for quick status checks'
metrics\t'Key=value pairs for monitoring systems'
slack\t'Human-friendly narrative for chat/notifications'
exitcode\t'Minimal output (exit code only)'
prose\t'Structured natural language for agent-to-user communication'"
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l timeout -d 'Abort if operation exceeds time limit (seconds)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l fields -d 'Select specific output fields (comma-separated or preset: minimal, standard, full)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l max-tokens -d 'Maximum token budget for output (enables truncation with continuation)' -r
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -s v -l verbose -d 'Increase verbosity (-v, -vv, -vvv)'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -s q -l quiet -d 'Decrease verbosity (quiet mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l no-color -d 'Disable colored output'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l robot -d 'Non-interactive mode; execute policy-approved actions automatically'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l shadow -d 'Full pipeline but never execute actions (calibration mode)'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l dry-run -d 'Compute plan only, no execution even with --robot'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l standalone -d 'Run without wrapper (uses detected/default capabilities)'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l compact -d 'Enable compact output (short keys, minified JSON)'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -l estimate-tokens -d 'Estimate token count without full response'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c pt-core -n "__fish_pt_core_using_subcommand version" -s V -l version -d 'Print version'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "run" -d 'Interactive golden path: scan → infer → plan → TUI approval → staged apply'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "scan" -d 'Scan processes, record observations, or replay recorded scores (no actions)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "replay" -d 'Review recorded processes and compare scoring configurations without actions'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "deep-scan" -d 'Full deep scan with all available probes'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "__deep-scan-worker"
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "diff" -d 'Compare two sessions and show differences'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "query" -d 'Query telemetry and history'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "bundle" -d 'Create or inspect diagnostic bundles'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "report" -d 'Generate HTML reports'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "check" -d 'Validate configuration and environment'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "doctor" -d 'Read-only host hygiene audit: VM tuning, swap/zram, oomd limits, journald, file-handle/inotify limits, zombie parents (suggests commands, never runs them)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "learn" -d 'Interactive tutorials and onboarding guidance'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "agent" -d 'Agent/robot subcommands for automated operation'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "config" -d 'Configuration management'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "daemon" -d 'Background monitoring daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "telemetry" -d 'Telemetry management'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "shadow" -d 'Shadow mode observation management'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "signature" -d 'Signature management (list, add, remove user signatures)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "schema" -d 'Generate JSON schemas for agent output types'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "update" -d 'Update management: rollback, backup, version history'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "mcp" -d 'MCP server for AI agent integration'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "completions" -d 'Generate shell completion scripts'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "version" -d 'Print version information'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and not __fish_seen_subcommand_from run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from replay" -f -a "label-template" -d 'Create a private review document with every captured identity left unlabeled'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from replay" -f -a "evaluate" -d 'Compare an incumbent and the current --config using the same reviewed capture'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from query" -f -a "sessions" -d 'Query recent sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from query" -f -a "actions" -d 'Query action history'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from query" -f -a "telemetry" -d 'Query recent rows from a persisted Parquet telemetry table'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from bundle" -f -a "create" -d 'Create a new diagnostic bundle from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from bundle" -f -a "inspect" -d 'Inspect an existing bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from bundle" -f -a "extract" -d 'Extract bundle contents'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from learn" -f -a "list" -d 'List all tutorials with completion status'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from learn" -f -a "show" -d 'Show one tutorial by id or slug (e.g., 01, first-run)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from learn" -f -a "verify" -d 'Verify tutorial commands under strict runtime budgets'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from learn" -f -a "complete" -d 'Mark a tutorial as completed manually'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from learn" -f -a "reset" -d 'Reset all tutorial progress'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "plan" -d 'Generate action plan without execution'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "explain" -d 'Explain reasoning for specific candidates'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "apply" -d 'Execute actions from a session'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "undo" -d 'Inspect or restore the recorded state of a reversible cgroup action'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "verify" -d 'Verify action outcomes'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "diff" -d 'Show changes between sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "snapshot" -d 'Create session snapshot for later comparison'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "capabilities" -d 'Dump current capabilities manifest'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "sessions" -d 'List and manage sessions'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "list-priors" -d 'List current prior configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "label" -d 'Record a human kill/spare verdict so future plans learn from it'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "inbox" -d 'View pending plans and notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "tail" -d 'Stream session progress events (JSONL)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "watch" -d 'Watch for new candidates and emit notifications'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "export-priors" -d 'Export priors to file for transfer between machines'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "import-priors" -d 'Import priors from file (bootstrap from external source)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "report" -d 'Generate HTML report from session'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "init" -d 'Initialize pt for installed coding agents'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "export" -d 'Export session bundle (alias for bundle create)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "fleet" -d 'Fleet-wide operations across multiple hosts'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "show" -d 'Show current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "schema" -d 'Print JSON schema for configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "validate" -d 'Validate configuration files'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "list-presets" -d 'List available configuration presets'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "show-preset" -d 'Show configuration values for a preset'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "diff-preset" -d 'Compare a preset with current configuration'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "export-preset" -d 'Export a preset to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "start" -d 'Start the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "stop" -d 'Stop the daemon'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "status" -d 'Check daemon status'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "install" -d 'Install a per-user monitoring service (use --dry-run to preview)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "service-status" -d 'Inspect the installed service definition and service-manager state'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from daemon" -f -a "uninstall" -d 'Disable, stop, and remove the verified managed service definition'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from telemetry" -f -a "status" -d 'Show telemetry status'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from telemetry" -f -a "export" -d 'Export one persisted telemetry table without changing its stored redaction'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from telemetry" -f -a "prune" -d 'Prune old telemetry data'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from telemetry" -f -a "redact" -d 'Create a private redacted copy of all persisted telemetry tables'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "start" -d 'Start shadow mode observation loop'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "run" -d 'Run a foreground shadow loop (internal)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "stop" -d 'Stop background shadow observer'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "status" -d 'Show shadow observer status and stats'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "export" -d 'Export shadow observations for calibration analysis'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from shadow" -f -a "report" -d 'Generate a calibration/validation report from shadow observations'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "list" -d 'List all signatures (built-in and user-defined)'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "show" -d 'Show details of a specific signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "add" -d 'Add a new user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "remove" -d 'Remove a user signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "test" -d 'Test if a process name matches any signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "validate" -d 'Validate user signatures file'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "export" -d 'Export signatures to a file'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "disable" -d 'Disable a signature without deleting it'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "enable" -d 'Re-enable a previously disabled signature'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "import" -d 'Import signatures from a file or .ptb bundle'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from signature" -f -a "stats" -d 'Show signature performance statistics'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from update" -f -a "rollback" -d 'Rollback to a previous version'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from update" -f -a "list-backups" -d 'List available backup versions'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from update" -f -a "show-backup" -d 'Show backup details'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from update" -f -a "verify-backup" -d 'Verify a backup\'s integrity'
complete -c pt-core -n "__fish_pt_core_using_subcommand help; and __fish_seen_subcommand_from update" -f -a "prune-backups" -d 'Remove old backups (keep most recent N)'
