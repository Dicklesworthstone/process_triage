//! Report generator implementation.

use crate::config::ReportConfig;
use crate::error::{ReportError, Result};
use crate::sections::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};
use tracing::{debug, info};

/// Complete report data structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    /// Report configuration.
    pub config: ReportConfig,
    /// Generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Generator version.
    pub generator_version: String,
    /// Overview section.
    pub overview: Option<OverviewSection>,
    /// Candidates section.
    pub candidates: Option<CandidatesSection>,
    /// Evidence section.
    pub evidence: Option<EvidenceSection>,
    /// Actions section.
    pub actions: Option<ActionsSection>,
    /// Galaxy-brain section.
    pub galaxy_brain: Option<GalaxyBrainSection>,
}

impl ReportData {
    /// Get the report title.
    pub fn title(&self) -> String {
        self.config
            .title
            .clone()
            .or_else(|| {
                self.overview
                    .as_ref()
                    .map(|o| format!("Session {}", o.session_id))
            })
            .unwrap_or_else(|| "Process Triage Report".to_string())
    }
}

/// Report generator.
pub struct ReportGenerator {
    config: ReportConfig,
}

/// A session ends at its recorded terminal transition, not at an update or
/// export. Resumed sessions and incomplete or inconsistent history stay unknown.
pub fn recorded_session_end(metadata: &serde_json::Value) -> Option<DateTime<Utc>> {
    let state = metadata["state"].as_str()?;
    if !matches!(state, "completed" | "cancelled" | "failed" | "archived") {
        return None;
    }
    let history = metadata["state_history"].as_array()?;
    if history.last()?["state"].as_str()? != state {
        return None;
    }
    let terminal = history
        .iter()
        .rev()
        .find(|transition| transition["state"].as_str() != Some("archived"))?;
    if !matches!(
        terminal["state"].as_str()?,
        "completed" | "cancelled" | "failed"
    ) {
        return None;
    }
    let started = DateTime::parse_from_rfc3339(metadata["timing"]["created_at"].as_str()?)
        .ok()?
        .with_timezone(&Utc);
    let ended = DateTime::parse_from_rfc3339(terminal["ts"].as_str()?)
        .ok()?
        .with_timezone(&Utc);
    (ended >= started).then_some(ended)
}

impl ReportGenerator {
    /// Create a new report generator with configuration.
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Create a generator with default configuration.
    pub fn default_config() -> Self {
        Self::new(ReportConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &ReportConfig {
        &self.config
    }

    /// Generate report from a bundle reader.
    pub fn generate_from_bundle<R: Read + Seek>(
        &self,
        reader: &mut pt_bundle::BundleReader<R>,
    ) -> Result<String> {
        debug!("Generating report from bundle");

        let overview = self.build_overview_from_manifest(reader.manifest());
        // Bundle creation is not session start, and an archive does not establish
        // that its session completed. Use saved session metadata when available.
        let mut recorded_overview = serde_json::to_value(&overview)?;
        recorded_overview["started_at"] = serde_json::Value::Null;
        recorded_overview["state"] = serde_json::Value::Null;
        recorded_overview["deep_scan"] = serde_json::Value::Null;
        if reader.has_file("session/context.json") {
            let context: serde_json::Value =
                serde_json::from_slice(&reader.read_verified("session/context.json")?)?;
            recorded_overview["host_id"] = context["host_id"].clone();
            recorded_overview["os_family"] = context["os"]["family"].clone();
            recorded_overview["arch"] = context["os"]["arch"].clone();
        }
        if reader.has_file("session/manifest.json") {
            let metadata: serde_json::Value =
                serde_json::from_slice(&reader.read_verified("session/manifest.json")?)?;
            recorded_overview["started_at"] = metadata["timing"]["created_at"].clone();
            recorded_overview["state"] = metadata["state"].clone();
            recorded_overview["mode"] = metadata["mode"].clone();
            recorded_overview["ended_at"] = serde_json::to_value(recorded_session_end(&metadata))?;
        }
        let plan: Option<serde_json::Value> = reader.read_plan()?;
        let plan = match plan {
            Some(plan) => plan,
            None if reader.has_file("summary.json") => {
                serde_json::json!({"summary": reader.read_summary::<serde_json::Value>()?})
            }
            None => serde_json::json!({}),
        };
        let outcomes = if reader.has_file("logs/outcomes.jsonl") {
            parse_outcomes(&reader.read_verified("logs/outcomes.jsonl")?)?
        } else {
            Vec::new()
        };
        self.generate_recorded_artifacts(overview, recorded_overview, &plan, &outcomes)
    }

    /// Render recorded plan evidence and outcomes without reconstructing missing
    /// measurements or applying today's inference configuration to an old session.
    pub fn generate_from_session_artifacts(
        &self,
        overview: OverviewSection,
        plan: &serde_json::Value,
        outcomes: &[serde_json::Value],
    ) -> Result<String> {
        let recorded_overview = serde_json::to_value(&overview)?;
        self.generate_recorded_artifacts(overview, recorded_overview, plan, outcomes)
    }

    fn generate_recorded_artifacts(
        &self,
        mut overview: OverviewSection,
        mut recorded_overview: serde_json::Value,
        plan: &serde_json::Value,
        outcomes: &[serde_json::Value],
    ) -> Result<String> {
        if !plan.is_object()
            || plan
                .get("candidates")
                .is_some_and(|value| !value.is_array())
        {
            return Err(ReportError::MissingData(
                "invalid recorded plan".to_string(),
            ));
        }
        let profile = pt_redact::ExportProfile::parse_str(&self.config.redaction_profile)
            .ok_or_else(|| ReportError::InvalidConfig("invalid redaction profile".to_string()))?;
        overview.export_profile = profile.to_string();
        recorded_overview["export_profile"] = serde_json::json!(overview.export_profile);
        overview.ended_at = serde_json::from_value(recorded_overview["ended_at"].clone())?;
        let engine = pt_redact::RedactionEngine::new(pt_redact::RedactionPolicy::default())
            .map_err(|error| ReportError::InvalidConfig(error.to_string()))?;
        let candidate_count = plan["candidates"].as_array().map(Vec::len);
        recorded_overview["candidates_found"] = candidate_count
            .map(serde_json::Value::from)
            .or_else(|| plan.pointer("/summary/candidates_returned").cloned())
            .or_else(|| plan.pointer("/summary/candidates").cloned())
            .unwrap_or(serde_json::Value::Null);
        recorded_overview["processes_scanned"] = plan
            .pointer("/scan/total_processes")
            .or_else(|| plan.pointer("/summary/total_processes_scanned"))
            .or_else(|| plan.pointer("/summary/total_processes"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        // The planner records elapsed deep-scan time only when --deep is set;
        // its explicit null means disabled. Missing history cannot establish
        // either state. Only unsigned millisecond durations are usable, and a
        // zero-millisecond recorded scan still counts.
        recorded_overview["deep_scan"] = match plan.pointer("/summary/deep_scan_ms") {
            Some(serde_json::Value::Number(value)) if value.as_u64().is_some() => {
                serde_json::json!(true)
            }
            Some(serde_json::Value::Null) => serde_json::json!(false),
            _ => serde_json::Value::Null,
        };
        // Missing action logs are unknown, not a measured zero. Only count
        // terminal outcomes whose recorded action can be established.
        for field in ["kills_attempted", "kills_successful", "spares"] {
            recorded_overview[field] = serde_json::Value::Null;
        }
        if !outcomes.is_empty() {
            let mut attempted = 0;
            let mut successful = 0;
            let mut complete_actions = true;
            for outcome in outcomes {
                let action = outcome
                    .get("action")
                    .and_then(|value| value.as_str())
                    .or_else(|| {
                        let id = outcome.get("action_id")?.as_str()?;
                        plan["actions"]
                            .as_array()?
                            .iter()
                            .find(|action| action["action_id"] == id)?
                            .get("action")?
                            .as_str()
                    });
                complete_actions &= action.is_some();
                let status = outcome["status"].as_str();
                if action.is_some_and(|action| action.eq_ignore_ascii_case("kill"))
                    && matches!(status, Some("success" | "failed"))
                {
                    attempted += 1;
                    successful += usize::from(status == Some("success"));
                }
            }
            if complete_actions {
                recorded_overview["kills_attempted"] = serde_json::json!(attempted);
                recorded_overview["kills_successful"] = serde_json::json!(successful);
            }
        }
        let overview: OverviewSection = serde_json::from_value(
            engine.redact_json_for_export(&serde_json::to_value(overview)?, profile),
        )?;
        let recorded_overview = engine.redact_json_for_export(&recorded_overview, profile);
        let recorded = if profile == pt_redact::ExportProfile::Minimal {
            serde_json::json!({"overview": recorded_overview, "candidate_count": candidate_count, "outcome_count": outcomes.len()})
        } else {
            // One engine preserves correlation between candidate and outcome
            // pseudonyms; sanitize before either HTML or embedded JSON is built.
            serde_json::json!({
                "overview": recorded_overview,
                "plan": engine.redact_json_for_export(plan, profile),
                "outcomes": outcomes.iter().map(|outcome| engine.redact_json_for_export(outcome, profile)).collect::<Vec<_>>(),
            })
        };
        let data = ReportData {
            config: self.config.clone(),
            generated_at: Utc::now(),
            generator_version: env!("CARGO_PKG_VERSION").to_string(),
            overview: Some(overview),
            candidates: None,
            evidence: None,
            actions: None,
            galaxy_brain: None,
        };
        let sections = self.generate_recorded_sections(&recorded)?;
        self.finish_html(
            self.generate_html(&data, &sections, Some(&recorded["overview"])),
            &data,
        )
    }

    /// Generate report from structured data.
    pub fn generate(&self, data: ReportData) -> Result<String> {
        self.render_html(&data)
    }

    /// Generate report from JSON data.
    pub fn generate_from_json(&self, json: &str) -> Result<String> {
        let data: ReportData = serde_json::from_str(json)?;
        self.render_html(&data)
    }

    fn build_overview_from_manifest(
        &self,
        manifest: &pt_bundle::BundleManifest,
    ) -> OverviewSection {
        OverviewSection {
            session_id: manifest.session_id.clone(),
            host_id: manifest.host_id.clone(),
            hostname: None,
            started_at: manifest.created_at,
            ended_at: None,
            duration_ms: None,
            state: "completed".to_string(),
            mode: "unknown".to_string(),
            deep_scan: false,
            processes_scanned: 0,
            candidates_found: 0,
            kills_attempted: 0,
            kills_successful: 0,
            spares: 0,
            os_family: None,
            os_version: None,
            kernel_version: None,
            arch: None,
            cores: None,
            memory_bytes: None,
            pt_version: manifest.pt_version.clone(),
            export_profile: manifest.export_profile.to_string(),
        }
    }

    fn render_html(&self, data: &ReportData) -> Result<String> {
        self.finish_html(self.generate_html(data, "", None), data)
    }

    fn finish_html(&self, html: String, data: &ReportData) -> Result<String> {
        // Optionally minify
        let output = if cfg!(debug_assertions) {
            html
        } else {
            let cfg = minify_html::Cfg {
                minify_js: true,
                minify_css: true,
                ..Default::default()
            };
            String::from_utf8(minify_html::minify(html.as_bytes(), &cfg)).unwrap_or(html)
        };

        info!(
            bytes = output.len(),
            title = %data.title(),
            "Report generated"
        );

        Ok(output)
    }

    fn generate_html(
        &self,
        data: &ReportData,
        recorded_sections: &str,
        recorded_overview: Option<&serde_json::Value>,
    ) -> String {
        let title = data.title();
        let theme_class = self.config.theme.css_class();
        let cdn_base = &self.config.cdn_config.base_url;
        let libs = &self.config.cdn_config.libraries;

        // Build CDN script/style tags
        let mut cdn_styles = String::new();
        let mut cdn_scripts = String::new();

        if let Some(lib) = libs
            .get("tailwindcss")
            .filter(|_| !self.config.embed_assets)
        {
            let url = lib.url(cdn_base, "tailwindcss");
            cdn_styles.push_str(&format!(
                r#"<link rel="stylesheet" href="{}" integrity="{}" crossorigin="anonymous">"#,
                url, lib.sri
            ));
        }

        if let Some(lib) = libs
            .get("tabulator-tables")
            .filter(|_| !self.config.embed_assets)
        {
            cdn_styles.push_str(&format!(
                r#"<link rel="stylesheet" href="{}/tabulator-tables@{}/dist/css/tabulator.min.css" integrity="{}" crossorigin="anonymous">"#,
                cdn_base, lib.version, lib.sri
            ));
            cdn_scripts.push_str(&format!(
                r#"<script src="{}/tabulator-tables@{}/dist/js/tabulator.min.js" integrity="{}" crossorigin="anonymous"></script>"#,
                cdn_base, lib.version, lib.sri
            ));
        }

        if let Some(lib) = libs.get("echarts").filter(|_| !self.config.embed_assets) {
            cdn_scripts.push_str(&format!(
                r#"<script src="{}/echarts@{}/dist/echarts.min.js" integrity="{}" crossorigin="anonymous"></script>"#,
                cdn_base, lib.version, lib.sri
            ));
        }

        if self.config.galaxy_brain && !self.config.embed_assets {
            if let Some(lib) = libs.get("katex") {
                cdn_styles.push_str(&format!(
                    r#"<link rel="stylesheet" href="{}/katex@{}/dist/katex.min.css" integrity="{}" crossorigin="anonymous">"#,
                    cdn_base, lib.version, lib.sri
                ));
                cdn_scripts.push_str(&format!(
                    r#"<script src="{}/katex@{}/dist/katex.min.js" integrity="{}" crossorigin="anonymous"></script>"#,
                    cdn_base, lib.version, lib.sri
                ));
            }
        }

        // Serialize data for JavaScript (escape to keep script tag safe)
        let mut data_json = serde_json::to_value(data).unwrap_or_default();
        if let Some(overview) = recorded_overview {
            data_json["overview"] = overview.clone();
        }
        let data_json = data_json.to_string();
        let data_json = json_script_escape(&data_json);

        format!(
            r##"<!DOCTYPE html>
<html lang="en" class="{theme_class}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <meta name="generator" content="pt-report {version}">
    <meta name="robots" content="noindex, nofollow">
    {cdn_styles}
    <style>
        /* Base styles */
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f9fafb;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
            --accent-color: #3b82f6;
        }}
        .dark {{
            --bg-primary: #111827;
            --bg-secondary: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --border-color: #374151;
            --accent-color: #60a5fa;
        }}
        @media (prefers-color-scheme: dark) {{
            :root:not(.light) {{
                --bg-primary: #111827;
                --bg-secondary: #1f2937;
                --text-primary: #f9fafb;
                --text-secondary: #9ca3af;
                --border-color: #374151;
                --accent-color: #60a5fa;
            }}
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: ui-sans-serif, system-ui, sans-serif;
            line-height: 1.5;
        }}
        .card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .stat-card {{
            text-align: center;
            padding: 1rem;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-color);
        }}
        .stat-label {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        .tab-btn {{
            padding: 0.75rem 1.5rem;
            border-bottom: 2px solid transparent;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .tab-btn:hover {{
            background-color: var(--bg-secondary);
        }}
        .tab-btn.active {{
            border-bottom-color: var(--accent-color);
            color: var(--accent-color);
        }}
        .js-enabled .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }}
        .evidence-bar {{
            height: 0.5rem;
            background-color: var(--border-color);
            border-radius: 0.25rem;
            overflow: hidden;
        }}
        .evidence-bar-fill {{
            height: 100%;
            transition: width 0.3s;
        }}
        .evidence-bar-fill.positive {{
            background-color: #ef4444;
        }}
        .evidence-bar-fill.negative {{
            background-color: #22c55e;
        }}
        /* Print styles */
        @media print {{
            .no-print {{ display: none !important; }}
            body {{ font-size: 10pt; }}
            .card {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="max-w-7xl mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8">
            <h1 class="text-3xl font-bold mb-2">{title}</h1>
            <p class="text-sm" style="color: var(--text-secondary)">
                Generated: {generated_at} | Profile: {profile}
            </p>
        </header>

        <!-- Navigation Tabs -->
        <nav class="flex border-b mb-6 no-print" style="border-color: var(--border-color)">
            {tab_buttons}
        </nav>

        <!-- Tab Contents -->
        <main>
            {tab_contents}
            {recorded_sections}
        </main>

        <!-- Footer -->
        <footer class="mt-8 pt-4 border-t text-sm text-center" style="border-color: var(--border-color); color: var(--text-secondary)">
            <p>Process Triage Report v{version}</p>
            <p class="mt-1">
                <a href="https://github.com/Dicklesworthstone/process_triage"
                   target="_blank" rel="noopener"
                   style="color: var(--accent-color)">Documentation</a>
            </p>
        </footer>
    </div>

    {cdn_scripts}
    <script>
        // Report data
        const REPORT_DATA = {data_json};
        document.documentElement.classList.add('js-enabled');

        // Tab switching
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.dataset.tab === tabId);
            }});
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.toggle('active', content.id === 'tab-' + tabId);
            }});
        }}

        // Initialize tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {{
            btn.addEventListener('click', () => switchTab(btn.dataset.tab));
        }});

        // Initialize first tab
        const firstTab = document.querySelector('.tab-btn');
        if (firstTab) switchTab(firstTab.dataset.tab);

        // Initialize Tabulator if available
        if (typeof Tabulator !== 'undefined' && REPORT_DATA.candidates) {{
            new Tabulator('#candidates-table', {{
                data: REPORT_DATA.candidates.candidates,
                layout: 'fitColumns',
                pagination: true,
                paginationSize: 25,
                columns: [
                    {{ title: 'PID', field: 'pid', sorter: 'number', width: 80 }},
                    {{ title: 'Command', field: 'cmd', sorter: 'string' }},
                    {{ title: 'Score', field: 'score', sorter: 'number',
                       formatter: cell => (cell.getValue() * 100).toFixed(1) + '%' }},
                    {{ title: 'Recommendation', field: 'recommendation', sorter: 'string' }},
                    {{ title: 'Age', field: 'age_s', sorter: 'number',
                       formatter: cell => formatAge(cell.getValue()) }},
                    {{ title: 'CPU %', field: 'cpu_pct', sorter: 'number',
                       formatter: cell => cell.getValue().toFixed(1) + '%' }},
                    {{ title: 'Memory', field: 'mem_mb', sorter: 'number',
                       formatter: cell => formatMem(cell.getValue()) }},
                ],
            }});
        }}

        // Initialize ECharts if available
        if (typeof echarts !== 'undefined' && REPORT_DATA.candidates) {{
            const scoreChart = echarts.init(document.getElementById('score-chart'));
            const scores = REPORT_DATA.candidates.candidates.map(c => c.score);
            scoreChart.setOption({{
                title: {{ text: 'Score Distribution', left: 'center' }},
                xAxis: {{ type: 'category', data: ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%'] }},
                yAxis: {{ type: 'value' }},
                series: [{{
                    type: 'bar',
                    data: [
                        scores.filter(s => s < 0.2).length,
                        scores.filter(s => s >= 0.2 && s < 0.4).length,
                        scores.filter(s => s >= 0.4 && s < 0.6).length,
                        scores.filter(s => s >= 0.6 && s < 0.8).length,
                        scores.filter(s => s >= 0.8).length,
                    ],
                    itemStyle: {{ color: '#3b82f6' }}
                }}]
            }});
            window.addEventListener('resize', () => scoreChart.resize());
        }}

        // Initialize KaTeX if available
        if (typeof katex !== 'undefined') {{
            document.querySelectorAll('.math').forEach(el => {{
                katex.render(el.textContent, el, {{ throwOnError: false }});
            }});
        }}

        // Utility functions
        function formatAge(seconds) {{
            if (seconds >= 86400) return Math.floor(seconds / 86400) + 'd';
            if (seconds >= 3600) return Math.floor(seconds / 3600) + 'h';
            if (seconds >= 60) return Math.floor(seconds / 60) + 'm';
            return seconds + 's';
        }}

        function formatMem(mb) {{
            if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB';
            return mb.toFixed(0) + ' MB';
        }}
    </script>
</body>
</html>"##,
            theme_class = theme_class,
            title = html_escape(&title),
            version = env!("CARGO_PKG_VERSION"),
            cdn_styles = cdn_styles,
            generated_at = data.generated_at.format("%Y-%m-%d %H:%M UTC"),
            profile = html_escape(&self.config.redaction_profile),
            tab_buttons = self.generate_tab_buttons(data),
            tab_contents = self.generate_tab_contents(data, recorded_overview),
            recorded_sections = recorded_sections,
            cdn_scripts = cdn_scripts,
            data_json = data_json,
        )
    }

    fn generate_tab_buttons(&self, data: &ReportData) -> String {
        let mut buttons = Vec::new();
        let sections = &self.config.sections;

        if sections.overview && data.overview.is_some() {
            buttons.push(r#"<button class="tab-btn" data-tab="overview">Overview</button>"#);
        }
        if sections.candidates && data.candidates.is_some() {
            buttons.push(r#"<button class="tab-btn" data-tab="candidates">Candidates</button>"#);
        }
        if sections.evidence && data.evidence.is_some() {
            buttons.push(r#"<button class="tab-btn" data-tab="evidence">Evidence</button>"#);
        }
        if sections.actions && data.actions.is_some() {
            buttons.push(r#"<button class="tab-btn" data-tab="actions">Actions</button>"#);
        }
        if sections.galaxy_brain && data.galaxy_brain.is_some() {
            buttons
                .push(r#"<button class="tab-btn" data-tab="galaxy-brain">Galaxy Brain</button>"#);
        }

        buttons.join("\n            ")
    }

    fn generate_recorded_sections(&self, recorded: &serde_json::Value) -> Result<String> {
        let mut html = String::new();
        if let Some(candidates) = recorded
            .pointer("/plan/candidates")
            .and_then(|v| v.as_array())
        {
            if self.config.sections.candidates {
                html.push_str("<section class=\"card\" id=\"recorded-candidates\"><h2>Candidate Processes</h2><div style=\"overflow-x:auto\"><table><thead><tr><th>PID</th><th>Command</th><th>Score (0–100)</th><th>Final recommendation</th><th>Useful</th><th>Useful bad</th><th>Abandoned</th><th>Zombie</th><th>Age (seconds)</th><th>CPU (%)</th><th>Memory (MB)</th></tr></thead><tbody>");
                for candidate in candidates.iter().take(self.config.limits.max_candidates) {
                    html.push_str("<tr>");
                    for paths in [
                        &["/pid"][..],
                        &["/command", "/cmd"],
                        &["/score"],
                        &["/recommended_action", "/recommendation"],
                        &["/posterior/useful"],
                        &["/posterior/useful_bad"],
                        &["/posterior/abandoned"],
                        &["/posterior/zombie"],
                        &["/age_seconds", "/age_s"],
                        &["/cpu_percent", "/cpu_pct"],
                        &["/memory_mb", "/mem_mb"],
                    ] {
                        html.push_str(&format!("<td>{}</td>", recorded_cell(candidate, paths)));
                    }
                    html.push_str("</tr>");
                }
                html.push_str("</tbody></table></div>");
                if candidates.len() > self.config.limits.max_candidates {
                    html.push_str(&format!(
                        "<p>Showing {} of {} recorded candidates.</p>",
                        self.config.limits.max_candidates,
                        candidates.len(),
                    ));
                }
                html.push_str("</section>");
            }
            if self.config.galaxy_brain && self.config.sections.evidence {
                html.push_str("<section class=\"card\" id=\"recorded-evidence\"><h2>Recorded Evidence Ledger</h2><p>These are saved inference terms. Historical priors or calibration results are shown only when recorded.</p>");
                for candidate in candidates.iter().take(self.config.limits.max_candidates) {
                    html.push_str(&format!(
                        "<details><summary>PID {}</summary>",
                        recorded_cell(candidate, &["/pid"]),
                    ));
                    if let Some(ledger) = candidate.get("evidence_ledger").filter(|v| v.is_object())
                    {
                        html.push_str(&format!(
                            "<pre>{}</pre>",
                            html_escape(&serde_json::to_string_pretty(ledger)?),
                        ));
                    } else {
                        html.push_str("<p>Exact ledger not recorded for this candidate.</p>");
                    }
                    html.push_str("</details>");
                }
                html.push_str("</section>");
            }
        } else if recorded.get("candidate_count").is_some() {
            html.push_str("<section class=\"card\"><h2>Aggregate Export</h2><p>Per-process candidates and outcomes are omitted by the minimal profile.</p></section>");
        } else {
            html.push_str("<section class=\"card\"><h2>Candidate Processes</h2><p>Candidate details were not recorded in this plan.</p></section>");
        }
        if self.config.sections.actions {
            if let Some(outcomes) = recorded.get("outcomes").and_then(|v| v.as_array()) {
                html.push_str("<section class=\"card\" id=\"recorded-outcomes\"><h2>Recorded Actions and Outcomes</h2>");
                if outcomes.is_empty() {
                    html.push_str("<p>No action outcomes were recorded.</p>");
                }
                for outcome in outcomes {
                    html.push_str(&format!(
                        "<pre>{}</pre>",
                        html_escape(&serde_json::to_string_pretty(outcome)?),
                    ));
                }
                html.push_str("</section>");
            }
        }
        for (field, title) in [
            ("goal_progress", "Recorded Goal Progress"),
            ("system", "Recorded System Pressure"),
        ] {
            if let Some(value) = recorded["plan"].get(field).filter(|v| !v.is_null()) {
                html.push_str(&format!(
                    "<section class=\"card\"><h2>{title}</h2><pre>{}</pre></section>",
                    html_escape(&serde_json::to_string_pretty(value)?),
                ));
            }
        }
        html.push_str(&format!(
            "<script type=\"application/json\" id=\"recorded-session-data\">{}</script>",
            json_script_escape(&serde_json::to_string(recorded)?),
        ));
        Ok(html)
    }

    fn generate_tab_contents(
        &self,
        data: &ReportData,
        recorded_overview: Option<&serde_json::Value>,
    ) -> String {
        let mut contents = Vec::new();
        let sections = &self.config.sections;

        if sections.overview {
            if let Some(ref overview) = data.overview {
                let overview = recorded_overview
                    .cloned()
                    .unwrap_or_else(|| serde_json::to_value(overview).unwrap_or_default());
                contents.push(self.generate_overview_tab(&overview));
            }
        }
        if sections.candidates {
            if let Some(ref candidates) = data.candidates {
                contents.push(self.generate_candidates_tab(candidates));
            }
        }
        if sections.evidence {
            if let Some(ref evidence) = data.evidence {
                contents.push(self.generate_evidence_tab(evidence));
            }
        }
        if sections.actions {
            if let Some(ref actions) = data.actions {
                contents.push(self.generate_actions_tab(actions));
            }
        }
        if sections.galaxy_brain {
            if let Some(ref gb) = data.galaxy_brain {
                contents.push(self.generate_galaxy_brain_tab(gb));
            }
        }

        contents.join("\n")
    }

    fn generate_overview_tab(&self, overview: &serde_json::Value) -> String {
        format!(
            r##"<section id="tab-overview" class="tab-content">
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="card stat-card">
            <div class="stat-value">{processes}</div>
            <div class="stat-label">Processes Scanned</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value">{candidates}</div>
            <div class="stat-label">Candidates Found</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value">{kills}</div>
            <div class="stat-label">Kills Successful</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value">{spares}</div>
            <div class="stat-label">Spared</div>
        </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="card">
            <h3 class="text-lg font-semibold mb-4">Session Details</h3>
            <dl class="grid grid-cols-2 gap-2 text-sm">
                <dt style="color: var(--text-secondary)">Session ID</dt>
                <dd class="font-mono">{session_id}</dd>
                <dt style="color: var(--text-secondary)">Host ID</dt>
                <dd class="font-mono">{host_id}</dd>
                <dt style="color: var(--text-secondary)">Started</dt>
                <dd>{started_at}</dd>
                <dt style="color: var(--text-secondary)">Duration (ms)</dt>
                <dd>{duration}</dd>
                <dt style="color: var(--text-secondary)">Mode</dt>
                <dd>{mode}</dd>
                <dt style="color: var(--text-secondary)">State</dt>
                <dd><span class="badge bg-green-100 text-green-800">{state}</span></dd>
            </dl>
        </div>

        <div class="card">
            <h3 class="text-lg font-semibold mb-4">System Information</h3>
            <dl class="grid grid-cols-2 gap-2 text-sm">
                <dt style="color: var(--text-secondary)">OS</dt>
                <dd>{os}</dd>
                <dt style="color: var(--text-secondary)">Architecture</dt>
                <dd>{arch}</dd>
                <dt style="color: var(--text-secondary)">Cores</dt>
                <dd>{cores}</dd>
                <dt style="color: var(--text-secondary)">Memory (bytes)</dt>
                <dd>{memory}</dd>
                <dt style="color: var(--text-secondary)">PT Version</dt>
                <dd>{pt_version}</dd>
                <dt style="color: var(--text-secondary)">Export Profile</dt>
                <dd><span class="badge bg-blue-100 text-blue-800">{profile}</span></dd>
            </dl>
        </div>
    </div>
</section>"##,
            processes = recorded_cell(overview, &["/processes_scanned"]),
            candidates = recorded_cell(overview, &["/candidates_found"]),
            kills = recorded_cell(overview, &["/kills_successful"]),
            spares = recorded_cell(overview, &["/spares"]),
            session_id = recorded_cell(overview, &["/session_id"]),
            host_id = recorded_cell(overview, &["/host_id"]),
            started_at = recorded_cell(overview, &["/started_at"]),
            duration = recorded_cell(overview, &["/duration_ms"]),
            mode = recorded_cell(overview, &["/mode"]),
            state = recorded_cell(overview, &["/state"]),
            os = recorded_cell(overview, &["/os_family"]),
            arch = recorded_cell(overview, &["/arch"]),
            cores = recorded_cell(overview, &["/cores"]),
            memory = recorded_cell(overview, &["/memory_bytes"]),
            pt_version = recorded_cell(overview, &["/pt_version"]),
            profile = recorded_cell(overview, &["/export_profile"]),
        )
    }

    fn generate_candidates_tab(&self, candidates: &CandidatesSection) -> String {
        format!(
            r##"<section id="tab-candidates" class="tab-content">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="card stat-card">
            <div class="stat-value text-red-500">{kill_count}</div>
            <div class="stat-label">Kill Recommendations</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value text-green-500">{spare_count}</div>
            <div class="stat-label">Spare Recommendations</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value text-yellow-500">{review_count}</div>
            <div class="stat-label">Review Needed</div>
        </div>
    </div>

    <div class="card">
        <div class="flex justify-between items-center mb-4">
            <h3 class="text-lg font-semibold">Candidate Processes</h3>
            {truncation_notice}
        </div>
        <div id="candidates-table"></div>
    </div>

    <div class="card mt-4">
        <h3 class="text-lg font-semibold mb-4">Score Distribution</h3>
        <div id="score-chart" style="height: 300px;"></div>
    </div>
</section>"##,
            kill_count = candidates.kill_count(),
            spare_count = candidates.spare_count(),
            review_count = candidates.review_count(),
            truncation_notice = if candidates.truncated {
                format!(
                    r#"<span class="text-sm" style="color: var(--text-secondary)">Showing {} of {} candidates</span>"#,
                    candidates.candidates.len(),
                    candidates.total_count
                )
            } else {
                String::new()
            },
        )
    }

    fn generate_evidence_tab(&self, evidence: &EvidenceSection) -> String {
        let mut ledger_html = String::new();
        for ledger in &evidence.ledgers {
            ledger_html.push_str(&self.generate_evidence_ledger(ledger));
        }

        format!(
            r##"<section id="tab-evidence" class="tab-content">
    <div class="card mb-4">
        <h3 class="text-lg font-semibold mb-4">Evidence Factor Legend</h3>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-sm">
            {factor_legend}
        </div>
    </div>

    <div class="space-y-4">
        {ledger_html}
    </div>
</section>"##,
            factor_legend = evidence
                .factor_definitions
                .iter()
                .map(|f| format!(
                    r#"<div class="p-2 rounded" style="background: var(--bg-secondary)">
                        <div class="font-medium">{}</div>
                        <div style="color: var(--text-secondary)">{}</div>
                    </div>"#,
                    html_escape(&f.name),
                    html_escape(&f.description)
                ))
                .collect::<Vec<_>>()
                .join("\n            "),
            ledger_html = ledger_html,
        )
    }

    fn generate_evidence_ledger(&self, ledger: &EvidenceLedger) -> String {
        let factors_html: String = ledger
            .factors
            .iter()
            .map(|f| {
                let bar_class = if f.favors_abandoned {
                    "positive"
                } else {
                    "negative"
                };
                format!(
                    r#"<div class="flex items-center gap-2 py-1">
                        <span class="w-20 text-sm">{}</span>
                        <div class="flex-1 evidence-bar">
                            <div class="evidence-bar-fill {}" style="width: {}%"></div>
                        </div>
                        <span class="w-16 text-right text-sm {}">{:+.2}</span>
                    </div>"#,
                    html_escape(&f.label),
                    bar_class,
                    f.bar_width(),
                    f.direction_class(),
                    f.log_odds
                )
            })
            .collect();

        format!(
            r##"<details class="card">
    <summary class="cursor-pointer flex justify-between items-center">
        <div>
            <span class="font-mono font-medium">PID {pid}</span>
            <span class="ml-2" style="color: var(--text-secondary)">{cmd}</span>
        </div>
        <div class="flex items-center gap-2">
            <span class="badge bg-blue-100 text-blue-800">{bf_interp}</span>
            <span class="font-medium">{posterior:.1}%</span>
        </div>
    </summary>
    <div class="mt-4 pt-4 border-t" style="border-color: var(--border-color)">
        <div class="grid grid-cols-3 gap-4 mb-4 text-sm">
            <div>
                <span style="color: var(--text-secondary)">Prior:</span>
                <span class="ml-1">{prior:.1}%</span>
            </div>
            <div>
                <span style="color: var(--text-secondary)">Log BF:</span>
                <span class="ml-1">{log_bf:+.2}</span>
            </div>
            <div>
                <span style="color: var(--text-secondary)">Tags:</span>
                <span class="ml-1">{tags}</span>
            </div>
        </div>
        <h4 class="text-sm font-semibold mb-2">Evidence Factors</h4>
        {factors_html}
    </div>
</details>"##,
            pid = ledger.pid,
            cmd = html_escape(&ledger.cmd),
            bf_interp = html_escape(&ledger.bf_interpretation),
            posterior = ledger.posterior_p * 100.0,
            prior = ledger.prior_p * 100.0,
            log_bf = ledger.log_bf,
            tags = ledger.tags.join(", "),
            factors_html = factors_html,
        )
    }

    fn generate_actions_tab(&self, actions: &ActionsSection) -> String {
        let rows_html: String = actions
            .actions
            .iter()
            .map(|a| {
                format!(
                    r#"<tr>
                        <td class="px-4 py-2 text-sm">{}</td>
                        <td class="px-4 py-2 font-mono">{}</td>
                        <td class="px-4 py-2">{}</td>
                        <td class="px-4 py-2"><span class="badge {}">{}</span></td>
                        <td class="px-4 py-2"><span class="badge {}">{}</span></td>
                        <td class="px-4 py-2">{}</td>
                        <td class="px-4 py-2">{}</td>
                    </tr>"#,
                    a.timestamp.format("%H:%M:%S"),
                    a.pid,
                    html_escape(&a.cmd),
                    a.recommendation_class(),
                    html_escape(&a.recommendation),
                    a.status_class(),
                    a.status_text(),
                    a.memory_freed_formatted().unwrap_or_default(),
                    a.user_feedback.as_deref().unwrap_or("-"),
                )
            })
            .collect();

        format!(
            r##"<section id="tab-actions" class="tab-content">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="card stat-card">
            <div class="stat-value">{total}</div>
            <div class="stat-label">Total Actions</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value text-green-500">{successful}</div>
            <div class="stat-label">Successful</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value text-red-500">{failed}</div>
            <div class="stat-label">Failed</div>
        </div>
        <div class="card stat-card">
            <div class="stat-value">{memory_freed}</div>
            <div class="stat-label">Memory Freed</div>
        </div>
    </div>

    <div class="card overflow-x-auto">
        <table class="w-full text-sm">
            <thead>
                <tr style="border-bottom: 1px solid var(--border-color)">
                    <th class="px-4 py-2 text-left">Time</th>
                    <th class="px-4 py-2 text-left">PID</th>
                    <th class="px-4 py-2 text-left">Command</th>
                    <th class="px-4 py-2 text-left">Recommendation</th>
                    <th class="px-4 py-2 text-left">Status</th>
                    <th class="px-4 py-2 text-left">Memory Freed</th>
                    <th class="px-4 py-2 text-left">Feedback</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</section>"##,
            total = actions.summary.total,
            successful = actions.summary.successful,
            failed = actions.summary.failed,
            memory_freed = actions.summary.memory_freed_formatted(),
            rows_html = rows_html,
        )
    }

    fn generate_galaxy_brain_tab(&self, gb: &GalaxyBrainSection) -> String {
        let factors_html: String = gb
            .factors
            .iter()
            .map(|f| {
                let examples_html: String = f
                    .examples
                    .iter()
                    .map(|ex| {
                        format!(
                            r#"<tr>
                                <td class="px-2 py-1">{}</td>
                                <td class="px-2 py-1 text-right">{:+.2}</td>
                                <td class="px-2 py-1">{}</td>
                            </tr>"#,
                            html_escape(&ex.input),
                            ex.log_odds,
                            html_escape(&ex.interpretation)
                        )
                    })
                    .collect();

                format!(
                    r##"<div class="card">
                        <h4 class="font-semibold mb-2">{name} <span class="text-sm font-normal" style="color: var(--text-secondary)">({category})</span></h4>
                        <div class="math mb-2">{formula}</div>
                        <p class="text-sm mb-3" style="color: var(--text-secondary)">{intuition}</p>
                        <table class="w-full text-sm">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-color)">
                                    <th class="px-2 py-1 text-left">Input</th>
                                    <th class="px-2 py-1 text-right">Log-Odds</th>
                                    <th class="px-2 py-1 text-left">Interpretation</th>
                                </tr>
                            </thead>
                            <tbody>{examples_html}</tbody>
                        </table>
                    </div>"##,
                    name = html_escape(&f.name),
                    category = html_escape(&f.category),
                    formula = html_escape(&f.formula),
                    intuition = html_escape(&f.intuition),
                    examples_html = examples_html,
                )
            })
            .collect();

        let thresholds_html: String = gb
            .bf_guide
            .thresholds
            .iter()
            .map(|t| {
                format!(
                    r#"<tr>
                        <td class="px-2 py-1">{}</td>
                        <td class="px-2 py-1">{}</td>
                    </tr>"#,
                    html_escape(&t.label),
                    html_escape(&t.description)
                )
            })
            .collect();

        format!(
            r##"<section id="tab-galaxy-brain" class="tab-content">
    <div class="card mb-6">
        <h3 class="text-xl font-bold mb-4">Bayesian Process Classification</h3>
        <p class="mb-4">
            Process Triage uses Bayesian inference to estimate the probability that a process
            has been abandoned. Each piece of evidence (age, CPU usage, memory, etc.) contributes
            a likelihood ratio that updates the prior probability.
        </p>

        <h4 class="font-semibold mb-2">Prior Probabilities</h4>
        <div class="math mb-2">{prior_formula}</div>
        <p class="text-sm mb-4" style="color: var(--text-secondary)">{prior_explanation}</p>

        <h4 class="font-semibold mb-2">Bayes Factor</h4>
        <div class="math mb-2">{bf_formula}</div>
        <p class="text-sm mb-4" style="color: var(--text-secondary)">{log_odds_explanation}</p>

        <h4 class="font-semibold mb-2">Interpretation Scale</h4>
        <table class="w-full text-sm mb-4">
            <thead>
                <tr style="border-bottom: 1px solid var(--border-color)">
                    <th class="px-2 py-1 text-left">Strength</th>
                    <th class="px-2 py-1 text-left">Meaning</th>
                </tr>
            </thead>
            <tbody>{thresholds_html}</tbody>
        </table>
    </div>

    <h3 class="text-lg font-semibold mb-4">Evidence Factors</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        {factors_html}
    </div>
</section>"##,
            prior_formula = html_escape(&gb.priors.formula),
            prior_explanation = html_escape(&gb.priors.explanation),
            bf_formula = html_escape(&gb.bf_guide.formula),
            log_odds_explanation = html_escape(&gb.bf_guide.log_odds_explanation),
            thresholds_html = thresholds_html,
            factors_html = factors_html,
        )
    }
}

impl ActionRow {
    fn recommendation_class(&self) -> &'static str {
        match self.recommendation.as_str() {
            "kill" => "bg-red-100 text-red-800",
            "spare" => "bg-green-100 text-green-800",
            _ => "bg-yellow-100 text-yellow-800",
        }
    }
}

/// Parse actual JSONL outcomes, propagating malformed records instead of hiding them.
pub fn parse_outcomes(bytes: &[u8]) -> Result<Vec<serde_json::Value>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .map(|line| serde_json::from_slice(line).map_err(ReportError::from))
        .collect()
}

fn recorded_cell(record: &serde_json::Value, paths: &[&str]) -> String {
    paths
        .iter()
        .find_map(|path| record.pointer(path).filter(|value| !value.is_null()))
        .map(|value| {
            html_escape(
                &value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string()),
            )
        })
        .unwrap_or_else(|| "Not recorded".to_string())
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn json_script_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            '&' => escaped.push_str("\\u0026"),
            '\u{2028}' => escaped.push_str("\\u2028"),
            '\u{2029}' => escaped.push_str("\\u2029"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_reports_use_terminal_history_and_the_active_export_profile() {
        let started = "2026-01-15T12:00:00Z";
        let ended = "2026-01-15T12:02:00Z";
        let updated = "2026-01-15T12:05:00Z";
        for (state, history, expected_end) in [
            (
                "planned",
                serde_json::json!([{"state":"planned","ts":updated}]),
                None,
            ),
            (
                "completed",
                serde_json::json!([{"state":"completed","ts":ended}]),
                Some(ended),
            ),
            (
                "cancelled",
                serde_json::json!([{"state":"cancelled","ts":ended}]),
                Some(ended),
            ),
            (
                "failed",
                serde_json::json!([{"state":"failed","ts":ended}]),
                Some(ended),
            ),
            (
                "archived",
                serde_json::json!([
                    {"state":"completed","ts":ended}, {"state":"archived","ts":updated}
                ]),
                Some(ended),
            ),
            ("completed", serde_json::json!([]), None),
            (
                "archived",
                serde_json::json!([{"state":"archived","ts":updated}]),
                None,
            ),
            (
                "completed",
                serde_json::json!([{"state":"completed","ts":"malformed"}]),
                None,
            ),
            (
                "completed",
                serde_json::json!([{"state":"failed","ts":ended}]),
                None,
            ),
            (
                "planned",
                serde_json::json!([
                    {"state":"failed","ts":ended}, {"state":"planned","ts":updated}
                ]),
                None,
            ),
            (
                "archived",
                serde_json::json!([
                    {"state":"completed","ts":ended}, {"state":"planned","ts":updated},
                    {"state":"archived","ts":updated}
                ]),
                None,
            ),
            (
                "completed",
                serde_json::json!([{"state":"completed","ts":"2026-01-15T11:00:00Z"}]),
                None,
            ),
        ] {
            let metadata = serde_json::json!({
                "state": state, "state_history": history, "mode": "robot_plan",
                "timing": {"created_at": started, "updated_at": updated}
            });
            // Exercise the real verified ZIP reader and rendered/embedded HTML;
            // the archive profile deliberately differs from the report override.
            for active_profile in ["safe", "FORENSIC"] {
                let mut config = ReportConfig::new().with_embed_assets(true);
                config.redaction_profile = active_profile.to_string();
                let generator = ReportGenerator::new(config);
                let mut writer = pt_bundle::BundleWriter::new(
                    "pt-20260115-120000-abcd",
                    "private-metadata-host",
                    if active_profile == "safe" {
                        pt_redact::ExportProfile::Forensic
                    } else {
                        pt_redact::ExportProfile::Safe
                    },
                );
                writer.add_json("session/manifest.json", &metadata).unwrap();
                writer
                    .add_plan(&serde_json::json!({"candidates": []}))
                    .unwrap();
                let (bytes, _) = writer.write_to_vec().unwrap();
                let mut reader = pt_bundle::BundleReader::from_bytes(bytes).unwrap();
                assert!(reader.verify_all().is_empty());
                let html = generator.generate_from_bundle(&mut reader).unwrap();
                let embedded = html
                    .split("id=\"recorded-session-data\">")
                    .nth(1)
                    .unwrap()
                    .split("</script>")
                    .next()
                    .unwrap();
                let recorded: serde_json::Value = serde_json::from_str(embedded).unwrap();
                let report_json = html
                    .split("const REPORT_DATA = ")
                    .nth(1)
                    .unwrap()
                    .split(";\n")
                    .next()
                    .unwrap();
                let report: serde_json::Value = serde_json::from_str(report_json).unwrap();
                let expected = expected_end.map(|ts| {
                    DateTime::parse_from_rfc3339(ts)
                        .unwrap()
                        .with_timezone(&Utc)
                });
                let expected = serde_json::to_value(expected).unwrap();
                assert_eq!(
                    recorded["overview"]["ended_at"], expected,
                    "{state}/{history}"
                );
                assert_eq!(
                    report["overview"]["ended_at"], expected,
                    "{state}/{history}"
                );
                assert_eq!(recorded["overview"]["state"], state);
                assert_eq!(recorded["overview"]["started_at"], started);
                assert_eq!(
                    recorded["overview"]["export_profile"],
                    active_profile.to_ascii_lowercase()
                );
                assert_eq!(
                    report["overview"]["export_profile"],
                    active_profile.to_ascii_lowercase()
                );
                assert!(!html.contains("private-metadata-host"));
            }
        }
    }

    #[test]
    fn recorded_deep_scan_indicator_agrees_across_session_and_bundle_reports() {
        let generator = ReportGenerator::new(
            ReportConfig::new()
                .with_embed_assets(true)
                .with_galaxy_brain(true),
        );
        for (summary, expected) in [
            (
                serde_json::json!({"deep_scan_ms": 0}),
                serde_json::json!(true),
            ),
            (
                serde_json::json!({"deep_scan_ms": 17}),
                serde_json::json!(true),
            ),
            (
                serde_json::json!({"deep_scan_ms": null}),
                serde_json::json!(false),
            ),
            (serde_json::json!({}), serde_json::Value::Null),
            (
                serde_json::json!({"deep_scan_ms": "unrecorded"}),
                serde_json::Value::Null,
            ),
            (
                serde_json::json!({"deep_scan_ms": -1}),
                serde_json::Value::Null,
            ),
            (
                serde_json::json!({"deep_scan_ms": 0.5}),
                serde_json::Value::Null,
            ),
        ] {
            // Controlled saved artifacts exercise actual ZIP and HTML adapters;
            // they do not establish live deep-probe or inference quality.
            let plan = serde_json::json!({
                "summary": summary,
                "scan": {"total_processes": 42},
                "candidates": [{
                    "pid": 4242, "command": "private-deep-scan-worker", "score": 87,
                    "recommended_action": "pause",
                    "posterior": {"useful": 0.1, "useful_bad": 0.03, "abandoned": 0.8, "zombie": 0.07},
                    "evidence_ledger": {"evidence_terms": [{
                        "feature": "cpu",
                        "log_likelihood": {"abandoned": -0.4, "useful": -2.0}
                    }]}
                }],
            });
            let outcome = serde_json::json!({
                "pid": 4242, "command": "private-deep-scan-worker",
                "action": "pause", "status": "success",
            });
            let mut overview =
                generator.build_overview_from_manifest(&pt_bundle::BundleManifest::new(
                    "pt-20261004-120500-abcd",
                    "private-deep-scan-host",
                    pt_redact::ExportProfile::Safe,
                ));
            // Stale caller defaults must not override the saved indicator.
            overview.deep_scan = expected != serde_json::json!(true);
            let session_html = generator
                .generate_from_session_artifacts(overview, &plan, std::slice::from_ref(&outcome))
                .unwrap();

            let mut writer = pt_bundle::BundleWriter::new(
                "pt-20261004-120500-abcd",
                "private-deep-scan-host",
                pt_redact::ExportProfile::Safe,
            );
            writer.add_plan(&plan).unwrap();
            writer.add_log("outcomes", format!("{outcome}\n").into_bytes());
            let (bytes, _) = writer.write_to_vec().unwrap();
            let mut reader = pt_bundle::BundleReader::from_bytes(bytes).unwrap();
            assert!(reader.verify_all().is_empty());
            let bundle_html = generator.generate_from_bundle(&mut reader).unwrap();

            for html in [session_html, bundle_html] {
                let embedded = html
                    .split("id=\"recorded-session-data\">")
                    .nth(1)
                    .expect("rendered recorded artifacts")
                    .split("</script>")
                    .next()
                    .unwrap();
                let recorded: serde_json::Value = serde_json::from_str(embedded).unwrap();
                let report_data = html
                    .split("const REPORT_DATA = ")
                    .nth(1)
                    .expect("rendered report overview")
                    .split(";\n")
                    .next()
                    .unwrap();
                let report: serde_json::Value = serde_json::from_str(report_data).unwrap();
                assert_eq!(recorded["overview"]["deep_scan"], expected);
                assert_eq!(report["overview"]["deep_scan"], expected);
                assert_eq!(recorded["overview"]["processes_scanned"], 42);
                assert_eq!(
                    recorded["plan"]["candidates"][0]["posterior"]["useful_bad"],
                    0.03
                );
                assert_eq!(
                    recorded["plan"]["candidates"][0]["evidence_ledger"]["evidence_terms"][0]
                        ["log_likelihood"]["abandoned"],
                    -0.4,
                );
                assert_eq!(recorded["outcomes"][0]["action"], "pause");
                assert_eq!(recorded["outcomes"][0]["status"], "success");
                assert!(html.contains("<td>4242</td>"));
                assert!(html.contains("<td>87</td><td>pause</td>"));
                assert!(html.contains("Recorded Evidence Ledger"));
                assert!(!html.contains("private-deep-scan"));
            }
        }
    }

    #[test]
    fn recorded_report_preserves_four_classes_and_final_action_without_private_data() {
        let generator = ReportGenerator::new(
            ReportConfig::new()
                .with_embed_assets(true)
                .with_galaxy_brain(true),
        );
        let overview = generator.build_overview_from_manifest(&pt_bundle::BundleManifest::new(
            "pt-20261004-120500-abcd",
            "private-customer-host",
            pt_redact::ExportProfile::Safe,
        ));
        let command =
            "python /home/private-customer/job.py </script><script>private-customer</script>";
        let plan = serde_json::json!({
            "scan": {"total_processes": 42},
            "candidates": [{
                "pid": 1234, "command": command, "score": 87,
                "recommended_action": "review",
                "posterior": {"useful": 0.1, "useful_bad": 0.03, "abandoned": 0.8, "zombie": 0.07},
                "environment": {"API_KEY": "AKIAIOSFODNN7EXAMPLE"},
                "evidence_ledger": {"evidence_terms": [{
                    "feature": "cpu",
                    "log_likelihood": {"useful": -2.0, "useful_bad": -1.0, "abandoned": -0.4, "zombie": -3.0}
                }]}
            }],
        });
        let outcomes = vec![serde_json::json!({
            "pid": 1234, "command": command, "action": "kill", "status": "blocked",
        })];
        let html = generator
            .generate_from_session_artifacts(overview, &plan, &outcomes)
            .unwrap();
        assert!(html.contains("<td>1234</td>"));
        assert!(html.contains("<td>87</td><td>review</td>"));
        assert!(html.contains("<td>0.1</td><td>0.03</td><td>0.8</td><td>0.07</td>"));
        assert!(html.contains("Not recorded"));
        assert!(html.contains("Recorded Evidence Ledger"));
        assert!(html.contains("log_likelihood"));
        assert!(html.contains("Recorded Actions and Outcomes"));
        assert!(!html.contains("private-customer"));
        assert!(!html.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!html.contains("<script src="));
        assert!(!html.contains("<link rel=\"stylesheet\""));
        assert!(!html.contains("P(S=legitimate)"));
        let embedded = html
            .split("id=\"recorded-session-data\">")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap();
        let recorded: serde_json::Value = serde_json::from_str(embedded).unwrap();
        assert_eq!(recorded["plan"]["candidates"][0]["pid"], 1234);
        assert_eq!(recorded["overview"]["processes_scanned"], 42);
        assert_eq!(recorded["overview"]["kills_successful"], 0);
        assert!(recorded["overview"]["spares"].is_null());
        assert_eq!(
            recorded["plan"]["candidates"][0]["recommended_action"],
            "review"
        );
        assert_eq!(
            recorded["plan"]["candidates"][0]["command"],
            recorded["outcomes"][0]["command"]
        );
    }

    #[test]
    fn old_session_reports_do_not_invent_exact_ledgers() {
        let generator = ReportGenerator::new(ReportConfig::new().with_galaxy_brain(true));
        let overview = generator.build_overview_from_manifest(&pt_bundle::BundleManifest::new(
            "pt-20261004-120500-abcd",
            "host",
            pt_redact::ExportProfile::Safe,
        ));
        let html = generator.generate_from_session_artifacts(
            overview,
            &serde_json::json!({"candidates": [{"pid": 1234, "score": 61, "evidence": [{"contribution": 9}]}]}),
            &[],
        ).unwrap();
        assert!(html.contains("Exact ledger not recorded for this candidate."));
        assert!(!html.contains("Bayesian Inference Model"));
        assert!(!html.contains("Historical Accuracy"));
    }

    #[test]
    fn outcomes_parser_rejects_corrupt_jsonl_and_profile_is_validated() {
        assert!(parse_outcomes(b"{\"pid\":1234}\nnot-json\n").is_err());
        assert_eq!(parse_outcomes(b"\n {\"pid\":1234}\n\n").unwrap().len(), 1);
        let mut config = ReportConfig::new();
        config.redaction_profile = "invalid".to_string();
        let generator = ReportGenerator::new(config);
        let overview = generator.build_overview_from_manifest(&pt_bundle::BundleManifest::new(
            "pt-20261004-120500-abcd",
            "host",
            pt_redact::ExportProfile::Safe,
        ));
        assert!(matches!(
            generator.generate_from_session_artifacts(
                overview,
                &serde_json::json!({"candidates": []}),
                &[]
            ),
            Err(ReportError::InvalidConfig(_)),
        ));
    }

    #[test]
    fn recorded_action_counts_join_real_action_ids_and_missing_data_stays_unknown() {
        let generator = ReportGenerator::default_config();
        let overview = generator.build_overview_from_manifest(&pt_bundle::BundleManifest::new(
            "pt-20261004-120500-abcd",
            "host",
            pt_redact::ExportProfile::Safe,
        ));
        let plan = serde_json::json!({"actions": [
            {"action_id": "a-one", "action": "kill"},
            {"action_id": "a-two", "action": "renice"},
            {"action_id": "a-three", "action": "kill"}
        ]});
        for (outcomes, expected) in [
            (Vec::new(), serde_json::Value::Null),
            (
                vec![serde_json::json!({"status": "success"})],
                serde_json::Value::Null,
            ),
            (
                vec![
                    serde_json::json!({"action_id": "a-one", "status": "success"}),
                    serde_json::json!({"action_id": "a-two", "status": "success"}),
                    serde_json::json!({"action_id": "a-three", "status": "failed"}),
                ],
                serde_json::json!(1),
            ),
        ] {
            let html = generator
                .generate_from_session_artifacts(overview.clone(), &plan, &outcomes)
                .unwrap();
            let embedded = html
                .split("id=\"recorded-session-data\">")
                .nth(1)
                .unwrap()
                .split("</script>")
                .next()
                .unwrap();
            let recorded: serde_json::Value = serde_json::from_str(embedded).unwrap();
            assert_eq!(recorded["overview"]["kills_successful"], expected);
            assert!(recorded["overview"]["processes_scanned"].is_null());
            assert!(recorded["overview"]["candidates_found"].is_null());
        }
        assert!(generator
            .generate_from_session_artifacts(overview, &serde_json::json!({"candidates": 4}), &[])
            .is_err());
    }

    #[test]
    fn test_report_generator_default() {
        let generator = ReportGenerator::default_config();
        assert!(!generator.config.embed_assets);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape(r#""quoted""#), "&quot;quoted&quot;");
    }

    #[test]
    fn test_json_script_escape() {
        let input = r#"<script>alert("x")</script>"#;
        let escaped = json_script_escape(input);
        assert!(escaped.contains("\\u003cscript\\u003e"));
        assert!(escaped.contains("\\u003c/script\\u003e"));
        assert!(!escaped.contains("<script>"));
    }

    #[test]
    fn test_empty_report() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        let data = ReportData {
            config: ReportConfig::default(),
            generated_at: Utc::now(),
            generator_version: "test".to_string(),
            overview: None,
            candidates: None,
            evidence: None,
            actions: None,
            galaxy_brain: None,
        };
        let html = generator.generate(data).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Process Triage Report"));
    }

    #[test]
    fn test_report_with_overview() {
        let generator = ReportGenerator::default_config();
        let data = ReportData {
            config: ReportConfig::default(),
            generated_at: Utc::now(),
            generator_version: "test".to_string(),
            overview: Some(OverviewSection {
                session_id: "test-123".to_string(),
                host_id: "host-abc".to_string(),
                hostname: Some("testhost".to_string()),
                started_at: Utc::now(),
                ended_at: None,
                duration_ms: Some(60000),
                state: "completed".to_string(),
                mode: "interactive".to_string(),
                deep_scan: false,
                processes_scanned: 100,
                candidates_found: 10,
                kills_attempted: 5,
                kills_successful: 4,
                spares: 5,
                os_family: Some("linux".to_string()),
                os_version: None,
                kernel_version: None,
                arch: Some("x86_64".to_string()),
                cores: Some(8),
                memory_bytes: Some(16_000_000_000),
                pt_version: Some("0.1.0".to_string()),
                export_profile: "safe".to_string(),
            }),
            candidates: None,
            evidence: None,
            actions: None,
            galaxy_brain: None,
        };
        let html = generator.generate(data).unwrap();
        assert!(html.contains("test-123"));
        assert!(html.contains("100")); // processes scanned
    }

    #[test]
    fn test_galaxy_brain_section() {
        let config = ReportConfig::default().with_galaxy_brain(true);
        let generator = ReportGenerator::new(config);
        let data = ReportData {
            config: ReportConfig::default().with_galaxy_brain(true),
            generated_at: Utc::now(),
            generator_version: "test".to_string(),
            overview: None,
            candidates: None,
            evidence: None,
            actions: None,
            galaxy_brain: Some(GalaxyBrainSection::default()),
        };
        let html = generator.generate(data).unwrap();
        assert!(html.contains("Galaxy Brain"));
        assert!(html.contains("Bayesian"));
    }
}
