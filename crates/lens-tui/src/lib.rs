//! The FQDN Lens terminal workbench.
//!
//! This crate owns terminal lifecycle, state reduction, key handling and
//! rendering only. Collection, credential storage, redaction, policy and
//! report semantics remain in `lens-core::ApplicationService`.

use anyhow::{Context, Result, anyhow};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::FutureExt;
use lens_core::i18n::{
    boolean_label, credential_state_label, display_language_code, display_language_label, message,
    report_format_label, report_language_label, result_scope_label, run_status_code,
    run_status_label, run_status_label_code, safe_path, scope_verdict_label, source_health_label,
    source_state_code, source_state_label_code, text,
};
use lens_core::{
    ApplicationError, ApplicationService, CollectOptions, CollectionProgressEvent,
    CollectionReport, DisplayLanguage, Evidence, EvidenceFilter, FindingsFilter, FqdnRecord, Page,
    ReportFormat, ReportLanguage, ResultScope, SnapshotDiff, SourceDoctorReport,
    SourcePreferenceSummary, SourceSummary, TargetResolution,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal, Stdout, Write};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Dashboard,
    Collect,
    Sources,
    Run,
    Findings,
    Evidence,
    Compare,
    Export,
    Settings,
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Modal {
    QuitConfirm,
    StartConfirm,
    RootConfirm,
    CancelConfirm,
    ConfigureCredential,
    ImportEnvironment,
    RemoveCredential,
    SaveSettings,
    ExportConfirm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditMode {
    None,
    Target,
    RootConfirmation,
    FindingSearch,
    ExportDestination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSort {
    Fqdn,
    EvidenceCount,
    SourceCount,
    FirstSeen,
    LastSeen,
}

#[must_use]
pub fn finding_sort_code(sort: FindingSort) -> &'static str {
    match sort {
        FindingSort::Fqdn => "fqdn",
        FindingSort::EvidenceCount => "evidence_count",
        FindingSort::SourceCount => "source_count",
        FindingSort::FirstSeen => "first_seen",
        FindingSort::LastSeen => "last_seen_desc",
    }
}

#[must_use]
pub fn finding_sort_label(language: DisplayLanguage, sort: FindingSort) -> String {
    let key = match sort {
        FindingSort::Fqdn => "sort_fqdn",
        FindingSort::EvidenceCount => "sort_evidence_count",
        FindingSort::SourceCount => "sort_source_count",
        FindingSort::FirstSeen => "sort_first_seen",
        FindingSort::LastSeen => "sort_last_seen",
    };
    format!("{} ({})", text(language, key), finding_sort_code(sort))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceProgressView {
    pub state_code: String,
    pub requests: u64,
    pub pages: u64,
    pub retries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub quota_rejections: u64,
    pub received: u64,
    pub accepted: u64,
    pub filtered: u64,
    pub evidence: u64,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActiveRunView {
    pub run_id: Option<Uuid>,
    pub target_domain: String,
    pub started_at: Instant,
    pub status_code: String,
    pub terminal: bool,
    pub accepted_findings: usize,
    pub evidence_count: usize,
    pub sources: BTreeMap<String, SourceProgressView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notice {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
}

impl From<lens_core::LocalizedMessage> for Notice {
    fn from(value: lens_core::LocalizedMessage) -> Self {
        Self {
            code: value.code,
            message: value.message,
            hint: value.hint,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub screen: Screen,
    pub return_screen: Option<Screen>,
    pub locale: DisplayLanguage,
    pub report_language: ReportLanguage,
    pub source_catalog: Vec<SourceSummary>,
    pub source_doctor: Vec<SourceDoctorReport>,
    pub source_preferences: Vec<SourcePreferenceSummary>,
    pub selected_source_index: usize,
    pub collect_focus: usize,
    pub selected_sources: BTreeSet<String>,
    pub target_draft: String,
    pub target_preview: Option<TargetResolution>,
    pub confirmed_root_domain: Option<String>,
    pub include_root: bool,
    pub edit_buffer: String,
    pub edit_mode: EditMode,
    pub modal: Option<Modal>,
    pub active_run: Option<ActiveRunView>,
    pub selected_run_id: Option<Uuid>,
    pub recent_runs: Vec<lens_core::CollectionRun>,
    pub project_domains: BTreeMap<Uuid, String>,
    pub run_counts: BTreeMap<Uuid, (usize, usize)>,
    pub selected_run_index: usize,
    pub findings: Option<Page<FqdnRecord>>,
    pub selected_finding_index: usize,
    pub finding_scope: ResultScope,
    pub finding_sort: FindingSort,
    pub finding_source_filter: Option<String>,
    pub finding_search: String,
    pub evidence: Option<Page<Evidence>>,
    pub selected_evidence_index: usize,
    pub compare_left_index: usize,
    pub compare_right_index: usize,
    pub comparison: Option<SnapshotDiff>,
    pub export_format: ReportFormat,
    pub export_destination: String,
    pub pending_display_language: DisplayLanguage,
    pub pending_report_language: ReportLanguage,
    pub show_low_frequency_fallback_sources: bool,
    pub pending_show_low_frequency_fallback_sources: bool,
    pub notice: Option<Notice>,
    pub should_exit: bool,
}

impl AppState {
    #[must_use]
    pub fn new(locale: DisplayLanguage, report_language: ReportLanguage) -> Self {
        Self {
            screen: Screen::Dashboard,
            return_screen: None,
            locale,
            report_language,
            source_catalog: Vec::new(),
            source_doctor: Vec::new(),
            source_preferences: Vec::new(),
            selected_source_index: 0,
            collect_focus: 0,
            selected_sources: BTreeSet::new(),
            target_draft: String::new(),
            target_preview: None,
            confirmed_root_domain: None,
            include_root: false,
            edit_buffer: String::new(),
            edit_mode: EditMode::None,
            modal: None,
            active_run: None,
            selected_run_id: None,
            recent_runs: Vec::new(),
            project_domains: BTreeMap::new(),
            run_counts: BTreeMap::new(),
            selected_run_index: 0,
            findings: None,
            selected_finding_index: 0,
            finding_scope: ResultScope::Accepted,
            finding_sort: FindingSort::Fqdn,
            finding_source_filter: None,
            finding_search: String::new(),
            evidence: None,
            selected_evidence_index: 0,
            compare_left_index: 0,
            compare_right_index: 1,
            comparison: None,
            export_format: ReportFormat::Json,
            export_destination: String::new(),
            pending_display_language: locale,
            pending_report_language: report_language,
            show_low_frequency_fallback_sources: false,
            pending_show_low_frequency_fallback_sources: false,
            notice: None,
            should_exit: false,
        }
    }

    #[must_use]
    pub fn can_start_collection(&self) -> bool {
        !self.selected_sources.is_empty()
            && self.target_preview.is_some()
            && self.target_preview.as_ref().is_none_or(|target| {
                !target.requires_root_confirmation
                    || self.confirmed_root_domain.as_deref() == Some(target.root_domain.as_str())
            })
    }

    #[must_use]
    pub fn selected_source_ids(&self) -> Vec<String> {
        self.selected_sources.iter().cloned().collect()
    }

    pub fn apply_progress(&mut self, event: CollectionProgressEvent) {
        match event {
            CollectionProgressEvent::RunCreated {
                run_id,
                target_domain,
            } => {
                self.active_run = Some(ActiveRunView {
                    run_id: Some(run_id),
                    target_domain,
                    started_at: Instant::now(),
                    status_code: "queued".to_owned(),
                    terminal: false,
                    accepted_findings: 0,
                    evidence_count: 0,
                    sources: BTreeMap::new(),
                });
                self.selected_run_id = Some(run_id);
            }
            CollectionProgressEvent::SourceQueued { source_id, .. } => {
                self.source_progress_mut(&source_id).state_code = "queued".to_owned();
            }
            CollectionProgressEvent::SourceStarted { source_id, .. } => {
                self.source_progress_mut(&source_id).state_code = "running".to_owned();
            }
            CollectionProgressEvent::RequestFinished {
                source_id,
                requests,
                pages,
                ..
            } => {
                let source = self.source_progress_mut(&source_id);
                source.requests = requests;
                source.pages = pages;
            }
            CollectionProgressEvent::SourceFinished {
                source_id,
                state,
                accepted,
                evidence,
                ..
            } => {
                let source = self.source_progress_mut(&source_id);
                source.state_code = source_state_code(&state).to_owned();
                source.accepted = accepted;
                source.evidence = evidence;
            }
            CollectionProgressEvent::Warning {
                source_id, code, ..
            } => {
                self.notice = Some(
                    message(
                        self.locale,
                        code,
                        lens_core::MessageArgs {
                            source_id,
                            ..lens_core::MessageArgs::default()
                        },
                    )
                    .into(),
                );
            }
            CollectionProgressEvent::RunFinished { status, .. } => {
                if let Some(active) = &mut self.active_run {
                    active.status_code = run_status_code(&status).to_owned();
                    active.terminal = true;
                }
            }
        }
    }

    fn source_progress_mut(&mut self, source_id: &str) -> &mut SourceProgressView {
        self.active_run
            .as_mut()
            .expect("progress event before run creation")
            .sources
            .entry(source_id.to_owned())
            .or_insert_with(|| SourceProgressView {
                state_code: "queued".to_owned(),
                ..SourceProgressView::default()
            })
    }
}

#[derive(Clone, Debug)]
pub enum Action {
    Open(Screen),
    MoveSelection(isize),
    ToggleSource(String),
    SetTarget(String),
    SetTargetPreview(TargetResolution),
    ToggleIncludeRoot,
    SetLocale(DisplayLanguage),
    OpenModal(Modal),
    CloseModal,
    Quit,
}

pub fn reduce(state: &mut AppState, action: Action) {
    match action {
        Action::Open(screen) => state.screen = screen,
        Action::MoveSelection(delta) => {
            let length = match state.screen {
                Screen::Sources | Screen::Collect => state.source_catalog.len(),
                Screen::Run => state.recent_runs.len(),
                Screen::Findings => state.findings.as_ref().map_or(0, |page| page.items.len()),
                Screen::Evidence => state.evidence.as_ref().map_or(0, |page| page.items.len()),
                _ => 0,
            };
            if length > 0 {
                let current = state.selected_source_index as isize;
                state.selected_source_index =
                    (current + delta).rem_euclid(length as isize) as usize;
            }
        }
        Action::ToggleSource(source_id) => {
            if !state.selected_sources.insert(source_id.clone()) {
                state.selected_sources.remove(&source_id);
            }
        }
        Action::SetTarget(value) => {
            state.target_draft = value;
            state.target_preview = None;
            state.confirmed_root_domain = None;
        }
        Action::SetTargetPreview(value) => {
            state.target_preview = Some(value);
            state.confirmed_root_domain = None;
        }
        Action::ToggleIncludeRoot => state.include_root = !state.include_root,
        Action::SetLocale(value) => {
            state.locale = value;
            state.pending_display_language = value;
        }
        Action::OpenModal(modal) => state.modal = Some(modal),
        Action::CloseModal => state.modal = None,
        Action::Quit => state.should_exit = true,
    }
}

struct TerminalGuard {
    stdout: Stdout,
}

impl TerminalGuard {
    fn enter(language: DisplayLanguage) -> Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(anyhow!(text(language, "terminal_not_interactive")));
        }
        let mut stdout = io::stdout();
        terminal::enable_raw_mode()
            .map_err(|error| anyhow!(error))
            .with_context(|| text(language, "terminal_not_interactive"))?;
        if let Err(error) = execute!(
            stdout,
            EnterAlternateScreen,
            cursor::Hide,
            Clear(ClearType::All)
        ) {
            let _ = terminal::disable_raw_mode();
            return Err(anyhow!(error));
        }
        Ok(Self { stdout })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            self.stdout,
            cursor::Show,
            LeaveAlternateScreen,
            Clear(ClearType::All)
        );
        let _ = terminal::disable_raw_mode();
    }
}

struct Controller<'a> {
    application: &'a mut ApplicationService,
    state: AppState,
    terminal: TerminalGuard,
    secret_input: String,
}

impl Drop for Controller<'_> {
    fn drop(&mut self) {
        self.secret_input.clear();
    }
}

fn draw_collection_state(state: &AppState, terminal: &mut TerminalGuard) -> Result<()> {
    let mut output = format!(
        "FQDN Lens TUI | {}={} | {}\n",
        text(state.locale, "display_language"),
        display_language_code(state.locale),
        text(state.locale, "run_monitor")
    );
    if let Some(active) = &state.active_run {
        output.push_str(&format!(
            "{}={} | {}={} | {}={} | {}={}s\n",
            text(state.locale, "run_id"),
            active
                .run_id
                .map_or_else(|| "<pending>".to_owned(), |id| id.to_string()),
            text(state.locale, "target"),
            active.target_domain,
            text(state.locale, "status"),
            run_status_label_code(state.locale, &active.status_code),
            text(state.locale, "elapsed"),
            active.started_at.elapsed().as_secs()
        ));
        output.push_str(&format!(
            "{}={} | {}={}\n",
            text(state.locale, "accepted_findings"),
            active.accepted_findings,
            text(state.locale, "evidence"),
            active.evidence_count
        ));
        for (source_id, source) in &active.sources {
            output.push_str(&format!(
                "  {source_id} | {}={} | {}={} | {}={} | {}={} | {}={}/{} | {}={} | {}={} | {}={} | {}={} | {}={} | {}={}\n",
                text(state.locale, "status"),
                source_state_label_code(state.locale, &source.state_code),
                text(state.locale, "metric_requests"),
                source.requests,
                text(state.locale, "metric_pages"),
                source.pages,
                text(state.locale, "metric_retries"),
                source.retries,
                text(state.locale, "metric_cache"),
                source.cache_hits,
                source.cache_misses,
                text(state.locale, "metric_quota_rejections"),
                source.quota_rejections,
                text(state.locale, "metric_received"),
                source.received,
                text(state.locale, "metric_accepted"),
                source.accepted,
                text(state.locale, "metric_filtered"),
                source.filtered,
                text(state.locale, "evidence"),
                source.evidence,
                text(state.locale, "metric_error"),
                source.error_code.as_deref().unwrap_or("-"),
            ));
        }
    } else {
        output.push_str(&format!(
            "{}=<pending>；{}\n",
            text(state.locale, "run_id"),
            text(state.locale, "pending_run_event")
        ));
    }
    output.push_str(&format!(
        "{}\n",
        text(state.locale, "network_after_confirm")
    ));
    if state.modal == Some(Modal::CancelConfirm) {
        output.push_str(&format!(
            "{}：{}\n",
            text(state.locale, "cancel_collection"),
            text(state.locale, "modal_yes_no")
        ));
    }
    output.push_str(&format!("{}\n", text(state.locale, "run_actions_active")));
    execute!(terminal.stdout, cursor::MoveTo(0, 0), Clear(ClearType::All))
        .map_err(|error| anyhow!(error))?;
    write!(terminal.stdout, "{output}").map_err(|error| anyhow!(error))?;
    terminal.stdout.flush().map_err(|error| anyhow!(error))?;
    Ok(())
}

pub async fn run(application: &mut ApplicationService, language: DisplayLanguage) -> Result<()> {
    let report_language = application.config().report_language;
    let terminal = TerminalGuard::enter(language)?;
    let mut controller = Controller {
        application,
        state: AppState::new(language, report_language),
        terminal,
        secret_input: String::new(),
    };
    controller.state.show_low_frequency_fallback_sources = controller
        .application
        .config()
        .show_low_frequency_fallback_sources;
    controller.state.pending_show_low_frequency_fallback_sources =
        controller.state.show_low_frequency_fallback_sources;
    controller.refresh_local()?;
    controller.run_loop().await
}

impl<'a> Controller<'a> {
    fn refresh_local(&mut self) -> Result<()> {
        let catalog = self.application.list_sources_for(self.state.locale);
        let ids = catalog
            .iter()
            .map(|source| source.source_id.clone())
            .collect::<Vec<_>>();
        self.state.source_doctor = self
            .application
            .source_doctor_for(&ids, self.state.locale)?;
        self.state.source_preferences = self.application.source_preferences();
        self.state.source_catalog = catalog;
        self.state.recent_runs = self.application.list_recent_runs(25)?;
        self.state.project_domains = self
            .application
            .list_projects()?
            .into_iter()
            .map(|project| (project.id, project.root_domain))
            .collect();
        self.state.run_counts.clear();
        for run in &self.state.recent_runs {
            let findings = self.application.list_findings(
                run.id,
                FindingsFilter {
                    scope: Some(ResultScope::Accepted),
                    limit: Some(500),
                    ..FindingsFilter::default()
                },
            )?;
            let evidence = self.application.list_evidence(
                run.id,
                EvidenceFilter {
                    limit: Some(500),
                    ..EvidenceFilter::default()
                },
            )?;
            self.state
                .run_counts
                .insert(run.id, (findings.items.len(), evidence.items.len()));
        }
        if self.state.selected_run_index >= self.state.recent_runs.len() {
            self.state.selected_run_index = self.state.recent_runs.len().saturating_sub(1);
        }
        Ok(())
    }

    async fn run_loop(&mut self) -> Result<()> {
        self.draw()?;
        while !self.state.should_exit {
            if event::poll(Duration::from_millis(50)).map_err(|error| anyhow!(error))?
                && let Event::Key(key) = event::read().map_err(|error| anyhow!(error))?
                && let Some(options) = self.handle_key(key)?
            {
                self.run_collection(options).await?;
            }
            self.draw()?;
        }
        Ok(())
    }

    async fn run_collection(&mut self, options: CollectOptions) -> Result<()> {
        self.state.screen = Screen::Run;
        self.state.modal = None;
        self.state.notice = None;
        let result = {
            let application = &*self.application;
            let state = &mut self.state;
            let terminal = &mut self.terminal;
            let (sender, mut receiver) = mpsc::channel(64);
            let sink: lens_core::ProgressSink = Arc::new(move |event| {
                let _ = sender.try_send(event);
            });
            let collection =
                AssertUnwindSafe(application.collect_with_progress(options, Some(sink)))
                    .catch_unwind();
            tokio::pin!(collection);
            let mut quit_after_cancel = false;
            let mut channel_closed = false;
            let result = loop {
                tokio::select! {
                    event = receiver.recv(), if !channel_closed => {
                        match event {
                            Some(event) => state.apply_progress(event),
                            None => {
                                channel_closed = true;
                                let mut notice: Notice = message(
                                    state.locale,
                                    lens_core::MessageCode::InternalUnclassified,
                                    lens_core::MessageArgs::default(),
                                )
                                .into();
                                notice.hint =
                                    Some("progress channel closed; final Store state will be used".into());
                                state.notice = Some(notice);
                            }
                        }
                    }
                    result = &mut collection => {
                        break match result {
                            Ok(result) => result,
                            Err(_) => Err(ApplicationError::Store(
                                lens_core::StoreError::InvalidData,
                            )),
                        };
                    },
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        while event::poll(Duration::from_millis(0)).map_err(|error| anyhow!(error))? {
                            if let Event::Key(key) = event::read().map_err(|error| anyhow!(error))? {
                                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                                    if let Some(run_id) = state.active_run.as_ref().and_then(|run| run.run_id) {
                                        let _ = application.cancel_run(run_id);
                                        quit_after_cancel = true;
                                    }
                                } else if key.code == KeyCode::Char('c') || key.code == KeyCode::Char('q') {
                                    state.modal = Some(Modal::CancelConfirm);
                                } else if key.code == KeyCode::Enter && state.modal == Some(Modal::CancelConfirm) {
                                    if let Some(run_id) = state.active_run.as_ref().and_then(|run| run.run_id) {
                                        let _ = application.cancel_run(run_id);
                                        state.modal = None;
                                    }
                                } else if key.code == KeyCode::Esc {
                                    state.modal = None;
                                } else if key.code == KeyCode::Char('?') {
                                    state.return_screen = Some(Screen::Run);
                                    state.screen = Screen::Help;
                                }
                            }
                        }
                    }
                }
                draw_collection_state(state, terminal)?;
            };
            if quit_after_cancel {
                state.should_exit = true;
            }
            result
        };
        self.finish_collection(result);
        self.refresh_local()?;
        Ok(())
    }

    fn finish_collection(&mut self, result: Result<CollectionReport, ApplicationError>) {
        match result {
            Ok(report) => {
                self.state.selected_run_id = Some(report.run_id);
                for status in report.statuses.values() {
                    let source = self
                        .state
                        .active_run
                        .as_mut()
                        .expect("active run exists")
                        .sources
                        .entry(status.source_id.clone())
                        .or_default();
                    source.state_code = source_state_code(&status.state).to_owned();
                    source.requests = status.requests;
                    source.pages = status.pages;
                    source.retries = status.retries;
                    source.cache_hits = status.cache_hits;
                    source.cache_misses = status.cache_misses;
                    source.quota_rejections = status.quota_rejections;
                    source.received = status.results_received;
                    source.accepted = status.results_accepted;
                    source.filtered = status.results_filtered;
                    source.error_code = status.error_code.clone();
                }
                if let Some(active) = &mut self.state.active_run {
                    active.accepted_findings = report.accepted_findings;
                    active.evidence_count = report.evidence_count;
                }
                self.state.notice = Some(Notice {
                    code: run_status_code(&report.status).to_owned(),
                    message: run_status_label(self.state.locale, &report.status),
                    hint: Some(format!("run_id={}", report.run_id)),
                });
            }
            Err(error) => {
                self.state.notice = Some(self.error_notice(&error));
            }
        }
        if let Some(active) = &mut self.state.active_run {
            active.terminal = true;
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<Option<CollectOptions>> {
        if self.state.modal.is_some() {
            return self.handle_modal_key(key);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.request_quit();
            return Ok(None);
        }
        match key.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('?') => {
                self.state.return_screen = Some(self.state.screen);
                self.state.screen = Screen::Help;
            }
            KeyCode::Esc => self.go_back(),
            KeyCode::Tab => self.advance_focus(if key.modifiers.contains(KeyModifiers::SHIFT) {
                -1
            } else {
                1
            }),
            KeyCode::BackTab => self.advance_focus(-1),
            KeyCode::Up | KeyCode::Left => self.move_selection(-1),
            KeyCode::Down | KeyCode::Right => self.move_selection(1),
            KeyCode::Char('c') if self.state.screen == Screen::Dashboard => self.open_collect(),
            KeyCode::Char('s') if self.state.screen == Screen::Dashboard => {
                self.state.screen = Screen::Sources
            }
            KeyCode::Char('r') if matches!(self.state.screen, Screen::Dashboard | Screen::Run) => {
                self.refresh_local()?
            }
            KeyCode::Char('e')
                if matches!(
                    self.state.screen,
                    Screen::Run | Screen::Findings | Screen::Evidence
                ) =>
            {
                self.open_export()
            }
            KeyCode::Char('l') if self.state.screen == Screen::Settings => {
                self.cycle_display_language()
            }
            KeyCode::Char(' ') => self.space_action()?,
            KeyCode::Enter => return self.enter_action(),
            KeyCode::Backspace => self.backspace_action(),
            KeyCode::Char(value) => self.char_action(value)?,
            _ => {}
        }
        Ok(None)
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> Result<Option<CollectOptions>> {
        let Some(modal) = self.state.modal else {
            return Ok(None);
        };
        if key.code == KeyCode::Esc || key.code == KeyCode::Char('n') {
            self.state.modal = None;
            self.secret_input.clear();
            self.state.edit_buffer.clear();
            return Ok(None);
        }
        if modal == Modal::ConfigureCredential {
            match key.code {
                KeyCode::Backspace => {
                    self.secret_input.pop();
                }
                KeyCode::Enter => {
                    let source_id = self.current_source_id().unwrap_or_default();
                    if self.secret_input.is_empty()
                        || self.secret_input.chars().any(char::is_control)
                    {
                        self.state.notice = Some(Notice {
                            code: "credential_invalid".into(),
                            message: text(self.state.locale, "not_configured"),
                            hint: None,
                        });
                    } else {
                        let mut secret = std::mem::take(&mut self.secret_input);
                        let result = self.application.configure_credential(&source_id, &secret);
                        secret.clear();
                        self.state.notice = Some(match result {
                            Ok(()) => Notice {
                                code: "configured".into(),
                                message: text(self.state.locale, "configured"),
                                hint: None,
                            },
                            Err(error) => self.error_notice(&error),
                        });
                        self.state.modal = None;
                        self.refresh_local()?;
                    }
                }
                KeyCode::Char(value) => self.secret_input.push(value),
                _ => {}
            }
            return Ok(None);
        }
        if modal == Modal::RootConfirm {
            match key.code {
                KeyCode::Backspace => {
                    self.state.edit_buffer.pop();
                    return Ok(None);
                }
                KeyCode::Char(value) => {
                    self.state.edit_buffer.push(value);
                    return Ok(None);
                }
                _ => {}
            }
        }
        if key.code != KeyCode::Enter {
            return Ok(None);
        }
        match modal {
            Modal::QuitConfirm => {
                self.state.should_exit = true;
                self.state.modal = None;
            }
            Modal::StartConfirm => {
                self.state.modal = None;
                return Ok(self.build_collect_options());
            }
            Modal::RootConfirm => {
                if let Some(target) = &self.state.target_preview {
                    if lens_core::normalize_root_domain(&self.state.edit_buffer)
                        .ok()
                        .as_deref()
                        == Some(target.root_domain.as_str())
                    {
                        self.state.confirmed_root_domain = Some(target.root_domain.clone());
                        self.state.modal = None;
                        self.state.edit_mode = EditMode::None;
                        self.state.edit_buffer.clear();
                    } else {
                        self.state.notice = Some(Notice {
                            code: "target_root_confirmation_required".into(),
                            message: text(self.state.locale, "scope_confirmation"),
                            hint: Some(target.root_domain.clone()),
                        });
                    }
                }
            }
            Modal::CancelConfirm => {
                if let Some(run_id) = self.state.active_run.as_ref().and_then(|run| run.run_id) {
                    let _ = self.application.cancel_run(run_id);
                }
                self.state.modal = None;
            }
            Modal::ImportEnvironment => {
                if let Some(source_id) = self.current_source_id() {
                    let result = self
                        .application
                        .import_environment_credential(&source_id, true);
                    self.state.notice = Some(self.result_notice(result.map(|_| ()), "configured"));
                    self.refresh_local()?;
                }
                self.state.modal = None;
            }
            Modal::RemoveCredential => {
                if let Some(source_id) = self.current_source_id() {
                    let result = self.application.remove_credential(&source_id);
                    self.state.notice = Some(match result {
                        Ok(true) => Notice {
                            code: "credential_removed".into(),
                            message: text(self.state.locale, "configured"),
                            hint: None,
                        },
                        Ok(false) => Notice {
                            code: "credential_not_found".into(),
                            message: text(self.state.locale, "not_configured"),
                            hint: None,
                        },
                        Err(error) => self.error_notice(&error),
                    });
                    self.refresh_local()?;
                }
                self.state.modal = None;
            }
            Modal::SaveSettings => {
                let display = self.state.pending_display_language;
                let report = self.state.pending_report_language;
                let show_fallback = self.state.pending_show_low_frequency_fallback_sources;
                let first = self.application.set_display_language(display);
                let result = first.and(self.application.set_report_language(report)).and(
                    self.application
                        .set_show_low_frequency_fallback_sources(show_fallback),
                );
                let saved = result.is_ok();
                self.state.notice = Some(self.result_notice(result, "save"));
                if saved {
                    self.state.locale = display;
                    self.state.report_language = report;
                    self.state.show_low_frequency_fallback_sources = show_fallback;
                    self.refresh_local()?;
                }
                self.state.modal = None;
            }
            Modal::ExportConfirm => {
                self.export_current()?;
                self.state.modal = None;
            }
            Modal::ConfigureCredential => unreachable!(),
        }
        Ok(None)
    }

    fn result_notice<T>(&self, result: Result<T, ApplicationError>, success_key: &str) -> Notice {
        match result {
            Ok(_) => Notice {
                code: success_key.to_owned(),
                message: text(self.state.locale, success_key),
                hint: None,
            },
            Err(error) => self.error_notice(&error),
        }
    }

    fn error_notice(&self, error: &ApplicationError) -> Notice {
        let (code, args) = match error {
            ApplicationError::InvalidTarget => (
                lens_core::MessageCode::TargetInvalid,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::UrlUserinfoDenied => (
                lens_core::MessageCode::UrlUserinfoDenied,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::PublicSuffixOnly => (
                lens_core::MessageCode::TargetInvalid,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::RootConfirmationRequired { root_domain }
            | ApplicationError::RootConfirmationMismatch { root_domain } => (
                lens_core::MessageCode::TargetRootConfirmationRequired,
                lens_core::MessageArgs {
                    root_domain: Some(root_domain.clone()),
                    ..lens_core::MessageArgs::default()
                },
            ),
            ApplicationError::NoSelectedSources => (
                lens_core::MessageCode::SourceSelectionRequired,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::UnknownSource(source_id) => (
                lens_core::MessageCode::SourceUnknown,
                lens_core::MessageArgs {
                    source_id: Some(source_id.clone()),
                    ..lens_core::MessageArgs::default()
                },
            ),
            ApplicationError::CredentialNotRequired(source_id) => (
                lens_core::MessageCode::CredentialNotRequired,
                lens_core::MessageArgs {
                    source_id: Some(source_id.clone()),
                    ..lens_core::MessageArgs::default()
                },
            ),
            ApplicationError::RunNotCancellable(run_id) => (
                lens_core::MessageCode::RunNotCancellable,
                lens_core::MessageArgs {
                    run_id: Some(run_id.to_string()),
                    ..lens_core::MessageArgs::default()
                },
            ),
            ApplicationError::ExportDestinationDenied => (
                lens_core::MessageCode::ExportDestinationDenied,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::Credential(_) => (
                lens_core::MessageCode::CredentialMissing,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::Config(_) => (
                lens_core::MessageCode::ConfigurationInvalid,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::Factory(_) => (
                lens_core::MessageCode::UpstreamFailed,
                lens_core::MessageArgs::default(),
            ),
            ApplicationError::Store(_)
            | ApplicationError::ExportIo(_)
            | ApplicationError::ExportJson(_)
            | ApplicationError::ExportCsv(_) => (
                lens_core::MessageCode::InternalUnclassified,
                lens_core::MessageArgs::default(),
            ),
        };
        message(self.state.locale, code, args).into()
    }

    fn request_quit(&mut self) {
        let active = self
            .state
            .active_run
            .as_ref()
            .is_some_and(|run| !run.terminal);
        let unsaved_settings = self.state.screen == Screen::Settings
            && (self.state.pending_display_language != self.application.config().display_language
                || self.state.pending_report_language != self.application.config().report_language
                || self.state.pending_show_low_frequency_fallback_sources
                    != self
                        .application
                        .config()
                        .show_low_frequency_fallback_sources);
        if active {
            self.state.modal = Some(Modal::CancelConfirm);
        } else if unsaved_settings {
            self.state.modal = Some(Modal::SaveSettings);
        } else {
            self.state.modal = Some(Modal::QuitConfirm);
        }
    }

    fn go_back(&mut self) {
        if self.state.screen == Screen::Settings {
            let config = self.application.config();
            self.state.locale = config.display_language;
            self.state.report_language = config.report_language;
            self.state.pending_display_language = config.display_language;
            self.state.pending_report_language = config.report_language;
            self.state.show_low_frequency_fallback_sources =
                config.show_low_frequency_fallback_sources;
            self.state.pending_show_low_frequency_fallback_sources =
                config.show_low_frequency_fallback_sources;
        }
        if let Some(return_screen) = self.state.return_screen.take() {
            self.state.screen = return_screen;
        } else if self.state.screen != Screen::Dashboard {
            self.state.screen = Screen::Dashboard;
        }
        self.state.edit_mode = EditMode::None;
        self.state.edit_buffer.clear();
    }

    fn advance_focus(&mut self, delta: isize) {
        if self.state.screen == Screen::Collect {
            let total = self.state.source_catalog.len() + 3;
            self.state.collect_focus =
                (self.state.collect_focus as isize + delta).rem_euclid(total as isize) as usize;
        } else if self.state.screen == Screen::Sources && !self.state.source_catalog.is_empty() {
            self.state.selected_source_index = (self.state.selected_source_index as isize + delta)
                .rem_euclid(self.state.source_catalog.len() as isize)
                as usize;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.state.screen {
            Screen::Sources => {
                self.advance_focus(delta);
            }
            Screen::Collect => self.advance_focus(delta),
            Screen::Run => {
                if !self.state.recent_runs.is_empty() {
                    self.state.selected_run_index = (self.state.selected_run_index as isize + delta)
                        .rem_euclid(self.state.recent_runs.len() as isize)
                        as usize;
                }
            }
            Screen::Findings => {
                if let Some(page) = &self.state.findings
                    && !page.items.is_empty()
                {
                    self.state.selected_finding_index =
                        (self.state.selected_finding_index as isize + delta)
                            .rem_euclid(page.items.len() as isize) as usize;
                }
            }
            Screen::Evidence => {
                if let Some(page) = &self.state.evidence
                    && !page.items.is_empty()
                {
                    self.state.selected_evidence_index =
                        (self.state.selected_evidence_index as isize + delta)
                            .rem_euclid(page.items.len() as isize) as usize;
                }
            }
            _ => {}
        }
    }

    fn open_collect(&mut self) {
        self.state.screen = Screen::Collect;
        self.state.target_draft.clear();
        self.state.target_preview = None;
        self.state.confirmed_root_domain = None;
        self.state.edit_buffer.clear();
        self.state.edit_mode = EditMode::Target;
        self.state.collect_focus = 0;
        self.state.selected_sources = self
            .state
            .source_preferences
            .iter()
            .filter(|source| source.effective_enabled)
            .map(|source| source.source_id.clone())
            .collect();
    }

    fn open_export(&mut self) {
        if self.state.selected_run_id.is_none() {
            self.state.notice = Some(Notice {
                code: "run_required".into(),
                message: text(self.state.locale, "no_runs"),
                hint: None,
            });
            return;
        }
        let run_id = self.state.selected_run_id.expect("checked above");
        let destination = self
            .application
            .config()
            .export_directory(self.application.paths())
            .join(format!("{run_id}.json"));
        self.state.export_destination = destination.display().to_string();
        self.state.screen = Screen::Export;
        self.state.edit_mode = EditMode::None;
    }

    fn current_source_id(&self) -> Option<String> {
        self.state
            .source_catalog
            .get(self.state.selected_source_index)
            .map(|source| source.source_id.clone())
    }

    fn space_action(&mut self) -> Result<()> {
        match self.state.screen {
            Screen::Collect => {
                let source_start = 1;
                let source_end = source_start + self.state.source_catalog.len();
                if (source_start..source_end).contains(&self.state.collect_focus) {
                    let id = self.state.source_catalog[self.state.collect_focus - source_start]
                        .source_id
                        .clone();
                    reduce(&mut self.state, Action::ToggleSource(id));
                } else if self.state.collect_focus == source_end {
                    reduce(&mut self.state, Action::ToggleIncludeRoot);
                }
            }
            Screen::Sources => {
                if let Some(source_id) = self.current_source_id() {
                    let enabled = self
                        .state
                        .source_preferences
                        .iter()
                        .find(|item| item.source_id == source_id)
                        .is_none_or(|item| !item.effective_enabled);
                    self.application.set_source_enabled(&source_id, enabled)?;
                    self.refresh_local()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn enter_action(&mut self) -> Result<Option<CollectOptions>> {
        match self.state.screen {
            Screen::Dashboard => {
                self.state.screen = Screen::Run;
                Ok(None)
            }
            Screen::Collect => {
                let source_start = 1;
                let source_end = source_start + self.state.source_catalog.len();
                if self.state.collect_focus == 0 {
                    self.resolve_target_input()?;
                } else if self.state.collect_focus == source_end + 1 {
                    if self.state.selected_sources.is_empty() {
                        self.state.notice = Some(Notice {
                            code: "source_selection_required".into(),
                            message: text(self.state.locale, "no_source_selected"),
                            hint: None,
                        });
                    } else if self.state.target_preview.is_none() {
                        self.state.notice = Some(Notice {
                            code: "target_invalid".into(),
                            message: text(self.state.locale, "target_preview"),
                            hint: None,
                        });
                    } else if self.state.can_start_collection() {
                        self.state.modal = Some(Modal::StartConfirm);
                    } else if let Some(target) = &self.state.target_preview {
                        self.state.modal = Some(Modal::RootConfirm);
                        self.state.edit_mode = EditMode::RootConfirmation;
                        self.state.edit_buffer.clear();
                        self.state.notice = Some(Notice {
                            code: "target_root_confirmation_required".into(),
                            message: text(self.state.locale, "scope_confirmation"),
                            hint: Some(target.root_domain.clone()),
                        });
                    }
                } else if self.state.collect_focus == source_end {
                    reduce(&mut self.state, Action::ToggleIncludeRoot);
                }
                Ok(None)
            }
            Screen::Sources => {
                if let Some(source_id) = self.current_source_id() {
                    self.state.modal = Some(Modal::ConfigureCredential);
                    self.secret_input.clear();
                    self.state.notice = Some(Notice {
                        code: "credential_prompt".into(),
                        message: format!(
                            "{}: {source_id}",
                            text(self.state.locale, "hidden_input")
                        ),
                        hint: Some(text(self.state.locale, "security_notice")),
                    });
                }
                Ok(None)
            }
            Screen::Run => {
                if let Some(run) = self.state.recent_runs.get(self.state.selected_run_index) {
                    self.state.selected_run_id = Some(run.id);
                    self.load_findings()?;
                } else if self.state.active_run.is_some() {
                    self.load_findings()?;
                }
                Ok(None)
            }
            Screen::Findings => {
                if let Some(page) = &self.state.findings
                    && let Some(record) = page.items.get(self.state.selected_finding_index)
                {
                    self.state.evidence = Some(self.application.list_evidence(
                        self.state.selected_run_id.expect("finding has run"),
                        EvidenceFilter {
                            fqdn: Some(record.fqdn.clone()),
                            limit: Some(50),
                            ..EvidenceFilter::default()
                        },
                    )?);
                    self.state.selected_evidence_index = 0;
                    self.state.screen = Screen::Evidence;
                }
                Ok(None)
            }
            Screen::Evidence => Ok(None),
            Screen::Compare => {
                self.compare_runs()?;
                Ok(None)
            }
            Screen::Export => {
                if self.state.edit_mode == EditMode::ExportDestination {
                    self.state.edit_mode = EditMode::None;
                    return Ok(None);
                }
                self.state.modal = Some(Modal::ExportConfirm);
                Ok(None)
            }
            Screen::Settings => {
                self.state.modal = Some(Modal::SaveSettings);
                Ok(None)
            }
            Screen::Help => {
                self.go_back();
                Ok(None)
            }
        }
    }

    fn resolve_target_input(&mut self) -> Result<()> {
        let target = self.state.edit_buffer.trim().to_owned();
        if target.is_empty() {
            self.state.notice = Some(Notice {
                code: "target_invalid".into(),
                message: text(self.state.locale, "target_preview"),
                hint: None,
            });
            return Ok(());
        }
        match self.application.resolve_target(&target) {
            Ok(preview) => {
                self.state.target_draft = preview.input_hostname.clone();
                self.state.target_preview = Some(preview.clone());
                self.state.confirmed_root_domain =
                    (!preview.requires_root_confirmation).then_some(preview.root_domain.clone());
                self.state.edit_mode = EditMode::None;
                self.state.notice = None;
                if preview.requires_root_confirmation {
                    self.state.modal = Some(Modal::RootConfirm);
                    self.state.edit_mode = EditMode::RootConfirmation;
                    self.state.edit_buffer.clear();
                }
            }
            Err(error) => {
                self.state.notice = Some(self.error_notice(&error));
            }
        }
        Ok(())
    }

    fn build_collect_options(&mut self) -> Option<CollectOptions> {
        let target = self.state.target_draft.trim().to_owned();
        if target.is_empty() || self.state.selected_sources.is_empty() {
            return None;
        }
        Some(CollectOptions {
            target,
            selected_sources: self.state.selected_source_ids(),
            include_root: self.state.include_root,
            confirmed_root_domain: self.state.confirmed_root_domain.clone(),
        })
    }

    fn char_action(&mut self, value: char) -> Result<()> {
        match self.state.screen {
            Screen::Collect if self.state.edit_mode == EditMode::Target => {
                self.state.edit_buffer.push(value)
            }
            Screen::Collect if self.state.edit_mode == EditMode::RootConfirmation => {
                self.state.edit_buffer.push(value)
            }
            Screen::Collect if value == 'l' => {
                self.state.report_language = match self.state.report_language {
                    ReportLanguage::ZhCn => ReportLanguage::EnUs,
                    ReportLanguage::EnUs => ReportLanguage::Bilingual,
                    ReportLanguage::Bilingual => ReportLanguage::ZhCn,
                };
            }
            Screen::Findings if self.state.edit_mode == EditMode::FindingSearch => {
                self.state.finding_search.push(value)
            }
            Screen::Export if self.state.edit_mode == EditMode::ExportDestination => {
                self.state.export_destination.push(value)
            }
            Screen::Sources if value == 'k' => {
                self.state.modal = Some(Modal::ConfigureCredential);
                self.secret_input.clear();
            }
            Screen::Sources if value == 'i' => self.state.modal = Some(Modal::ImportEnvironment),
            Screen::Sources if value == 'x' => self.state.modal = Some(Modal::RemoveCredential),
            Screen::Run if value == 'f' => self.load_findings()?,
            Screen::Run if value == 'v' => self.load_evidence_for_selected_run()?,
            Screen::Run if value == 'd' => self.open_compare(),
            Screen::Findings if value == '/' => {
                self.state.edit_mode = EditMode::FindingSearch;
                self.state.finding_search.clear();
            }
            Screen::Findings if value == 'p' => {
                let ids = self
                    .state
                    .source_catalog
                    .iter()
                    .map(|source| source.source_id.clone())
                    .collect::<Vec<_>>();
                self.state.finding_source_filter = match self.state.finding_source_filter.take() {
                    None => ids.first().cloned(),
                    Some(current) => ids
                        .iter()
                        .position(|id| id == &current)
                        .and_then(|index| ids.get(index + 1).cloned()),
                };
                self.load_findings()?;
            }
            Screen::Findings if value == 'n' => self.load_next_findings()?,
            Screen::Findings if value == 'a' => {
                self.state.finding_scope = match self.state.finding_scope {
                    ResultScope::Accepted => ResultScope::Filtered,
                    ResultScope::Filtered => ResultScope::All,
                    ResultScope::All => ResultScope::Accepted,
                };
                self.load_findings()?;
            }
            Screen::Findings if value == 's' => {
                self.state.finding_sort = match self.state.finding_sort {
                    FindingSort::Fqdn => FindingSort::EvidenceCount,
                    FindingSort::EvidenceCount => FindingSort::SourceCount,
                    FindingSort::SourceCount => FindingSort::FirstSeen,
                    FindingSort::FirstSeen => FindingSort::LastSeen,
                    FindingSort::LastSeen => FindingSort::Fqdn,
                };
                self.sort_findings();
            }
            Screen::Findings if value == 'e' => self.open_export(),
            Screen::Evidence if value == 'f' => self.state.screen = Screen::Findings,
            Screen::Evidence if value == 'e' => self.open_export(),
            Screen::Evidence if value == 'n' => self.load_next_evidence()?,
            Screen::Compare if value == '[' => {
                if self.state.recent_runs.len() > 1 {
                    self.state.compare_left_index =
                        (self.state.compare_left_index + self.state.recent_runs.len() - 1)
                            % self.state.recent_runs.len();
                }
            }
            Screen::Compare if value == ']' => {
                if self.state.recent_runs.len() > 1 {
                    self.state.compare_right_index =
                        (self.state.compare_right_index + 1) % self.state.recent_runs.len();
                }
            }
            Screen::Export if value == 'f' => {
                self.state.export_format = match self.state.export_format {
                    ReportFormat::Json => ReportFormat::Markdown,
                    ReportFormat::Markdown => ReportFormat::Csv,
                    ReportFormat::Csv => ReportFormat::Json,
                }
            }
            Screen::Export if value == 'l' => {
                self.state.report_language = match self.state.report_language {
                    ReportLanguage::ZhCn => ReportLanguage::EnUs,
                    ReportLanguage::EnUs => ReportLanguage::Bilingual,
                    ReportLanguage::Bilingual => ReportLanguage::ZhCn,
                }
            }
            Screen::Export if value == 'd' => {
                self.state.edit_mode = EditMode::ExportDestination;
                self.state.edit_buffer.clear();
            }
            Screen::Settings if value == 'r' => {
                self.state.pending_report_language = match self.state.pending_report_language {
                    ReportLanguage::ZhCn => ReportLanguage::EnUs,
                    ReportLanguage::EnUs => ReportLanguage::Bilingual,
                    ReportLanguage::Bilingual => ReportLanguage::ZhCn,
                }
            }
            Screen::Settings if value == 'f' => {
                self.state.pending_show_low_frequency_fallback_sources =
                    !self.state.pending_show_low_frequency_fallback_sources;
            }
            Screen::Settings if value == 'l' => self.cycle_display_language(),
            _ => {}
        }
        Ok(())
    }

    fn backspace_action(&mut self) {
        match self.state.edit_mode {
            EditMode::Target | EditMode::RootConfirmation => {
                self.state.edit_buffer.pop();
            }
            EditMode::FindingSearch => {
                self.state.finding_search.pop();
            }
            EditMode::ExportDestination => {
                self.state.export_destination.pop();
            }
            EditMode::None => {}
        }
    }

    fn cycle_display_language(&mut self) {
        self.state.pending_display_language = match self.state.pending_display_language {
            DisplayLanguage::ZhCn => DisplayLanguage::EnUs,
            DisplayLanguage::EnUs => DisplayLanguage::ZhCn,
        };
        self.state.locale = self.state.pending_display_language;
    }

    fn load_findings(&mut self) -> Result<()> {
        let Some(run_id) = self.state.selected_run_id else {
            return Ok(());
        };
        self.state.findings = Some(
            self.application.list_findings(
                run_id,
                FindingsFilter {
                    source_id: self.state.finding_source_filter.clone(),
                    fqdn_contains: (!self.state.finding_search.is_empty())
                        .then_some(self.state.finding_search.clone()),
                    scope: Some(self.state.finding_scope),
                    limit: Some(50),
                    ..FindingsFilter::default()
                },
            )?,
        );
        self.state.selected_finding_index = 0;
        self.sort_findings();
        self.state.screen = Screen::Findings;
        Ok(())
    }

    fn load_next_findings(&mut self) -> Result<()> {
        let Some(run_id) = self.state.selected_run_id else {
            return Ok(());
        };
        let Some(cursor) = self
            .state
            .findings
            .as_ref()
            .and_then(|page| page.next_cursor.clone())
        else {
            return Ok(());
        };
        self.state.findings = Some(
            self.application.list_findings(
                run_id,
                FindingsFilter {
                    source_id: self.state.finding_source_filter.clone(),
                    fqdn_contains: (!self.state.finding_search.is_empty())
                        .then_some(self.state.finding_search.clone()),
                    scope: Some(self.state.finding_scope),
                    cursor: Some(cursor),
                    limit: Some(50),
                },
            )?,
        );
        self.state.selected_finding_index = 0;
        self.sort_findings();
        Ok(())
    }

    fn sort_findings(&mut self) {
        if let Some(page) = &mut self.state.findings {
            match self.state.finding_sort {
                FindingSort::Fqdn => page.items.sort_by(|a, b| a.fqdn.cmp(&b.fqdn)),
                FindingSort::EvidenceCount => page.items.sort_by_key(|item| item.evidence_count),
                FindingSort::SourceCount => page.items.sort_by_key(|item| item.source_count),
                FindingSort::FirstSeen => page.items.sort_by_key(|item| item.first_seen_at),
                FindingSort::LastSeen => page.items.sort_by_key(|item| item.last_seen_at),
            }
        }
    }

    fn load_evidence_for_selected_run(&mut self) -> Result<()> {
        let Some(run_id) = self.state.selected_run_id else {
            return Ok(());
        };
        self.state.evidence = Some(self.application.list_evidence(
            run_id,
            EvidenceFilter {
                limit: Some(50),
                ..EvidenceFilter::default()
            },
        )?);
        self.state.selected_evidence_index = 0;
        self.state.screen = Screen::Evidence;
        Ok(())
    }

    fn load_next_evidence(&mut self) -> Result<()> {
        let Some(run_id) = self.state.selected_run_id else {
            return Ok(());
        };
        let Some(cursor) = self
            .state
            .evidence
            .as_ref()
            .and_then(|page| page.next_cursor.clone())
        else {
            return Ok(());
        };
        self.state.evidence = Some(self.application.list_evidence(
            run_id,
            EvidenceFilter {
                cursor: Some(cursor),
                limit: Some(50),
                ..EvidenceFilter::default()
            },
        )?);
        self.state.selected_evidence_index = 0;
        Ok(())
    }

    fn open_compare(&mut self) {
        self.state.screen = Screen::Compare;
        if self.state.recent_runs.len() > 1
            && self.state.compare_left_index == self.state.compare_right_index
        {
            self.state.compare_right_index =
                (self.state.compare_left_index + 1) % self.state.recent_runs.len();
        }
    }

    fn compare_runs(&mut self) -> Result<()> {
        if self.state.recent_runs.len() < 2 {
            self.state.notice = Some(Notice {
                code: "compare_requires_two_runs".into(),
                message: text(self.state.locale, "no_runs"),
                hint: None,
            });
            return Ok(());
        }
        let left = self.state.recent_runs[self.state.compare_left_index].id;
        let right = self.state.recent_runs[self.state.compare_right_index].id;
        self.state.comparison = match self.application.compare_runs(left, right) {
            Ok(value) => Some(value),
            Err(error) => {
                self.state.notice = Some(self.error_notice(&error));
                None
            }
        };
        Ok(())
    }

    fn export_current(&mut self) -> Result<()> {
        let Some(run_id) = self.state.selected_run_id else {
            return Ok(());
        };
        let metadata = match self.application.export_report(
            run_id,
            self.state.export_format,
            &self.state.export_destination,
            Some(self.state.report_language),
            true,
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.state.notice = Some(self.error_notice(&error));
                return Ok(());
            }
        };
        self.state.notice = Some(Notice {
            code: "exported".into(),
            message: text(self.state.locale, "exported"),
            hint: Some(format!(
                "{} schema={} run={}",
                safe_path(&metadata.destination),
                metadata.schema_version,
                metadata.run_id
            )),
        });
        Ok(())
    }

    fn draw(&mut self) -> Result<()> {
        let mut output = String::new();
        let (width, height) = terminal::size().unwrap_or((80, 24));
        output.push_str(&format!(
            "FQDN Lens TUI | {}={} | terminal={}x{}\n",
            text(self.state.locale, "display_language"),
            display_language_code(self.state.locale),
            width,
            height
        ));
        if width < 60 || height < 12 {
            output.push_str(&format!(
                "{}\n",
                text(self.state.locale, "minimum_terminal_warning")
            ));
        }
        output.push_str(&format!(
            "{}\n",
            text(
                self.state.locale,
                match self.state.screen {
                    Screen::Dashboard => "dashboard",
                    Screen::Collect => "quick_collect",
                    Screen::Sources => "sources_credentials",
                    Screen::Run => "run_monitor",
                    Screen::Findings => "findings",
                    Screen::Evidence => "evidence",
                    Screen::Compare => "compare",
                    Screen::Export => "export",
                    Screen::Settings => "settings",
                    Screen::Help => "help",
                }
            )
        ));
        match self.state.screen {
            Screen::Dashboard => self.render_dashboard(&mut output),
            Screen::Collect => self.render_collect(&mut output),
            Screen::Sources => self.render_sources(&mut output),
            Screen::Run => self.render_run(&mut output),
            Screen::Findings => self.render_findings(&mut output),
            Screen::Evidence => self.render_evidence(&mut output),
            Screen::Compare => self.render_compare(&mut output),
            Screen::Export => self.render_export(&mut output),
            Screen::Settings => self.render_settings(&mut output),
            Screen::Help => self.render_help(&mut output),
        };
        if let Some(notice) = &self.state.notice {
            output.push_str(&format!("\n[{}] {}\n", notice.code, notice.message));
            if let Some(hint) = &notice.hint {
                output.push_str(&format!("{}: {hint}\n", text(self.state.locale, "hint")));
            }
        }
        if let Some(modal) = self.state.modal {
            self.render_modal(&mut output, modal);
        }
        output.push_str(&format!("\n{}\n", text(self.state.locale, "global_hint")));
        execute!(
            self.terminal.stdout,
            cursor::MoveTo(0, 0),
            Clear(ClearType::All)
        )
        .map_err(|error| anyhow!(error))?;
        write!(self.terminal.stdout, "{output}").map_err(|error| anyhow!(error))?;
        self.terminal
            .stdout
            .flush()
            .map_err(|error| anyhow!(error))?;
        Ok(())
    }

    fn render_dashboard(&self, output: &mut String) {
        output.push_str(&format!(
            "{}: {}\n",
            text(self.state.locale, "source_count"),
            self.state.source_catalog.len()
        ));
        for source in &self.state.source_catalog {
            let enabled = self
                .state
                .source_preferences
                .iter()
                .find(|item| item.source_id == source.source_id)
                .is_some_and(|item| item.effective_enabled);
            let health = self
                .state
                .source_doctor
                .iter()
                .find(|report| report.source.source_id == source.source_id)
                .and_then(|report| report.latest_health.as_ref())
                .map(|health| source_health_label(self.state.locale, &health.health))
                .unwrap_or_else(|| source_state_label_code(self.state.locale, "empty"));
            output.push_str(&format!(
                "  {} | {} | {}={} | {}={} | {}={} | {}={}\n",
                source.source_id,
                source.display_name,
                text(self.state.locale, "credential_state"),
                credential_state_label(self.state.locale, source.credential_state),
                text(self.state.locale, "enabled"),
                boolean_label(self.state.locale, enabled),
                text(self.state.locale, "health"),
                health,
                text(self.state.locale, "endpoint"),
                source.endpoint
            ));
        }
        output.push_str(&format!("\n{}:\n", text(self.state.locale, "recent_runs")));
        if self.state.recent_runs.is_empty() {
            output.push_str(&format!("  {}\n", text(self.state.locale, "no_runs")));
        } else {
            for run in self.state.recent_runs.iter().take(8) {
                let target = self
                    .state
                    .project_domains
                    .get(&run.project_id)
                    .map(String::as_str)
                    .unwrap_or("-");
                let (findings, evidence) = self
                    .state
                    .run_counts
                    .get(&run.id)
                    .copied()
                    .unwrap_or_default();
                output.push_str(&format!(
                    "  {} | {}={} | {}={} | {}={} | {}={} | {}={}\n",
                    run.id,
                    text(self.state.locale, "target"),
                    target,
                    text(self.state.locale, "status"),
                    run_status_label(self.state.locale, &run.status),
                    text(self.state.locale, "started"),
                    run.started_at,
                    text(self.state.locale, "accepted_findings"),
                    findings,
                    text(self.state.locale, "evidence"),
                    evidence
                ));
            }
        }
        output.push_str(&format!(
            "\n{}\n",
            if self
                .state
                .active_run
                .as_ref()
                .is_some_and(|run| !run.terminal)
            {
                text(self.state.locale, "active_run")
            } else {
                text(self.state.locale, "no_active_run")
            }
        ));
        output.push_str(&format!(
            "{}\n",
            text(self.state.locale, "cache_retry_quota_summary")
        ));
        output.push_str(&format!("{}\n", text(self.state.locale, "dashboard_hint")));
    }

    fn render_collect(&self, output: &mut String) {
        output.push_str(&format!(
            "{}: {}\n",
            text(self.state.locale, "target_input"),
            if self.state.edit_mode == EditMode::Target {
                &self.state.edit_buffer
            } else {
                &self.state.target_draft
            }
        ));
        if let Some(preview) = &self.state.target_preview {
            output.push_str(&format!(
                "{}: {}={} {}={} {}={}\n",
                text(self.state.locale, "target_preview"),
                text(self.state.locale, "hostname"),
                preview.input_hostname,
                text(self.state.locale, "root_domain"),
                preview.root_domain,
                text(self.state.locale, "requires_confirmation"),
                boolean_label(self.state.locale, preview.requires_root_confirmation)
            ));
        }
        output.push_str(&format!(
            "{}:\n",
            text(self.state.locale, "selected_sources")
        ));
        for (index, source) in self.state.source_catalog.iter().enumerate() {
            let marker = if self.state.selected_sources.contains(&source.source_id) {
                "[x]"
            } else {
                "[ ]"
            };
            let focus = if self.state.collect_focus == index + 1 {
                ">"
            } else {
                " "
            };
            output.push_str(&format!(
                "{focus}{marker} {} | {}={} | {} | {}={}\n",
                source.source_id,
                text(self.state.locale, "credential_state"),
                credential_state_label(self.state.locale, source.credential_state),
                source.purpose,
                text(self.state.locale, "passive"),
                boolean_label(self.state.locale, source.passive_only)
            ));
        }
        let include_focus = if self.state.collect_focus == self.state.source_catalog.len() + 1 {
            ">"
        } else {
            " "
        };
        output.push_str(&format!(
            "{include_focus}[{}] {}\n",
            if self.state.include_root { "x" } else { " " },
            text(self.state.locale, "include_root_domain")
        ));
        let start_focus = if self.state.collect_focus == self.state.source_catalog.len() + 2 {
            ">"
        } else {
            " "
        };
        output.push_str(&format!(
            "{start_focus}{} [{}]\n",
            text(self.state.locale, "start_collection"),
            if self.state.can_start_collection() {
                text(self.state.locale, "start_enabled")
            } else {
                text(self.state.locale, "start_disabled")
            }
        ));
        output.push_str(&format!(
            "{}={} | {}={}\n",
            text(self.state.locale, "report_language"),
            report_language_label(self.state.locale, self.state.report_language),
            text(self.state.locale, "cancel_behavior_label"),
            text(self.state.locale, "cancel_behavior")
        ));
        output.push_str(&format!(
            "\n{}\n",
            text(self.state.locale, "network_after_confirm")
        ));
    }

    fn render_sources(&self, output: &mut String) {
        output.push_str(&format!(
            "{}\n",
            text(self.state.locale, "source_actions_hint")
        ));
        for (index, source) in self.state.source_catalog.iter().enumerate() {
            let marker = if index == self.state.selected_source_index {
                ">"
            } else {
                " "
            };
            let pref = self
                .state
                .source_preferences
                .iter()
                .find(|item| item.source_id == source.source_id);
            let enabled = pref.is_some_and(|item| item.effective_enabled);
            output.push_str(&format!(
                "{marker} {} | {} | {}={} | {}={} | {}={} | {}={} | {}\n",
                source.source_id,
                source.display_name,
                text(self.state.locale, "credential_state"),
                credential_state_label(self.state.locale, source.credential_state),
                text(self.state.locale, "enabled"),
                boolean_label(self.state.locale, enabled),
                text(self.state.locale, "quota"),
                source.quota_limit,
                text(self.state.locale, "cache_ttl_ms"),
                source.cache_ttl_ms,
                source.terms_notice
            ));
        }
        output.push_str(&format!(
            "\n{}\n",
            text(self.state.locale, "security_notice")
        ));
        output.push_str(&format!("{}\n", text(self.state.locale, "api_txt_notice")));
    }

    fn render_run(&self, output: &mut String) {
        if let Some(active) = &self.state.active_run {
            output.push_str(&format!(
                "{}={} | {}={} | {}={} | {}={}s\n",
                text(self.state.locale, "run_id"),
                active
                    .run_id
                    .map_or_else(|| "<pending>".into(), |id| id.to_string()),
                text(self.state.locale, "target"),
                active.target_domain,
                text(self.state.locale, "status"),
                run_status_label_code(self.state.locale, &active.status_code),
                text(self.state.locale, "elapsed"),
                active.started_at.elapsed().as_secs()
            ));
            output.push_str(&format!(
                "{}={} | {}={}\n",
                text(self.state.locale, "accepted_findings"),
                active.accepted_findings,
                text(self.state.locale, "evidence"),
                active.evidence_count
            ));
            for (source_id, source) in &active.sources {
                output.push_str(&format!(
                    "  {} | {}={} | {}={} | {}={} | {}={} | {}={}/{} | {}={} | {}={} | {}={} | {}={} | {}={} | {}={}\n",
                    source_id,
                    text(self.state.locale, "status"),
                    source_state_label_code(self.state.locale, &source.state_code),
                    text(self.state.locale, "metric_requests"),
                    source.requests,
                    text(self.state.locale, "metric_pages"),
                    source.pages,
                    text(self.state.locale, "metric_retries"),
                    source.retries,
                    text(self.state.locale, "metric_cache"),
                    source.cache_hits,
                    source.cache_misses,
                    text(self.state.locale, "metric_quota_rejections"),
                    source.quota_rejections,
                    text(self.state.locale, "metric_received"),
                    source.received,
                    text(self.state.locale, "metric_accepted"),
                    source.accepted,
                    text(self.state.locale, "metric_filtered"),
                    source.filtered,
                    text(self.state.locale, "evidence"),
                    source.evidence,
                    text(self.state.locale, "metric_error"),
                    source.error_code.as_deref().unwrap_or("-"),
                ));
            }
            if !active.terminal {
                output.push_str(&format!(
                    "{}\n",
                    text(self.state.locale, "run_actions_active")
                ));
            } else {
                output.push_str(&format!(
                    "{}\n",
                    text(self.state.locale, "run_actions_terminal")
                ));
            }
        } else {
            output.push_str(&format!("{}\n", text(self.state.locale, "no_active_run")));
        }
        output.push_str(&format!("\n{}:\n", text(self.state.locale, "recent_runs")));
        for (index, run) in self.state.recent_runs.iter().enumerate() {
            output.push_str(&format!(
                "{}{} | {} | {} | {}\n",
                if index == self.state.selected_run_index {
                    ">"
                } else {
                    " "
                },
                run.id,
                run_status_label(self.state.locale, &run.status),
                run.started_at,
                run.source_profile
            ));
        }
    }

    fn render_findings(&self, output: &mut String) {
        output.push_str(&format!("{}\n", text(self.state.locale, "findings_hint")));
        output.push_str(&format!(
            "{}={} | {}={} | {}={}\n",
            text(self.state.locale, "scope_filter"),
            result_scope_label(self.state.locale, &self.state.finding_scope),
            text(self.state.locale, "sort"),
            finding_sort_label(self.state.locale, self.state.finding_sort),
            text(self.state.locale, "search"),
            if self.state.finding_search.is_empty() {
                "-"
            } else {
                &self.state.finding_search
            }
        ));
        if let Some(page) = &self.state.findings {
            if page.items.is_empty() {
                output.push_str(&format!("{}\n", text(self.state.locale, "empty")));
            } else {
                for (index, item) in page.items.iter().enumerate() {
                    output.push_str(&format!(
                        "{}{} | {}={} | {}={} | {}={} | {}={}\n",
                        if index == self.state.selected_finding_index {
                            ">"
                        } else {
                            " "
                        },
                        item.fqdn,
                        text(self.state.locale, "evidence"),
                        item.evidence_count,
                        text(self.state.locale, "sources"),
                        item.source_count,
                        text(self.state.locale, "first_seen"),
                        item.first_seen_at,
                        text(self.state.locale, "last_seen"),
                        item.last_seen_at
                    ));
                }
                if let Some(cursor) = &page.next_cursor {
                    output.push_str(&format!(
                        "{}={}\n",
                        text(self.state.locale, "next_cursor"),
                        cursor
                    ));
                }
            }
        }
    }

    fn render_evidence(&self, output: &mut String) {
        output.push_str(&format!(
            "{}\n",
            text(self.state.locale, "local_only_notice")
        ));
        if let Some(page) = &self.state.evidence {
            if page.items.is_empty() {
                output.push_str(&format!("{}\n", text(self.state.locale, "empty")));
            } else {
                for (index, item) in page.items.iter().enumerate() {
                    output.push_str(&format!(
                        "{}{} | {}={} | {}={} | {}={} | {}={} | {}={} | {}={}\n  {}={} | {}={}\n",
                        if index == self.state.selected_evidence_index {
                            ">"
                        } else {
                            " "
                        },
                        item.fqdn,
                        text(self.state.locale, "source"),
                        item.source_id,
                        text(self.state.locale, "kind"),
                        item.source_kind,
                        text(self.state.locale, "fetched"),
                        item.fetched_at,
                        text(self.state.locale, "response_digest"),
                        item.response_digest,
                        text(self.state.locale, "record_digest"),
                        item.record_digest.as_deref().unwrap_or("-"),
                        text(self.state.locale, "verdict"),
                        scope_verdict_label(self.state.locale, &item.scope_verdict),
                        text(self.state.locale, "reference"),
                        item.raw_reference.as_deref().unwrap_or("-"),
                        text(self.state.locale, "notes"),
                        item.normalization_notes.join(","),
                    ));
                }
            }
        }
    }

    fn render_compare(&self, output: &mut String) {
        output.push_str(&format!(
            "{}\n",
            text(self.state.locale, "select_compare_runs")
        ));
        if self.state.recent_runs.len() < 2 {
            output.push_str(&format!("{}\n", text(self.state.locale, "no_runs")));
            return;
        }
        let left = &self.state.recent_runs[self.state.compare_left_index];
        let right = &self.state.recent_runs[self.state.compare_right_index];
        output.push_str(&format!(
            "{}={} {}\n{}={} {}\n",
            text(self.state.locale, "left"),
            left.id,
            left.started_at,
            text(self.state.locale, "right"),
            right.id,
            right.started_at
        ));
        if let Some(diff) = &self.state.comparison {
            output.push_str(&format!(
                "{}\n",
                text(self.state.locale, "compare_counts")
                    .replacen("{}", &diff.added.len().to_string(), 1)
                    .replacen("{}", &diff.removed.len().to_string(), 1)
                    .replacen("{}", &diff.provenance_changed.len().to_string(), 1),
            ));
            for record in &diff.added {
                output.push_str(&format!("  + {}\n", record.fqdn));
            }
            for record in &diff.removed {
                output.push_str(&format!("  - {}\n", record.fqdn));
            }
            for record in &diff.provenance_changed {
                output.push_str(&format!("  ~ {}\n", record.fqdn));
            }
        }
    }

    fn render_export(&self, output: &mut String) {
        output.push_str(&format!("{}\n", text(self.state.locale, "export_hint")));
        output.push_str(&format!(
            "{}={} | {}={} | {}={} | {}={}\n",
            text(self.state.locale, "run_id"),
            self.state
                .selected_run_id
                .map_or_else(|| "-".into(), |id| id.to_string()),
            text(self.state.locale, "format"),
            report_format_label(self.state.locale, self.state.export_format),
            text(self.state.locale, "report_language"),
            report_language_label(self.state.locale, self.state.report_language),
            text(self.state.locale, "destination"),
            self.state.export_destination
        ));
        output.push_str(&format!(
            "{}\n",
            text(self.state.locale, "export_policy_notice")
        ));
    }

    fn render_settings(&self, output: &mut String) {
        output.push_str(&format!("{}\n", text(self.state.locale, "settings_hint")));
        output.push_str(&format!(
            "{}={} | {}={}\n{}={} | {}={}\n",
            text(self.state.locale, "display_language"),
            display_language_label(self.state.locale),
            text(self.state.locale, "pending"),
            display_language_label(self.state.pending_display_language),
            text(self.state.locale, "report_language"),
            report_language_label(self.state.locale, self.state.report_language),
            text(self.state.locale, "pending"),
            report_language_label(self.state.locale, self.state.pending_report_language)
        ));
        output.push_str(&format!(
            "{}={} | {}={} (f toggle)\n",
            text(self.state.locale, "fallback_sources"),
            boolean_label(
                self.state.locale,
                self.state.show_low_frequency_fallback_sources
            ),
            text(self.state.locale, "pending"),
            boolean_label(
                self.state.locale,
                self.state.pending_show_low_frequency_fallback_sources
            )
        ));
        output.push_str(&format!(
            "{}={}\n{}={}\n",
            text(self.state.locale, "data_directory"),
            safe_path(&self.application.paths().data_dir),
            text(self.state.locale, "config_file"),
            safe_path(&self.application.paths().config_file)
        ));
        output.push_str(&format!("{}\n", text(self.state.locale, "api_txt_notice")));
    }

    fn render_help(&self, output: &mut String) {
        for key in [
            "help_target",
            "help_sources",
            "help_credentials",
            "help_cancel_evidence",
        ] {
            output.push_str(&format!("{}\n", text(self.state.locale, key)));
        }
        output.push_str(&format!("{}\n", text(self.state.locale, "api_txt_notice")));
        output.push_str(&format!("{}\n", text(self.state.locale, "help_keymap")));
    }

    fn render_modal(&self, output: &mut String, modal: Modal) {
        output.push_str(&format!(
            "\n--- {} ---\n",
            text(self.state.locale, "confirm_action")
        ));
        let target = self
            .state
            .target_preview
            .as_ref()
            .map(|preview| preview.root_domain.as_str())
            .unwrap_or_else(|| self.state.target_draft.as_str());
        let selected_sources = self.state.selected_source_ids().join(",");
        let run_id = self
            .state
            .selected_run_id
            .map_or_else(|| "-".to_owned(), |id| id.to_string());
        match modal {
            Modal::QuitConfirm => output.push_str(&format!(
                "{} {}\n",
                text(self.state.locale, "modal_quit"),
                text(self.state.locale, "modal_yes_no")
            )),
            Modal::StartConfirm => output.push_str(&format!(
                "{}: {}\n{}\n",
                text(self.state.locale, "start_collection"),
                text(self.state.locale, "modal_yes_no"),
                text(self.state.locale, "modal_start_details")
                    .replacen("{}", target, 1)
                    .replacen("{}", &selected_sources, 1)
            )),
            Modal::RootConfirm => output.push_str(&format!(
                "{}\ninput={}\n{}\n",
                text(self.state.locale, "scope_confirmation"),
                self.state.edit_buffer,
                text(self.state.locale, "modal_root_prompt")
            )),
            Modal::CancelConfirm => output.push_str(&format!(
                "{}: {}\n{}\n",
                text(self.state.locale, "cancel_collection"),
                text(self.state.locale, "modal_yes_no"),
                text(self.state.locale, "modal_cancel_details").replacen("{}", &run_id, 1)
            )),
            Modal::ConfigureCredential => output.push_str(&format!(
                "{}\n",
                text(self.state.locale, "modal_credential_details")
                    .replacen(
                        "{}",
                        &self.current_source_id().unwrap_or_else(|| "-".to_owned()),
                        1,
                    )
                    .replacen(
                        "{}",
                        self.state
                            .source_catalog
                            .get(self.state.selected_source_index)
                            .map(|source| source.endpoint.as_str())
                            .unwrap_or("-"),
                        1,
                    )
                    .replacen("{}", &text(self.state.locale, "hidden_input"), 1)
            )),
            Modal::ImportEnvironment => output.push_str(&format!(
                "{} {}\n",
                text(self.state.locale, "modal_import"),
                text(self.state.locale, "modal_yes_no")
            )),
            Modal::RemoveCredential => output.push_str(&format!(
                "{} {}\n",
                text(self.state.locale, "modal_remove"),
                text(self.state.locale, "modal_yes_no")
            )),
            Modal::SaveSettings => output.push_str(&format!(
                "{}\n{}\n",
                text(self.state.locale, "modal_save_settings")
                    .replacen("{}", &text(self.state.locale, "pending_changes"), 1)
                    .replacen("{}", &safe_path(&self.application.paths().config_file), 1),
                text(self.state.locale, "modal_yes_no")
            )),
            Modal::ExportConfirm => output.push_str(&format!(
                "{}\n{}\n",
                text(self.state.locale, "modal_export")
                    .replacen("{}", &run_id, 1)
                    .replacen(
                        "{}",
                        &report_format_label(self.state.locale, self.state.export_format),
                        1,
                    )
                    .replacen(
                        "{}",
                        &report_language_label(self.state.locale, self.state.report_language),
                        1,
                    )
                    .replacen("{}", &self.state.export_destination, 1),
                text(self.state.locale, "modal_yes_no")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_locale_fixture(locale: DisplayLanguage) -> String {
        let mut output = String::new();
        for (screen, key) in [
            (Screen::Dashboard, "dashboard"),
            (Screen::Collect, "quick_collect"),
            (Screen::Sources, "sources_credentials"),
            (Screen::Run, "run_monitor"),
            (Screen::Findings, "findings"),
            (Screen::Evidence, "evidence"),
            (Screen::Compare, "compare"),
            (Screen::Export, "export"),
            (Screen::Settings, "settings"),
            (Screen::Help, "help"),
        ] {
            output.push_str(&format!("{screen:?}: {}\n", text(locale, key)));
        }
        output.push_str(&format!(
            "{} | {} | {} | {} | {}\n",
            result_scope_label(locale, &ResultScope::Accepted),
            finding_sort_label(locale, FindingSort::LastSeen),
            scope_verdict_label(locale, &lens_core::ScopeVerdict::OutOfScope),
            report_format_label(locale, ReportFormat::Markdown),
            run_status_label_code(locale, "succeeded")
        ));
        output.push_str("source_id=ct-crtsh run_id=00000000-0000-0000-0000-000000000000 fqdn=app.example.com cursor=next-1 digest=abc123\n");
        output
    }

    #[test]
    fn startup_is_dashboard_and_empty_source_selection_cannot_start() {
        let state = AppState::new(DisplayLanguage::ZhCn, ReportLanguage::Bilingual);
        assert_eq!(state.screen, Screen::Dashboard);
        assert!(!state.can_start_collection());
    }

    #[test]
    fn reducer_keeps_machine_selection_stable_when_language_changes() {
        let mut state = AppState::new(DisplayLanguage::ZhCn, ReportLanguage::Bilingual);
        state.selected_sources.insert("ct-certspotter".to_owned());
        reduce(&mut state, Action::SetLocale(DisplayLanguage::EnUs));
        assert_eq!(state.locale, DisplayLanguage::EnUs);
        assert!(state.selected_sources.contains("ct-certspotter"));
    }

    #[test]
    fn progress_reaches_terminal_state_without_fake_percentage() {
        let mut state = AppState::new(DisplayLanguage::ZhCn, ReportLanguage::Bilingual);
        state.apply_progress(CollectionProgressEvent::RunCreated {
            run_id: Uuid::nil(),
            target_domain: "example.com".into(),
        });
        state.apply_progress(CollectionProgressEvent::SourceQueued {
            run_id: Uuid::nil(),
            source_id: "ct-crtsh".into(),
        });
        state.apply_progress(CollectionProgressEvent::SourceStarted {
            run_id: Uuid::nil(),
            source_id: "ct-crtsh".into(),
        });
        state.apply_progress(CollectionProgressEvent::RunFinished {
            run_id: Uuid::nil(),
            status: lens_core::RunStatus::Cancelled,
        });
        assert_eq!(
            state
                .active_run
                .as_ref()
                .map(|run| run.status_code.as_str()),
            Some("cancelled")
        );
        assert!(state.active_run.as_ref().is_some_and(|run| run.terminal));
    }

    #[test]
    fn target_preview_never_requires_raw_url_storage() {
        let mut state = AppState::new(DisplayLanguage::ZhCn, ReportLanguage::Bilingual);
        reduce(
            &mut state,
            Action::SetTargetPreview(TargetResolution {
                input_hostname: "app.example.com".into(),
                root_domain: "example.com".into(),
                input_was_url: true,
                requires_root_confirmation: true,
            }),
        );
        assert_eq!(
            state
                .target_preview
                .as_ref()
                .map(|value| value.input_hostname.as_str()),
            Some("app.example.com")
        );
        assert!(
            state
                .target_preview
                .as_ref()
                .is_some_and(|value| value.requires_root_confirmation)
        );
    }

    #[test]
    fn renderer_locale_matrix_keeps_machine_values_stable() {
        let zh = deterministic_locale_fixture(DisplayLanguage::ZhCn);
        let en = deterministic_locale_fixture(DisplayLanguage::EnUs);
        assert!(zh.contains("仪表盘"));
        assert!(zh.contains("已接受 (accepted)"));
        assert!(en.contains("Dashboard"));
        assert!(en.contains("Accepted (accepted)"));
        for stable in [
            "ct-crtsh",
            "00000000-0000-0000-0000-000000000000",
            "app.example.com",
            "next-1",
            "abc123",
        ] {
            assert!(zh.contains(stable), "zh fixture lost stable value {stable}");
            assert!(en.contains(stable), "en fixture lost stable value {stable}");
        }
    }

    #[test]
    fn renderer_source_has_no_debug_or_json_status_presentation() {
        let implementation = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("implementation section");
        assert!(!implementation.contains("{:?}"));
        assert!(!implementation.contains("serde_json::to_string"));
        for forbidden in [
            "Quit TUI? Enter=yes Esc=no",
            "scope={:?}",
            "verdict={:?}",
            "format={:?}",
            "Export policy remains enforced by ApplicationService",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "found raw UI text: {forbidden}"
            );
        }
    }

    #[test]
    fn presentation_fixture_never_contains_fake_secret_or_url_userinfo() {
        let secret = "repair-secret-must-never-render";
        let fixture = deterministic_locale_fixture(DisplayLanguage::ZhCn);
        assert!(!fixture.contains(secret));
        assert!(!fixture.contains("user:password@"));
        assert!(!fixture.contains("?token="));
        assert!(!fixture.contains("#fragment"));
    }

    #[test]
    fn locale_change_preserves_all_machine_selections() {
        let mut state = AppState::new(DisplayLanguage::ZhCn, ReportLanguage::Bilingual);
        let run_id = Uuid::nil();
        state.selected_sources.insert("ct-crtsh".to_owned());
        state.selected_run_id = Some(run_id);
        state.finding_search = "app.example.com".to_owned();
        state.finding_source_filter = Some("ct-crtsh".to_owned());
        state.finding_scope = ResultScope::Filtered;
        state.finding_sort = FindingSort::LastSeen;
        state.export_destination = "C:\\exports\\report.md".to_owned();
        reduce(&mut state, Action::SetLocale(DisplayLanguage::EnUs));
        assert_eq!(state.selected_run_id, Some(run_id));
        assert_eq!(
            state.selected_sources.iter().collect::<Vec<_>>(),
            vec![&"ct-crtsh".to_owned()]
        );
        assert_eq!(state.finding_search, "app.example.com");
        assert_eq!(state.finding_source_filter.as_deref(), Some("ct-crtsh"));
        assert_eq!(state.finding_scope, ResultScope::Filtered);
        assert_eq!(state.finding_sort, FindingSort::LastSeen);
        assert_eq!(state.export_destination, "C:\\exports\\report.md");
    }
}
