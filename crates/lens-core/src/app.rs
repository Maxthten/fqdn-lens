//! V0.4 application service: the sole orchestration boundary for every UI.
//!
//! CLI, future TUI, MCP and desktop GUI callers use this module instead of
//! constructing adapters, reading SQLite, or making network-policy decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::config::{AppConfig, AppPaths, ConfigError, DisplayLanguage, ReportLanguage};
use crate::credentials::{CredentialError, CredentialProvider, CredentialState};
use crate::domain::normalize_root_domain;
use crate::evidence::{CollectionRun, Evidence, FqdnRecord, Project, RunMode, RunStatus};
use crate::i18n::localize_source;
use crate::production::{
    ProductionFactoryError, ProductionSourceDefinition, ProductionSourceFactory,
    ProductionSourceRegistry, SourceRunDiagnostics, production_scheduler_policy,
};
use crate::query::{QueryService, RunExport};
use crate::scheduler::{
    CollectionProgressEvent, CollectionScheduler, EgressPolicy, ProgressSink, RealWaiter,
    SystemClock,
};
use crate::source::SourceStatus;
use crate::store::{ResultScope, RunFinalization, SnapshotDiff, Store, StoreError};

pub const APPLICATION_SCHEMA: &str = "fqdn-lens.application.v0.4";

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("source factory error: {0}")]
    Factory(#[from] ProductionFactoryError),
    #[error("input does not identify a supported domain or HTTP(S) URL")]
    InvalidTarget,
    #[error("input includes URL userinfo, which is not accepted")]
    UrlUserinfoDenied,
    #[error("input has no registrable root domain")]
    PublicSuffixOnly,
    #[error("target confirmation is required; confirm root domain {root_domain}")]
    RootConfirmationRequired { root_domain: String },
    #[error("the supplied confirmation does not match root domain {root_domain}")]
    RootConfirmationMismatch { root_domain: String },
    #[error("at least one explicitly selected registered source is required")]
    NoSelectedSources,
    #[error("unknown registered source: {0}")]
    UnknownSource(String),
    #[error("source {0} does not require a credential")]
    CredentialNotRequired(String),
    #[error("run {0} is terminal or is not managed by this local process")]
    RunNotCancellable(Uuid),
    #[error("export destination is outside the configured export directory")]
    ExportDestinationDenied,
    #[error("export I/O failed: {0}")]
    ExportIo(#[from] std::io::Error),
    #[error("export serialization failed: {0}")]
    ExportJson(#[from] serde_json::Error),
    #[error("export CSV failed: {0}")]
    ExportCsv(#[from] csv::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TargetResolution {
    pub input_hostname: String,
    pub root_domain: String,
    pub input_was_url: bool,
    pub requires_root_confirmation: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceSummary {
    pub source_id: String,
    pub display_name: String,
    pub purpose: String,
    pub terms_notice: String,
    pub endpoint: String,
    pub auth_required: bool,
    pub credential_state: CredentialState,
    pub enabled_by_default: bool,
    pub cache_ttl_ms: u64,
    pub quota_limit: usize,
    pub passive_only: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceDoctorReport {
    pub source: SourceSummary,
    pub latest_health: Option<SourceRunDiagnostics>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourcePreferenceSummary {
    pub source_id: String,
    pub persisted_enabled: Option<bool>,
    pub default_enabled: bool,
    pub effective_enabled: bool,
    pub credential_state: CredentialState,
}

#[derive(Clone, Debug)]
pub struct CollectOptions {
    pub target: String,
    pub selected_sources: Vec<String>,
    pub include_root: bool,
    pub confirmed_root_domain: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CollectionReport {
    pub schema_version: &'static str,
    pub project_id: Uuid,
    pub run_id: Uuid,
    pub target_domain: String,
    pub status: RunStatus,
    pub accepted_findings: usize,
    pub evidence_count: usize,
    pub virtual_waited_ms: u64,
    pub statuses: BTreeMap<String, SourceStatus>,
    pub diagnostics: Vec<SourceRunDiagnostics>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FindingsFilter {
    pub source_id: Option<String>,
    pub fqdn_contains: Option<String>,
    pub scope: Option<ResultScope>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EvidenceFilter {
    pub source_id: Option<String>,
    pub fqdn: Option<String>,
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Markdown,
    Csv,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportMetadata {
    pub schema_version: &'static str,
    pub run_id: Uuid,
    pub format: ReportFormat,
    pub report_language: ReportLanguage,
    pub destination: PathBuf,
    pub findings: usize,
    pub evidence: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LocalizedSummary {
    pub language: ReportLanguage,
    pub texts: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize)]
struct JsonReport {
    schema_version: &'static str,
    export: RunExport,
    localized_summary: LocalizedSummary,
}

pub struct ApplicationService {
    paths: AppPaths,
    config: AppConfig,
    store: Store,
    credentials: CredentialProvider,
    registry: ProductionSourceRegistry,
    active_runs: Arc<Mutex<BTreeMap<Uuid, CancellationToken>>>,
}

impl ApplicationService {
    pub fn open(paths: AppPaths) -> Result<Self, ApplicationError> {
        paths.ensure_directories()?;
        let config = AppConfig::load_or_default(&paths.config_file)?;
        fs::create_dir_all(config.export_directory(&paths))?;
        Ok(Self {
            store: Store::open(&paths.database_file)?,
            paths,
            config,
            credentials: CredentialProvider::system(),
            registry: ProductionSourceRegistry::new(),
            active_runs: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn open_in_data_dir(data_dir: PathBuf) -> Result<Self, ApplicationError> {
        Self::open(AppPaths::in_data_dir(data_dir))
    }

    #[must_use]
    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    #[must_use]
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn set_display_language(&mut self, value: DisplayLanguage) -> Result<(), ApplicationError> {
        self.config.display_language = value;
        self.config.save(&self.paths.config_file)?;
        Ok(())
    }

    pub fn set_report_language(&mut self, value: ReportLanguage) -> Result<(), ApplicationError> {
        self.config.report_language = value;
        self.config.save(&self.paths.config_file)?;
        Ok(())
    }

    pub fn set_show_low_frequency_fallback_sources(
        &mut self,
        value: bool,
    ) -> Result<(), ApplicationError> {
        self.config.show_low_frequency_fallback_sources = value;
        self.config.save(&self.paths.config_file)?;
        Ok(())
    }

    pub fn set_source_enabled(
        &mut self,
        source_id: &str,
        enabled: bool,
    ) -> Result<(), ApplicationError> {
        self.ensure_source(source_id)?;
        self.config
            .sources
            .entry(source_id.to_owned())
            .or_default()
            .enabled = enabled;
        self.config.save(&self.paths.config_file)?;
        Ok(())
    }

    pub fn resolve_target(&self, input: &str) -> Result<TargetResolution, ApplicationError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ApplicationError::InvalidTarget);
        }
        let (host, input_was_url) = match Url::parse(trimmed) {
            Ok(url) => {
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(ApplicationError::InvalidTarget);
                }
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(ApplicationError::UrlUserinfoDenied);
                }
                (
                    url.host_str()
                        .ok_or(ApplicationError::InvalidTarget)?
                        .to_owned(),
                    true,
                )
            }
            Err(_) => (trimmed.to_owned(), false),
        };
        let input_hostname =
            normalize_root_domain(&host).map_err(|_| ApplicationError::InvalidTarget)?;
        let root_domain = psl::domain_str(&input_hostname)
            .ok_or(ApplicationError::PublicSuffixOnly)?
            .to_owned();
        Ok(TargetResolution {
            requires_root_confirmation: input_hostname != root_domain,
            input_hostname,
            root_domain,
            input_was_url,
        })
    }

    #[must_use]
    pub fn list_sources(&self) -> Vec<SourceSummary> {
        self.list_sources_for(self.config.display_language)
    }

    #[must_use]
    pub fn list_sources_for(&self, language: DisplayLanguage) -> Vec<SourceSummary> {
        self.registry
            .definitions()
            .iter()
            .copied()
            .map(|definition| self.source_summary(definition, language))
            .collect()
    }

    pub fn source_doctor(
        &self,
        source_ids: &[String],
    ) -> Result<Vec<SourceDoctorReport>, ApplicationError> {
        self.source_doctor_for(source_ids, self.config.display_language)
    }

    pub fn source_doctor_for(
        &self,
        source_ids: &[String],
        language: DisplayLanguage,
    ) -> Result<Vec<SourceDoctorReport>, ApplicationError> {
        self.selected_definitions(source_ids)?
            .into_iter()
            .map(|definition| {
                Ok(SourceDoctorReport {
                    source: self.source_summary(definition, language),
                    latest_health: self.latest_source_health(definition.id)?,
                })
            })
            .collect()
    }

    #[must_use]
    pub fn source_preferences(&self) -> Vec<SourcePreferenceSummary> {
        self.registry
            .definitions()
            .iter()
            .copied()
            .map(|definition| {
                let persisted_enabled = self
                    .config
                    .sources
                    .get(definition.id)
                    .map(|preference| preference.enabled);
                let effective_enabled = persisted_enabled.unwrap_or(definition.default_enabled);
                SourcePreferenceSummary {
                    source_id: definition.id.to_owned(),
                    persisted_enabled,
                    default_enabled: definition.default_enabled,
                    effective_enabled,
                    credential_state: self
                        .credentials
                        .state(definition.id, definition.auth.env_var()),
                }
            })
            .collect()
    }

    pub fn configure_credential(
        &mut self,
        source_id: &str,
        value: &str,
    ) -> Result<(), ApplicationError> {
        let definition = self.ensure_source(source_id)?;
        if definition.auth.env_var().is_none() {
            return Err(ApplicationError::CredentialNotRequired(
                source_id.to_owned(),
            ));
        }
        self.credentials.configure(source_id, value)?;
        Ok(())
    }

    pub fn import_environment_credential(
        &mut self,
        source_id: &str,
        confirmed: bool,
    ) -> Result<(), ApplicationError> {
        let definition = self.ensure_source(source_id)?;
        if definition.auth.env_var().is_none() {
            return Err(ApplicationError::CredentialNotRequired(
                source_id.to_owned(),
            ));
        }
        self.credentials
            .import_environment(source_id, definition.auth.env_var(), confirmed)?;
        Ok(())
    }

    pub fn remove_credential(&mut self, source_id: &str) -> Result<bool, ApplicationError> {
        let definition = self.ensure_source(source_id)?;
        if definition.auth.env_var().is_none() {
            return Err(ApplicationError::CredentialNotRequired(
                source_id.to_owned(),
            ));
        }
        Ok(self.credentials.remove(source_id)?)
    }

    pub async fn collect(
        &self,
        options: CollectOptions,
    ) -> Result<CollectionReport, ApplicationError> {
        self.collect_with_progress(options, None).await
    }

    pub async fn collect_with_progress(
        &self,
        options: CollectOptions,
        progress: Option<ProgressSink>,
    ) -> Result<CollectionReport, ApplicationError> {
        if options.selected_sources.is_empty() {
            return Err(ApplicationError::NoSelectedSources);
        }
        let target = self.resolve_target(&options.target)?;
        if target.requires_root_confirmation {
            let confirmed = options.confirmed_root_domain.as_deref().ok_or_else(|| {
                ApplicationError::RootConfirmationRequired {
                    root_domain: target.root_domain.clone(),
                }
            })?;
            if normalize_root_domain(confirmed).ok().as_deref() != Some(&target.root_domain) {
                return Err(ApplicationError::RootConfirmationMismatch {
                    root_domain: target.root_domain,
                });
            }
        }
        let definitions = self.selected_definitions(&options.selected_sources)?;
        let mut egress = EgressPolicy::production();
        for definition in &definitions {
            let origin =
                Url::parse(definition.origin).map_err(|_| ApplicationError::InvalidTarget)?;
            egress
                .allow_public_https_url(&origin, "/")
                .map_err(|_| ApplicationError::InvalidTarget)?;
        }
        let policy = production_scheduler_policy(&definitions);
        let project = self.store.create_project(&target.root_domain)?;
        let profile = format!("production:v0.4:{}", options.selected_sources.join(","));
        let run = self
            .store
            .create_run(project.id, RunMode::LiveReserved, &profile)?;
        let cancellation = CancellationToken::new();
        self.active_runs
            .lock()
            .expect("active run registry lock")
            .insert(run.id, cancellation.clone());
        if let Some(progress) = &progress {
            progress(CollectionProgressEvent::RunCreated {
                run_id: run.id,
                target_domain: target.root_domain.clone(),
            });
        }
        let result = async {
            let factory =
                ProductionSourceFactory::with_credentials(self.registry, self.credentials.clone());
            let sources = definitions
                .iter()
                .map(|definition| factory.build(definition.id, &target.root_domain, run.id))
                .collect::<Result<Vec<_>, _>>()?;
            let scheduler = CollectionScheduler::new(
                policy,
                cancellation,
                Arc::new(RealWaiter),
                Arc::new(SystemClock),
                egress,
            )
            .map_err(|_| ApplicationError::InvalidTarget)?;
            let outcome = scheduler
                .collect_with_progress(
                    run.id,
                    &target.root_domain,
                    options.include_root,
                    sources,
                    progress.clone(),
                )
                .await;
            let diagnostics = outcome
                .statuses
                .values()
                .map(SourceRunDiagnostics::from_status)
                .collect::<Vec<_>>();
            self.store.finalize_run(
                run.id,
                RunFinalization {
                    status: outcome.status.clone(),
                    diagnostics_summary: outcome.diagnostics_summary.as_deref(),
                    source_statuses: outcome.statuses.values().cloned().collect(),
                    evidence: &outcome.evidence,
                },
            )?;
            if let Some(progress) = &progress {
                progress(CollectionProgressEvent::RunFinished {
                    run_id: run.id,
                    status: outcome.status.clone(),
                });
            }
            Ok(CollectionReport {
                schema_version: APPLICATION_SCHEMA,
                project_id: project.id,
                run_id: run.id,
                target_domain: target.root_domain,
                status: outcome.status,
                accepted_findings: outcome.accepted.values().map(Vec::len).sum(),
                evidence_count: outcome.evidence.len(),
                virtual_waited_ms: outcome.virtual_waited_ms,
                statuses: outcome.statuses,
                diagnostics,
            })
        }
        .await;
        self.active_runs
            .lock()
            .expect("active run registry lock")
            .remove(&run.id);
        result
    }

    pub fn get_run_status(&self, run_id: Uuid) -> Result<CollectionRun, ApplicationError> {
        Ok(self.store.get_run(run_id)?)
    }

    pub fn list_findings(
        &self,
        run_id: Uuid,
        filter: FindingsFilter,
    ) -> Result<Page<FqdnRecord>, ApplicationError> {
        let scope = filter.scope.unwrap_or(ResultScope::Accepted);
        let mut records = self.store.list_run_results(run_id, scope)?;
        if let Some(source_id) = filter.source_id.as_deref() {
            let matching = self
                .store
                .list_run_evidence(run_id)?
                .into_iter()
                .filter(|item| item.source_id == source_id)
                .map(|item| item.fqdn)
                .collect::<BTreeSet<_>>();
            records.retain(|item| matching.contains(&item.fqdn));
        }
        if let Some(needle) = filter.fqdn_contains.as_deref() {
            let needle = needle.to_ascii_lowercase();
            records.retain(|item| item.fqdn.contains(&needle));
        }
        Ok(page(records, filter.cursor.as_deref(), filter.limit))
    }

    pub fn list_evidence(
        &self,
        run_id: Uuid,
        filter: EvidenceFilter,
    ) -> Result<Page<Evidence>, ApplicationError> {
        let mut records = self.store.list_run_evidence(run_id)?;
        if let Some(source_id) = filter.source_id.as_deref() {
            records.retain(|item| item.source_id == source_id);
        }
        if let Some(fqdn) = filter.fqdn.as_deref() {
            records
                .retain(|item| item.fqdn == fqdn.trim().trim_end_matches('.').to_ascii_lowercase());
        }
        if let Some(after) = filter.after {
            records.retain(|item| item.fetched_at >= after);
        }
        if let Some(before) = filter.before {
            records.retain(|item| item.fetched_at <= before);
        }
        Ok(page(records, filter.cursor.as_deref(), filter.limit))
    }

    pub fn compare_runs(
        &self,
        left_run_id: Uuid,
        right_run_id: Uuid,
    ) -> Result<SnapshotDiff, ApplicationError> {
        let left = self.store.get_run(left_run_id)?;
        let right = self.store.get_run(right_run_id)?;
        if left.project_id != right.project_id {
            return Err(ApplicationError::Store(StoreError::InvalidData));
        }
        Ok(self
            .store
            .get_snapshot_diff(left.project_id, left_run_id, right_run_id)?)
    }

    pub fn cancel_run(&self, run_id: Uuid) -> Result<CollectionRun, ApplicationError> {
        let run = self.store.get_run(run_id)?;
        if run.finished_at.is_some() {
            return Err(ApplicationError::RunNotCancellable(run_id));
        }
        let token = self
            .active_runs
            .lock()
            .expect("active run registry lock")
            .get(&run_id)
            .cloned()
            .ok_or(ApplicationError::RunNotCancellable(run_id))?;
        token.cancel();
        Ok(run)
    }

    pub fn export_report(
        &self,
        run_id: Uuid,
        format: ReportFormat,
        destination: impl AsRef<Path>,
        language: Option<ReportLanguage>,
        enforce_export_directory: bool,
    ) -> Result<ExportMetadata, ApplicationError> {
        let destination = destination.as_ref().to_path_buf();
        if enforce_export_directory
            && !is_under(&destination, self.config.export_directory(&self.paths))
        {
            return Err(ApplicationError::ExportDestinationDenied);
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let report_language = language.unwrap_or(self.config.report_language);
        let document = QueryService::new(&self.store).export_run(run_id)?;
        match format {
            ReportFormat::Json => {
                let report = JsonReport {
                    schema_version: "fqdn-lens.report.v0.4",
                    localized_summary: localized_summary(&document, report_language),
                    export: document.clone(),
                };
                fs::write(&destination, serde_json::to_vec_pretty(&report)?)?;
            }
            ReportFormat::Markdown => {
                fs::write(&destination, markdown_report(&document, report_language))?
            }
            ReportFormat::Csv => write_csv(&destination, &document, report_language)?,
        }
        Ok(ExportMetadata {
            schema_version: APPLICATION_SCHEMA,
            run_id,
            format,
            report_language,
            destination,
            findings: document.results.len(),
            evidence: document.evidence.len(),
        })
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, ApplicationError> {
        Ok(self.store.list_projects()?)
    }

    pub fn list_runs(&self, project_id: Uuid) -> Result<Vec<CollectionRun>, ApplicationError> {
        Ok(self.store.list_runs(project_id)?)
    }

    pub fn list_recent_runs(&self, limit: usize) -> Result<Vec<CollectionRun>, ApplicationError> {
        let mut runs = Vec::new();
        for project in self.store.list_projects()? {
            runs.extend(self.store.list_runs(project.id)?);
        }
        runs.sort_by_key(|run| std::cmp::Reverse(run.started_at));
        runs.truncate(limit.clamp(1, 500));
        Ok(runs)
    }

    #[must_use]
    pub fn active_run_ids(&self) -> Vec<Uuid> {
        self.active_runs
            .lock()
            .expect("active run registry lock")
            .keys()
            .copied()
            .collect()
    }

    pub fn source_statuses(&self, run_id: Uuid) -> Result<Vec<SourceStatus>, ApplicationError> {
        Ok(self.store.list_source_statuses(run_id)?)
    }

    fn source_summary(
        &self,
        definition: ProductionSourceDefinition,
        language: DisplayLanguage,
    ) -> SourceSummary {
        let (display_name, purpose, terms_notice) = localize_source(definition, language);
        SourceSummary {
            source_id: definition.id.to_owned(),
            display_name,
            purpose,
            terms_notice,
            endpoint: format!("{}{}", definition.origin, definition.path),
            auth_required: definition.auth.env_var().is_some(),
            credential_state: self
                .credentials
                .state(definition.id, definition.auth.env_var()),
            enabled_by_default: self
                .config
                .sources
                .get(definition.id)
                .is_some_and(|preference| preference.enabled),
            cache_ttl_ms: definition.cache_ttl_ms,
            quota_limit: definition.quota_limit,
            passive_only: definition.passive_only,
        }
    }

    fn selected_definitions(
        &self,
        source_ids: &[String],
    ) -> Result<Vec<ProductionSourceDefinition>, ApplicationError> {
        if source_ids.is_empty() {
            return Ok(self.registry.definitions().to_vec());
        }
        source_ids
            .iter()
            .map(|source_id| self.ensure_source(source_id))
            .collect()
    }

    fn ensure_source(
        &self,
        source_id: &str,
    ) -> Result<ProductionSourceDefinition, ApplicationError> {
        self.registry
            .get(source_id)
            .ok_or_else(|| ApplicationError::UnknownSource(source_id.to_owned()))
    }

    fn latest_source_health(
        &self,
        source_id: &str,
    ) -> Result<Option<SourceRunDiagnostics>, ApplicationError> {
        for project in self.store.list_projects()? {
            for run in self.store.list_runs(project.id)? {
                if let Some(status) = self
                    .store
                    .list_source_statuses(run.id)?
                    .into_iter()
                    .find(|status| status.source_id == source_id)
                {
                    return Ok(Some(SourceRunDiagnostics::from_status(&status)));
                }
            }
        }
        Ok(None)
    }
}

fn page<T: Clone>(records: Vec<T>, cursor: Option<&str>, limit: Option<usize>) -> Page<T> {
    let offset = cursor
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let items = records
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let next = (offset + items.len() < records.len()).then(|| (offset + items.len()).to_string());
    Page {
        items,
        next_cursor: next,
    }
}

fn is_under(path: &Path, directory: &Path) -> bool {
    let Some(path) = canonical_path_for_policy(path) else {
        return false;
    };
    let Some(directory) = canonical_path_for_policy(directory) else {
        return false;
    };
    path.starts_with(directory)
}

/// Canonicalizes the existing prefix of a destination before output files are
/// created. This prevents `exports\\..\\outside` or a symlinked ancestor from
/// bypassing the MCP export-directory policy.
fn canonical_path_for_policy(path: &Path) -> Option<PathBuf> {
    let mut candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut suffix = Vec::new();
    while !candidate.exists() {
        suffix.push(candidate.file_name()?.to_owned());
        candidate = candidate.parent()?.to_path_buf();
    }
    let mut canonical = candidate.canonicalize().ok()?;
    for part in suffix.iter().rev() {
        canonical.push(part);
    }
    Some(canonical)
}

fn localized_summary(document: &RunExport, language: ReportLanguage) -> LocalizedSummary {
    let entries = [
        ("title", "FQDN Lens 运行报告", "FQDN Lens run report"),
        ("accepted_findings", "已接受发现数", "Accepted findings"),
        ("evidence_count", "证据数量", "Evidence count"),
        ("overall_status", "整体状态", "Overall status"),
    ];
    let mut texts = BTreeMap::new();
    for (key, zh, en) in entries {
        let mut item = BTreeMap::new();
        match language {
            ReportLanguage::ZhCn => {
                item.insert("zh-CN".to_owned(), zh.to_owned());
            }
            ReportLanguage::EnUs => {
                item.insert("en-US".to_owned(), en.to_owned());
            }
            ReportLanguage::Bilingual => {
                item.insert("zh-CN".to_owned(), zh.to_owned());
                item.insert("en-US".to_owned(), en.to_owned());
            }
        }
        texts.insert(key.to_owned(), item);
    }
    let _ = document;
    LocalizedSummary { language, texts }
}

fn bilingual(language: ReportLanguage, zh: &str, en: &str) -> String {
    match language {
        ReportLanguage::ZhCn => zh.to_owned(),
        ReportLanguage::EnUs => en.to_owned(),
        ReportLanguage::Bilingual => format!("{zh} / {en}"),
    }
}

fn markdown_report(document: &RunExport, language: ReportLanguage) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "# {}\n\n",
        bilingual(language, "FQDN Lens 运行报告", "FQDN Lens run report")
    ));
    output.push_str(&format!(
        "- {}: `{}`\n- {}: `{}`\n- {}: `{}`\n- {}: `{}`\n- {}: {}\n- {}: {}\n\n",
        bilingual(language, "运行 ID", "Run ID"),
        document.run.id,
        bilingual(language, "目标域", "Target domain"),
        document.target_domain,
        bilingual(language, "状态", "Status"),
        serde_json::to_string(&document.run.status).unwrap_or_else(|_| "unknown".to_owned()),
        bilingual(language, "开始时间", "Started at"),
        document.run.started_at.to_rfc3339(),
        bilingual(language, "已接受发现", "Accepted findings"),
        document.results.len(),
        bilingual(language, "证据数量", "Evidence count"),
        document.evidence.len(),
    ));
    output.push_str(&format!(
        "## {}\n\n| {} | {} | {} | {} |\n|---|---:|---:|---|\n",
        bilingual(language, "发现", "Findings"),
        bilingual(language, "FQDN", "FQDN"),
        bilingual(language, "证据数", "Evidence"),
        bilingual(language, "来源数", "Sources"),
        bilingual(language, "最近发现", "Last seen"),
    ));
    for record in &document.results {
        output.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            record.fqdn,
            record.evidence_count,
            record.source_count,
            record.last_seen_at.to_rfc3339()
        ));
    }
    output.push_str(&format!(
        "\n## {}\n\n| {} | {} | {} | {} |\n|---|---|---|---|\n",
        bilingual(language, "来源状态", "Source status"),
        bilingual(language, "来源", "Source"),
        bilingual(language, "状态", "State"),
        bilingual(language, "请求数", "Requests"),
        bilingual(language, "错误代码", "Error code"),
    ));
    for status in &document.source_statuses {
        output.push_str(&format!(
            "| `{}` | `{}` | {} | `{}` |\n",
            status.source_id,
            serde_json::to_string(&status.state).unwrap_or_else(|_| "unknown".to_owned()),
            status.requests,
            status.error_code.as_deref().unwrap_or(""),
        ));
    }
    output
}

fn write_csv(
    path: &Path,
    document: &RunExport,
    language: ReportLanguage,
) -> Result<(), ApplicationError> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record([
        bilingual(language, "FQDN", "FQDN"),
        bilingual(language, "首次发现", "First seen"),
        bilingual(language, "最近发现", "Last seen"),
        bilingual(language, "证据数量", "Evidence count"),
        bilingual(language, "来源数量", "Source count"),
    ])?;
    for record in &document.results {
        writer.write_record([
            &record.fqdn,
            &record.first_seen_at.to_rfc3339(),
            &record.last_seen_at.to_rfc3339(),
            &record.evidence_count.to_string(),
            &record.source_count.to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn url_target_only_keeps_hostname_and_requires_root_confirmation() {
        let temp = tempdir().expect("temp directory");
        let service =
            ApplicationService::open_in_data_dir(temp.path().to_path_buf()).expect("service");
        let target = service
            .resolve_target("https://app.example.com/path?token=never-read#fragment")
            .expect("target");
        assert_eq!(target.input_hostname, "app.example.com");
        assert_eq!(target.root_domain, "example.com");
        assert!(target.input_was_url);
        assert!(target.requires_root_confirmation);
    }

    #[test]
    fn url_userinfo_is_rejected_before_any_collection() {
        let temp = tempdir().expect("temp directory");
        let service =
            ApplicationService::open_in_data_dir(temp.path().to_path_buf()).expect("service");
        assert!(matches!(
            service.resolve_target("https://user:secret@app.example.com/path"),
            Err(ApplicationError::UrlUserinfoDenied)
        ));
    }

    #[test]
    fn export_language_keeps_machine_ids_unchanged() {
        let temp = tempdir().expect("temp directory");
        let service =
            ApplicationService::open_in_data_dir(temp.path().to_path_buf()).expect("service");
        let result = service.list_sources();
        assert_eq!(result[0].source_id, "ct-certspotter");
        assert!(result[0].purpose.contains('被'));
    }

    #[test]
    fn markdown_report_uses_the_stored_root_domain_not_source_profile() {
        let document = RunExport {
            schema_version: "test".to_owned(),
            run: CollectionRun {
                id: Uuid::nil(),
                project_id: Uuid::nil(),
                mode: RunMode::LiveReserved,
                status: RunStatus::Succeeded,
                started_at: Utc::now(),
                finished_at: None,
                source_profile: "production:v0.4:ct-certspotter".to_owned(),
                diagnostics_summary: None,
                fingerprint: None,
            },
            target_domain: "example.test".to_owned(),
            source_statuses: Vec::new(),
            results: Vec::new(),
            evidence: Vec::new(),
        };
        let markdown = markdown_report(&document, ReportLanguage::Bilingual);
        assert!(markdown.contains("`example.test`"));
        assert!(!markdown.contains("Target domain: `production:v0.4"));
    }

    #[test]
    fn export_directory_policy_rejects_parent_traversal() {
        let temp = tempdir().expect("temp directory");
        let exports = temp.path().join("exports");
        std::fs::create_dir_all(&exports).expect("exports directory");
        let escape = exports.join("..").join("outside").join("report.md");
        assert!(!is_under(&escape, &exports));
    }
}
