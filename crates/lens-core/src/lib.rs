//! Strictly passive collection primitives for FQDN Lens.
//!
//! This crate has no knowledge of FQDN Forge, command-line rendering, or any
//! real-world data provider. It accepts explicitly configured loopback sources
//! and exposes stable read models for future interfaces.

pub mod app;
pub mod config;
pub mod credentials;
pub mod domain;
pub mod evidence;
pub mod i18n;
pub mod production;
pub mod query;
pub mod scheduler;
pub mod source;
pub mod store;

pub use app::{
    APPLICATION_SCHEMA, ApplicationError, ApplicationService, CollectOptions, CollectionReport,
    EvidenceFilter, ExportMetadata, FindingsFilter, Page, ReportFormat, SourceDoctorReport,
    SourcePreferenceSummary, SourceSummary, TargetResolution,
};
pub use config::{
    AppConfig, AppPaths, ConfigError, DisplayLanguage, ReportLanguage, SourcePreference,
};
pub use credentials::{CredentialError, CredentialProvider, CredentialState};
pub use domain::{DomainCandidate, ScopeVerdict, normalize_candidate, normalize_root_domain};
pub use evidence::{
    CollectionRun, Evidence, FqdnRecord, Project, RunFingerprint, RunMode, RunStatus,
};
pub use i18n::{LocalizedMessage, MessageArgs, MessageCode, Severity};
pub use production::{
    ProductionAuth, ProductionFactoryError, ProductionSourceDefinition, ProductionSourceFactory,
    ProductionSourceRegistry, SourceHealthState, SourceRunDiagnostics, production_scheduler_policy,
};
pub use query::{QueryService, RunExport};
pub use scheduler::{
    BoundedHttpClient, BoundedResponse, CacheEntry, CachePolicy, Clock, CollectionOutcome,
    CollectionProgressEvent, CollectionScheduler, EgressPolicy, FixedClock, ProgressSink,
    QuotaRule, QuotaScope, RealWaiter, RetryOptions, SchedulerPolicy, SchedulerRuntime,
    SystemClock,
};
pub use source::{
    HttpMethod, PaginationState, RawObservation, SourceKind, SourceMetadata, SourceState,
    SourceStatus,
};
pub use store::{
    ProvenanceDifference, ResultScope, RunFinalization, SnapshotDiff, Store, StoreError,
};
