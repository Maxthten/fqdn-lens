use crate::domain::ScopeVerdict;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub root_domain: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub collection_policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Lab,
    LiveReserved,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionRun {
    pub id: Uuid,
    pub project_id: Uuid,
    pub mode: RunMode,
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub source_profile: String,
    pub diagnostics_summary: Option<String>,
    /// A redaction-safe, stable description of the request/scheduler profile
    /// used for replay and diff. It contains no capability or credential.
    pub fingerprint: Option<RunFingerprint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct RunFingerprint {
    pub normalized_root_domain: String,
    pub source_profile_identifiers: Vec<String>,
    pub scheduler_policy_digest: String,
    pub manifest_schema_version: String,
    pub source_request_shape_digests: Vec<String>,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub run_id: Uuid,
    pub fqdn: String,
    pub source_id: String,
    pub source_kind: String,
    /// Sanitized local source endpoint that returned this observation.
    pub source_url: Option<String>,
    pub raw_value: String,
    pub raw_reference: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub fetched_at: DateTime<Utc>,
    /// SHA-256 of the bounded, decoded HTTP response body which produced this
    /// observation. `payload_digest` is retained for backward-compatible read
    /// models and has the same value for newly written records.
    pub response_digest: String,
    /// Optional SHA-256 of the source record or text fragment inside the
    /// response. It gives callers a narrower reproducible reference without
    /// persisting an unbounded raw record.
    pub record_digest: Option<String>,
    pub payload_digest: String,
    pub normalization_notes: Vec<String>,
    pub scope_verdict: ScopeVerdict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FqdnRecord {
    pub project_id: Uuid,
    pub fqdn: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub evidence_count: u64,
    pub source_count: u64,
}
