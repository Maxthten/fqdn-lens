use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use crate::domain::ScopeVerdict;
use crate::evidence::{
    CollectionRun, Evidence, FqdnRecord, Project, RunFingerprint, RunMode, RunStatus,
};
use crate::scheduler::redact_sensitive;
use crate::source::{SourceState, SourceStatus};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error")]
    Database(#[from] rusqlite::Error),
    #[error("invalid persisted data")]
    InvalidData,
    #[error("project was not found")]
    ProjectNotFound,
    #[error("project already exists for this root domain")]
    ProjectAlreadyExists,
    #[error("run was not found")]
    RunNotFound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultScope {
    Accepted,
    Filtered,
    All,
}

#[derive(Clone, Debug)]
pub struct RunFinalization<'a> {
    pub status: RunStatus,
    pub diagnostics_summary: Option<&'a str>,
    pub source_statuses: Vec<SourceStatus>,
    pub evidence: &'a [Evidence],
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SnapshotDiff {
    pub project_id: Uuid,
    pub from_run: Uuid,
    pub to_run: Uuid,
    pub added: Vec<FqdnRecord>,
    pub removed: Vec<FqdnRecord>,
    pub provenance_changed: Vec<ProvenanceDifference>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProvenanceDifference {
    pub fqdn: String,
    pub from_response_digests: Vec<String>,
    pub to_response_digests: Vec<String>,
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    /// Migrations are append-only and each version is committed atomically.
    /// Old databases created by the prototype upgrade through v2/v3 instead
    /// of silently reinterpreting columns in place.
    fn migrate(&self) -> Result<(), StoreError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);",
        )?;
        let versions = self.migration_versions()?;
        if !versions.contains(&1) {
            let transaction = self.connection.unchecked_transaction()?;
            transaction.execute_batch(MIGRATION_1)?;
            transaction.execute("INSERT INTO schema_migrations(version) VALUES (1)", [])?;
            transaction.commit()?;
        }
        let versions = self.migration_versions()?;
        if !versions.contains(&2) {
            let needs_column = !self.has_column("evidence", "source_url")?;
            let transaction = self.connection.unchecked_transaction()?;
            if needs_column {
                transaction.execute_batch("ALTER TABLE evidence ADD COLUMN source_url TEXT;")?;
            }
            transaction.execute("INSERT INTO schema_migrations(version) VALUES (2)", [])?;
            transaction.commit()?;
        }
        let versions = self.migration_versions()?;
        if !versions.contains(&3) {
            let needs_response_digest = !self.has_column("evidence", "response_digest")?;
            let needs_record_digest = !self.has_column("evidence", "record_digest")?;
            let transaction = self.connection.unchecked_transaction()?;
            if needs_response_digest {
                transaction
                    .execute_batch("ALTER TABLE evidence ADD COLUMN response_digest TEXT;")?;
                // A v1 record has only the legacy field. Preserve it verbatim
                // as historical provenance rather than pretending it can be
                // recomputed without the bounded source response.
                transaction.execute(
                    "UPDATE evidence SET response_digest = payload_digest WHERE response_digest IS NULL",
                    [],
                )?;
            }
            if needs_record_digest {
                transaction.execute_batch("ALTER TABLE evidence ADD COLUMN record_digest TEXT;")?;
            }
            transaction.execute("INSERT INTO schema_migrations(version) VALUES (3)", [])?;
            transaction.commit()?;
        }
        let versions = self.migration_versions()?;
        if !versions.contains(&4) {
            let transaction = self.connection.unchecked_transaction()?;
            for (column, definition) in [
                ("cache_hits", "INTEGER NOT NULL DEFAULT 0"),
                ("cache_misses", "INTEGER NOT NULL DEFAULT 0"),
                ("quota_rejections", "INTEGER NOT NULL DEFAULT 0"),
            ] {
                if !self.has_column("source_statuses", column)? {
                    transaction.execute_batch(&format!(
                        "ALTER TABLE source_statuses ADD COLUMN {column} {definition};"
                    ))?;
                }
            }
            transaction.execute("INSERT INTO schema_migrations(version) VALUES (4)", [])?;
            transaction.commit()?;
        }
        let versions = self.migration_versions()?;
        if !versions.contains(&5) {
            let transaction = self.connection.unchecked_transaction()?;
            if !self.has_column("collection_runs", "run_fingerprint")? {
                transaction.execute_batch(
                    "ALTER TABLE collection_runs ADD COLUMN run_fingerprint TEXT;",
                )?;
            }
            transaction.execute("INSERT INTO schema_migrations(version) VALUES (5)", [])?;
            transaction.commit()?;
        }
        Ok(())
    }

    fn migration_versions(&self) -> Result<BTreeSet<i64>, StoreError> {
        self.connection
            .prepare("SELECT version FROM schema_migrations ORDER BY version")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(StoreError::from)
    }

    fn has_column(&self, table: &str, column: &str) -> Result<bool, StoreError> {
        self.connection
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()
            .map(|columns| columns.into_iter().any(|name| name == column))
            .map_err(StoreError::from)
    }

    pub fn create_project(&self, root_domain: &str) -> Result<Project, StoreError> {
        if let Some(project) = self.get_project_by_domain(root_domain)? {
            return Ok(project);
        }
        self.insert_project(root_domain)
    }

    pub fn create_new_project(&self, root_domain: &str) -> Result<Project, StoreError> {
        if self.get_project_by_domain(root_domain)?.is_some() {
            return Err(StoreError::ProjectAlreadyExists);
        }
        self.insert_project(root_domain)
    }

    fn insert_project(&self, root_domain: &str) -> Result<Project, StoreError> {
        let now = Utc::now();
        let project = Project {
            id: Uuid::new_v4(),
            root_domain: root_domain.to_owned(),
            created_at: now,
            updated_at: now,
            collection_policy: "strict_passive".to_owned(),
        };
        self.connection.execute(
            "INSERT INTO projects(id, root_domain, created_at, updated_at, collection_policy) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                project.id.to_string(),
                project.root_domain,
                timestamp(project.created_at),
                timestamp(project.updated_at),
                project.collection_policy
            ],
        )?;
        Ok(project)
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, root_domain, created_at, updated_at, collection_policy FROM projects ORDER BY root_domain",
        )?;
        statement
            .query_map([], project_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_project(&self, id: Uuid) -> Result<Project, StoreError> {
        self.connection
            .query_row(
                "SELECT id, root_domain, created_at, updated_at, collection_policy FROM projects WHERE id = ?1",
                [id.to_string()],
                project_from_row,
            )
            .optional()?
            .ok_or(StoreError::ProjectNotFound)
    }

    pub fn get_project_by_domain(&self, root_domain: &str) -> Result<Option<Project>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, root_domain, created_at, updated_at, collection_policy FROM projects WHERE root_domain = ?1",
                [root_domain],
                project_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn create_run(
        &self,
        project_id: Uuid,
        mode: RunMode,
        source_profile: &str,
    ) -> Result<CollectionRun, StoreError> {
        self.get_project(project_id)?;
        let run = CollectionRun {
            id: Uuid::new_v4(),
            project_id,
            mode,
            status: RunStatus::Running,
            started_at: Utc::now(),
            finished_at: None,
            source_profile: source_profile.to_owned(),
            diagnostics_summary: None,
            fingerprint: None,
        };
        self.connection.execute(
            "INSERT INTO collection_runs(id, project_id, mode, status, started_at, source_profile) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run.id.to_string(),
                run.project_id.to_string(),
                run_mode(&run.mode),
                run_status(&run.status),
                timestamp(run.started_at),
                run.source_profile
            ],
        )?;
        Ok(run)
    }

    /// Persists only the redaction-safe fingerprint after the public manifest
    /// and final scheduler policy are known. It deliberately has no field for
    /// run access capability, authorization, cookies or request-body values.
    pub fn set_run_fingerprint(
        &self,
        run_id: Uuid,
        fingerprint: &RunFingerprint,
    ) -> Result<(), StoreError> {
        let encoded = serde_json::to_string(fingerprint).map_err(|_| StoreError::InvalidData)?;
        if self.connection.execute(
            "UPDATE collection_runs SET run_fingerprint = ?2 WHERE id = ?1",
            params![run_id.to_string(), encoded],
        )? == 0
        {
            return Err(StoreError::RunNotFound);
        }
        Ok(())
    }

    /// The sole normal run-termination path. Evidence, project aggregates,
    /// source statuses and the terminal run state commit in one transaction.
    pub fn finalize_run(
        &self,
        run_id: Uuid,
        finalization: RunFinalization<'_>,
    ) -> Result<(), StoreError> {
        let run = self.get_run(run_id)?;
        if finalization
            .evidence
            .iter()
            .any(|item| item.run_id != run_id)
        {
            return Err(StoreError::InvalidData);
        }
        let transaction = self.connection.unchecked_transaction()?;
        save_source_statuses_tx(&transaction, run_id, finalization.source_statuses)?;
        save_evidence_tx(&transaction, run.project_id, finalization.evidence)?;
        if transaction.execute(
            "UPDATE collection_runs SET status = ?2, finished_at = ?3, diagnostics_summary = ?4 WHERE id = ?1",
            params![
                run_id.to_string(),
                run_status(&finalization.status),
                timestamp(Utc::now()),
                finalization.diagnostics_summary.map(redact_sensitive),
            ],
        )? == 0 {
            return Err(StoreError::RunNotFound);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Compatibility helper for callers which have no evidence to persist.
    pub fn finish_run(
        &self,
        run_id: Uuid,
        status: RunStatus,
        diagnostics_summary: Option<&str>,
    ) -> Result<(), StoreError> {
        self.finalize_run(
            run_id,
            RunFinalization {
                status,
                diagnostics_summary,
                source_statuses: Vec::new(),
                evidence: &[],
            },
        )
    }

    pub fn save_source_statuses(
        &self,
        run_id: Uuid,
        statuses: impl IntoIterator<Item = SourceStatus>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        save_source_statuses_tx(&transaction, run_id, statuses.into_iter().collect())?;
        transaction.commit()?;
        Ok(())
    }

    pub fn save_evidence(&self, project_id: Uuid, evidence: &[Evidence]) -> Result<(), StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        save_evidence_tx(&transaction, project_id, evidence)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_run(&self, run_id: Uuid) -> Result<CollectionRun, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, mode, status, started_at, finished_at, source_profile, diagnostics_summary, run_fingerprint FROM collection_runs WHERE id = ?1",
                [run_id.to_string()],
                run_from_row,
            )
            .optional()?
            .ok_or(StoreError::RunNotFound)
    }

    pub fn list_runs(&self, project_id: Uuid) -> Result<Vec<CollectionRun>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, mode, status, started_at, finished_at, source_profile, diagnostics_summary, run_fingerprint FROM collection_runs WHERE project_id = ?1 ORDER BY started_at DESC",
        )?;
        statement
            .query_map([project_id.to_string()], run_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Aggregates only evidence produced by the requested run. Project-wide
    /// history deliberately lives in `list_project_fqdns`.
    pub fn list_run_results(
        &self,
        run_id: Uuid,
        scope: ResultScope,
    ) -> Result<Vec<FqdnRecord>, StoreError> {
        let run = self.get_run(run_id)?;
        let where_scope = match scope {
            ResultScope::Accepted => "scope_verdict = 'accepted'",
            ResultScope::Filtered => "scope_verdict <> 'accepted'",
            ResultScope::All => "1 = 1",
        };
        let query = format!(
            "SELECT ?2 AS project_id, CASE WHEN fqdn = '' THEN raw_value ELSE fqdn END AS display_fqdn, MIN(COALESCE(observed_at, fetched_at)), MAX(COALESCE(observed_at, fetched_at)), COUNT(*), COUNT(DISTINCT source_id) FROM evidence WHERE run_id = ?1 AND {where_scope} GROUP BY display_fqdn ORDER BY display_fqdn"
        );
        let mut statement = self.connection.prepare(&query)?;
        statement
            .query_map(
                params![run_id.to_string(), run.project_id.to_string()],
                fqdn_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_project_fqdns(&self, project_id: Uuid) -> Result<Vec<FqdnRecord>, StoreError> {
        self.get_project(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT record.project_id, record.fqdn, record.first_seen_at, record.last_seen_at, record.evidence_count, record.source_count FROM fqdn_records record WHERE record.project_id = ?1 ORDER BY record.fqdn",
        )?;
        statement
            .query_map([project_id.to_string()], fqdn_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_snapshot_diff(
        &self,
        project_id: Uuid,
        from_run: Uuid,
        to_run: Uuid,
    ) -> Result<SnapshotDiff, StoreError> {
        let from = self.get_run(from_run)?;
        let to = self.get_run(to_run)?;
        if from.project_id != project_id || to.project_id != project_id {
            return Err(StoreError::InvalidData);
        }
        let from_records = self
            .list_run_results(from_run, ResultScope::Accepted)?
            .into_iter()
            .map(|record| (record.fqdn.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let to_records = self
            .list_run_results(to_run, ResultScope::Accepted)?
            .into_iter()
            .map(|record| (record.fqdn.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let provenance = |run_id| -> Result<BTreeMap<String, BTreeSet<String>>, StoreError> {
            Ok(self
                .list_run_evidence(run_id)?
                .into_iter()
                .filter(|evidence| evidence.scope_verdict == ScopeVerdict::Accepted)
                .fold(
                    BTreeMap::<String, BTreeSet<String>>::new(),
                    |mut values, evidence| {
                        values.entry(evidence.fqdn).or_default().insert(format!(
                            "{}:{}:{}",
                            evidence.source_id,
                            evidence.response_digest,
                            evidence.record_digest.unwrap_or_default()
                        ));
                        values
                    },
                ))
        };
        let from_provenance = provenance(from_run)?;
        let to_provenance = provenance(to_run)?;
        Ok(SnapshotDiff {
            project_id,
            from_run,
            to_run,
            added: to_records
                .iter()
                .filter(|(fqdn, _)| !from_records.contains_key(*fqdn))
                .map(|(_, record)| record.clone())
                .collect(),
            removed: from_records
                .iter()
                .filter(|(fqdn, _)| !to_records.contains_key(*fqdn))
                .map(|(_, record)| record.clone())
                .collect(),
            provenance_changed: from_provenance
                .iter()
                .filter_map(|(fqdn, from_values)| {
                    let to_values = to_provenance.get(fqdn)?;
                    (from_values != to_values).then(|| ProvenanceDifference {
                        fqdn: fqdn.clone(),
                        from_response_digests: from_values.iter().cloned().collect(),
                        to_response_digests: to_values.iter().cloned().collect(),
                    })
                })
                .collect(),
        })
    }

    pub fn get_fqdn_evidence(
        &self,
        project_id: Uuid,
        fqdn: &str,
    ) -> Result<Vec<Evidence>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT evidence.id, evidence.run_id, evidence.fqdn, evidence.source_id, evidence.source_kind, evidence.source_url, evidence.raw_value, evidence.raw_reference, evidence.observed_at, evidence.fetched_at, evidence.response_digest, evidence.record_digest, evidence.payload_digest, evidence.normalization_notes, evidence.scope_verdict FROM evidence JOIN collection_runs run ON run.id = evidence.run_id WHERE run.project_id = ?1 AND evidence.fqdn = ?2 ORDER BY evidence.fetched_at, evidence.id",
        )?;
        statement
            .query_map(params![project_id.to_string(), fqdn], evidence_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_run_evidence(&self, run_id: Uuid) -> Result<Vec<Evidence>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT evidence.id, evidence.run_id, evidence.fqdn, evidence.source_id, evidence.source_kind, evidence.source_url, evidence.raw_value, evidence.raw_reference, evidence.observed_at, evidence.fetched_at, evidence.response_digest, evidence.record_digest, evidence.payload_digest, evidence.normalization_notes, evidence.scope_verdict FROM evidence WHERE evidence.run_id = ?1 ORDER BY evidence.fqdn, evidence.id",
        )?;
        statement
            .query_map([run_id.to_string()], evidence_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_source_statuses(&self, run_id: Uuid) -> Result<Vec<SourceStatus>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT source_id, state, requests, pages, results_received, results_accepted, results_filtered, retries, cache_hits, cache_misses, quota_rejections, error_code, retry_after_ms FROM source_statuses WHERE run_id = ?1 ORDER BY source_id",
        )?;
        statement
            .query_map([run_id.to_string()], source_status_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

const MIGRATION_1: &str = "
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        root_domain TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        collection_policy TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS collection_runs (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES projects(id),
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        source_profile TEXT NOT NULL,
        diagnostics_summary TEXT,
        run_fingerprint TEXT
    );
    CREATE INDEX IF NOT EXISTS collection_runs_project_idx ON collection_runs(project_id, started_at DESC);
    CREATE TABLE IF NOT EXISTS source_statuses (
        run_id TEXT NOT NULL REFERENCES collection_runs(id),
        source_id TEXT NOT NULL,
        state TEXT NOT NULL,
        requests INTEGER NOT NULL,
        pages INTEGER NOT NULL,
        results_received INTEGER NOT NULL,
        results_accepted INTEGER NOT NULL,
        results_filtered INTEGER NOT NULL,
        retries INTEGER NOT NULL,
        cache_hits INTEGER NOT NULL DEFAULT 0,
        cache_misses INTEGER NOT NULL DEFAULT 0,
        quota_rejections INTEGER NOT NULL DEFAULT 0,
        error_code TEXT,
        retry_after_ms INTEGER,
        PRIMARY KEY (run_id, source_id)
    );
    CREATE TABLE IF NOT EXISTS fqdn_records (
        project_id TEXT NOT NULL REFERENCES projects(id),
        fqdn TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        evidence_count INTEGER NOT NULL,
        source_count INTEGER NOT NULL,
        PRIMARY KEY (project_id, fqdn)
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES collection_runs(id),
        fqdn TEXT NOT NULL,
        source_id TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        raw_reference TEXT,
        observed_at TEXT,
        fetched_at TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        normalization_notes TEXT NOT NULL,
        scope_verdict TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS evidence_run_idx ON evidence(run_id, fqdn);
    CREATE INDEX IF NOT EXISTS evidence_source_idx ON evidence(source_id);
";

fn save_source_statuses_tx(
    transaction: &Transaction<'_>,
    run_id: Uuid,
    statuses: Vec<SourceStatus>,
) -> Result<(), StoreError> {
    for status in statuses {
        transaction.execute(
            "INSERT OR REPLACE INTO source_statuses(run_id, source_id, state, requests, pages, results_received, results_accepted, results_filtered, retries, cache_hits, cache_misses, quota_rejections, error_code, retry_after_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                run_id.to_string(),
                status.source_id,
                source_state(&status.state),
                status.requests,
                status.pages,
                status.results_received,
                status.results_accepted,
                status.results_filtered,
                status.retries,
                status.cache_hits,
                status.cache_misses,
                status.quota_rejections,
                status.error_code.map(|value| redact_sensitive(&value)),
                status.retry_after_ms,
            ],
        )?;
    }
    Ok(())
}

fn save_evidence_tx(
    transaction: &Transaction<'_>,
    project_id: Uuid,
    evidence: &[Evidence],
) -> Result<(), StoreError> {
    for item in evidence {
        if item.response_digest != item.payload_digest {
            return Err(StoreError::InvalidData);
        }
        transaction.execute(
            "INSERT INTO evidence(id, run_id, fqdn, source_id, source_kind, source_url, raw_value, raw_reference, observed_at, fetched_at, response_digest, record_digest, payload_digest, normalization_notes, scope_verdict) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                item.id.to_string(),
                item.run_id.to_string(),
                item.fqdn,
                item.source_id,
                item.source_kind,
                item.source_url.as_deref().map(redact_sensitive),
                redact_sensitive(&item.raw_value),
                item.raw_reference.as_deref().map(redact_sensitive),
                item.observed_at.map(timestamp),
                timestamp(item.fetched_at),
                item.response_digest,
                item.record_digest,
                item.payload_digest,
                serde_json::to_string(&item.normalization_notes).map_err(|_| StoreError::InvalidData)?,
                scope_verdict(&item.scope_verdict),
            ],
        )?;
        if item.scope_verdict == ScopeVerdict::Accepted {
            update_fqdn_record(transaction, project_id, item)?;
        }
    }
    Ok(())
}

fn update_fqdn_record(
    transaction: &Transaction<'_>,
    project_id: Uuid,
    item: &Evidence,
) -> Result<(), StoreError> {
    let seen_at = item.observed_at.unwrap_or(item.fetched_at);
    transaction.execute(
        "INSERT INTO fqdn_records(project_id, fqdn, first_seen_at, last_seen_at, evidence_count, source_count) VALUES (?1, ?2, ?3, ?3, 1, 1) ON CONFLICT(project_id, fqdn) DO UPDATE SET first_seen_at = MIN(first_seen_at, excluded.first_seen_at), last_seen_at = MAX(last_seen_at, excluded.last_seen_at), evidence_count = evidence_count + 1, source_count = (SELECT COUNT(DISTINCT source_id) FROM evidence JOIN collection_runs run ON run.id = evidence.run_id WHERE run.project_id = excluded.project_id AND evidence.fqdn = excluded.fqdn)",
        params![project_id.to_string(), item.fqdn, timestamp(seen_at)],
    )?;
    Ok(())
}

fn project_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        root_domain: row.get(1)?,
        created_at: parse_time(row.get::<_, String>(2)?)?,
        updated_at: parse_time(row.get::<_, String>(3)?)?,
        collection_policy: row.get(4)?,
    })
}

fn run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CollectionRun> {
    Ok(CollectionRun {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        project_id: parse_uuid(row.get::<_, String>(1)?)?,
        mode: parse_run_mode(&row.get::<_, String>(2)?)?,
        status: parse_run_status(&row.get::<_, String>(3)?)?,
        started_at: parse_time(row.get::<_, String>(4)?)?,
        finished_at: row
            .get::<_, Option<String>>(5)?
            .map(parse_time)
            .transpose()?,
        source_profile: row.get(6)?,
        diagnostics_summary: row.get(7)?,
        fingerprint: row
            .get::<_, Option<String>>(8)?
            .map(|value| serde_json::from_str::<RunFingerprint>(&value))
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn evidence_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Evidence> {
    Ok(Evidence {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        run_id: parse_uuid(row.get::<_, String>(1)?)?,
        fqdn: row.get(2)?,
        source_id: row.get(3)?,
        source_kind: row.get(4)?,
        source_url: row.get(5)?,
        raw_value: row.get(6)?,
        raw_reference: row.get(7)?,
        observed_at: row
            .get::<_, Option<String>>(8)?
            .map(parse_time)
            .transpose()?,
        fetched_at: parse_time(row.get::<_, String>(9)?)?,
        response_digest: row.get(10)?,
        record_digest: row.get(11)?,
        payload_digest: row.get(12)?,
        normalization_notes: serde_json::from_str(&row.get::<_, String>(13)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        scope_verdict: parse_scope_verdict(&row.get::<_, String>(14)?)?,
    })
}

fn fqdn_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FqdnRecord> {
    Ok(FqdnRecord {
        project_id: parse_uuid(row.get::<_, String>(0)?)?,
        fqdn: row.get(1)?,
        first_seen_at: parse_time(row.get::<_, String>(2)?)?,
        last_seen_at: parse_time(row.get::<_, String>(3)?)?,
        evidence_count: row.get::<_, i64>(4)? as u64,
        source_count: row.get::<_, i64>(5)? as u64,
    })
}

fn source_status_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SourceStatus> {
    Ok(SourceStatus {
        source_id: row.get(0)?,
        state: parse_source_state(&row.get::<_, String>(1)?)?,
        requests: row.get::<_, i64>(2)? as u64,
        pages: row.get::<_, i64>(3)? as u64,
        results_received: row.get::<_, i64>(4)? as u64,
        results_accepted: row.get::<_, i64>(5)? as u64,
        results_filtered: row.get::<_, i64>(6)? as u64,
        retries: row.get::<_, i64>(7)? as u64,
        cache_hits: row.get::<_, i64>(8)? as u64,
        cache_misses: row.get::<_, i64>(9)? as u64,
        quota_rejections: row.get::<_, i64>(10)? as u64,
        error_code: row.get(11)?,
        retry_after_ms: row.get::<_, Option<i64>>(12)?.map(|value| value as u64),
    })
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_time(value: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn run_mode(value: &RunMode) -> &'static str {
    match value {
        RunMode::Lab => "lab",
        RunMode::LiveReserved => "live_reserved",
    }
}

fn parse_run_mode(value: &str) -> rusqlite::Result<RunMode> {
    match value {
        "lab" => Ok(RunMode::Lab),
        "live_reserved" => Ok(RunMode::LiveReserved),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn run_status(value: &RunStatus) -> &'static str {
    match value {
        RunStatus::Queued => "queued",
        RunStatus::Running => "running",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Partial => "partial",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

fn parse_run_status(value: &str) -> rusqlite::Result<RunStatus> {
    match value {
        "queued" => Ok(RunStatus::Queued),
        "running" => Ok(RunStatus::Running),
        "succeeded" => Ok(RunStatus::Succeeded),
        "partial" => Ok(RunStatus::Partial),
        "failed" => Ok(RunStatus::Failed),
        "cancelled" => Ok(RunStatus::Cancelled),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn source_state(value: &SourceState) -> &'static str {
    match value {
        SourceState::Succeeded => "succeeded",
        SourceState::Empty => "empty",
        SourceState::Failed => "failed",
        SourceState::Skipped => "skipped",
        SourceState::RateLimited => "rate_limited",
        SourceState::Cancelled => "cancelled",
    }
}

fn parse_source_state(value: &str) -> rusqlite::Result<SourceState> {
    match value {
        "succeeded" => Ok(SourceState::Succeeded),
        "empty" => Ok(SourceState::Empty),
        "failed" => Ok(SourceState::Failed),
        "skipped" => Ok(SourceState::Skipped),
        "rate_limited" => Ok(SourceState::RateLimited),
        "cancelled" => Ok(SourceState::Cancelled),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn scope_verdict(value: &ScopeVerdict) -> &'static str {
    match value {
        ScopeVerdict::Accepted => "accepted",
        ScopeVerdict::Root => "root",
        ScopeVerdict::Wildcard => "wildcard",
        ScopeVerdict::OutOfScope => "out_of_scope",
        ScopeVerdict::Invalid => "invalid",
    }
}

fn parse_scope_verdict(value: &str) -> rusqlite::Result<ScopeVerdict> {
    match value {
        "accepted" => Ok(ScopeVerdict::Accepted),
        "root" => Ok(ScopeVerdict::Root),
        "wildcard" => Ok(ScopeVerdict::Wildcard),
        "out_of_scope" => Ok(ScopeVerdict::OutOfScope),
        "invalid" => Ok(ScopeVerdict::Invalid),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ScopeVerdict;

    fn evidence(run_id: Uuid, source_id: &str, fqdn: &str) -> Evidence {
        let now = Utc::now();
        Evidence {
            id: Uuid::new_v4(),
            run_id,
            fqdn: fqdn.to_owned(),
            source_id: source_id.to_owned(),
            source_kind: source_id.to_owned(),
            source_url: Some("http://127.0.0.1:18080/source?token=fake".to_owned()),
            raw_value: fqdn.to_owned(),
            raw_reference: None,
            observed_at: Some(now),
            fetched_at: now,
            response_digest: "response-digest".to_owned(),
            record_digest: Some("record-digest".to_owned()),
            payload_digest: "response-digest".to_owned(),
            normalization_notes: vec![],
            scope_verdict: ScopeVerdict::Accepted,
        }
    }

    #[test]
    fn finalization_is_atomic_and_run_results_do_not_use_project_history() {
        let store = Store::open_in_memory().expect("store");
        let project = store.create_project("acme.test").expect("project");
        let first = store
            .create_run(project.id, RunMode::Lab, "lab")
            .expect("run");
        store
            .finalize_run(
                first.id,
                RunFinalization {
                    status: RunStatus::Succeeded,
                    diagnostics_summary: None,
                    source_statuses: vec![SourceStatus::pending("certificate")],
                    evidence: &[evidence(first.id, "certificate", "api.acme.test")],
                },
            )
            .expect("finalize first");
        let second = store
            .create_run(project.id, RunMode::Lab, "lab")
            .expect("run");
        store
            .finalize_run(
                second.id,
                RunFinalization {
                    status: RunStatus::Succeeded,
                    diagnostics_summary: None,
                    source_statuses: vec![SourceStatus::pending("archive")],
                    evidence: &[evidence(second.id, "archive", "www.acme.test")],
                },
            )
            .expect("finalize second");
        assert_eq!(
            store.get_run(first.id).expect("run").status,
            RunStatus::Succeeded
        );
        assert_eq!(
            store
                .list_run_results(first.id, ResultScope::Accepted)
                .expect("results")
                .len(),
            1
        );
        assert_eq!(
            store.list_project_fqdns(project.id).expect("history").len(),
            2
        );
        let diff = store
            .get_snapshot_diff(project.id, first.id, second.id)
            .expect("diff");
        assert_eq!(diff.added[0].fqdn, "www.acme.test");
        assert_eq!(diff.removed[0].fqdn, "api.acme.test");
    }

    #[test]
    fn upgrades_v1_database_without_editing_prior_migration() {
        let file = tempfile::NamedTempFile::new().expect("temp db");
        let connection = Connection::open(file.path()).expect("connection");
        connection.execute_batch(MIGRATION_1).expect("v1 schema");
        connection
            .execute_batch("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY); INSERT INTO schema_migrations(version) VALUES (1);")
            .expect("v1 version");
        drop(connection);
        let store = Store::open(file.path()).expect("upgrade");
        assert!(
            store
                .has_column("evidence", "source_url")
                .expect("source url")
        );
        assert!(
            store
                .has_column("evidence", "response_digest")
                .expect("response digest")
        );
        assert_eq!(
            store.migration_versions().expect("versions"),
            BTreeSet::from([1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn redacts_sensitive_fields_before_persistence() {
        let store = Store::open_in_memory().expect("store");
        let project = store.create_project("acme.test").expect("project");
        let run = store
            .create_run(project.id, RunMode::Lab, "lab")
            .expect("run");
        store
            .finalize_run(
                run.id,
                RunFinalization {
                    status: RunStatus::Succeeded,
                    diagnostics_summary: Some("Bearer fake-secret"),
                    source_statuses: vec![],
                    evidence: &[evidence(run.id, "source", "api.acme.test")],
                },
            )
            .expect("finalize");
        let stored = store
            .get_fqdn_evidence(project.id, "api.acme.test")
            .expect("evidence");
        assert!(
            !stored[0]
                .source_url
                .as_deref()
                .unwrap_or_default()
                .contains("fake")
        );
        assert!(
            !store
                .get_run(run.id)
                .expect("run")
                .diagnostics_summary
                .unwrap_or_default()
                .contains("fake-secret")
        );
    }

    #[test]
    fn persists_only_a_redaction_safe_run_fingerprint() {
        let store = Store::open_in_memory().expect("store");
        let project = store.create_project("acme.test").expect("project");
        let run = store
            .create_run(project.id, RunMode::Lab, "lab")
            .expect("run");
        let fingerprint = RunFingerprint {
            normalized_root_domain: "acme.test".to_owned(),
            source_profile_identifiers: vec!["passive_dns:passive_dns".to_owned()],
            scheduler_policy_digest: "policy".to_owned(),
            manifest_schema_version: "v1".to_owned(),
            source_request_shape_digests: vec!["shape".to_owned()],
            seed: Some(1),
        };
        store
            .set_run_fingerprint(run.id, &fingerprint)
            .expect("fingerprint");
        assert_eq!(
            store.get_run(run.id).expect("run").fingerprint,
            Some(fingerprint)
        );
    }
}
