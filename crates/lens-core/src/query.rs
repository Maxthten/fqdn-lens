//! Stable, read-only query model used by the CLI and reserved for future MCP
//! and GUI clients. No caller needs to construct SQL directly.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::evidence::{CollectionRun, Evidence, FqdnRecord, Project};
use crate::source::SourceStatus;
use crate::store::{ResultScope, SnapshotDiff, Store, StoreError};

pub struct QueryService<'a> {
    store: &'a Store,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunExport {
    pub schema_version: String,
    pub run: CollectionRun,
    pub target_domain: String,
    pub source_statuses: Vec<SourceStatus>,
    pub results: Vec<FqdnRecord>,
    pub evidence: Vec<Evidence>,
}

impl<'a> QueryService<'a> {
    #[must_use]
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub fn list_projects(&self) -> Result<Vec<Project>, StoreError> {
        self.store.list_projects()
    }
    pub fn get_run(&self, run_id: Uuid) -> Result<CollectionRun, StoreError> {
        self.store.get_run(run_id)
    }
    pub fn list_run_results(
        &self,
        run_id: Uuid,
        scope: ResultScope,
    ) -> Result<Vec<FqdnRecord>, StoreError> {
        self.store.list_run_results(run_id, scope)
    }
    pub fn list_project_fqdns(&self, project_id: Uuid) -> Result<Vec<FqdnRecord>, StoreError> {
        self.store.list_project_fqdns(project_id)
    }
    pub fn get_snapshot_diff(
        &self,
        project_id: Uuid,
        from_run: Uuid,
        to_run: Uuid,
    ) -> Result<SnapshotDiff, StoreError> {
        self.store.get_snapshot_diff(project_id, from_run, to_run)
    }
    pub fn get_fqdn_evidence(
        &self,
        project_id: Uuid,
        fqdn: &str,
    ) -> Result<Vec<Evidence>, StoreError> {
        self.store.get_fqdn_evidence(project_id, fqdn)
    }
    pub fn list_source_statuses(&self, run_id: Uuid) -> Result<Vec<SourceStatus>, StoreError> {
        self.store.list_source_statuses(run_id)
    }

    pub fn export_run(&self, run_id: Uuid) -> Result<RunExport, StoreError> {
        let run = self.get_run(run_id)?;
        let project = self.store.get_project(run.project_id)?;
        Ok(RunExport {
            schema_version: "fqdn-lens.export.v1".to_owned(),
            run,
            target_domain: project.root_domain,
            source_statuses: self.list_source_statuses(run_id)?,
            results: self.list_run_results(run_id, ResultScope::Accepted)?,
            evidence: self.store.list_run_evidence(run_id)?,
        })
    }
}
