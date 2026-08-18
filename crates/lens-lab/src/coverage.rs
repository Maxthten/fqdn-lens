//! Versioned FQDN Forge coverage registry and public-contract verifier.
//!
//! The registry is embedded from Lens-owned documentation. It drives only
//! test selection and reporting; collector behavior is never keyed by a
//! Forge scenario ID.

use super::*;
use futures_util::future::join_all;
use lens_core::scheduler::redact_sensitive;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

const MATRIX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/forge-coverage-matrix.yaml"
));
const COVERAGE_SCHEMA: &str = "fqdn-lens.forge-coverage.v2";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverageMatrix {
    pub schema_version: String,
    pub scenarios: Vec<CoverageEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoverageEntry {
    pub id: String,
    pub group: String,
    pub classification: String,
    pub capability: String,
    pub verifier_profile: String,
    pub seeds: Vec<u64>,
    pub assertions: Vec<String>,
    pub owner: String,
    pub notes: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationProfile {
    DirectCore,
    TransportQuota,
    SafeRejection,
    Lifecycle,
    Resilience,
    Full,
}

impl VerificationProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "direct-core" => Ok(Self::DirectCore),
            "transport-quota" => Ok(Self::TransportQuota),
            "safe-rejection" => Ok(Self::SafeRejection),
            "lifecycle" => Ok(Self::Lifecycle),
            "resilience" => Ok(Self::Resilience),
            "full" => Ok(Self::Full),
            _ => Err(anyhow!("unknown Forge verification profile")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectCore => "direct-core",
            Self::TransportQuota => "transport-quota",
            Self::SafeRejection => "safe-rejection",
            Self::Lifecycle => "lifecycle",
            Self::Resilience => "resilience",
            Self::Full => "full",
        }
    }

    fn includes(self, entry: &CoverageEntry) -> bool {
        self == Self::Full || entry.verifier_profile == self.as_str()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageScenarioResult {
    pub id: String,
    pub classification: String,
    pub seed: Option<u64>,
    pub runtime_ms: u128,
    pub forge_run_id: Option<String>,
    pub lens_run_id: Option<Uuid>,
    pub status: String,
    pub failure: Option<String>,
    pub deferred_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub schema_version: &'static str,
    pub matrix_schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub profile: String,
    pub repeat: u32,
    pub scenario_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub status: String,
    pub scenarios: Vec<CoverageScenarioResult>,
}

pub fn coverage_matrix() -> Result<CoverageMatrix> {
    // JSON is valid YAML and makes the registry readable without adding a
    // parser dependency to the collector. The extension remains .yaml as the
    // versioned machine-readable release artifact required by V0.2.
    let matrix: CoverageMatrix = serde_json::from_str(MATRIX).context("invalid coverage matrix")?;
    validate_matrix(&matrix)?;
    Ok(matrix)
}

pub fn planned_coverage_report() -> Result<CoverageReport> {
    let matrix = coverage_matrix()?;
    let classification_counts = classification_counts(&matrix.scenarios);
    Ok(CoverageReport {
        schema_version: COVERAGE_SCHEMA,
        matrix_schema_version: matrix.schema_version,
        generated_at: Utc::now(),
        profile: "planned".to_owned(),
        repeat: 0,
        scenario_count: matrix.scenarios.len(),
        classification_counts,
        status: "not_run".to_owned(),
        scenarios: matrix
            .scenarios
            .into_iter()
            .map(|entry| CoverageScenarioResult {
                id: entry.id,
                classification: entry.classification,
                seed: entry.seeds.first().copied(),
                runtime_ms: 0,
                forge_run_id: None,
                lens_run_id: None,
                status: "not_run".to_owned(),
                failure: None,
                deferred_reason: None,
            })
            .collect(),
    })
}

pub async fn verify(
    store: &Store,
    base_url: String,
    profile: VerificationProfile,
    repeat: u32,
    cancellation: CancellationToken,
) -> Result<CoverageReport> {
    if repeat == 0 {
        return Err(anyhow!("repeat must be at least one"));
    }
    let matrix = coverage_matrix()?;
    let entries = matrix
        .scenarios
        .iter()
        .filter(|entry| profile.includes(entry))
        .cloned()
        .collect::<Vec<_>>();
    let mut scenarios = Vec::with_capacity(entries.len() * repeat as usize);

    for _round in 0..repeat {
        for entry in &entries {
            if cancellation.is_cancelled() {
                scenarios.push(failed_result(
                    entry,
                    None,
                    0,
                    "cancelled before coverage scenario started",
                ));
                continue;
            }
            let seed = entry.seeds.first().copied();
            let started = Instant::now();
            if entry.classification == "forge-owned" {
                scenarios.push(
                    verify_forge_owned(entry, &base_url, cancellation.clone(), started).await,
                );
                continue;
            }

            if entry
                .assertions
                .iter()
                .any(|assertion| assertion == "lifecycle_soak")
            {
                scenarios.push(
                    verify_lifecycle_soak(
                        entry,
                        store,
                        &base_url,
                        seed,
                        cancellation.clone(),
                        started,
                    )
                    .await,
                );
                continue;
            }

            if entry
                .assertions
                .iter()
                .any(|assertion| assertion == "eight_concurrent_lanes")
            {
                scenarios.push(
                    verify_eight_concurrent_lanes(
                        entry,
                        store,
                        &base_url,
                        seed,
                        cancellation.clone(),
                        started,
                    )
                    .await,
                );
                continue;
            }

            if entry
                .assertions
                .iter()
                .any(|assertion| assertion == "replay_provenance_diff")
            {
                scenarios.push(
                    verify_replay_provenance_diff(
                        entry,
                        store,
                        &base_url,
                        seed,
                        cancellation.clone(),
                        started,
                    )
                    .await,
                );
                continue;
            }

            if entry
                .assertions
                .iter()
                .any(|assertion| assertion == "concurrent_run_isolation")
            {
                scenarios.push(
                    verify_concurrent_run_isolation(
                        entry,
                        store,
                        &base_url,
                        seed,
                        cancellation.clone(),
                        started,
                    )
                    .await,
                );
                continue;
            }

            let acceptance = if entry.classification == "supported-forge-pass" {
                LabAcceptance::ForgePass
            } else {
                LabAcceptance::LensLocalAssertion
            };
            let options = LabRunOptions::new(base_url.clone(), entry.id.clone(), seed)
                .create_project(true)
                .acceptance(acceptance)
                .lifecycle_checks(
                    entry
                        .assertions
                        .iter()
                        .any(|assertion| assertion == "stale_capability_rejected"),
                );
            match super::run(store, options, cancellation.clone()).await {
                Ok(result) => {
                    let failure = validate_result(entry, &result, store).err();
                    scenarios.push(CoverageScenarioResult {
                        id: entry.id.clone(),
                        classification: entry.classification.clone(),
                        seed,
                        runtime_ms: started.elapsed().as_millis(),
                        forge_run_id: Some(result.forge_run_id),
                        lens_run_id: Some(result.run_id),
                        status: if failure.is_some() {
                            "failed".to_owned()
                        } else {
                            "passed".to_owned()
                        },
                        // `036-custom-rest-post` now receives its body template through
                        // Forge's public manifest. Do not turn a historical contract gap
                        // into deferred metadata for a current verification result.
                        deferred_reason: None,
                        failure: failure.map(|error| bounded_failure(&error.to_string())),
                    });
                }
                Err(error) => scenarios.push(failed_result(
                    entry,
                    seed,
                    started.elapsed().as_millis(),
                    &error.to_string(),
                )),
            }
        }
    }
    let status = if scenarios.iter().all(|scenario| scenario.status == "passed") {
        "passed"
    } else {
        "failed"
    };
    Ok(CoverageReport {
        schema_version: COVERAGE_SCHEMA,
        matrix_schema_version: matrix.schema_version,
        generated_at: Utc::now(),
        profile: profile.as_str().to_owned(),
        repeat,
        scenario_count: scenarios.len(),
        classification_counts: classification_counts(&matrix.scenarios),
        status: status.to_owned(),
        scenarios,
    })
}

pub fn coverage_markdown(report: &CoverageReport) -> String {
    let mut markdown = format!(
        "# FQDN Lens Forge coverage\n\nStatus: {}\n\nProfile: {}\n\nRuns: {}\n\n",
        report.status, report.profile, report.scenario_count
    );
    markdown.push_str("## Classification\n\n| Classification | Count |\n|---|---:|\n");
    for (classification, count) in &report.classification_counts {
        markdown.push_str(&format!("| {classification} | {count} |\n"));
    }
    markdown.push_str("\n## Scenario results\n\n| Scenario | Classification | Seed | Status | Forge run | Lens run | Runtime ms | Failure / deferred reason |\n|---|---|---:|---|---|---|---:|---|\n");
    for scenario in &report.scenarios {
        let detail = scenario
            .failure
            .as_deref()
            .or(scenario.deferred_reason.as_deref())
            .unwrap_or("");
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            scenario.id,
            scenario.classification,
            scenario
                .seed
                .map_or_else(|| "-".to_owned(), |seed| seed.to_string()),
            scenario.status,
            scenario.forge_run_id.as_deref().unwrap_or("-"),
            scenario
                .lens_run_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            scenario.runtime_ms,
            detail.replace('|', "\\|")
        ));
    }
    markdown
}

pub fn write_coverage_report(report: &CoverageReport, format: &str, output: &Path) -> Result<()> {
    let rendered = match format {
        "json" => serde_json::to_vec_pretty(report)?,
        "markdown" => coverage_markdown(report).into_bytes(),
        _ => return Err(anyhow!("coverage format must be json or markdown")),
    };
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, rendered)?;
    Ok(())
}

fn validate_matrix(matrix: &CoverageMatrix) -> Result<()> {
    if matrix.scenarios.len() != 114 {
        return Err(anyhow!(
            "coverage matrix must contain exactly 114 scenarios"
        ));
    }
    let allowed = BTreeSet::from([
        "supported-forge-pass",
        "supported-lens-local",
        "safe-rejection",
        "forge-owned",
        "public-contract-gap",
    ]);
    let mut seen = BTreeSet::new();
    for entry in &matrix.scenarios {
        if !seen.insert(&entry.id) || !allowed.contains(entry.classification.as_str()) {
            return Err(anyhow!(
                "coverage matrix contains an invalid or duplicate scenario"
            ));
        }
        if entry.seeds.is_empty()
            || entry.verifier_profile.is_empty()
            || entry.assertions.is_empty()
        {
            return Err(anyhow!(
                "coverage matrix contains an incomplete scenario entry"
            ));
        }
    }
    let counts = classification_counts(&matrix.scenarios);
    if counts.get("safe-rejection") != Some(&12)
        || counts.get("forge-owned") != Some(&1)
        || counts
            .get("supported-forge-pass")
            .copied()
            .unwrap_or_default()
            + counts
                .get("supported-lens-local")
                .copied()
                .unwrap_or_default()
            != 101
    {
        return Err(anyhow!(
            "coverage matrix classification targets do not satisfy V0.2"
        ));
    }
    Ok(())
}

fn classification_counts(entries: &[CoverageEntry]) -> BTreeMap<String, usize> {
    entries.iter().fold(BTreeMap::new(), |mut counts, entry| {
        *counts.entry(entry.classification.clone()).or_default() += 1;
        counts
    })
}

fn validate_result(entry: &CoverageEntry, result: &LabRunResult, store: &Store) -> Result<()> {
    let local_run = store.get_run(result.run_id)?;
    if local_run.finished_at.is_none() {
        return Err(anyhow!("Lens run did not reach a terminal state"));
    }
    match entry.classification.as_str() {
        "supported-forge-pass" => {
            if result.verdict.as_deref() != Some("passed") {
                return Err(anyhow!("Forge verdict was not passed"));
            }
        }
        "supported-lens-local" => {
            if !matches!(
                local_run.status,
                RunStatus::Succeeded
                    | RunStatus::Partial
                    | RunStatus::Failed
                    | RunStatus::Cancelled
            ) {
                return Err(anyhow!("Lens-local result has a non-terminal run status"));
            }
            if entry
                .assertions
                .iter()
                .any(|assertion| assertion == "stale_capability_rejected")
                && (result.lifecycle.get("status").and_then(Value::as_str) != Some("passed")
                    || result
                        .lifecycle
                        .get("stale_access_rejected")
                        .and_then(Value::as_bool)
                        != Some(true)
                    || result.lifecycle.get("deleted").and_then(Value::as_bool) != Some(true))
            {
                return Err(anyhow!(
                    "Lab lifecycle control checks were incomplete: {}",
                    result.lifecycle
                ));
            }
        }
        "safe-rejection" => {
            let statuses = store.list_source_statuses(result.run_id)?;
            if result.status != "safe_rejection"
                || statuses.is_empty()
                || statuses.iter().any(|status| {
                    status.state != SourceState::Skipped
                        || status.requests != 0
                        || status.retries != 0
                        || status.error_code.as_deref() != Some("strict_direct_proxy_rejected")
                })
                || audit_has_side_effect(&result.audit)
            {
                return Err(anyhow!(
                    "strict direct safe rejection was not side-effect free"
                ));
            }
        }
        "forge-owned" | "public-contract-gap" => {
            return Err(anyhow!("invalid Lens run classification"));
        }
        _ => return Err(anyhow!("unknown coverage classification")),
    }
    Ok(())
}

fn audit_has_side_effect(audit: &Value) -> bool {
    audit
        .get("requests")
        .and_then(Value::as_array)
        .is_some_and(|requests| {
            requests.iter().any(|request| {
                matches!(
                    request.get("event_type").and_then(Value::as_str),
                    Some("source_request") | Some("proxy_request") | Some("quota_decision")
                ) || request.get("consumed").and_then(Value::as_bool) == Some(true)
            })
        })
}

async fn verify_concurrent_run_isolation(
    entry: &CoverageEntry,
    store: &Store,
    base_url: &str,
    seed: Option<u64>,
    cancellation: CancellationToken,
    started: Instant,
) -> CoverageScenarioResult {
    let make_options = || {
        LabRunOptions::new(base_url.to_owned(), entry.id.clone(), seed)
            .create_project(true)
            .acceptance(LabAcceptance::LensLocalAssertion)
    };
    let (left, right) = tokio::join!(
        super::run(store, make_options(), cancellation.clone()),
        super::run(store, make_options(), cancellation.clone())
    );
    match (left, right) {
        (Ok(left), Ok(right)) => {
            let valid = left.run_id != right.run_id
                && left.forge_run_id != right.forge_run_id
                && left.project_id == right.project_id
                && validate_result(entry, &left, store).is_ok()
                && validate_result(entry, &right, store).is_ok();
            CoverageScenarioResult {
                id: entry.id.clone(),
                classification: entry.classification.clone(),
                seed,
                runtime_ms: started.elapsed().as_millis(),
                forge_run_id: Some(left.forge_run_id),
                lens_run_id: Some(left.run_id),
                status: if valid { "passed" } else { "failed" }.to_owned(),
                failure: (!valid).then(|| {
                    "concurrent runs did not preserve distinct run/capability/evidence state"
                        .to_owned()
                }),
                deferred_reason: None,
            }
        }
        (left, right) => failed_result(
            entry,
            seed,
            started.elapsed().as_millis(),
            &format!(
                "concurrent run failure: left={} right={}",
                left.err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string()),
                right
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error.to_string())
            ),
        ),
    }
}

async fn verify_lifecycle_soak(
    entry: &CoverageEntry,
    store: &Store,
    base_url: &str,
    seed: Option<u64>,
    cancellation: CancellationToken,
    started: Instant,
) -> CoverageScenarioResult {
    let mut results = Vec::new();
    for _ in 0..8 {
        match super::run(
            store,
            LabRunOptions::new(base_url.to_owned(), entry.id.clone(), seed)
                .create_project(true)
                .acceptance(LabAcceptance::LensLocalAssertion)
                .lifecycle_checks(true),
            cancellation.clone(),
        )
        .await
        {
            Ok(result) => results.push(result),
            Err(error) => {
                return failed_result(
                    entry,
                    seed,
                    started.elapsed().as_millis(),
                    &error.to_string(),
                );
            }
        }
    }
    let valid = results.iter().all(|result| {
        result.lifecycle.get("status").and_then(Value::as_str) == Some("passed")
            && store
                .get_run(result.run_id)
                .is_ok_and(|run| run.finished_at.is_some())
    });
    CoverageScenarioResult {
        id: entry.id.clone(),
        classification: entry.classification.clone(),
        seed,
        runtime_ms: started.elapsed().as_millis(),
        forge_run_id: results.last().map(|result| result.forge_run_id.clone()),
        lens_run_id: results.last().map(|result| result.run_id),
        status: if valid { "passed" } else { "failed" }.to_owned(),
        failure: (!valid).then(|| "lifecycle soak left a non-terminal local run".to_owned()),
        deferred_reason: None,
    }
}

async fn verify_eight_concurrent_lanes(
    entry: &CoverageEntry,
    store: &Store,
    base_url: &str,
    seed: Option<u64>,
    cancellation: CancellationToken,
    started: Instant,
) -> CoverageScenarioResult {
    let policy = SchedulerPolicy {
        source_concurrency: 8,
        ..SchedulerPolicy::default()
    };
    let runs = join_all((0..8).map(|_| {
        super::run(
            store,
            LabRunOptions::new(base_url.to_owned(), entry.id.clone(), seed)
                .create_project(true)
                .acceptance(LabAcceptance::LensLocalAssertion)
                .scheduler_policy(policy.clone()),
            cancellation.clone(),
        )
    }))
    .await;
    let results = runs
        .into_iter()
        .collect::<Result<Vec<_>>>()
        .map_err(|error| error.to_string());
    match results {
        Ok(results) => {
            let lens_ids = results
                .iter()
                .map(|result| result.run_id)
                .collect::<BTreeSet<_>>();
            let forge_ids = results
                .iter()
                .map(|result| result.forge_run_id.clone())
                .collect::<BTreeSet<_>>();
            let valid = results.len() == 8
                && lens_ids.len() == 8
                && forge_ids.len() == 8
                && results.iter().all(|result| {
                    store
                        .get_run(result.run_id)
                        .is_ok_and(|run| run.finished_at.is_some())
                });
            CoverageScenarioResult {
                id: entry.id.clone(),
                classification: entry.classification.clone(),
                seed,
                runtime_ms: started.elapsed().as_millis(),
                forge_run_id: results.first().map(|result| result.forge_run_id.clone()),
                lens_run_id: results.first().map(|result| result.run_id),
                status: if valid { "passed" } else { "failed" }.to_owned(),
                failure: (!valid).then(|| "eight concurrent lanes were not isolated".to_owned()),
                deferred_reason: None,
            }
        }
        Err(error) => failed_result(entry, seed, started.elapsed().as_millis(), &error),
    }
}

async fn verify_replay_provenance_diff(
    entry: &CoverageEntry,
    store: &Store,
    base_url: &str,
    seed: Option<u64>,
    cancellation: CancellationToken,
    started: Instant,
) -> CoverageScenarioResult {
    let normal = || {
        LabRunOptions::new(base_url.to_owned(), entry.id.clone(), seed)
            .create_project(true)
            .acceptance(LabAcceptance::LensLocalAssertion)
    };
    let first = match super::run(store, normal(), cancellation.clone()).await {
        Ok(result) => result,
        Err(error) => {
            return failed_result(
                entry,
                seed,
                started.elapsed().as_millis(),
                &error.to_string(),
            );
        }
    };
    let second = match super::run(store, normal(), cancellation.clone()).await {
        Ok(result) => result,
        Err(error) => {
            return failed_result(
                entry,
                seed,
                started.elapsed().as_millis(),
                &error.to_string(),
            );
        }
    };
    let changed_policy = SchedulerPolicy {
        source_concurrency: 1,
        ..SchedulerPolicy::default()
    };
    let third = match super::run(
        store,
        normal().scheduler_policy(changed_policy),
        cancellation,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return failed_result(
                entry,
                seed,
                started.elapsed().as_millis(),
                &error.to_string(),
            );
        }
    };
    let valid = (|| -> Result<bool> {
        let first_run = store.get_run(first.run_id)?;
        let second_run = store.get_run(second.run_id)?;
        let third_run = store.get_run(third.run_id)?;
        let same_fingerprint =
            first_run.fingerprint.is_some() && first_run.fingerprint == second_run.fingerprint;
        let different_fingerprint = first_run.fingerprint != third_run.fingerprint;
        let first_evidence = store.list_run_evidence(first.run_id)?;
        let second_evidence = store.list_run_evidence(second.run_id)?;
        let provenance_preserved = !first_evidence.is_empty()
            && first_evidence
                .iter()
                .all(|evidence| !evidence.source_kind.is_empty())
            && second_evidence
                .iter()
                .all(|evidence| !evidence.response_digest.is_empty());
        Ok(same_fingerprint && different_fingerprint && provenance_preserved)
    })()
    .unwrap_or(false);
    CoverageScenarioResult {
        id: entry.id.clone(),
        classification: entry.classification.clone(),
        seed,
        runtime_ms: started.elapsed().as_millis(),
        forge_run_id: Some(first.forge_run_id),
        lens_run_id: Some(first.run_id),
        status: if valid { "passed" } else { "failed" }.to_owned(),
        failure: (!valid).then(|| "replay fingerprint or provenance invariants failed".to_owned()),
        deferred_reason: None,
    }
}

async fn verify_forge_owned(
    entry: &CoverageEntry,
    base_url: &str,
    cancellation: CancellationToken,
    started: Instant,
) -> CoverageScenarioResult {
    let result = async {
        let base = super::checked_url(base_url)?;
        let mut egress = EgressPolicy::default();
        super::allow_url_path(&mut egress, &base, "/api/analysis/coverage")?;
        let policy = SchedulerPolicy::default();
        let waiter = Arc::new(VirtualWaiter::default());
        let context = super::request_context(
            policy.clone(),
            cancellation,
            waiter,
            Arc::new(super::forge_clock(None)),
            egress,
        );
        let http = BoundedHttpClient::new(policy)
            .map_err(|_| anyhow!("could not initialize coverage transport"))?;
        let url = super::public_url(&base, "/api/analysis/coverage")?;
        let mut status = SourceStatus::pending("forge-coverage");
        let mut waited = 0;
        let response = http
            .send_with_retry(
                http.get(url),
                RetryOptions {
                    allow_retry: false,
                    virtual_wait_header: None,
                    quota_identity: None,
                },
                &context,
                &mut status,
                &mut waited,
            )
            .await
            .map_err(|error| anyhow!("Forge coverage check failed: {error}"))?;
        let value: Value = serde_json::from_slice(&response.body)
            .context("Forge coverage response was invalid")?;
        let count = value
            .pointer("/scenario_count")
            .or_else(|| value.pointer("/report/scenario_count"))
            .or_else(|| value.pointer("/data/summary/scenario_count"))
            .and_then(Value::as_u64);
        if count != Some(114) {
            return Err(anyhow!(
                "Forge coverage report did not confirm 114 scenarios"
            ));
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => CoverageScenarioResult {
            id: entry.id.clone(),
            classification: entry.classification.clone(),
            seed: entry.seeds.first().copied(),
            runtime_ms: started.elapsed().as_millis(),
            forge_run_id: None,
            lens_run_id: None,
            status: "passed".to_owned(),
            failure: None,
            deferred_reason: None,
        },
        Err(error) => failed_result(
            entry,
            entry.seeds.first().copied(),
            started.elapsed().as_millis(),
            &error.to_string(),
        ),
    }
}

fn failed_result(
    entry: &CoverageEntry,
    seed: Option<u64>,
    runtime_ms: u128,
    failure: &str,
) -> CoverageScenarioResult {
    CoverageScenarioResult {
        id: entry.id.clone(),
        classification: entry.classification.clone(),
        seed,
        runtime_ms,
        forge_run_id: None,
        lens_run_id: None,
        status: "failed".to_owned(),
        failure: Some(bounded_failure(failure)),
        deferred_reason: None,
    }
}

fn bounded_failure(value: &str) -> String {
    redact_sensitive(value).chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_complete_and_classified() {
        let matrix = coverage_matrix().expect("matrix");
        assert_eq!(matrix.scenarios.len(), 114);
        assert_eq!(
            classification_counts(&matrix.scenarios)["safe-rejection"],
            12
        );
    }

    #[test]
    fn proxy_audit_records_are_side_effects() {
        assert!(audit_has_side_effect(&serde_json::json!({
            "requests": [{"event_type": "proxy_request", "consumed": false}]
        })));
        assert!(!audit_has_side_effect(&serde_json::json!({"requests": []})));
    }
}
