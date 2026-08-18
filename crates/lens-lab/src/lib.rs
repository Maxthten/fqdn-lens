//! FQDN Forge external-collector bridge.
//!
//! This crate uses only FQDN Forge's public run, manifest, source,
//! submission, report, and audit HTTP interfaces. It never opens scenario,
//! truth, or fixture files and it is not used by the production core.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use lens_core::domain::normalize_root_domain;
use lens_core::evidence::RunFingerprint;
use lens_core::evidence::{RunMode, RunStatus};
use lens_core::scheduler::{
    BoundedHttpClient, CachePolicy, CollectionContext, CollectionScheduler, EgressPolicy,
    FixedClock, QuotaRule, QuotaScope, RetryOptions, SchedulerPolicy, SchedulerRuntime,
    VirtualWaiter, hex_digest,
};
use lens_core::source::{
    DynSourceAdapter, HttpMethod, HttpSourceAdapter, KeyRequirement, PaginationState,
    ParserProfile, SourceKind, SourceMetadata, SourceRequestConfig, SourceState, SourceStatus,
};
use lens_core::{QueryService, RunFinalization, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

pub mod coverage;

#[derive(Clone, Debug)]
pub struct LabRunOptions {
    pub base_url: String,
    pub scenario_id: String,
    pub seed: Option<u64>,
    pub scheduler_policy: SchedulerPolicy,
    pub project_id: Option<Uuid>,
    pub create_project: bool,
    pub acceptance: LabAcceptance,
    pub lifecycle_checks: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabAcceptance {
    ForgePass,
    LensLocalAssertion,
}

impl LabRunOptions {
    #[must_use]
    pub fn new(base_url: String, scenario_id: String, seed: Option<u64>) -> Self {
        Self {
            base_url,
            scenario_id,
            seed,
            scheduler_policy: SchedulerPolicy::default(),
            // Library callers opt into an explicit transient project. The CLI
            // requires the user to pass either --project or --create-project.
            project_id: None,
            create_project: true,
            acceptance: LabAcceptance::ForgePass,
            lifecycle_checks: false,
        }
    }

    #[must_use]
    pub fn for_project(mut self, project_id: Uuid) -> Self {
        self.project_id = Some(project_id);
        self.create_project = false;
        self
    }

    #[must_use]
    pub fn create_project(mut self, enabled: bool) -> Self {
        self.create_project = enabled;
        self
    }

    #[must_use]
    pub fn acceptance(mut self, acceptance: LabAcceptance) -> Self {
        self.acceptance = acceptance;
        self
    }

    #[must_use]
    pub fn lifecycle_checks(mut self, enabled: bool) -> Self {
        self.lifecycle_checks = enabled;
        self
    }

    #[must_use]
    pub fn scheduler_policy(mut self, policy: SchedulerPolicy) -> Self {
        self.scheduler_policy = policy;
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LabRunResult {
    pub project_id: Uuid,
    pub run_id: Uuid,
    pub forge_run_id: String,
    pub target_domain: String,
    pub status: String,
    pub findings: usize,
    pub evidence: usize,
    pub virtual_waited_ms: u64,
    pub verdict: Option<String>,
    pub report: Value,
    pub audit: Value,
    pub lifecycle: Value,
}

pub async fn run(
    store: &Store,
    options: LabRunOptions,
    cancel: CancellationToken,
) -> Result<LabRunResult> {
    if options.project_id.is_some() == options.create_project {
        return Err(anyhow!(
            "choose exactly one Lab project mode: an existing project or explicit project creation"
        ));
    }
    let base_url = checked_url(&options.base_url)?;
    let waiter = Arc::new(VirtualWaiter::default());
    let initial_clock = Arc::new(forge_clock(None));
    let mut base_policy = EgressPolicy::default();
    allow_url_path(&mut base_policy, &base_url, "/api/runs")?;
    let control_context = request_context(
        options.scheduler_policy.clone(),
        cancel.clone(),
        waiter.clone(),
        initial_clock,
        base_policy,
    );
    let http = BoundedHttpClient::new(options.scheduler_policy.clone())
        .map_err(|_| anyhow!("could not initialize strict-passive HTTP transport"))?;
    let created = create_run(
        &http,
        &control_context,
        base_url.as_str(),
        &options.scenario_id,
        options.seed,
    )
    .await?;

    let manifest_context = request_context(
        options.scheduler_policy.clone(),
        cancel.clone(),
        waiter.clone(),
        Arc::new(forge_clock(None)),
        control_egress(&base_url, &created, None)?,
    );
    let manifest = fetch_manifest(&http, &manifest_context, &created).await?;
    let root_domain = normalize_root_domain(&manifest.target_domain)
        .map_err(|_| anyhow!("Lab manifest supplied an invalid target domain"))?;
    let project = match options.project_id {
        Some(project_id) => {
            let project = store.get_project(project_id)?;
            if project.root_domain != root_domain {
                return Err(anyhow!(
                    "Lab manifest root domain does not exactly match the selected project"
                ));
            }
            project
        }
        // Lab coverage runs may execute several public scenarios for the same
        // synthetic root. Reuse that explicit strict-passive project while
        // retaining a distinct local run and evidence set for every scenario.
        None => store.create_project(&root_domain)?,
    };
    let local_run = store.create_run(project.id, RunMode::Lab, "fqdn_forge_manifest")?;
    let scheduler_policy = scheduler_policy_from_manifest(&options.scheduler_policy, &manifest)?;
    store.set_run_fingerprint(
        local_run.id,
        &run_fingerprint(&root_domain, &manifest, &scheduler_policy)?,
    )?;

    // A proxy or CONNECT manifest is a safety test, not an instruction to
    // weaken Lens's strict-direct collector. Reject it before creating source
    // adapters, before reserving quota, and before any source request can be
    // built. Control/audit reads remain allowed through the per-run policy so
    // the Lab can prove the absence of side effects.
    if !manifest.network_profile.is_direct() {
        let statuses = manifest
            .sources
            .iter()
            .map(|source| SourceStatus {
                source_id: source.source_id.clone(),
                state: SourceState::Skipped,
                requests: 0,
                pages: 0,
                results_received: 0,
                results_accepted: 0,
                results_filtered: 0,
                retries: 0,
                cache_hits: 0,
                cache_misses: 0,
                quota_rejections: 0,
                error_code: Some("strict_direct_proxy_rejected".to_owned()),
                retry_after_ms: None,
            })
            .collect::<Vec<_>>();
        store.finalize_run(
            local_run.id,
            RunFinalization {
                status: RunStatus::Failed,
                diagnostics_summary: Some("strict_direct_proxy_rejected"),
                source_statuses: statuses,
                evidence: &[],
            },
        )?;
        let audit_path = format!("/api/runs/{}/requests", created.run_id);
        let audit = get_json(&http, &manifest_context, &created, &audit_path).await?;
        let lifecycle = if options.lifecycle_checks {
            run_lifecycle_checks(&http, &manifest_context, &created).await?
        } else {
            json!({"status":"not_applicable"})
        };
        return Ok(LabRunResult {
            project_id: project.id,
            run_id: local_run.id,
            forge_run_id: created.run_id,
            target_domain: root_domain,
            status: "safe_rejection".to_owned(),
            findings: 0,
            evidence: 0,
            virtual_waited_ms: waiter.waited_ms().await,
            verdict: Some("safe_rejection".to_owned()),
            report: json!({
                "status": "safe_rejection",
                "reason": "strict_direct_proxy_rejected",
                "schema_version": "fqdn-lens.safe-rejection.v1"
            }),
            audit: redact_value(audit),
            lifecycle: redact_value(lifecycle),
        });
    }

    let clock = Arc::new(forge_clock(manifest.virtual_now));
    let egress = match run_egress(&base_url, &created, &manifest) {
        Ok(egress) => egress,
        Err(error) => {
            finalize_setup_failure(store, local_run.id, &error)?;
            return Err(error);
        }
    };
    let adapters = match manifest
        .sources
        .iter()
        .map(|source| make_adapter(source, &created.run_id, &root_domain))
        .collect::<Result<Vec<_>>>()
    {
        Ok(adapters) => adapters,
        Err(error) => {
            finalize_setup_failure(store, local_run.id, &error)?;
            return Err(error);
        }
    };
    let collection_cancel = cancel.clone();
    let scheduler = match CollectionScheduler::with_http(
        scheduler_policy.clone(),
        collection_cancel,
        waiter.clone(),
        clock,
        egress,
        http.with_policy(scheduler_policy.clone()),
    ) {
        Ok(scheduler) => scheduler,
        Err(_) => {
            let error = anyhow!("could not initialize strict-passive scheduler");
            finalize_setup_failure(store, local_run.id, &error)?;
            return Err(error);
        }
    };
    let outcome = scheduler
        .collect(local_run.id, &root_domain, false, adapters)
        .await;

    let operation = async {
        let submission = submission_body(
            &root_domain,
            &manifest.schema_version,
            &local_run.id.to_string(),
            &outcome,
        );
        if serde_json::to_vec(&submission)?.len() > manifest.submission.max_bytes {
            if options.acceptance == LabAcceptance::LensLocalAssertion {
                return Ok::<(Value, Value), anyhow::Error>((
                    json!({
                        "status": "deferred",
                        "reason": "public submission schema byte limit",
                        "schema_version": "fqdn-lens.local-assertion.v1"
                    }),
                    json!({
                        "status": "not_requested",
                        "reason": "public submission schema byte limit"
                    }),
                ));
            }
            return Err(anyhow!("submission exceeds the manifest byte limit"));
        }
        let post_manifest_context = request_context(
            scheduler_policy.clone(),
            cancel.clone(),
            waiter.clone(),
            Arc::new(forge_clock(manifest.virtual_now)),
            run_egress(&base_url, &created, &manifest)?,
        );
        if let Err(error) = submit(
            &http,
            &post_manifest_context,
            &created,
            &manifest.submission.url,
            &submission,
        )
        .await
        {
            if options.acceptance == LabAcceptance::LensLocalAssertion {
                return Ok::<(Value, Value), anyhow::Error>(local_deferred(&error.to_string()));
            }
            return Err(error);
        }
        let report =
            match get_json(&http, &post_manifest_context, &created, &created.report_url).await {
                Ok(report) => report,
                Err(error) if options.acceptance == LabAcceptance::LensLocalAssertion => {
                    return Ok::<(Value, Value), anyhow::Error>(local_deferred(&error.to_string()));
                }
                Err(error) => return Err(error),
            };
        let audit_path = format!("/api/runs/{}/requests", created.run_id);
        let audit = get_json(&http, &post_manifest_context, &created, &audit_path).await?;
        Ok::<(Value, Value), anyhow::Error>((report, audit))
    }
    .await;

    let (report, audit) = match operation {
        Ok(values) => {
            store.finalize_run(
                local_run.id,
                RunFinalization {
                    status: outcome.status.clone(),
                    diagnostics_summary: outcome.diagnostics_summary.as_deref(),
                    source_statuses: outcome.statuses.values().cloned().collect(),
                    evidence: &outcome.evidence,
                },
            )?;
            values
        }
        Err(error) => {
            let terminal = terminal_failure_status(&outcome.status);
            store.finalize_run(
                local_run.id,
                RunFinalization {
                    status: terminal,
                    diagnostics_summary: Some(&error.to_string()),
                    source_statuses: outcome.statuses.values().cloned().collect(),
                    evidence: &outcome.evidence,
                },
            )?;
            return Err(error);
        }
    };
    let query = QueryService::new(store);
    let findings = query
        .list_run_results(local_run.id, lens_core::ResultScope::Accepted)?
        .len();
    let verdict = report
        .get("status")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            report
                .pointer("/report/status")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let lifecycle = if options.lifecycle_checks {
        let lifecycle_context = request_context(
            scheduler_policy.clone(),
            cancel.clone(),
            waiter.clone(),
            Arc::new(forge_clock(manifest.virtual_now)),
            control_egress(&base_url, &created, Some(&manifest))?,
        );
        run_lifecycle_checks(&http, &lifecycle_context, &created).await?
    } else {
        json!({"status":"not_requested"})
    };
    Ok(LabRunResult {
        project_id: project.id,
        run_id: local_run.id,
        forge_run_id: created.run_id,
        target_domain: root_domain,
        status: format!("{:?}", outcome.status).to_ascii_lowercase(),
        findings,
        evidence: outcome.evidence.len(),
        virtual_waited_ms: outcome.virtual_waited_ms.max(waiter.waited_ms().await),
        verdict,
        report: redact_value(report),
        audit: redact_value(audit),
        lifecycle: redact_value(lifecycle),
    })
}

fn finalize_setup_failure(store: &Store, run_id: Uuid, error: &anyhow::Error) -> Result<()> {
    store.finalize_run(
        run_id,
        RunFinalization {
            status: RunStatus::Failed,
            diagnostics_summary: Some(&error.to_string()),
            source_statuses: Vec::new(),
            evidence: &[],
        },
    )?;
    Ok(())
}

fn local_deferred(reason: &str) -> (Value, Value) {
    (
        json!({
            "status": "deferred",
            "reason": lens_core::scheduler::redact_sensitive(reason),
            "schema_version": "fqdn-lens.local-assertion.v1"
        }),
        json!({
            "status": "not_requested",
            "reason": lens_core::scheduler::redact_sensitive(reason)
        }),
    )
}

fn terminal_failure_status(outcome: &RunStatus) -> RunStatus {
    match outcome {
        RunStatus::Cancelled => RunStatus::Cancelled,
        RunStatus::Partial => RunStatus::Partial,
        RunStatus::Failed => RunStatus::Failed,
        RunStatus::Queued | RunStatus::Running | RunStatus::Succeeded => RunStatus::Failed,
    }
}

fn scheduler_policy_from_manifest(
    base: &SchedulerPolicy,
    manifest: &LabManifest,
) -> Result<SchedulerPolicy> {
    let mut policy = base.clone();
    if manifest.transport_profile.client_visible_decoded_limit > 0 {
        policy.max_body_bytes = policy
            .max_body_bytes
            .min(manifest.transport_profile.client_visible_decoded_limit);
    }
    policy.quota_rules = manifest
        .quota_profiles
        .iter()
        .map(|profile| {
            let scope = match profile.scope {
                ManifestQuotaScope::PerSource => QuotaScope::PerSource,
                ManifestQuotaScope::PerKey => QuotaScope::PerKey,
                ManifestQuotaScope::GlobalRun => QuotaScope::GlobalRun,
                ManifestQuotaScope::Other => {
                    return Err(anyhow!("manifest contains an unsupported quota scope"));
                }
            };
            Ok(QuotaRule {
                source_id: profile.source_id.clone(),
                scope,
                limit: profile.client_visible_limit,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Cache scope is explicitly run-local. It is never shared across root
    // domains or runs, and the cache key excludes all secret material.
    policy.cache_policy = CachePolicy::RunLocal;
    Ok(policy)
}

fn run_fingerprint(
    root_domain: &str,
    manifest: &LabManifest,
    policy: &SchedulerPolicy,
) -> Result<RunFingerprint> {
    let mut source_profile_identifiers = manifest
        .sources
        .iter()
        .map(|source| {
            format!(
                "{}:{}",
                source.source_kind,
                source
                    .parser_profile
                    .map(|profile| format!("{profile:?}").to_ascii_lowercase())
                    .unwrap_or_else(|| SourceKind::from_manifest(&source.source_kind)
                        .as_str()
                        .to_owned())
            )
        })
        .collect::<Vec<_>>();
    source_profile_identifiers.sort();
    let mut source_request_shape_digests = manifest
        .sources
        .iter()
        .map(|source| {
            let shape = json!({
                "id": source.source_id,
                "kind": source.source_kind,
                "parser_profile": source.parser_profile,
                "method": source.method,
                "path_template": source.path_template,
                "required_query": source.required_query,
                "required_headers": source.required_headers,
                "pagination_mode": format!("{:?}", source.pagination_mode),
                "pagination_parameter": source.pagination_parameter,
                "next_page_field": source.next_page_field,
                "body_shape": source.request_body_template.as_ref().or(source.request_body.as_ref()).or(source.body_template.as_ref()).map(body_template_shape),
            });
            serde_json::to_vec(&shape)
                .map(|bytes| hex_digest(&bytes))
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    source_request_shape_digests.sort();
    Ok(RunFingerprint {
        normalized_root_domain: root_domain.to_owned(),
        source_profile_identifiers,
        scheduler_policy_digest: hex_digest(&serde_json::to_vec(policy)?),
        manifest_schema_version: manifest.schema_version.clone(),
        source_request_shape_digests,
        seed: manifest.seed,
    })
}

fn body_template_shape(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::Bool(_) => json!("boolean"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(values) => Value::Array(values.iter().map(body_template_shape).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), body_template_shape(value)))
                .collect(),
        ),
    }
}

fn forge_clock(value: Option<DateTime<Utc>>) -> FixedClock {
    // Forge versions prior to exposing this optional field use this published
    // deterministic Lab epoch. It is deliberately not a wall-clock fallback.
    let default = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixed Lab epoch")
        .with_timezone(&Utc);
    FixedClock::new(value.unwrap_or(default))
}

fn request_context(
    policy: SchedulerPolicy,
    cancel: CancellationToken,
    waiter: Arc<VirtualWaiter>,
    clock: Arc<FixedClock>,
    egress: EgressPolicy,
) -> CollectionContext {
    CollectionContext {
        cancel,
        policy,
        waiter,
        clock,
        egress,
        runtime: Arc::new(SchedulerRuntime::default()),
    }
}

fn checked_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("Lab base URL is invalid")?;
    lens_core::scheduler::validate_egress_url(&url)
        .map_err(|_| anyhow!("Lab base URL violates strict passive egress policy"))?;
    Ok(url)
}

fn allow_url_path(policy: &mut EgressPolicy, url: &Url, path: &str) -> Result<()> {
    policy
        .allow_url(url, path)
        .map_err(|_| anyhow!("FQDN Forge returned a disallowed loopback destination"))
}

fn public_url(base_url: &Url, path: &str) -> Result<Url> {
    let url = Url::parse(path)
        .or_else(|_| base_url.join(path))
        .context("FQDN Forge returned an invalid URL")?;
    lens_core::scheduler::validate_egress_url(&url)
        .map_err(|_| anyhow!("FQDN Forge returned a non-loopback URL"))?;
    Ok(url)
}

fn control_egress(
    requested_base: &Url,
    created: &CreatedRun,
    manifest: Option<&LabManifest>,
) -> Result<EgressPolicy> {
    let created_base = checked_url(&created.base_url)?;
    let mut policy = EgressPolicy::default();
    allow_url_path(&mut policy, requested_base, "/api/runs")?;
    allow_url_path(&mut policy, &created_base, &created.manifest_url)?;
    allow_url_path(&mut policy, &created_base, &created.report_url)?;
    allow_url_path(
        &mut policy,
        &created_base,
        &format!("/api/runs/{}/reset", created.run_id),
    )?;
    allow_url_path(
        &mut policy,
        &created_base,
        &format!("/api/runs/{}", created.run_id),
    )?;
    allow_url_path(
        &mut policy,
        &created_base,
        &format!("/api/runs/{}/requests", created.run_id),
    )?;
    if let Some(manifest) = manifest {
        let submission = public_url(&created_base, &manifest.submission.url)?;
        allow_url_path(&mut policy, &submission, submission.path())?;
    }
    Ok(policy)
}

fn run_egress(
    requested_base: &Url,
    created: &CreatedRun,
    manifest: &LabManifest,
) -> Result<EgressPolicy> {
    let created_base = checked_url(&created.base_url)?;
    let mut policy = control_egress(requested_base, created, Some(manifest))?;
    for source in &manifest.sources {
        let source_base = checked_url(&source.base_url)?;
        let endpoint = public_url(&source_base, &source.path_template)?;
        allow_url_path(&mut policy, &endpoint, endpoint.path())?;
    }
    // Keep the base authority in the run set even when manifest paths are
    // absolute, as required for the public manifest/report/audit endpoints.
    allow_url_path(&mut policy, &created_base, &created.manifest_url)?;
    Ok(policy)
}

async fn create_run(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    base_url: &str,
    scenario_id: &str,
    seed: Option<u64>,
) -> Result<CreatedRun> {
    let mut body = serde_json::Map::new();
    body.insert(
        "scenario_id".to_owned(),
        Value::String(scenario_id.to_owned()),
    );
    if let Some(seed) = seed {
        body.insert("seed".to_owned(), Value::Number(seed.into()));
    }
    let url = public_url(&checked_url(base_url)?, "/api/runs")?;
    let response = send_control(http, context, http.post(url).json(&body)).await?;
    serde_json::from_slice(&response.body).context("invalid scoped run response")
}

async fn fetch_manifest(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    run: &CreatedRun,
) -> Result<LabManifest> {
    let value = get_json(http, context, run, &run.manifest_url).await?;
    serde_json::from_value(value).context("invalid FQDN Forge manifest")
}

async fn get_json(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    run: &CreatedRun,
    path: &str,
) -> Result<Value> {
    let url = public_url(&checked_url(&run.base_url)?, path)?;
    let response = send_control(
        http,
        context,
        http.get(url)
            .header(&run.run_access_header, &run.run_access_token),
    )
    .await?;
    serde_json::from_slice(&response.body).context("invalid FQDN Forge control response")
}

async fn submit(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    run: &CreatedRun,
    path: &str,
    body: &Value,
) -> Result<()> {
    let url = public_url(&checked_url(&run.base_url)?, path)?;
    let response = send_control(
        http,
        context,
        http.post(url)
            .header(&run.run_access_header, &run.run_access_token)
            .json(body),
    )
    .await?;
    if response.status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("FQDN Forge rejected collector submission"))
    }
}

async fn send_control(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    request: reqwest::RequestBuilder,
) -> Result<lens_core::BoundedResponse> {
    let mut status = SourceStatus::pending("forge-control");
    let mut virtual_waited_ms = 0;
    http.send_with_retry(
        request,
        RetryOptions {
            allow_retry: false,
            virtual_wait_header: None,
            quota_identity: None,
        },
        context,
        &mut status,
        &mut virtual_waited_ms,
    )
    .await
    .map_err(|code| anyhow!("FQDN Forge control request failed: {code}"))
}

/// Reset a public Forge run and rotate the in-memory capability. The old
/// capability is deliberately never returned or persisted by Lens.
pub async fn reset_lab_run(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    access: &mut LabRunAccess,
) -> Result<()> {
    let url = public_url(
        &checked_url(&access.base_url)?,
        &format!("/api/runs/{}/reset", access.run_id),
    )?;
    let response = send_control(
        http,
        context,
        http.post(url).header(&access.header, &access.token),
    )
    .await?;
    let value: Value = serde_json::from_slice(&response.body).context("invalid reset response")?;
    let token = value
        .get("run_access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("reset response omitted rotated capability"))?;
    access.token = token.to_owned();
    Ok(())
}

/// Verify that a capability rotated by `reset_lab_run` cannot read the public
/// manifest. Only the boolean outcome is retained in a coverage report.
pub async fn verify_stale_capability_rejected(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    access: &LabRunAccess,
    stale_token: &str,
) -> Result<()> {
    let url = public_url(
        &checked_url(&access.base_url)?,
        &format!("/api/runs/{}/manifest", access.run_id),
    )?;
    let mut status = SourceStatus::pending("forge-lifecycle-stale-probe");
    let mut waited = 0;
    match http
        .send_with_retry(
            http.get(url).header(&access.header, stale_token),
            RetryOptions {
                allow_retry: false,
                virtual_wait_header: None,
                quota_identity: None,
            },
            context,
            &mut status,
            &mut waited,
        )
        .await
    {
        Err(code) if code == "http_403" => Ok(()),
        Err(_) => Err(anyhow!("stale capability was not rejected with HTTP 403")),
        Ok(_) => Err(anyhow!("stale capability remained usable")),
    }
}

/// Delete a Lab run through its public control endpoint. The current access
/// token remains only in this in-memory value until the request completes.
pub async fn delete_lab_run(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    access: &LabRunAccess,
) -> Result<()> {
    let url = public_url(
        &checked_url(&access.base_url)?,
        &format!("/api/runs/{}", access.run_id),
    )?;
    send_control(
        http,
        context,
        http.delete(url).header(&access.header, &access.token),
    )
    .await?;
    Ok(())
}

async fn run_lifecycle_checks(
    http: &BoundedHttpClient,
    context: &CollectionContext,
    created: &CreatedRun,
) -> Result<Value> {
    let mut access = LabRunAccess {
        base_url: created.base_url.clone(),
        run_id: created.run_id.clone(),
        header: created.run_access_header.clone(),
        token: created.run_access_token.clone(),
    };
    let stale_token = access.token.clone();
    reset_lab_run(http, context, &mut access).await?;
    verify_stale_capability_rejected(http, context, &access, &stale_token).await?;
    delete_lab_run(http, context, &access).await?;
    Ok(json!({
        "status": "passed",
        "reset": true,
        "stale_access_rejected": true,
        "deleted": true
    }))
}

fn make_adapter(
    source: &ManifestSource,
    run_id: &str,
    target_domain: &str,
) -> Result<DynSourceAdapter> {
    let base_url = checked_url(&source.base_url)?;
    let key_requirement = if source.authentication.is_empty() {
        KeyRequirement::None
    } else {
        KeyRequirement::Required
    };
    let metadata = SourceMetadata {
        id: source.source_id.clone(),
        display_name: source.source_label.clone(),
        kind: SourceKind::from_manifest(&source.source_kind),
        key_requirement,
        recursive_support: false,
        passive_only: true,
        default_enabled: true,
    };
    let mut headers = source.authentication.clone();
    // The manifest's explicit header list is authoritative about which values
    // are transport headers. Its credential values remain in memory only.
    headers.retain(|name, value| {
        !value.is_empty()
            && (source
                .required_headers
                .iter()
                .any(|header| header.eq_ignore_ascii_case(name))
                || source
                    .authentication_field_names
                    .iter()
                    .any(|field| field.eq_ignore_ascii_case(name)))
    });
    headers.insert("x-lab-data-profile".to_owned(), "default".to_owned());
    let body_template = source
        .request_body_template
        .clone()
        .or_else(|| source.request_body.clone())
        .or_else(|| source.body_template.clone());
    if source.method == HttpMethod::Post
        && matches!(source.pagination_mode, ManifestPaginationMode::None)
        && body_template.is_none()
    {
        return Err(anyhow!(
            "public_request_body_template_missing: strict Lens will not infer a POST body"
        ));
    }
    let config = SourceRequestConfig {
        metadata,
        source_kind: source.source_kind.clone(),
        parser_profile: source.parser_profile,
        base_url: base_url.to_string().trim_end_matches('/').to_owned(),
        method: source.method.clone(),
        path_template: source.path_template.clone(),
        target_domain: target_domain.to_owned(),
        required_query: source.required_query.clone(),
        headers,
        virtual_wait_header: Some("x-lab-client-virtual-wait-ms".to_owned()),
        run_header_name: source.run_header_name.clone(),
        run_id: run_id.to_owned(),
        allow_retry: source.allow_retry,
        allow_redirect: source.allow_redirect,
        pagination: pagination_state(source)?,
        body_template,
        body_content_type: source.request_body_content_type.clone(),
        cache_ttl_ms: None,
    };
    Ok(Arc::new(HttpSourceAdapter::new(config)))
}

fn pagination_state(source: &ManifestSource) -> Result<PaginationState> {
    let parameter =
        source
            .pagination_parameter
            .clone()
            .unwrap_or_else(|| match source.pagination_mode {
                ManifestPaginationMode::Page => "page".to_owned(),
                ManifestPaginationMode::Offset => "offset".to_owned(),
                ManifestPaginationMode::Cursor => "cursor".to_owned(),
                _ => "page".to_owned(),
            });
    let next = source
        .next_page_field
        .clone()
        .unwrap_or_else(|| "next_cursor".to_owned());
    let initial = source
        .pagination_initial
        .unwrap_or(match source.pagination_mode {
            ManifestPaginationMode::Offset => 0,
            _ => 1,
        });
    let step = source.pagination_step.unwrap_or(1);
    if step <= 0 {
        return Err(anyhow!("manifest pagination step must move forward"));
    }
    match (&source.method, &source.pagination_mode) {
        (_, ManifestPaginationMode::None) => Ok(PaginationState::None),
        (HttpMethod::Get, ManifestPaginationMode::Page) => Ok(PaginationState::QueryPage {
            parameter,
            initial,
            step,
            next_value_path: source.next_page_field.clone(),
        }),
        (HttpMethod::Get, ManifestPaginationMode::Offset) => Ok(PaginationState::QueryOffset {
            parameter,
            initial,
            step,
            next_value_path: source.next_page_field.clone(),
        }),
        (HttpMethod::Get, ManifestPaginationMode::Cursor) => Ok(PaginationState::QueryCursor {
            parameter,
            next_value_path: next,
        }),
        (HttpMethod::Post, ManifestPaginationMode::Page) => Ok(PaginationState::PostBodyPage {
            parameter,
            initial,
            step,
            next_value_path: source.next_page_field.clone(),
        }),
        (HttpMethod::Post, ManifestPaginationMode::Cursor) => Ok(PaginationState::PostBodyCursor {
            parameter,
            next_value_path: next,
        }),
        (_, ManifestPaginationMode::LinkHeader) => Ok(PaginationState::LinkHeader),
        (_, ManifestPaginationMode::Other) | (HttpMethod::Post, ManifestPaginationMode::Offset) => {
            Err(anyhow!(
                "manifest pagination mode is explicitly unsupported"
            ))
        }
    }
}

fn submission_body(
    target_domain: &str,
    schema_version: &str,
    local_run_id: &str,
    outcome: &lens_core::CollectionOutcome,
) -> Value {
    let findings = outcome
        .accepted
        .iter()
        .map(|(fqdn, evidence)| {
            let evidence = evidence
                .iter()
                .map(|item| {
                    json!({
                        "source_id": item.source_id,
                        "source_kind": item.source_kind,
                        "record_id": forge_record_id(item.raw_reference.as_deref()),
                        "url": item.source_url,
                        "observed_at": item.observed_at,
                        "tags": ["passive"],
                        "confidence": 80.0,
                    })
                })
                .collect::<Vec<_>>();
            json!({ "fqdn": fqdn, "evidence": evidence })
        })
        .collect::<Vec<_>>();
    let source_statuses = outcome
        .statuses
        .iter()
        .map(|(id, status)| (id.clone(), forge_source_state(&status.state)))
        .collect::<BTreeMap<_, _>>();
    json!({
        "schema_version": schema_version,
        "collector": { "name": "fqdn-lens", "version": format!("{}+lab-{local_run_id}", env!("CARGO_PKG_VERSION")) },
        "target_domain": target_domain,
        "source_statuses": source_statuses,
        "findings": findings,
    })
}

fn forge_record_id(reference: Option<&str>) -> Option<String> {
    let reference = reference?;
    reference
        .rsplit_once(";record:")
        .map(|(_, value)| value.to_owned())
        .or_else(|| {
            reference
                .rsplit_once(":record:")
                .map(|(_, value)| value.to_owned())
        })
        .or_else(|| Some(reference.to_owned()))
}

fn forge_source_state(state: &SourceState) -> &'static str {
    match state {
        SourceState::Succeeded | SourceState::Empty => "succeeded",
        SourceState::Failed => "failed",
        SourceState::Skipped => "blocked",
        SourceState::RateLimited => "rate_limited",
        SourceState::Cancelled => "cancelled",
    }
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let sensitive = key.to_ascii_lowercase().contains("token")
                        || key.to_ascii_lowercase().contains("cookie")
                        || key.to_ascii_lowercase().contains("authorization")
                        || key.to_ascii_lowercase().contains("capability")
                        || key.to_ascii_lowercase().contains("api_key");
                    (
                        key,
                        if sensitive {
                            Value::String("[REDACTED]".to_owned())
                        } else {
                            redact_value(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::String(value) => Value::String(lens_core::scheduler::redact_sensitive(&value)),
        value => value,
    }
}

#[derive(Deserialize)]
struct CreatedRun {
    base_url: String,
    manifest_url: String,
    report_url: String,
    run_access_header: String,
    run_access_token: String,
    run_id: String,
}

/// Run capability bundle. It is intentionally opaque to callers and never
/// serialized; only `lens-lab` control helpers may use it transiently.
pub struct LabRunAccess {
    base_url: String,
    run_id: String,
    header: String,
    token: String,
}

#[derive(Deserialize)]
struct LabManifest {
    schema_version: String,
    #[serde(default)]
    seed: Option<u64>,
    target_domain: String,
    sources: Vec<ManifestSource>,
    submission: ManifestSubmission,
    transport_profile: ManifestTransportProfile,
    #[serde(default)]
    quota_profiles: Vec<ManifestQuotaProfile>,
    #[serde(default)]
    network_profile: ManifestNetworkProfile,
    #[serde(default)]
    virtual_now: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct ManifestTransportProfile {
    #[serde(default)]
    client_visible_decoded_limit: usize,
}

#[derive(Deserialize)]
struct ManifestQuotaProfile {
    source_id: String,
    scope: ManifestQuotaScope,
    #[serde(default)]
    client_visible_limit: usize,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestQuotaScope {
    PerSource,
    PerKey,
    GlobalRun,
    #[serde(other)]
    Other,
}

#[derive(Default, Deserialize)]
struct ManifestNetworkProfile {
    #[serde(default)]
    mode: ManifestNetworkMode,
}

impl ManifestNetworkProfile {
    fn is_direct(&self) -> bool {
        self.mode == ManifestNetworkMode::Direct
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ManifestNetworkMode {
    #[default]
    Direct,
    HttpProxy,
    ConnectProxy,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ManifestSubmission {
    url: String,
    max_bytes: usize,
    #[allow(dead_code)]
    max_submission_time_ms: u64,
    #[allow(dead_code)]
    finalizes_run: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestPaginationMode {
    None,
    Cursor,
    Page,
    Offset,
    #[serde(alias = "link")]
    LinkHeader,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ManifestSource {
    source_id: String,
    source_kind: String,
    #[serde(default)]
    parser_profile: Option<ParserProfile>,
    source_label: String,
    base_url: String,
    method: HttpMethod,
    path_template: String,
    #[serde(default)]
    required_query: BTreeMap<String, String>,
    #[serde(default)]
    required_headers: Vec<String>,
    #[serde(default)]
    authentication_field_names: Vec<String>,
    #[serde(default)]
    authentication: BTreeMap<String, String>,
    pagination_mode: ManifestPaginationMode,
    pagination_parameter: Option<String>,
    next_page_field: Option<String>,
    #[serde(default)]
    pagination_initial: Option<i64>,
    #[serde(default)]
    pagination_step: Option<i64>,
    #[serde(default)]
    request_body: Option<Value>,
    #[serde(default)]
    body_template: Option<Value>,
    #[serde(default)]
    request_body_template: Option<Value>,
    #[serde(default)]
    request_body_content_type: Option<String>,
    run_header_name: String,
    allow_retry: bool,
    allow_redirect: bool,
    #[allow(dead_code)]
    local_test_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_empty_source_to_forge_success() {
        assert_eq!(forge_source_state(&SourceState::Empty), "succeeded");
    }

    #[test]
    fn rejects_non_loopback_lab_urls() {
        assert!(checked_url("http://127.0.0.1:18080").is_ok());
        assert!(checked_url("http://localhost:18080").is_err());
    }

    #[test]
    fn pagination_mapping_supports_query_post_and_link_states() {
        let source = |method, pagination_mode| ManifestSource {
            source_id: "source".to_owned(),
            source_kind: "generic_json".to_owned(),
            parser_profile: None,
            source_label: "source".to_owned(),
            base_url: "http://127.0.0.1:18080".to_owned(),
            method,
            path_template: "/api/source".to_owned(),
            request_body_template: None,
            request_body_content_type: None,
            required_query: BTreeMap::new(),
            required_headers: vec![],
            authentication_field_names: vec![],
            authentication: BTreeMap::new(),
            pagination_mode,
            pagination_parameter: Some("page".to_owned()),
            next_page_field: Some("next".to_owned()),
            pagination_initial: Some(1),
            pagination_step: Some(2),
            request_body: None,
            body_template: None,
            run_header_name: "x-run".to_owned(),
            allow_retry: false,
            allow_redirect: false,
            local_test_only: true,
        };
        assert!(matches!(
            pagination_state(&source(HttpMethod::Get, ManifestPaginationMode::Page)).expect("page"),
            PaginationState::QueryPage { step: 2, .. }
        ));
        assert!(matches!(
            pagination_state(&source(HttpMethod::Post, ManifestPaginationMode::Cursor))
                .expect("cursor"),
            PaginationState::PostBodyCursor { .. }
        ));
        assert!(matches!(
            pagination_state(&source(HttpMethod::Get, ManifestPaginationMode::LinkHeader))
                .expect("link"),
            PaginationState::LinkHeader
        ));
    }
}
