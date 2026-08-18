use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use reqwest::{Client, RequestBuilder, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::domain::{ScopeVerdict, normalize_candidate};
use crate::evidence::{Evidence, RunStatus};
use crate::i18n::MessageCode;
use crate::source::{DynSourceAdapter, SourceState, SourceStatus};

/// Redaction-safe, bounded metadata emitted while a collection is running.
/// Consumers must treat the English identifiers as machine values and use
/// core i18n resources for display text.
#[derive(Clone, Debug, Serialize)]
pub enum CollectionProgressEvent {
    RunCreated {
        run_id: uuid::Uuid,
        target_domain: String,
    },
    SourceQueued {
        run_id: uuid::Uuid,
        source_id: String,
    },
    SourceStarted {
        run_id: uuid::Uuid,
        source_id: String,
    },
    RequestFinished {
        run_id: uuid::Uuid,
        source_id: String,
        requests: u64,
        pages: u64,
    },
    SourceFinished {
        run_id: uuid::Uuid,
        source_id: String,
        state: SourceState,
        accepted: u64,
        evidence: u64,
    },
    Warning {
        run_id: uuid::Uuid,
        source_id: Option<String>,
        code: MessageCode,
    },
    RunFinished {
        run_id: uuid::Uuid,
        status: RunStatus,
    },
}

/// A bounded consumer normally passes `try_send` here. Dropping an
/// intermediate progress event under pressure is intentional: the final
/// `CollectionReport` and Store state remain authoritative, so the UI never
/// needs an unbounded queue to display a truthful terminal state.
pub type ProgressSink = Arc<dyn Fn(CollectionProgressEvent) + Send + Sync + 'static>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchedulerPolicy {
    pub max_body_bytes: usize,
    pub max_results_per_source: usize,
    pub max_pages: usize,
    pub max_retries: usize,
    pub max_retry_after_ms: u64,
    pub source_concurrency: usize,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub quota_rules: Vec<QuotaRule>,
    #[serde(default)]
    pub cache_policy: CachePolicy,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self {
            max_body_bytes: 2 * 1024 * 1024,
            max_results_per_source: 10_000,
            max_pages: 100,
            max_retries: 3,
            max_retry_after_ms: 30_000,
            source_concurrency: 2,
            connect_timeout_ms: 3_000,
            request_timeout_ms: 10_000,
            quota_rules: Vec::new(),
            cache_policy: CachePolicy::Disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScope {
    PerSource,
    PerKey,
    GlobalRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaRule {
    pub source_id: String,
    pub scope: QuotaScope,
    pub limit: usize,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    #[default]
    Disabled,
    RunLocal,
    ProjectLocal,
}

/// Non-sensitive cache metadata. Capability, authorization, cookies and raw
/// request bodies are intentionally excluded from the fingerprint and never
/// retained in this structure.
#[derive(Clone, Debug, Serialize)]
pub struct CacheEntry {
    pub source_id: String,
    pub request_fingerprint: String,
    pub response_digest: String,
    pub stored_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub validator: Option<String>,
}

#[derive(Clone, Debug)]
pub struct QuotaIdentity {
    pub source_id: String,
    pub key_id: String,
}

impl QuotaIdentity {
    #[must_use]
    pub fn new(source_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            key_id: key_id.into(),
        }
    }
}

pub struct RetryOptions<'a> {
    pub allow_retry: bool,
    pub virtual_wait_header: Option<&'a str>,
    pub quota_identity: Option<&'a QuotaIdentity>,
}

#[derive(Clone)]
struct CachedResponse {
    entry: CacheEntry,
    response: BoundedResponse,
}

#[derive(Default)]
pub struct SchedulerRuntime {
    quota_usage: Mutex<BTreeMap<String, usize>>,
    cache: Mutex<BTreeMap<String, CachedResponse>>,
}

impl SchedulerRuntime {
    async fn reserve_quota(&self, policy: &SchedulerPolicy, identity: &QuotaIdentity) -> bool {
        let Some(rule) = policy
            .quota_rules
            .iter()
            .find(|rule| rule.source_id == identity.source_id)
        else {
            return true;
        };
        let bucket = match rule.scope {
            QuotaScope::PerSource => format!("source:{}", identity.source_id),
            QuotaScope::PerKey => format!("key:{}:{}", identity.source_id, identity.key_id),
            QuotaScope::GlobalRun => "global".to_owned(),
        };
        let mut usage = self.quota_usage.lock().await;
        let consumed = usage.entry(bucket).or_default();
        if *consumed >= rule.limit {
            return false;
        }
        *consumed += 1;
        true
    }

    pub async fn cache_get(&self, key: &str) -> Option<BoundedResponse> {
        let cache = self.cache.lock().await;
        cache.get(key).and_then(|cached| {
            let _entry = &cached.entry;
            cached
                .entry
                .expires_at
                .is_none_or(|expires_at| expires_at > Utc::now())
                .then(|| cached.response.clone())
        })
    }

    pub async fn cache_put(&self, key: String, source_id: String, response: BoundedResponse) {
        self.cache_put_with_ttl(key, source_id, response, None)
            .await;
    }

    pub async fn cache_put_with_ttl(
        &self,
        key: String,
        source_id: String,
        response: BoundedResponse,
        ttl_ms: Option<u64>,
    ) {
        let entry = CacheEntry {
            source_id,
            request_fingerprint: key.clone(),
            response_digest: response.response_digest.clone(),
            stored_at: Utc::now(),
            expires_at: ttl_ms
                .map(|value| Utc::now() + chrono::Duration::milliseconds(value as i64)),
            validator: None,
        };
        self.cache
            .lock()
            .await
            .insert(key, CachedResponse { entry, response });
    }
}

/// The clock is explicit so HTTP-date `Retry-After` calculations are
/// deterministic in the Lab profile and never depend on wall-clock time in
/// business logic.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct FixedClock {
    now: DateTime<Utc>,
}

impl FixedClock {
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Authority {
    host: String,
    port: u16,
}

/// A per-run destination allow-list. An address is allowed only when its
/// numeric loopback authority *and* its path family were supplied by the
/// current Forge run's public contract.
#[derive(Clone, Debug, Default)]
pub struct EgressPolicy {
    allowed_paths: BTreeMap<Authority, BTreeSet<String>>,
    allow_public_https: bool,
}

impl EgressPolicy {
    #[must_use]
    pub fn production() -> Self {
        Self {
            allowed_paths: BTreeMap::new(),
            allow_public_https: true,
        }
    }

    pub fn allow_url(&mut self, url: &Url, path_prefix: &str) -> Result<(), String> {
        validate_egress_url(url)?;
        self.allowed_paths
            .entry(authority(url)?)
            .or_default()
            .insert(normalized_path_prefix(path_prefix));
        Ok(())
    }

    pub fn allow_public_https_url(&mut self, url: &Url, path_prefix: &str) -> Result<(), String> {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err("egress_policy_denied".to_owned());
        }
        self.allow_public_https = true;
        self.allowed_paths
            .entry(authority(url)?)
            .or_default()
            .insert(normalized_path_prefix(path_prefix));
        Ok(())
    }

    pub fn allow_url_path(&mut self, value: &str, path_prefix: &str) -> Result<(), String> {
        let url = Url::parse(value).map_err(|_| "egress_policy_denied".to_owned())?;
        self.allow_url(&url, path_prefix)
    }

    pub fn validate(&self, url: &Url) -> Result<(), String> {
        if url.scheme() == "https" {
            if !self.allow_public_https || !url.username().is_empty() || url.password().is_some() {
                return Err("egress_policy_denied".to_owned());
            }
        } else {
            validate_egress_url(url)?;
        }
        let key = authority(url)?;
        let path = url.path();
        let allowed = self.allowed_paths.get(&key).is_some_and(|prefixes| {
            prefixes.iter().any(|prefix| {
                prefix == "/" || path == prefix || path.starts_with(&format!("{prefix}/"))
            })
        });
        if allowed {
            Ok(())
        } else {
            Err("egress_policy_denied".to_owned())
        }
    }
}

fn normalized_path_prefix(value: &str) -> String {
    let value = if value.is_empty() { "/" } else { value };
    let mut prefix = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    while prefix.len() > 1 && prefix.ends_with('/') {
        prefix.pop();
    }
    prefix
}

fn authority(url: &Url) -> Result<Authority, String> {
    Ok(Authority {
        host: url
            .host_str()
            .ok_or_else(|| "egress_policy_denied".to_owned())?
            .to_owned(),
        port: url
            .port_or_known_default()
            .ok_or_else(|| "egress_policy_denied".to_owned())?,
    })
}

#[derive(Clone)]
pub struct CollectionContext {
    pub cancel: CancellationToken,
    pub policy: SchedulerPolicy,
    pub waiter: Arc<dyn Waiter>,
    pub clock: Arc<dyn Clock>,
    pub egress: EgressPolicy,
    pub runtime: Arc<SchedulerRuntime>,
}

#[async_trait::async_trait]
pub trait Waiter: Send + Sync {
    async fn wait(&self, duration: Duration, cancellation: &CancellationToken) -> bool;
}

pub struct RealWaiter;

#[async_trait::async_trait]
impl Waiter for RealWaiter {
    async fn wait(&self, duration: Duration, cancellation: &CancellationToken) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(duration) => true,
            _ = cancellation.cancelled() => false,
        }
    }
}

/// A deterministic test/Lab waiter: it records requested wait time without
/// sleeping. This lets FQDN Forge retry scenarios complete quickly while the
/// scheduler still accounts for virtual cooldowns.
#[derive(Default)]
pub struct VirtualWaiter {
    waited_ms: Mutex<u64>,
}

impl VirtualWaiter {
    pub async fn waited_ms(&self) -> u64 {
        *self.waited_ms.lock().await
    }
}

#[async_trait::async_trait]
impl Waiter for VirtualWaiter {
    async fn wait(&self, duration: Duration, cancellation: &CancellationToken) -> bool {
        if cancellation.is_cancelled() {
            return false;
        }
        let mut waited = self.waited_ms.lock().await;
        *waited = waited.saturating_add(duration.as_millis().try_into().unwrap_or(u64::MAX));
        true
    }
}

/// The only adapter-visible HTTP result. It intentionally exposes a bounded,
/// decoded body and a small safe header allow-list rather than reqwest's live
/// response object.
#[derive(Clone, Debug)]
pub struct BoundedResponse {
    pub status: StatusCode,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub final_url: Url,
    pub response_digest: String,
}

impl BoundedResponse {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[derive(Clone)]
pub struct BoundedHttpClient {
    client: Client,
    policy: SchedulerPolicy,
}

impl BoundedHttpClient {
    pub fn new(policy: SchedulerPolicy) -> Result<Self, String> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_millis(policy.connect_timeout_ms))
            .timeout(Duration::from_millis(policy.request_timeout_ms))
            .build()
            .map_err(|_| "http_client_initialization_failed".to_owned())?;
        Ok(Self { client, policy })
    }

    pub fn get(&self, url: Url) -> RequestBuilder {
        self.client.get(url)
    }

    pub fn post(&self, url: Url) -> RequestBuilder {
        self.client.post(url)
    }

    pub fn delete(&self, url: Url) -> RequestBuilder {
        self.client.delete(url)
    }

    /// Reuses the same reqwest session while applying a narrower policy after
    /// a Forge manifest advertises a smaller decoded-body limit.
    #[must_use]
    pub fn with_policy(&self, policy: SchedulerPolicy) -> Self {
        Self {
            client: self.client.clone(),
            policy,
        }
    }

    pub async fn send_with_retry(
        &self,
        request: RequestBuilder,
        options: RetryOptions<'_>,
        context: &CollectionContext,
        status: &mut SourceStatus,
        virtual_waited_ms: &mut u64,
    ) -> Result<BoundedResponse, String> {
        let prototype = request
            .try_clone()
            .ok_or_else(|| "request_not_replayable".to_owned())?;
        for attempt in 0..=self.policy.max_retries {
            if context.cancel.is_cancelled() {
                status.state = SourceState::Cancelled;
                return Err("cancelled".to_owned());
            }
            let mut request = prototype
                .try_clone()
                .ok_or_else(|| "request_not_replayable".to_owned())?;
            if let Some(header) = options.virtual_wait_header {
                request = request.header(header, virtual_waited_ms.to_string());
            }
            if let Err(error) = validate_egress_request(
                request
                    .try_clone()
                    .ok_or_else(|| "request_not_replayable".to_owned())?,
                &context.egress,
            ) {
                status.state = SourceState::Skipped;
                return Err(error);
            }
            if let Some(identity) = options.quota_identity
                && !context
                    .runtime
                    .reserve_quota(&context.policy, identity)
                    .await
            {
                status.state = SourceState::RateLimited;
                status.quota_rejections += 1;
                return Err("quota_exhausted".to_owned());
            }
            status.requests += 1;
            let response = tokio::select! {
                result = request.send() => result.map_err(|_| "transport_error".to_owned())?,
                _ = context.cancel.cancelled() => {
                    status.state = SourceState::Cancelled;
                    return Err("cancelled".to_owned());
                }
            };
            let response_status = response.status();
            if response_status.is_redirection() {
                let external = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|location| response.url().join(location).ok())
                    .is_some_and(|target| context.egress.validate(&target).is_err());
                if external {
                    status.state = SourceState::Skipped;
                    return Err("egress_policy_denied".to_owned());
                }
                status.state = SourceState::Failed;
                return Err("redirect_rejected".to_owned());
            }
            if response_status.is_success() {
                return self.read_limited(response).await;
            }
            let retryable = response_status == StatusCode::TOO_MANY_REQUESTS
                || response_status.is_server_error();
            if retryable && options.allow_retry && attempt < self.policy.max_retries {
                status.retries += 1;
                let parsed_wait_ms = retry_after_ms(
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok()),
                    context.clock.as_ref(),
                );
                let requested_wait_ms = parsed_wait_ms.unwrap_or(100).min(
                    self.policy
                        .max_retry_after_ms
                        .saturating_sub(*virtual_waited_ms),
                );
                let wait_ms = requested_wait_ms;
                status.retry_after_ms = Some(wait_ms);
                // Forge's virtual clock advances only for a declared,
                // parseable Retry-After. Invalid/missing headers use a small
                // deterministic local fallback without pretending the server
                // clock advanced.
                if parsed_wait_ms.is_some() {
                    *virtual_waited_ms = virtual_waited_ms.saturating_add(wait_ms);
                }
                if !context
                    .waiter
                    .wait(Duration::from_millis(wait_ms), &context.cancel)
                    .await
                {
                    status.state = SourceState::Cancelled;
                    return Err("cancelled".to_owned());
                }
                continue;
            }
            status.state = if response_status == StatusCode::TOO_MANY_REQUESTS {
                SourceState::RateLimited
            } else {
                SourceState::Failed
            };
            return Err(format!("http_{}", response_status.as_u16()));
        }
        Err("retry_limit_reached".to_owned())
    }

    async fn read_limited(&self, response: reqwest::Response) -> Result<BoundedResponse, String> {
        if response
            .content_length()
            .is_some_and(|length| length > self.policy.max_body_bytes as u64)
        {
            return Err("response_body_limit_exceeded".to_owned());
        }
        let status = response.status();
        let final_url = response.url().clone();
        let headers = ["content-type", "content-length", "retry-after", "link"]
            .into_iter()
            .filter_map(|name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| (name.to_owned(), value.to_owned()))
            })
            .collect();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "response_body_read_error".to_owned())?;
            if body.len().saturating_add(chunk.len()) > self.policy.max_body_bytes {
                return Err("response_body_limit_exceeded".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(BoundedResponse {
            status,
            headers,
            response_digest: hex_digest(&body),
            body,
            final_url,
        })
    }
}

fn validate_egress_request(request: RequestBuilder, egress: &EgressPolicy) -> Result<(), String> {
    let request = request.build().map_err(|_| "invalid_request".to_owned())?;
    egress.validate(request.url())
}

/// The only V0.1.1 destination host is a numeric loopback HTTP address. The
/// per-run `EgressPolicy` supplies the additional authority and path pinning.
pub fn validate_egress_url(url: &Url) -> Result<(), String> {
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("egress_policy_denied".to_owned());
    }
    Ok(())
}

pub fn retry_after_ms(value: Option<&str>, clock: &dyn Clock) -> Option<u64> {
    let value = value?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|timestamp| {
            (timestamp.with_timezone(&Utc) - clock.now())
                .num_milliseconds()
                .max(0)
                .try_into()
                .ok()
        })
}

pub struct CollectionScheduler {
    context: CollectionContext,
    http: BoundedHttpClient,
}

impl CollectionScheduler {
    pub fn new(
        policy: SchedulerPolicy,
        cancel: CancellationToken,
        waiter: Arc<dyn Waiter>,
        clock: Arc<dyn Clock>,
        egress: EgressPolicy,
    ) -> Result<Self, String> {
        let http = BoundedHttpClient::new(policy.clone())?;
        Self::with_http(policy, cancel, waiter, clock, egress, http)
    }

    pub fn with_http(
        policy: SchedulerPolicy,
        cancel: CancellationToken,
        waiter: Arc<dyn Waiter>,
        clock: Arc<dyn Clock>,
        egress: EgressPolicy,
        http: BoundedHttpClient,
    ) -> Result<Self, String> {
        Ok(Self {
            context: CollectionContext {
                cancel,
                policy,
                waiter,
                clock,
                egress,
                runtime: Arc::new(SchedulerRuntime::default()),
            },
            http,
        })
    }

    pub async fn collect(
        &self,
        run_id: uuid::Uuid,
        root_domain: &str,
        include_root: bool,
        sources: Vec<DynSourceAdapter>,
    ) -> CollectionOutcome {
        self.collect_with_progress(run_id, root_domain, include_root, sources, None)
            .await
    }

    pub async fn collect_with_progress(
        &self,
        run_id: uuid::Uuid,
        root_domain: &str,
        include_root: bool,
        sources: Vec<DynSourceAdapter>,
        progress: Option<ProgressSink>,
    ) -> CollectionOutcome {
        for source in &sources {
            emit_progress(
                &progress,
                CollectionProgressEvent::SourceQueued {
                    run_id,
                    source_id: source.metadata().id.clone(),
                },
            );
        }
        let mut collected = stream::iter(sources)
            .map(|source| {
                let source_id = source.metadata().id.clone();
                emit_progress(
                    &progress,
                    CollectionProgressEvent::SourceStarted {
                        run_id,
                        source_id: source_id.clone(),
                    },
                );
                let progress = progress.clone();
                async move {
                    let result = source.collect(&self.context, &self.http).await;
                    emit_progress(
                        &progress,
                        CollectionProgressEvent::RequestFinished {
                            run_id,
                            source_id: source_id.clone(),
                            requests: result.status.requests,
                            pages: result.status.pages,
                        },
                    );
                    if let Some(error_code) = result.status.error_code.as_deref() {
                        emit_progress(
                            &progress,
                            CollectionProgressEvent::Warning {
                                run_id,
                                source_id: Some(source_id),
                                code: progress_message_code(error_code),
                            },
                        );
                    }
                    result
                }
            })
            .buffer_unordered(self.context.policy.source_concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
        collected.sort_by(|left, right| left.status.source_id.cmp(&right.status.source_id));

        let fetched_at = self.context.clock.now();
        let mut statuses = BTreeMap::new();
        let mut evidence = Vec::new();
        let mut accepted = BTreeMap::<String, Vec<Evidence>>::new();
        let mut seen_evidence = BTreeSet::new();
        let mut virtual_waited_ms: u64 = 0;

        for mut collected_source in collected {
            let source_id = collected_source.status.source_id.clone();
            let mut source_evidence = 0;
            virtual_waited_ms =
                virtual_waited_ms.saturating_add(collected_source.virtual_waited_ms);
            for observation in collected_source.observations {
                let candidate = normalize_candidate(&observation.value, root_domain, include_root);
                let fqdn = candidate.value.clone().unwrap_or_default();
                let raw_value = redact_sensitive(&observation.value);
                let key = format!(
                    "{}\u{1f}{}\u{1f}{}",
                    observation.source_id,
                    observation.raw_reference.as_deref().unwrap_or_default(),
                    raw_value
                );
                if !seen_evidence.insert(key) {
                    continue;
                }
                let response_digest = observation
                    .response_digest
                    .unwrap_or_else(|| hex_digest(&[]));
                let item = Evidence {
                    id: uuid::Uuid::new_v4(),
                    run_id,
                    fqdn: fqdn.clone(),
                    source_id: observation.source_id,
                    source_kind: observation.source_kind,
                    source_url: observation.source_url.map(|url| redact_sensitive(&url)),
                    raw_value: raw_value.clone(),
                    raw_reference: observation
                        .raw_reference
                        .map(|reference| redact_sensitive(&reference)),
                    observed_at: observation.observed_at,
                    fetched_at,
                    response_digest: response_digest.clone(),
                    record_digest: observation.record_digest,
                    payload_digest: response_digest,
                    normalization_notes: candidate.notes,
                    scope_verdict: candidate.verdict.clone(),
                };
                if item.scope_verdict == ScopeVerdict::Accepted {
                    collected_source.status.results_accepted += 1;
                    accepted.entry(fqdn).or_default().push(item.clone());
                } else {
                    collected_source.status.results_filtered += 1;
                }
                source_evidence += 1;
                evidence.push(item);
            }
            emit_progress(
                &progress,
                CollectionProgressEvent::SourceFinished {
                    run_id,
                    source_id: source_id.clone(),
                    state: collected_source.status.state.clone(),
                    accepted: collected_source.status.results_accepted,
                    evidence: source_evidence,
                },
            );
            statuses.insert(source_id, collected_source.status);
        }

        let status = overall_status(statuses.values());
        let diagnostics_summary = statuses
            .values()
            .find_map(|status| status.error_code.clone());
        CollectionOutcome {
            status,
            statuses,
            evidence,
            accepted,
            virtual_waited_ms,
            diagnostics_summary,
        }
    }
}

fn emit_progress(progress: &Option<ProgressSink>, event: CollectionProgressEvent) {
    if let Some(progress) = progress {
        progress(event);
    }
}

fn progress_message_code(error_code: &str) -> MessageCode {
    match error_code {
        "missing_credentials" => MessageCode::CredentialMissing,
        "authentication_failed" => MessageCode::AuthenticationFailed,
        "rate_limited" | "quota_exhausted" => MessageCode::RateLimited,
        _ => MessageCode::UpstreamFailed,
    }
}

#[derive(Clone, Debug)]
pub struct CollectionOutcome {
    pub status: RunStatus,
    pub statuses: BTreeMap<String, SourceStatus>,
    pub evidence: Vec<Evidence>,
    pub accepted: BTreeMap<String, Vec<Evidence>>,
    pub virtual_waited_ms: u64,
    pub diagnostics_summary: Option<String>,
}

fn overall_status<'a>(statuses: impl Iterator<Item = &'a SourceStatus>) -> RunStatus {
    let statuses = statuses.collect::<Vec<_>>();
    if statuses
        .iter()
        .any(|status| status.state == SourceState::Cancelled)
    {
        return RunStatus::Cancelled;
    }
    let success_count = statuses
        .iter()
        .filter(|status| matches!(status.state, SourceState::Succeeded | SourceState::Empty))
        .count();
    if success_count == statuses.len() {
        RunStatus::Succeeded
    } else if success_count > 0 {
        RunStatus::Partial
    } else {
        RunStatus::Failed
    }
}

pub fn hex_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

/// Removes credentials from values which may reach SQLite, CLI output or a
/// diagnostic. It intentionally recognises both URLs and common free-form
/// header/query spellings.
pub fn redact_sensitive(value: &str) -> String {
    let mut value = value.trim().chars().take(1024).collect::<String>();
    if let Ok(mut url) = Url::parse(&value) {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        let pairs = url
            .query_pairs()
            .map(|(key, query_value)| (key.into_owned(), query_value.into_owned()))
            .collect::<Vec<_>>();
        if pairs.iter().any(|(key, _)| is_sensitive_name(key)) {
            let mut query = url.query_pairs_mut();
            query.clear();
            for (key, query_value) in pairs {
                query.append_pair(
                    &key,
                    if is_sensitive_name(&key) {
                        "[REDACTED]"
                    } else {
                        &query_value
                    },
                );
            }
        }
        value = url.to_string();
    }
    for marker in [
        "authorization=",
        "api_key=",
        "api-key=",
        "token=",
        "key=",
        "cookie=",
        "proxy-authorization=",
        "bearer+",
    ] {
        if let Some(index) = value.to_ascii_lowercase().find(marker) {
            let start = index + marker.len();
            let end = value[start..]
                .find(['&', ' ', ';', '\r', '\n'])
                .map_or(value.len(), |offset| start + offset);
            value.replace_range(start..end, "[REDACTED]");
        }
    }
    if let Some(index) = value.to_ascii_lowercase().find("bearer ") {
        let start = index + "bearer ".len();
        let end = value[start..]
            .find([' ', ';', '\r', '\n'])
            .map_or(value.len(), |offset| start + offset);
        value.replace_range(start..end, "[REDACTED]");
    }
    value
}

fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("token")
        || name.contains("key")
        || name.contains("cookie")
        || name.contains("authorization")
        || name.contains("capability")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{
        KeyRequirement, SourceAdapter, SourceCollection, SourceKind, SourceMetadata,
    };
    use async_trait::async_trait;

    struct CancellingAdapter {
        metadata: SourceMetadata,
        cancel_on_start: bool,
    }

    #[async_trait]
    impl SourceAdapter for CancellingAdapter {
        fn metadata(&self) -> &SourceMetadata {
            &self.metadata
        }

        async fn collect(
            &self,
            context: &CollectionContext,
            _http: &BoundedHttpClient,
        ) -> SourceCollection {
            let mut status = SourceStatus::pending(self.metadata.id.clone());
            if self.cancel_on_start {
                context.cancel.cancel();
            } else {
                status.state = SourceState::Cancelled;
                status.error_code = Some("cancelled".to_owned());
            }
            SourceCollection {
                observations: Vec::new(),
                status,
                virtual_waited_ms: 0,
            }
        }

        fn parse(
            &self,
            _response: &[u8],
        ) -> Result<Vec<crate::source::RawObservation>, crate::source::SourceError> {
            Err(crate::source::SourceError::Parse)
        }
    }

    fn test_metadata(id: &str) -> SourceMetadata {
        SourceMetadata {
            id: id.to_owned(),
            display_name: id.to_owned(),
            kind: SourceKind::GenericJson,
            key_requirement: KeyRequirement::None,
            recursive_support: false,
            passive_only: true,
            default_enabled: true,
        }
    }

    #[test]
    fn egress_guard_requires_exact_authority_and_path() {
        let allowed = Url::parse("http://127.0.0.1:18080/api/runs/one/source").expect("url");
        let mut policy = EgressPolicy::default();
        policy.allow_url(&allowed, "/api/runs/one").expect("allow");
        assert!(policy.validate(&allowed).is_ok());
        assert!(
            policy
                .validate(&Url::parse("http://127.0.0.1:18081/api/runs/one/source").expect("url"))
                .is_err()
        );
        assert!(
            policy
                .validate(&Url::parse("http://127.0.0.1:18080/api/other").expect("url"))
                .is_err()
        );
    }

    #[test]
    fn egress_guard_allows_only_numeric_loopback_http() {
        assert!(validate_egress_url(&Url::parse("http://127.0.0.1:18080/a").expect("url")).is_ok());
        for url in [
            "http://localhost:18080/a",
            "https://127.0.0.1/a",
            "http://127.0.0.2/a",
            "http://user:pass@127.0.0.1/a",
        ] {
            assert!(
                validate_egress_url(&Url::parse(url).expect("url")).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn redacts_url_userinfo_query_and_bearer_values() {
        let value =
            redact_sensitive("https://user:password@api.acme.test/x?token=secret&x=1 Bearer abc");
        assert!(!value.contains("password"));
        assert!(!value.contains("secret"));
        assert!(!value.contains("abc"));
    }

    #[test]
    fn http_date_retry_after_uses_the_injected_clock() {
        let clock = FixedClock::new(
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .expect("time")
                .with_timezone(&Utc),
        );
        assert_eq!(
            retry_after_ms(Some("Thu, 01 Jan 2026 00:00:02 GMT"), &clock),
            Some(2_000)
        );
    }

    #[tokio::test]
    async fn virtual_waiter_does_not_sleep() {
        let waiter = VirtualWaiter::default();
        let cancellation = CancellationToken::new();
        assert!(waiter.wait(Duration::from_secs(10), &cancellation).await);
        assert_eq!(waiter.waited_ms().await, 10_000);
    }

    #[tokio::test]
    async fn virtual_waiter_honors_cancellation() {
        let waiter = VirtualWaiter::default();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(!waiter.wait(Duration::from_secs(1), &cancellation).await);
        assert_eq!(waiter.waited_ms().await, 0);
    }

    #[tokio::test]
    async fn cancellation_stops_the_next_source_without_leaving_a_success() {
        let cancel = CancellationToken::new();
        let policy = SchedulerPolicy {
            source_concurrency: 1,
            ..SchedulerPolicy::default()
        };
        let scheduler = CollectionScheduler::new(
            policy,
            cancel,
            Arc::new(VirtualWaiter::default()),
            Arc::new(FixedClock::new(Utc::now())),
            EgressPolicy::default(),
        )
        .expect("scheduler");
        let sources: Vec<DynSourceAdapter> = vec![
            Arc::new(CancellingAdapter {
                metadata: test_metadata("first"),
                cancel_on_start: true,
            }),
            Arc::new(CancellingAdapter {
                metadata: test_metadata("second"),
                cancel_on_start: false,
            }),
        ];
        let outcome = scheduler
            .collect(uuid::Uuid::new_v4(), "acme.test", false, sources)
            .await;
        assert_eq!(outcome.status, RunStatus::Cancelled);
        assert_eq!(outcome.statuses["second"].state, SourceState::Cancelled);
    }

    #[tokio::test]
    async fn quota_reservation_is_atomic_for_global_scope() {
        let policy = SchedulerPolicy {
            quota_rules: vec![QuotaRule {
                source_id: "first".to_owned(),
                scope: QuotaScope::GlobalRun,
                limit: 1,
            }],
            ..SchedulerPolicy::default()
        };
        let runtime = SchedulerRuntime::default();
        let first = QuotaIdentity::new("first", "anonymous");
        let second = QuotaIdentity::new("first", "anonymous");
        let (left, right) = tokio::join!(
            runtime.reserve_quota(&policy, &first),
            runtime.reserve_quota(&policy, &second)
        );
        assert_eq!(
            [left, right].into_iter().filter(|allowed| *allowed).count(),
            1
        );
    }

    #[tokio::test]
    async fn run_local_cache_returns_a_bounded_response_without_request_material() {
        let runtime = SchedulerRuntime::default();
        let response = BoundedResponse {
            status: StatusCode::OK,
            headers: BTreeMap::new(),
            body: b"[]".to_vec(),
            final_url: Url::parse("http://127.0.0.1:18080/source").expect("url"),
            response_digest: hex_digest(b"[]"),
        };
        runtime
            .cache_put(
                "non-sensitive-fingerprint".to_owned(),
                "source".to_owned(),
                response,
            )
            .await;
        assert_eq!(
            runtime
                .cache_get("non-sensitive-fingerprint")
                .await
                .expect("cache hit")
                .body,
            b"[]"
        );
    }
}
