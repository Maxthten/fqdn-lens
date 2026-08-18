//! Explicit, passive production-source definitions for V0.3.
//!
//! This module is intentionally separate from the Forge/Lab bridge. Providers
//! are fixed in code, credentials come only from named environment variables,
//! and the existing scheduler remains responsible for bounds, retries,
//! cancellation, cache, quota, egress, normalization, and evidence.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::credentials::CredentialProvider;
pub use crate::credentials::CredentialState;
use crate::scheduler::{
    BoundedHttpClient, BoundedResponse, CachePolicy, CollectionContext, QuotaIdentity, QuotaRule,
    QuotaScope, RetryOptions, SchedulerPolicy, hex_digest,
};
use crate::source::{
    DynSourceAdapter, HttpMethod, HttpSourceAdapter, KeyRequirement, PaginationState,
    ParserProfile, RawObservation, SourceAdapter, SourceCollection, SourceError, SourceKind,
    SourceMetadata, SourceState, SourceStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionAuth {
    None,
    BearerToken { env_var: &'static str },
    ApiKey { env_var: &'static str },
}

impl ProductionAuth {
    #[must_use]
    pub const fn env_var(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::BearerToken { env_var } | Self::ApiKey { env_var } => Some(env_var),
        }
    }

    #[must_use]
    pub const fn key_requirement(self) -> KeyRequirement {
        match self {
            Self::None => KeyRequirement::None,
            Self::BearerToken { .. } | Self::ApiKey { .. } => KeyRequirement::Required,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ProductionSourceDefinition {
    pub id: &'static str,
    pub display_name: &'static str,
    pub origin: &'static str,
    pub path: &'static str,
    pub source_kind: &'static str,
    pub parser_profile: ParserProfile,
    pub auth: ProductionAuth,
    pub passive_only: bool,
    pub default_enabled: bool,
    pub cache_ttl_ms: u64,
    pub quota_limit: usize,
    pub terms_notice: &'static str,
}

impl ProductionSourceDefinition {
    #[must_use]
    pub fn metadata(self) -> SourceMetadata {
        SourceMetadata {
            id: self.id.to_owned(),
            display_name: self.display_name.to_owned(),
            kind: SourceKind::from_manifest(self.source_kind),
            key_requirement: self.auth.key_requirement(),
            recursive_support: true,
            passive_only: self.passive_only,
            default_enabled: self.default_enabled,
        }
    }

    #[must_use]
    pub fn credential_state(self) -> CredentialState {
        CredentialProvider::system().state(self.id, self.auth.env_var())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionSourceRegistry;

impl ProductionSourceRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn definitions(self) -> &'static [ProductionSourceDefinition] {
        &[
            ProductionSourceDefinition {
                id: "ct-certspotter",
                display_name: "Cert Spotter",
                origin: "https://api.certspotter.com",
                path: "/v1/issuances",
                source_kind: "certificate",
                parser_profile: ParserProfile::CertSpotter,
                auth: ProductionAuth::BearerToken {
                    env_var: "FQDN_LENS_CERTSPOTTER_TOKEN",
                },
                passive_only: true,
                default_enabled: false,
                cache_ttl_ms: 15 * 60 * 1000,
                quota_limit: 4,
                terms_notice: "Certificate Transparency issuance search; provider terms and rate limits apply.",
            },
            ProductionSourceDefinition {
                id: "web-urlscan-search",
                display_name: "URLScan Search",
                origin: "https://urlscan.io",
                path: "/api/v1/search/",
                source_kind: "url_search",
                parser_profile: ParserProfile::UrlScan,
                auth: ProductionAuth::ApiKey {
                    env_var: "FQDN_LENS_URLSCAN_API_KEY",
                },
                passive_only: true,
                default_enabled: false,
                cache_ttl_ms: 10 * 60 * 1000,
                quota_limit: 4,
                terms_notice: "Read-only public search; this adapter never submits scans or fetches result URLs.",
            },
            ProductionSourceDefinition {
                id: "ct-crtsh",
                display_name: "crt.sh",
                origin: "https://crt.sh",
                path: "/",
                source_kind: "certificate",
                parser_profile: ParserProfile::CrtSh,
                auth: ProductionAuth::None,
                passive_only: true,
                default_enabled: false,
                cache_ttl_ms: 60 * 60 * 1000,
                quota_limit: 1,
                terms_notice: "Low-frequency public fallback; no production SLA is assumed.",
            },
            ProductionSourceDefinition {
                id: "archive-commoncrawl-cdxj",
                display_name: "Common Crawl CDXJ",
                origin: "https://index.commoncrawl.org",
                path: "/collinfo.json",
                source_kind: "archive",
                parser_profile: ParserProfile::Archive,
                auth: ProductionAuth::None,
                passive_only: true,
                default_enabled: false,
                cache_ttl_ms: 6 * 60 * 60 * 1000,
                quota_limit: 2,
                terms_notice: "Bounded historical index lookup; no WARC download or webpage fetch is performed.",
            },
        ]
    }

    #[must_use]
    pub fn get(self, id: &str) -> Option<ProductionSourceDefinition> {
        self.definitions()
            .iter()
            .copied()
            .find(|definition| definition.id == id)
    }
}

#[derive(Debug, Error)]
pub enum ProductionFactoryError {
    #[error("unknown production source: {0}")]
    UnknownSource(String),
    #[error("invalid registered production endpoint")]
    InvalidEndpoint,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthState {
    Succeeded,
    Empty,
    MissingCredentials,
    AuthenticationFailed,
    RateLimited,
    UpstreamFailed,
    ParseFailed,
    Cancelled,
    SecurityRejected,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceRunDiagnostics {
    pub source_id: String,
    pub health: SourceHealthState,
    pub error_code: Option<String>,
    pub requests: u64,
    pub pages: u64,
    pub results_received: u64,
}

impl SourceRunDiagnostics {
    #[must_use]
    pub fn from_status(status: &SourceStatus) -> Self {
        let health = if status.state == SourceState::RateLimited {
            SourceHealthState::RateLimited
        } else {
            match status.error_code.as_deref() {
                Some("missing_credentials") => SourceHealthState::MissingCredentials,
                Some("authentication_failed") => SourceHealthState::AuthenticationFailed,
                Some("rate_limited") | Some("quota_exhausted") => SourceHealthState::RateLimited,
                Some("response_parse_error") | Some("metadata_parse_error") => {
                    SourceHealthState::ParseFailed
                }
                Some("egress_policy_denied") | Some("redirect_rejected") => {
                    SourceHealthState::SecurityRejected
                }
                Some("cancelled") => SourceHealthState::Cancelled,
                Some(_) => SourceHealthState::UpstreamFailed,
                None if status.state == SourceState::Empty => SourceHealthState::Empty,
                None => SourceHealthState::Succeeded,
            }
        };
        Self {
            source_id: status.source_id.clone(),
            health,
            error_code: status.error_code.clone(),
            requests: status.requests,
            pages: status.pages,
            results_received: status.results_received,
        }
    }
}

pub struct ProductionSourceFactory {
    registry: ProductionSourceRegistry,
    credentials: CredentialProvider,
}

impl Default for ProductionSourceFactory {
    fn default() -> Self {
        Self::new(ProductionSourceRegistry::new())
    }
}

impl ProductionSourceFactory {
    #[must_use]
    pub fn new(registry: ProductionSourceRegistry) -> Self {
        Self::with_credentials(registry, CredentialProvider::system())
    }

    #[must_use]
    pub fn with_credentials(
        registry: ProductionSourceRegistry,
        credentials: CredentialProvider,
    ) -> Self {
        Self {
            registry,
            credentials,
        }
    }

    pub fn build(
        &self,
        source_id: &str,
        target_domain: &str,
        run_id: Uuid,
    ) -> Result<DynSourceAdapter, ProductionFactoryError> {
        let definition = self
            .registry
            .get(source_id)
            .ok_or_else(|| ProductionFactoryError::UnknownSource(source_id.to_owned()))?;
        let metadata = definition.metadata();
        let credential = self
            .credentials
            .resolve(definition.id, definition.auth.env_var());
        if definition.auth != ProductionAuth::None && credential.is_none() {
            return Ok(Arc::new(MissingCredentialAdapter { metadata }));
        }
        let mut headers = BTreeMap::new();
        headers.insert(
            "user-agent".to_owned(),
            format!(
                "FQDN-Lens/{} (passive; source={})",
                env!("CARGO_PKG_VERSION"),
                definition.id
            ),
        );
        if let Some(credential) = credential {
            match definition.auth {
                ProductionAuth::BearerToken { .. } => {
                    headers.insert(
                        "authorization".to_owned(),
                        format!("Bearer {}", credential.expose()),
                    );
                }
                ProductionAuth::ApiKey { .. } => {
                    headers.insert("api-key".to_owned(), credential.expose().to_owned());
                }
                ProductionAuth::None => {}
            }
        }

        if definition.id == "archive-commoncrawl-cdxj" {
            return Ok(Arc::new(CommonCrawlAdapter {
                metadata,
                target_domain: target_domain.to_owned(),
                run_id: run_id.to_string(),
                headers,
                cache_ttl_ms: definition.cache_ttl_ms,
            }));
        }

        let mut required_query = BTreeMap::new();
        let pagination = match definition.id {
            "ct-certspotter" => {
                required_query.insert("domain".to_owned(), target_domain.to_owned());
                required_query.insert("include_subdomains".to_owned(), "true".to_owned());
                required_query.insert("expand".to_owned(), "dns_names".to_owned());
                PaginationState::QueryCursor {
                    parameter: "after".to_owned(),
                    next_value_path: "after".to_owned(),
                }
            }
            "web-urlscan-search" => {
                required_query.insert(
                    "q".to_owned(),
                    format!("domain:{target_domain} AND date:>now-30d"),
                );
                required_query.insert("size".to_owned(), "100".to_owned());
                PaginationState::QueryCursor {
                    parameter: "search_after".to_owned(),
                    next_value_path: "search_after".to_owned(),
                }
            }
            "ct-crtsh" => {
                required_query.insert("q".to_owned(), format!("%.{target_domain}"));
                required_query.insert("output".to_owned(), "json".to_owned());
                PaginationState::None
            }
            _ => PaginationState::None,
        };
        let base_url =
            Url::parse(definition.origin).map_err(|_| ProductionFactoryError::InvalidEndpoint)?;
        if base_url.scheme() != "https" {
            return Err(ProductionFactoryError::InvalidEndpoint);
        }
        let config = crate::source::SourceRequestConfig {
            metadata,
            source_kind: definition.source_kind.to_owned(),
            parser_profile: Some(definition.parser_profile),
            base_url: definition.origin.to_owned(),
            method: HttpMethod::Get,
            path_template: definition.path.to_owned(),
            target_domain: target_domain.to_owned(),
            required_query,
            headers,
            virtual_wait_header: None,
            run_header_name: "x-fqdn-lens-run-id".to_owned(),
            run_id: run_id.to_string(),
            allow_retry: true,
            allow_redirect: false,
            pagination,
            body_template: None,
            body_content_type: None,
            cache_ttl_ms: Some(definition.cache_ttl_ms),
        };
        Ok(Arc::new(HttpSourceAdapter::new(config)))
    }
}

#[must_use]
pub fn production_scheduler_policy(definitions: &[ProductionSourceDefinition]) -> SchedulerPolicy {
    SchedulerPolicy {
        max_body_bytes: 2 * 1024 * 1024,
        max_results_per_source: 5_000,
        max_pages: 8,
        max_retries: 2,
        max_retry_after_ms: 30_000,
        source_concurrency: 1,
        connect_timeout_ms: 5_000,
        request_timeout_ms: 15_000,
        quota_rules: definitions
            .iter()
            .map(|definition| QuotaRule {
                source_id: definition.id.to_owned(),
                scope: QuotaScope::PerSource,
                limit: definition.quota_limit,
            })
            .collect(),
        cache_policy: CachePolicy::RunLocal,
    }
}

struct MissingCredentialAdapter {
    metadata: SourceMetadata,
}

#[async_trait]
impl SourceAdapter for MissingCredentialAdapter {
    fn metadata(&self) -> &SourceMetadata {
        &self.metadata
    }

    async fn collect(
        &self,
        _context: &CollectionContext,
        _http: &BoundedHttpClient,
    ) -> SourceCollection {
        let mut status = SourceStatus::pending(self.metadata.id.clone());
        status.state = SourceState::Skipped;
        status.error_code = Some("missing_credentials".to_owned());
        SourceCollection {
            observations: Vec::new(),
            status,
            virtual_waited_ms: 0,
        }
    }

    fn parse(&self, _response: &[u8]) -> Result<Vec<RawObservation>, SourceError> {
        Err(SourceError::Parse)
    }
}

struct CommonCrawlAdapter {
    metadata: SourceMetadata,
    target_domain: String,
    run_id: String,
    headers: BTreeMap<String, String>,
    cache_ttl_ms: u64,
}

impl CommonCrawlAdapter {
    fn metadata_url(&self) -> Url {
        Url::parse("https://index.commoncrawl.org/collinfo.json").expect("registered URL")
    }

    fn query_url(&self, index_id: &str) -> Url {
        let mut url = Url::parse("https://index.commoncrawl.org").expect("registered URL");
        url.set_path(&format!("/{index_id}-index"));
        let mut query = url.query_pairs_mut();
        query.append_pair("url", &format!("*.{}", self.target_domain));
        query.append_pair("output", "json");
        query.append_pair("filter", "status:200");
        query.append_pair("collapse", "urlkey");
        query.append_pair("limit", "5000");
        drop(query);
        url
    }

    fn with_headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.headers.iter().fold(
            request.header("x-fqdn-lens-run-id", &self.run_id),
            |request, (key, value)| request.header(key, value),
        )
    }

    async fn fetch(
        &self,
        request: reqwest::RequestBuilder,
        cache_key: String,
        http: &BoundedHttpClient,
        context: &CollectionContext,
        status: &mut SourceStatus,
        virtual_waited_ms: &mut u64,
    ) -> Result<BoundedResponse, String> {
        if matches!(
            context.policy.cache_policy,
            CachePolicy::RunLocal | CachePolicy::ProjectLocal
        ) {
            if let Some(response) = context.runtime.cache_get(&cache_key).await {
                status.cache_hits += 1;
                return Ok(response);
            }
            status.cache_misses += 1;
        }
        let quota = QuotaIdentity::new(self.metadata.id.clone(), "anonymous");
        let result = http
            .send_with_retry(
                request,
                RetryOptions {
                    allow_retry: true,
                    virtual_wait_header: None,
                    quota_identity: Some(&quota),
                },
                context,
                status,
                virtual_waited_ms,
            )
            .await;
        if let Ok(response) = &result {
            context
                .runtime
                .cache_put_with_ttl(
                    cache_key,
                    self.metadata.id.clone(),
                    response.clone(),
                    Some(self.cache_ttl_ms),
                )
                .await;
        }
        result
    }

    fn parse_index_id(body: &[u8]) -> Result<String, String> {
        let records: Vec<Value> =
            serde_json::from_slice(body).map_err(|_| "metadata_parse_error")?;
        records
            .iter()
            .filter_map(|record| record.get("id").or_else(|| record.get("name")))
            .filter_map(Value::as_str)
            .find(|id| id.starts_with("CC-MAIN-"))
            .map(ToOwned::to_owned)
            .ok_or_else(|| "metadata_parse_error".to_owned())
    }

    fn parse_cdxj(
        body: &[u8],
        metadata: &SourceMetadata,
        crawl_id: &str,
    ) -> Result<Vec<RawObservation>, SourceError> {
        let mut output = Vec::new();
        for line in std::str::from_utf8(body)
            .map_err(|_| SourceError::Parse)?
            .lines()
            .take(5_000)
        {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (url_value, record) = if line.starts_with('{') {
                let Ok(record) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let Some(url_value) = record.get("url").and_then(Value::as_str) else {
                    continue;
                };
                (url_value.to_owned(), record)
            } else {
                let Some((url_value, json)) = line.split_once('\t') else {
                    continue;
                };
                let Ok(record) = serde_json::from_str(json) else {
                    continue;
                };
                (url_value.to_owned(), record)
            };
            let Ok(url) = Url::parse(&url_value) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https") {
                continue;
            }
            let Some(host) = url.host_str() else { continue };
            let digest = record
                .get("digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| Some(hex_digest(line.as_bytes())));
            let reference = digest
                .clone()
                .map(|value| format!("commoncrawl:crawl:{crawl_id};record:{value}"));
            let observed_at = record
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(parse_capture_time);
            output.push(RawObservation {
                value: host.to_owned(),
                raw_reference: reference,
                source_url: None,
                observed_at,
                source_id: metadata.id.clone(),
                source_kind: metadata.kind.as_str().to_owned(),
                response_digest: None,
                record_digest: digest,
            });
        }
        Ok(output)
    }
}

#[async_trait]
impl SourceAdapter for CommonCrawlAdapter {
    fn metadata(&self) -> &SourceMetadata {
        &self.metadata
    }

    async fn collect(
        &self,
        context: &CollectionContext,
        http: &BoundedHttpClient,
    ) -> SourceCollection {
        let mut status = SourceStatus::pending(self.metadata.id.clone());
        let mut virtual_waited_ms = 0;
        if context.cancel.is_cancelled() {
            status.state = SourceState::Cancelled;
            status.error_code = Some("cancelled".to_owned());
            return SourceCollection {
                observations: Vec::new(),
                status,
                virtual_waited_ms,
            };
        }
        let metadata_url = self.metadata_url();
        let metadata_request = self.with_headers(http.get(metadata_url.clone()));
        let metadata_response = match self
            .fetch(
                metadata_request,
                hex_digest(metadata_url.as_str().as_bytes()),
                http,
                context,
                &mut status,
                &mut virtual_waited_ms,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                status.error_code = Some(error);
                if status.state == SourceState::Succeeded {
                    status.state = SourceState::Failed;
                }
                return SourceCollection {
                    observations: Vec::new(),
                    status,
                    virtual_waited_ms,
                };
            }
        };
        status.pages += 1;
        let index_id = match Self::parse_index_id(&metadata_response.body) {
            Ok(value) => value,
            Err(error) => {
                status.state = SourceState::Failed;
                status.error_code = Some(error);
                return SourceCollection {
                    observations: Vec::new(),
                    status,
                    virtual_waited_ms,
                };
            }
        };
        let query_url = self.query_url(&index_id);
        let query_request = self.with_headers(http.get(query_url.clone()));
        let query_response = match self
            .fetch(
                query_request,
                hex_digest(query_url.as_str().as_bytes()),
                http,
                context,
                &mut status,
                &mut virtual_waited_ms,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                status.error_code = Some(error);
                if status.state == SourceState::Succeeded {
                    status.state = SourceState::Failed;
                }
                return SourceCollection {
                    observations: Vec::new(),
                    status,
                    virtual_waited_ms,
                };
            }
        };
        status.pages += 1;
        let mut observations =
            match Self::parse_cdxj(&query_response.body, &self.metadata, &index_id) {
                Ok(value) => value,
                Err(_) => {
                    status.state = SourceState::Failed;
                    status.error_code = Some("response_parse_error".to_owned());
                    return SourceCollection {
                        observations: Vec::new(),
                        status,
                        virtual_waited_ms,
                    };
                }
            };
        for observation in &mut observations {
            observation.source_url = Some(query_response.final_url.to_string());
            observation.response_digest = Some(query_response.response_digest.clone());
        }
        status.results_received = observations.len() as u64;
        observations.truncate(context.policy.max_results_per_source);
        if observations.is_empty() {
            status.state = SourceState::Empty;
        }
        SourceCollection {
            observations,
            status,
            virtual_waited_ms,
        }
    }

    fn parse(&self, response: &[u8]) -> Result<Vec<RawObservation>, SourceError> {
        Self::parse_cdxj(response, &self.metadata, "unknown")
    }
}

fn parse_capture_time(value: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S")
        .ok()
        .map(|value| Utc.from_utc_datetime(&value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{EgressPolicy, FixedClock, SchedulerRuntime, VirtualWaiter};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn registry_contains_exactly_the_four_v03_sources() {
        let ids = ProductionSourceRegistry::new()
            .definitions()
            .iter()
            .map(|definition| definition.id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "ct-certspotter",
                "web-urlscan-search",
                "ct-crtsh",
                "archive-commoncrawl-cdxj"
            ]
        );
    }

    #[test]
    fn credential_state_never_exposes_a_secret_value() {
        let provider = CredentialProvider::system();
        assert_eq!(
            provider.state(
                "test-source",
                Some("FQDN_LENS_TEST_MISSING_CREDENTIAL_9C4A")
            ),
            CredentialState::Missing
        );
        let state = provider.state(
            "test-source",
            Some("FQDN_LENS_TEST_MISSING_CREDENTIAL_9C4A"),
        );
        let json = serde_json::to_string(&state).expect("state JSON");
        assert_eq!(json, "\"missing\"");
    }

    #[test]
    fn cdxj_parser_extracts_host_and_digest_without_fetching_the_url() {
        let metadata = ProductionSourceRegistry::new()
            .get("archive-commoncrawl-cdxj")
            .expect("definition")
            .metadata();
        let body = include_bytes!("../tests/fixtures/v0_3/commoncrawl.cdxj");
        let observations =
            CommonCrawlAdapter::parse_cdxj(body, &metadata, "CC-MAIN-2026-01").expect("CDXJ");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].value, "api.example.test");
        assert_eq!(observations[0].record_digest.as_deref(), Some("sha256:abc"));
        assert!(
            observations[0]
                .raw_reference
                .as_deref()
                .is_some_and(|reference| reference.contains("crawl:CC-MAIN-2026-01"))
        );
        assert!(observations[0].source_url.is_none());
    }

    #[test]
    fn production_egress_accepts_only_registered_https_authorities() {
        let mut policy = EgressPolicy::production();
        let registered = Url::parse("https://crt.sh/").expect("URL");
        let unregistered = Url::parse("https://example.test/").expect("URL");
        policy
            .allow_public_https_url(&registered, "/")
            .expect("registered authority");
        assert!(policy.validate(&registered).is_ok());
        assert!(policy.validate(&unregistered).is_err());
    }

    #[tokio::test]
    async fn missing_credentials_adapter_never_sends_a_request() {
        let adapter = MissingCredentialAdapter {
            metadata: ProductionSourceRegistry::new()
                .get("ct-certspotter")
                .expect("definition")
                .metadata(),
        };
        let policy = SchedulerPolicy::default();
        let context = CollectionContext {
            cancel: CancellationToken::new(),
            policy: policy.clone(),
            waiter: Arc::new(VirtualWaiter::default()),
            clock: Arc::new(FixedClock::new(Utc::now())),
            egress: EgressPolicy::production(),
            runtime: Arc::new(SchedulerRuntime::default()),
        };
        let http = BoundedHttpClient::new(policy).expect("client");
        let result = adapter.collect(&context, &http).await;
        assert_eq!(result.status.state, SourceState::Skipped);
        assert_eq!(
            result.status.error_code.as_deref(),
            Some("missing_credentials")
        );
        assert_eq!(result.status.requests, 0);
    }
}
