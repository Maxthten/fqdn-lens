use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{RequestBuilder, Url};
use scraper::Html;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

use crate::scheduler::{
    BoundedHttpClient, BoundedResponse, CachePolicy, CollectionContext, QuotaIdentity,
    RetryOptions, hex_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Certificate,
    PassiveDns,
    Archive,
    UrlSearch,
    ThreatIntel,
    CodeSearch,
    SearchEngine,
    Organization,
    UserImport,
    GenericJson,
    GenericHtml,
    GenericCsv,
    GenericText,
    CustomRest,
    Other(String),
}

impl SourceKind {
    #[must_use]
    pub fn from_manifest(value: &str) -> Self {
        match value {
            "certificate" => Self::Certificate,
            "passive_dns" => Self::PassiveDns,
            "archive" => Self::Archive,
            "internet_search" | "url_search" => Self::UrlSearch,
            "threat_intel" => Self::ThreatIntel,
            "code_search" => Self::CodeSearch,
            "search_engine" => Self::SearchEngine,
            "organization" => Self::Organization,
            "user_import" => Self::UserImport,
            "generic_json" | "key_api" => Self::GenericJson,
            "generic_html" => Self::GenericHtml,
            "csv" => Self::GenericCsv,
            "generic_text" | "text" => Self::GenericText,
            "custom" | "custom_rest" => Self::CustomRest,
            other => Self::Other(other.to_owned()),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Certificate => "certificate",
            Self::PassiveDns => "passive_dns",
            Self::Archive => "archive",
            Self::UrlSearch => "url_search",
            Self::ThreatIntel => "threat_intel",
            Self::CodeSearch => "code_search",
            Self::SearchEngine => "search_engine",
            Self::Organization => "organization",
            Self::UserImport => "user_import",
            Self::GenericJson => "generic_json",
            Self::GenericHtml => "generic_html",
            Self::GenericCsv => "generic_csv",
            Self::GenericText => "generic_text",
            Self::CustomRest => "custom_rest",
            Self::Other(value) => value,
        }
    }
}

/// Parser selection is deliberately separate from the provenance-preserving
/// [`SourceKind`]. Multiple source kinds can use the same bounded JSON reader,
/// but the profile remains explicit and auditable instead of collapsing every
/// provider into a generic source name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserProfile {
    Certificate,
    CertSpotter,
    UrlScan,
    CrtSh,
    PassiveDns,
    Archive,
    UrlSearch,
    ThreatIntel,
    CodeSearch,
    SearchHtml,
    Organization,
    Csv,
    Text,
    GenericJson,
    GenericHtml,
    CustomRest,
}

impl ParserProfile {
    #[must_use]
    pub fn from_source_kind(kind: &SourceKind) -> Self {
        match kind {
            SourceKind::Certificate => Self::Certificate,
            SourceKind::PassiveDns => Self::PassiveDns,
            SourceKind::Archive => Self::Archive,
            SourceKind::UrlSearch => Self::UrlSearch,
            SourceKind::ThreatIntel => Self::ThreatIntel,
            SourceKind::CodeSearch => Self::CodeSearch,
            SourceKind::SearchEngine => Self::SearchHtml,
            SourceKind::Organization => Self::Organization,
            SourceKind::UserImport | SourceKind::GenericCsv => Self::Csv,
            SourceKind::GenericText => Self::Text,
            SourceKind::GenericHtml => Self::GenericHtml,
            SourceKind::CustomRest => Self::CustomRest,
            SourceKind::GenericJson | SourceKind::Other(_) => Self::GenericJson,
        }
    }
}

/// A redaction-safe description of source request semantics. It deliberately
/// contains no credential values or request body content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestProfile {
    pub method: HttpMethod,
    pub pagination: &'static str,
    pub has_body_template: bool,
    pub authentication_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub id: String,
    pub display_name: String,
    pub kind: SourceKind,
    pub key_requirement: KeyRequirement,
    pub recursive_support: bool,
    pub passive_only: bool,
    pub default_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRequirement {
    None,
    Optional,
    Required,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Succeeded,
    Empty,
    Failed,
    Skipped,
    RateLimited,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceStatus {
    pub source_id: String,
    pub state: SourceState,
    pub requests: u64,
    pub pages: u64,
    pub results_received: u64,
    pub results_accepted: u64,
    pub results_filtered: u64,
    pub retries: u64,
    #[serde(default)]
    pub cache_hits: u64,
    #[serde(default)]
    pub cache_misses: u64,
    #[serde(default)]
    pub quota_rejections: u64,
    pub error_code: Option<String>,
    pub retry_after_ms: Option<u64>,
}

impl SourceStatus {
    #[must_use]
    pub fn pending(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            state: SourceState::Succeeded,
            requests: 0,
            pages: 0,
            results_received: 0,
            results_accepted: 0,
            results_filtered: 0,
            retries: 0,
            cache_hits: 0,
            cache_misses: 0,
            quota_rejections: 0,
            error_code: None,
            retry_after_ms: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RawObservation {
    pub value: String,
    pub raw_reference: Option<String>,
    pub source_url: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub source_id: String,
    pub source_kind: String,
    pub response_digest: Option<String>,
    pub record_digest: Option<String>,
}

#[derive(Clone)]
pub struct SourceRequestConfig {
    pub metadata: SourceMetadata,
    /// Exact source-kind spelling from the external manifest. Parser choice is
    /// represented by `metadata.kind`; this field preserves provenance for
    /// evidence and external submissions (for example `passive_dns`).
    pub source_kind: String,
    /// Optional explicit parser profile from an external manifest. When it is
    /// absent, Lens derives a stable profile from `metadata.kind`.
    pub parser_profile: Option<ParserProfile>,
    pub base_url: String,
    pub method: HttpMethod,
    pub path_template: String,
    /// Normalized target domain supplied by the public Lab manifest. It is
    /// used only for controlled body-template substitution and never logged.
    pub target_domain: String,
    pub required_query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    /// Optional caller-configured header which carries accumulated virtual
    /// cooldown time on every request. The core treats it generically; only
    /// the Lab bridge elects to use it.
    pub virtual_wait_header: Option<String>,
    pub run_header_name: String,
    pub run_id: String,
    pub allow_retry: bool,
    /// Forge metadata only. Redirects are categorically rejected by the
    /// transport, regardless of this value.
    pub allow_redirect: bool,
    pub pagination: PaginationState,
    pub body_template: Option<Value>,
    /// Explicit content type for a public request body template. Lens treats
    /// a missing value as JSON and never derives it from a scenario fixture.
    pub body_content_type: Option<String>,
    /// Provider-specific bounded cache lifetime. `None` preserves the V0.2
    /// run-local cache behavior with no expiry.
    pub cache_ttl_ms: Option<u64>,
}

impl std::fmt::Debug for SourceRequestConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRequestConfig")
            .field("metadata", &self.metadata)
            .field("parser_profile", &self.parser_profile)
            .field("base_url", &self.base_url)
            .field("method", &self.method)
            .field("path_template", &self.path_template)
            .field("target_domain", &self.target_domain)
            .field("required_query", &self.required_query)
            .field("headers", &"[REDACTED]")
            .field("run_header_name", &self.run_header_name)
            .field("run_id", &"[REDACTED]")
            .field("allow_retry", &self.allow_retry)
            .field("allow_redirect", &self.allow_redirect)
            .field("pagination", &self.pagination)
            .field("body_template", &"[REDACTED]")
            .field("body_content_type", &self.body_content_type)
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
}

/// Typed pagination state. The adapter never assumes a JSON cursor for every
/// source: the request construction and transition rule are tied together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaginationState {
    None,
    QueryPage {
        parameter: String,
        initial: i64,
        step: i64,
        next_value_path: Option<String>,
    },
    QueryOffset {
        parameter: String,
        initial: i64,
        step: i64,
        next_value_path: Option<String>,
    },
    QueryCursor {
        parameter: String,
        next_value_path: String,
    },
    PostBodyPage {
        parameter: String,
        initial: i64,
        step: i64,
        next_value_path: Option<String>,
    },
    PostBodyCursor {
        parameter: String,
        next_value_path: String,
    },
    LinkHeader,
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("transport failure")]
    Transport,
    #[error("response parsing failure")]
    Parse,
    #[error("pagination repeated a token")]
    PaginationLoop,
}

#[async_trait]
pub trait SourceAdapter: Send + Sync {
    fn metadata(&self) -> &SourceMetadata;
    async fn collect(
        &self,
        context: &CollectionContext,
        http: &BoundedHttpClient,
    ) -> SourceCollection;
    fn parse(&self, response: &[u8]) -> Result<Vec<RawObservation>, SourceError>;
}

pub struct SourceCollection {
    pub observations: Vec<RawObservation>,
    pub status: SourceStatus,
    pub virtual_waited_ms: u64,
}

/// A data-driven HTTP adapter whose source shape chooses only parser behavior;
/// domain filtering and persistence remain outside the adapter.
#[derive(Clone)]
pub struct HttpSourceAdapter {
    config: SourceRequestConfig,
}

impl HttpSourceAdapter {
    #[must_use]
    pub fn new(mut config: SourceRequestConfig) -> Self {
        if config.parser_profile.is_none() {
            config.parser_profile = Some(ParserProfile::from_source_kind(&config.metadata.kind));
        }
        Self { config }
    }

    #[must_use]
    pub fn request_profile(&self) -> RequestProfile {
        let pagination = match self.config.pagination {
            PaginationState::None => "none",
            PaginationState::QueryPage { .. } => "query_page",
            PaginationState::QueryOffset { .. } => "query_offset",
            PaginationState::QueryCursor { .. } => "query_cursor",
            PaginationState::PostBodyPage { .. } => "post_body_page",
            PaginationState::PostBodyCursor { .. } => "post_body_cursor",
            PaginationState::LinkHeader => "link_header",
        };
        RequestProfile {
            method: self.config.method.clone(),
            pagination,
            has_body_template: self.config.body_template.is_some(),
            authentication_required: self.config.metadata.key_requirement
                == KeyRequirement::Required,
        }
    }

    fn endpoint(&self, page: &PageRequest) -> Result<Url, SourceError> {
        if let PageRequest::Link(url) = page {
            return Ok(url.clone());
        }
        let mut url = Url::parse(&self.config.base_url).map_err(|_| SourceError::Transport)?;
        url.set_path(&self.config.path_template);
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in &self.config.required_query {
                query.append_pair(key, value);
            }
            if let Some((parameter, value)) = self.query_value(page) {
                query.append_pair(parameter, &value);
            }
        }
        Ok(url)
    }

    fn query_value(&self, page: &PageRequest) -> Option<(&str, String)> {
        match (&self.config.pagination, page) {
            (PaginationState::QueryPage { parameter, .. }, PageRequest::Number(value))
            | (PaginationState::QueryOffset { parameter, .. }, PageRequest::Number(value)) => {
                Some((parameter, value.to_string()))
            }
            (PaginationState::QueryCursor { parameter, .. }, PageRequest::Cursor(Some(value))) => {
                Some((parameter, value.clone()))
            }
            _ => None,
        }
    }

    fn body(&self, page: &PageRequest) -> Result<Option<Value>, SourceError> {
        let mut body = self.config.body_template.clone();
        if let Some(body) = &mut body {
            substitute_body_template(body, &self.config.target_domain, page);
        }
        match (&self.config.pagination, page) {
            (PaginationState::PostBodyPage { parameter, .. }, PageRequest::Number(value)) => {
                set_json_path(
                    body.get_or_insert_with(|| Value::Object(serde_json::Map::new())),
                    parameter,
                    Value::Number((*value).into()),
                )?;
            }
            (
                PaginationState::PostBodyCursor { parameter, .. },
                PageRequest::Cursor(Some(value)),
            ) => {
                set_json_path(
                    body.get_or_insert_with(|| Value::Object(serde_json::Map::new())),
                    parameter,
                    Value::String(value.clone()),
                )?;
            }
            _ => {}
        }
        if body
            .as_ref()
            .and_then(|value| serde_json::to_vec(value).ok())
            .is_some_and(|encoded| encoded.len() > 64 * 1024)
        {
            return Err(SourceError::Transport);
        }
        Ok(body)
    }

    fn request(
        &self,
        http: &BoundedHttpClient,
        page: &PageRequest,
    ) -> Result<RequestBuilder, SourceError> {
        let endpoint = self.endpoint(page)?;
        let request = match self.config.method {
            HttpMethod::Get => http.get(endpoint),
            HttpMethod::Post => http.post(endpoint),
        }
        .header(&self.config.run_header_name, &self.config.run_id);
        let request = self
            .config
            .headers
            .iter()
            .fold(request, |request, (key, value)| request.header(key, value));
        match self.body(page)? {
            Some(body) => {
                let encoded = serde_json::to_vec(&body).map_err(|_| SourceError::Parse)?;
                let content_type = self
                    .config
                    .body_content_type
                    .as_deref()
                    .unwrap_or("application/json");
                Ok(request.header("content-type", content_type).body(encoded))
            }
            None => Ok(request),
        }
    }

    fn cache_key(&self, page: &PageRequest) -> String {
        // The request fingerprint intentionally includes only source/root and
        // normalized request shape. Authentication, capability, cookie and
        // body values never participate in a cache key.
        let endpoint = self
            .endpoint(page)
            .map(|url| url.to_string())
            .unwrap_or_else(|_| "invalid-endpoint".to_owned());
        hex_digest(
            format!(
                "{}\u{1f}{}\u{1f}{:?}\u{1f}{}\u{1f}{}",
                self.config.metadata.id,
                self.config.target_domain,
                self.config.method,
                endpoint,
                page.key()
            )
            .as_bytes(),
        )
    }

    fn initial_page(&self) -> PageRequest {
        match &self.config.pagination {
            PaginationState::None | PaginationState::LinkHeader => PageRequest::Initial,
            PaginationState::QueryPage { initial, .. }
            | PaginationState::QueryOffset { initial, .. }
            | PaginationState::PostBodyPage { initial, .. } => PageRequest::Number(*initial),
            PaginationState::QueryCursor { .. } | PaginationState::PostBodyCursor { .. } => {
                PageRequest::Cursor(None)
            }
        }
    }

    fn next_page(
        &self,
        page: &PageRequest,
        response: &BoundedResponse,
        observations_empty: bool,
    ) -> Result<Option<PageRequest>, SourceError> {
        match (&self.config.pagination, page) {
            (PaginationState::None, _) => Ok(None),
            (
                PaginationState::QueryPage {
                    step,
                    next_value_path,
                    ..
                },
                PageRequest::Number(value),
            )
            | (
                PaginationState::QueryOffset {
                    step,
                    next_value_path,
                    ..
                },
                PageRequest::Number(value),
            )
            | (
                PaginationState::PostBodyPage {
                    step,
                    next_value_path,
                    ..
                },
                PageRequest::Number(value),
            ) => {
                if let Some(path) = next_value_path {
                    let Some(next) = json_next_number(&response.body, path) else {
                        return Ok(None);
                    };
                    if next <= *value {
                        return Err(SourceError::PaginationLoop);
                    }
                    return Ok(Some(PageRequest::Number(next)));
                }
                if observations_empty {
                    Ok(None)
                } else {
                    Ok(Some(PageRequest::Number(value.saturating_add(*step))))
                }
            }
            (
                PaginationState::QueryCursor {
                    next_value_path, ..
                }
                | PaginationState::PostBodyCursor {
                    next_value_path, ..
                },
                _,
            ) => Ok(json_next_cursor(&response.body, next_value_path)
                .map(|value| PageRequest::Cursor(Some(value)))),
            (PaginationState::LinkHeader, _) => match link_next(response)? {
                Some(target) => {
                    let url = response
                        .final_url
                        .join(&target)
                        .or_else(|_| Url::parse(&target))
                        .map_err(|_| SourceError::Parse)?;
                    Ok(Some(PageRequest::Link(url)))
                }
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PageRequest {
    Initial,
    Number(i64),
    Cursor(Option<String>),
    Link(Url),
}

fn substitute_body_template(value: &mut Value, target_domain: &str, page: &PageRequest) {
    match value {
        Value::String(text) => {
            let page_or_cursor = match page {
                PageRequest::Number(value) => value.to_string(),
                PageRequest::Cursor(Some(value)) => value.clone(),
                PageRequest::Initial | PageRequest::Cursor(None) | PageRequest::Link(_) => {
                    String::new()
                }
            };
            *text = text
                .replace("{{target_domain}}", target_domain)
                .replace("{{page_or_cursor}}", &page_or_cursor);
        }
        Value::Array(values) => {
            for value in values {
                substitute_body_template(value, target_domain, page);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                substitute_body_template(value, target_domain, page);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl PageRequest {
    fn key(&self) -> String {
        match self {
            Self::Initial => "initial".to_owned(),
            Self::Number(value) => format!("number:{value}"),
            Self::Cursor(Some(value)) => format!("cursor:{value}"),
            Self::Cursor(None) => "cursor:initial".to_owned(),
            Self::Link(url) => format!("link:{url}"),
        }
    }
}

#[async_trait]
impl SourceAdapter for HttpSourceAdapter {
    fn metadata(&self) -> &SourceMetadata {
        &self.config.metadata
    }

    async fn collect(
        &self,
        context: &CollectionContext,
        http: &BoundedHttpClient,
    ) -> SourceCollection {
        let mut status = SourceStatus::pending(self.config.metadata.id.clone());
        let mut observations = Vec::new();
        let mut page = self.initial_page();
        let mut seen_pages = std::collections::BTreeSet::new();
        let mut virtual_waited_ms = 0;

        for page_index in 0..context.policy.max_pages {
            if context.cancel.is_cancelled() {
                status.state = SourceState::Cancelled;
                status.error_code = Some("cancelled".to_owned());
                break;
            }
            if !seen_pages.insert(page.key()) {
                status.state = SourceState::Failed;
                status.error_code = Some("pagination_loop_detected".to_owned());
                break;
            }
            let request = match self.request(http, &page) {
                Ok(value) => value,
                Err(_) => {
                    status.state = SourceState::Failed;
                    status.error_code = Some("invalid_source_request".to_owned());
                    break;
                }
            };
            let cache_key = self.cache_key(&page);
            let cache_enabled = matches!(
                context.policy.cache_policy,
                CachePolicy::RunLocal | CachePolicy::ProjectLocal
            );
            let quota_identity = QuotaIdentity::new(
                self.config.metadata.id.clone(),
                if self.config.metadata.key_requirement == KeyRequirement::None {
                    "anonymous"
                } else {
                    "configured-key"
                },
            );
            let fetched = if cache_enabled {
                if let Some(response) = context.runtime.cache_get(&cache_key).await {
                    status.cache_hits += 1;
                    Ok(response)
                } else {
                    status.cache_misses += 1;
                    let result = http
                        .send_with_retry(
                            request,
                            RetryOptions {
                                allow_retry: self.config.allow_retry,
                                virtual_wait_header: self.config.virtual_wait_header.as_deref(),
                                quota_identity: Some(&quota_identity),
                            },
                            context,
                            &mut status,
                            &mut virtual_waited_ms,
                        )
                        .await;
                    if let Ok(response) = &result {
                        context
                            .runtime
                            .cache_put_with_ttl(
                                cache_key,
                                self.config.metadata.id.clone(),
                                response.clone(),
                                self.config.cache_ttl_ms,
                            )
                            .await;
                    }
                    result
                }
            } else {
                http.send_with_retry(
                    request,
                    RetryOptions {
                        allow_retry: self.config.allow_retry,
                        virtual_wait_header: self.config.virtual_wait_header.as_deref(),
                        quota_identity: Some(&quota_identity),
                    },
                    context,
                    &mut status,
                    &mut virtual_waited_ms,
                )
                .await
            };
            let response = match fetched {
                Ok(value) => value,
                Err(code) => {
                    let code = if self.config.metadata.key_requirement == KeyRequirement::Required
                        && matches!(code.as_str(), "http_401" | "http_403")
                    {
                        "authentication_failed".to_owned()
                    } else {
                        code
                    };
                    status.error_code = Some(code);
                    if status.state == SourceState::Succeeded {
                        status.state = SourceState::Failed;
                    }
                    break;
                }
            };
            status.pages += 1;
            if response.body.is_empty() {
                break;
            }
            if let Some(error_code) = source_error_payload(&response.body, &self.config.metadata) {
                status.state = SourceState::Failed;
                status.error_code = Some(error_code);
                break;
            }
            let mut parsed = match self.parse(&response.body) {
                Ok(value) => value,
                Err(_) => {
                    status.state = SourceState::Failed;
                    status.error_code = Some("response_parse_error".to_owned());
                    break;
                }
            };
            for observation in &mut parsed {
                observation.source_url = Some(response.final_url.to_string());
                observation.response_digest = Some(response.response_digest.clone());
            }
            status.results_received += parsed.len() as u64;
            let parsed_empty = parsed.is_empty();
            let remaining = context
                .policy
                .max_results_per_source
                .saturating_sub(observations.len());
            parsed.truncate(remaining);
            observations.append(&mut parsed);
            if observations.len() >= context.policy.max_results_per_source {
                status.error_code = Some("max_results_reached".to_owned());
                break;
            }
            let next = match self.next_page(&page, &response, parsed_empty) {
                Ok(value) => value,
                Err(_) => {
                    status.state = SourceState::Failed;
                    status.error_code = Some("pagination_transition_invalid".to_owned());
                    break;
                }
            };
            let Some(next) = next else { break };
            if page_index.saturating_add(1) >= context.policy.max_pages {
                status.state = SourceState::Failed;
                status.error_code = Some("max_pages_reached".to_owned());
                break;
            }
            if seen_pages.contains(&next.key()) {
                status.state = SourceState::Failed;
                status.error_code = Some("pagination_loop_detected".to_owned());
                break;
            }
            page = next;
        }
        if status.state == SourceState::Succeeded && observations.is_empty() {
            status.state = SourceState::Empty;
        }
        SourceCollection {
            observations,
            status,
            virtual_waited_ms,
        }
    }

    fn parse(&self, response: &[u8]) -> Result<Vec<RawObservation>, SourceError> {
        let profile = self
            .config
            .parser_profile
            .unwrap_or_else(|| ParserProfile::from_source_kind(&self.config.metadata.kind));
        let mut observations = match profile {
            ParserProfile::Certificate => parse_certificate(response, &self.config.metadata),
            ParserProfile::CertSpotter => parse_certspotter(response, &self.config.metadata),
            ParserProfile::UrlScan => parse_urlscan(response, &self.config.metadata),
            ParserProfile::CrtSh => parse_crtsh(response, &self.config.metadata),
            ParserProfile::Archive => parse_archive(response, &self.config.metadata),
            ParserProfile::SearchHtml | ParserProfile::GenericHtml => {
                parse_html(response, &self.config.metadata)
            }
            ParserProfile::Csv | ParserProfile::Text => parse_text(response, &self.config.metadata),
            ParserProfile::PassiveDns
            | ParserProfile::UrlSearch
            | ParserProfile::ThreatIntel
            | ParserProfile::Organization => parse_structured_json(response, &self.config.metadata),
            ParserProfile::CodeSearch => parse_code_search_json(response, &self.config.metadata),
            ParserProfile::GenericJson | ParserProfile::CustomRest => {
                parse_generic_json(response, &self.config.metadata)
            }
        }?;
        for observation in &mut observations {
            observation.source_kind.clone_from(&self.config.source_kind);
        }
        Ok(observations)
    }
}

fn parse_certificate(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value: Value = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .ok_or(SourceError::Parse)?;
    let mut output = Vec::new();
    for record in records {
        let reference = record_id(record).map(|id| format!("certificate:record:{id}"));
        let observed_at = timestamp(record, &["observed_at", "seen_at", "not_before"]);
        let record_digest = digest_value(record);
        let names = record
            .get("name")
            .and_then(Value::as_str)
            .map(|name| vec![name.to_owned()])
            .or_else(|| {
                ["names", "dns_names", "subject_alternative_names"]
                    .iter()
                    .find_map(|key| {
                        record.get(*key).and_then(Value::as_array).map(|values| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect::<Vec<_>>()
                        })
                    })
            })
            .unwrap_or_default();
        output.extend(names.into_iter().map(|name| {
            observation(
                name,
                reference.clone(),
                observed_at,
                metadata,
                record_digest.clone(),
            )
        }));
    }
    Ok(output)
}

fn parse_certspotter(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let records: Vec<Value> = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    for record in records {
        let reference = record_id(&record).map(|id| format!("certspotter:issuance:{id}"));
        let observed_at = timestamp(&record, &["not_before", "seen_at", "observed_at"]);
        let record_digest = digest_value(&record);
        if let Some(names) = record.get("dns_names").and_then(Value::as_array) {
            output.extend(names.iter().filter_map(Value::as_str).map(|name| {
                observation(
                    name.to_owned(),
                    reference.clone(),
                    observed_at,
                    metadata,
                    record_digest.clone(),
                )
            }));
        }
    }
    Ok(output)
}

fn parse_urlscan(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value: Value = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let records = value
        .get("results")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or(SourceError::Parse)?;
    let mut output = Vec::new();
    for record in records {
        let reference = record
            .get("task")
            .and_then(|task| task.get("uuid").or_else(|| task.get("id")))
            .and_then(Value::as_str)
            .map(|id| format!("urlscan:task:{id}"));
        let observed_at = record
            .get("task")
            .and_then(|task| timestamp(task, &["time", "created_at"]))
            .or_else(|| timestamp(record, &["time", "observed_at"]));
        let record_digest = digest_value(record);
        for key in ["domain", "hostname"] {
            if let Some(value) = record.get(key).and_then(Value::as_str)
                && looks_like_candidate(value)
            {
                output.push(observation(
                    value.to_owned(),
                    reference.clone(),
                    observed_at,
                    metadata,
                    record_digest.clone(),
                ));
            }
        }
        for container_key in ["task", "page"] {
            if let Some(container) = record.get(container_key) {
                for key in ["url", "domain", "hostname"] {
                    if let Some(value) = container.get(key).and_then(Value::as_str) {
                        let candidate = Url::parse(value)
                            .ok()
                            .and_then(|url| url.host_str().map(ToOwned::to_owned))
                            .unwrap_or_else(|| value.to_owned());
                        if looks_like_candidate(&candidate) {
                            output.push(observation(
                                candidate,
                                reference.clone(),
                                observed_at,
                                metadata,
                                record_digest.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(output)
}

fn parse_crtsh(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let records: Vec<Value> = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    for record in records {
        let reference = record_id(&record).map(|id| format!("crtsh:certificate:{id}"));
        let observed_at = timestamp(&record, &["not_before", "entry_timestamp"]);
        let record_digest = digest_value(&record);
        if let Some(names) = record.get("name_value").and_then(Value::as_str) {
            output.extend(
                names
                    .lines()
                    .filter(|name| looks_like_candidate(name))
                    .map(|name| {
                        observation(
                            name.trim().to_owned(),
                            reference.clone(),
                            observed_at,
                            metadata,
                            record_digest.clone(),
                        )
                    }),
            );
        }
    }
    Ok(output)
}

fn parse_archive(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value = serde_json::from_slice(response)
        .or_else(|_| {
            let records = response
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(serde_json::from_slice::<Value>)
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<Value, serde_json::Error>(Value::Array(records))
        })
        .map_err(|_| SourceError::Parse)?;
    let captures = value
        .get("captures")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or(SourceError::Parse)?;
    Ok(captures
        .iter()
        .filter_map(|capture| {
            let raw = capture
                .get("url")
                .or_else(|| capture.get("original"))
                .and_then(Value::as_str)?
                .to_owned();
            Some(observation(
                raw,
                record_id(capture).map(|id| format!("archive:record:{id}")),
                timestamp(capture, &["captured_at", "observed_at", "timestamp"]),
                metadata,
                digest_value(capture),
            ))
        })
        .collect())
}

fn parse_generic_json(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value: Value = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    collect_json_strings(
        &value,
        "$",
        &JsonRecordContext::default(),
        metadata,
        JsonStrategy::Conservative,
        &mut output,
    );
    Ok(output)
}

fn parse_structured_json(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value: Value = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    collect_json_strings(
        &value,
        "$",
        &JsonRecordContext::default(),
        metadata,
        JsonStrategy::Structured,
        &mut output,
    );
    Ok(output)
}

fn parse_code_search_json(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let value: Value = serde_json::from_slice(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    collect_json_strings(
        &value,
        "$",
        &JsonRecordContext::default(),
        metadata,
        JsonStrategy::Tokenize,
        &mut output,
    );
    Ok(output)
}

fn source_error_payload(body: &[u8], metadata: &SourceMetadata) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let has_error = value.get("error").is_some()
        || value.get("errors").is_some()
        || value.get("message").is_some_and(Value::is_string);
    if !has_error {
        return None;
    }
    if metadata.key_requirement == KeyRequirement::Required {
        Some("authentication_failed".to_owned())
    } else {
        Some("source_error_payload".to_owned())
    }
}

#[derive(Clone, Default)]
struct JsonRecordContext {
    record_id: Option<String>,
    observed_at: Option<DateTime<Utc>>,
    digest: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JsonStrategy {
    /// Generic JSON accepts only scalar values in object fields. This avoids
    /// treating arbitrary untyped arrays as a discovery source.
    Conservative,
    /// A profile-specific structured response may expose hostname arrays as
    /// record fields (for example passive DNS names or threat indicators).
    Structured,
    /// Code-search payloads may carry hostnames inside bounded code snippets.
    Tokenize,
}

fn collect_json_strings(
    value: &Value,
    path: &str,
    context: &JsonRecordContext,
    metadata: &SourceMetadata,
    strategy: JsonStrategy,
    output: &mut Vec<RawObservation>,
) {
    match value {
        Value::String(value) => {
            let reference = json_reference(path, context);
            if looks_like_candidate(value) {
                output.push(observation(
                    value.to_owned(),
                    reference,
                    context.observed_at,
                    metadata,
                    context.digest.clone(),
                ));
            } else if strategy == JsonStrategy::Tokenize {
                output.extend(extract_json_tokens(value, path, context, metadata));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if value.is_object() || value.is_array() || strategy != JsonStrategy::Conservative {
                    collect_json_strings(
                        value,
                        &format!("{path}[{index}]"),
                        context,
                        metadata,
                        strategy,
                        output,
                    );
                }
            }
        }
        Value::Object(values) => {
            let mut nested = context.clone();
            if let Some(id) = record_id(value) {
                nested.record_id = Some(id);
                nested.observed_at = timestamp(
                    value,
                    &[
                        "observed_at",
                        "seen_at",
                        "captured_at",
                        "timestamp",
                        "created_at",
                        "first_seen",
                        "last_seen",
                        "first_seen_at",
                        "last_seen_at",
                        "detected_at",
                        "reported_at",
                        "published_at",
                        "last_analysis_date",
                    ],
                )
                .or(context.observed_at);
                nested.digest = digest_value(value);
            }
            for (key, value) in values {
                collect_json_strings(
                    value,
                    &format!("{path}.{key}"),
                    &nested,
                    metadata,
                    strategy,
                    output,
                );
            }
        }
    }
}

fn json_reference(path: &str, context: &JsonRecordContext) -> Option<String> {
    match &context.record_id {
        Some(id) => Some(format!("json:path:{path};record:{id}")),
        None => Some(format!("json:path:{path}")),
    }
}

fn extract_json_tokens(
    input: &str,
    path: &str,
    context: &JsonRecordContext,
    metadata: &SourceMetadata,
) -> Vec<RawObservation> {
    tokenize_candidates(input)
        .into_iter()
        .map(|value| {
            observation(
                value.clone(),
                json_reference(path, context),
                context.observed_at,
                metadata,
                context
                    .digest
                    .clone()
                    .or_else(|| Some(hex_digest(value.as_bytes()))),
            )
        })
        .collect()
}

fn parse_html(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let input = std::str::from_utf8(response).map_err(|_| SourceError::Parse)?;
    let document = Html::parse_document(input);
    let mut output = Vec::new();
    for (index, element) in document.tree.root().descendants().enumerate() {
        if let Some(text) = element.value().as_text() {
            output.extend(extract_tokens(
                text,
                &format!("html:text:{index}"),
                metadata,
            ));
        }
        if let Some(element) = element.value().as_element() {
            for attribute in ["href", "src", "data-host"] {
                if let Some(value) = element.attr(attribute) {
                    output.extend(extract_tokens(
                        value,
                        &format!("html:{attribute}:{index}"),
                        metadata,
                    ));
                }
            }
        }
    }
    Ok(output)
}

fn parse_text(
    response: &[u8],
    metadata: &SourceMetadata,
) -> Result<Vec<RawObservation>, SourceError> {
    let input = std::str::from_utf8(response).map_err(|_| SourceError::Parse)?;
    let mut output = Vec::new();
    for (line_index, line) in input.lines().enumerate() {
        let columns = line.split(',').collect::<Vec<_>>();
        if columns.len() > 1 {
            for (column_index, column) in columns.into_iter().enumerate() {
                output.extend(extract_tokens(
                    column,
                    &format!("csv:line:{}:column:{}", line_index + 1, column_index + 1),
                    metadata,
                ));
            }
        } else {
            output.extend(extract_tokens(
                line,
                &format!("text:line:{}", line_index + 1),
                metadata,
            ));
        }
    }
    Ok(output)
}

fn extract_tokens(input: &str, reference: &str, metadata: &SourceMetadata) -> Vec<RawObservation> {
    tokenize_candidates(input)
        .into_iter()
        .map(|value| {
            observation(
                value.clone(),
                Some(reference.to_owned()),
                None,
                metadata,
                Some(hex_digest(value.as_bytes())),
            )
        })
        .collect()
}

fn tokenize_candidates(input: &str) -> Vec<String> {
    input
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '<' | '>' | '"' | '\'' | '(' | ')' | ',' | ';' | '=' | '{' | '}' | '[' | ']'
                )
        })
        .map(|token| token.trim_matches(['.', ':', '/']).to_owned())
        .filter(|token| looks_like_candidate(token))
        .collect()
}

fn looks_like_candidate(value: &str) -> bool {
    let value = value.trim();
    if let Ok(url) = Url::parse(value) {
        return url.host_str().is_some_and(hostname_like);
    }
    let value = value.strip_prefix("*.").unwrap_or(value);
    hostname_like(value)
}

fn hostname_like(value: &str) -> bool {
    if value.len() > 253 || !value.contains('.') || value.contains(['/', '@', ':', '?', '#']) {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_alphanumeric() || character == '-')
    })
}

fn observation(
    value: String,
    raw_reference: Option<String>,
    observed_at: Option<DateTime<Utc>>,
    metadata: &SourceMetadata,
    record_digest: Option<String>,
) -> RawObservation {
    RawObservation {
        value,
        raw_reference,
        source_url: None,
        observed_at,
        source_id: metadata.id.clone(),
        source_kind: metadata.kind.as_str().to_owned(),
        response_digest: None,
        record_digest,
    }
}

fn record_id(record: &Value) -> Option<String> {
    for key in ["id", "record_id", "uuid"] {
        if let Some(value) = record.get(key).and_then(Value::as_str) {
            return Some(value.to_owned());
        }
        if let Some(value) = record.get(key).and_then(Value::as_u64) {
            return Some(value.to_string());
        }
    }
    None
}

fn timestamp(record: &Value, keys: &[&str]) -> Option<DateTime<Utc>> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
    })
}

fn digest_value(value: &Value) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|value| hex_digest(&value))
}

fn json_next_cursor(body: &[u8], path: &str) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    json_path(&value, path)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn json_next_number(body: &[u8], path: &str) -> Option<i64> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let next = json_path(&value, path)?;
    next.as_i64()
        .or_else(|| next.as_u64().and_then(|value| value.try_into().ok()))
        .or_else(|| next.as_str().and_then(|value| value.parse().ok()))
}

fn json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .filter(|segment| !segment.is_empty())
        .try_fold(value, |current, segment| current.get(segment))
}

fn set_json_path(value: &mut Value, path: &str, replacement: Value) -> Result<(), SourceError> {
    let mut segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .peekable();
    let mut current = value;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            current
                .as_object_mut()
                .ok_or(SourceError::Parse)?
                .insert(segment.to_owned(), replacement);
            return Ok(());
        }
        let object = current.as_object_mut().ok_or(SourceError::Parse)?;
        current = object
            .entry(segment.to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    Err(SourceError::Parse)
}

fn link_next(response: &BoundedResponse) -> Result<Option<String>, SourceError> {
    let Some(header) = response.header("link") else {
        return Ok(None);
    };
    for entry in header.split(',') {
        let mut sections = entry.split(';');
        let Some(target) = sections.next().map(str::trim) else {
            continue;
        };
        let is_next = sections.any(|section| {
            let section = section.trim();
            section.eq_ignore_ascii_case("rel=next") || section.eq_ignore_ascii_case("rel=\"next\"")
        });
        if is_next {
            let target = target.trim_start_matches('<').trim_end_matches('>');
            if target.is_empty() {
                return Err(SourceError::Parse);
            }
            return Ok(Some(target.to_owned()));
        }
    }
    Ok(None)
}

pub type DynSourceAdapter = Arc<dyn SourceAdapter>;

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(kind: SourceKind) -> SourceMetadata {
        SourceMetadata {
            id: "source".to_owned(),
            display_name: "Source".to_owned(),
            kind,
            key_requirement: KeyRequirement::None,
            recursive_support: false,
            passive_only: true,
            default_enabled: true,
        }
    }

    #[test]
    fn request_config_debug_redacts_credentials_run_ids_and_body_values() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "authorization".to_owned(),
            "Bearer fake-certspotter-token".to_owned(),
        );
        let config = SourceRequestConfig {
            metadata: metadata(SourceKind::Certificate),
            source_kind: "certificate".to_owned(),
            parser_profile: Some(ParserProfile::CertSpotter),
            base_url: "https://api.certspotter.test".to_owned(),
            method: HttpMethod::Get,
            path_template: "/v1/issuances".to_owned(),
            target_domain: "acme.test".to_owned(),
            required_query: BTreeMap::new(),
            headers,
            virtual_wait_header: None,
            run_header_name: "x-run".to_owned(),
            run_id: "fake-run-capability".to_owned(),
            allow_retry: true,
            allow_redirect: false,
            pagination: PaginationState::None,
            body_template: Some(serde_json::json!({"token":"fake-body-secret"})),
            body_content_type: None,
            cache_ttl_ms: Some(60_000),
        };
        let rendered = format!("{config:?}");
        for secret in [
            "fake-certspotter-token",
            "fake-run-capability",
            "fake-body-secret",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn v03_certspotter_fixture_extracts_dns_names_and_issuance_context() {
        let observations = parse_certspotter(
            include_bytes!("../tests/fixtures/v0_3/certspotter.json"),
            &metadata(SourceKind::Certificate),
        )
        .expect("Cert Spotter fixture");
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|item| {
            item.raw_reference
                .as_deref()
                .is_some_and(|reference| reference.contains("issuance-1"))
        }));
    }

    #[test]
    fn v03_urlscan_fixture_extracts_hosts_without_following_result_urls() {
        let observations = parse_urlscan(
            include_bytes!("../tests/fixtures/v0_3/urlscan-search.json"),
            &metadata(SourceKind::UrlSearch),
        )
        .expect("URLScan fixture");
        assert!(
            observations
                .iter()
                .any(|item| item.value == "api.acme.test")
        );
        assert!(
            observations
                .iter()
                .any(|item| item.value == "www.acme.test")
        );
        assert!(
            observations
                .iter()
                .all(|item| !item.value.contains("fake-urlscan-token"))
        );
    }

    #[test]
    fn v03_crtsh_fixture_splits_name_value_and_keeps_certificate_context() {
        let observations = parse_crtsh(
            include_bytes!("../tests/fixtures/v0_3/crtsh.json"),
            &metadata(SourceKind::Certificate),
        )
        .expect("crt.sh fixture");
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|item| {
            item.raw_reference
                .as_deref()
                .is_some_and(|reference| reference.contains("certificate:42"))
        }));
    }

    #[test]
    fn v03_provider_parsers_reject_malformed_json() {
        assert!(parse_certspotter(b"not-json", &metadata(SourceKind::Certificate)).is_err());
        assert!(parse_urlscan(b"not-json", &metadata(SourceKind::UrlSearch)).is_err());
        assert!(parse_crtsh(b"not-json", &metadata(SourceKind::Certificate)).is_err());
    }

    #[test]
    fn parses_certificate_and_archive_shapes_with_record_context() {
        let certificate = parse_certificate(
            br#"{"records":[{"id":"1","name":"api.acme.test","observed_at":"2026-01-01T00:00:00Z"}]}"#,
            &metadata(SourceKind::Certificate),
        )
        .expect("certificate");
        assert_eq!(certificate[0].value, "api.acme.test");
        assert!(certificate[0].record_digest.is_some());
        let archive = parse_archive(
            br#"{"captures":[{"id":"2","url":"https://www.acme.test/x","captured_at":"2026-01-01T00:00:00Z"}]}"#,
            &metadata(SourceKind::Archive),
        )
        .expect("archive");
        assert_eq!(archive[0].value, "https://www.acme.test/x");
        assert!(
            archive[0]
                .raw_reference
                .as_deref()
                .is_some_and(|reference| reference.contains("record:2"))
        );
    }

    #[test]
    fn generic_json_recurses_and_preserves_path_record_and_time() {
        let observations = parse_generic_json(
            br#"{"items":[{"id":"synthetic-61-1","observed_at":"2026-01-01T00:00:00Z","dns":{"name":"api.acme.test"}}, {"url":"https://www.acme.test/a"}]}"#,
            &metadata(SourceKind::GenericJson),
        )
        .expect("generic json");
        assert_eq!(observations.len(), 2);
        assert!(
            observations[0]
                .raw_reference
                .as_deref()
                .is_some_and(|reference| reference.contains("synthetic-61-1"))
        );
        assert!(observations[0].observed_at.is_some());
    }

    #[test]
    fn generic_json_skips_scalar_strings_inside_untyped_arrays() {
        let observations = parse_generic_json(
            br#"{"items":[{"host":["noise.acme.test"]},{"host":"typed.acme.test"}]}"#,
            &metadata(SourceKind::GenericJson),
        )
        .expect("generic json");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].value, "typed.acme.test");
    }

    #[test]
    fn html_and_csv_keep_location_references() {
        let html = parse_html(
            b"<a href='https://api.acme.test/x'>cdn.acme.test</a>",
            &metadata(SourceKind::GenericHtml),
        )
        .expect("html");
        assert!(html.iter().any(|item| {
            item.raw_reference
                .as_deref()
                .is_some_and(|reference| reference.starts_with("html:"))
        }));
        let csv = parse_text(
            b"id,host\n1,api.acme.test\n",
            &metadata(SourceKind::GenericText),
        )
        .expect("csv");
        assert!(csv.iter().any(|item| {
            item.raw_reference
                .as_deref()
                .is_some_and(|reference| reference.starts_with("csv:line:2:column:2"))
        }));
    }

    #[test]
    fn link_header_only_accepts_next_relation() {
        let response = BoundedResponse {
            status: reqwest::StatusCode::OK,
            headers: BTreeMap::from([(
                "link".to_owned(),
                "</first>; rel=prev, </second>; rel=\"next\"".to_owned(),
            )]),
            body: Vec::new(),
            final_url: Url::parse("http://127.0.0.1:18080/api/source").expect("url"),
            response_digest: String::new(),
        };
        assert_eq!(
            link_next(&response).expect("link"),
            Some("/second".to_owned())
        );
    }

    #[test]
    fn structured_and_code_profiles_do_not_collapse_to_generic_json() {
        let structured = parse_structured_json(
            br#"{"records":[{"id":"one","names":["api.acme.test"]}]}"#,
            &metadata(SourceKind::PassiveDns),
        )
        .expect("structured");
        assert_eq!(structured[0].value, "api.acme.test");
        let code = parse_code_search_json(
            br#"{"items":[{"id":"two","snippet":"const host = api.acme.test;"}]}"#,
            &metadata(SourceKind::CodeSearch),
        )
        .expect("code search");
        assert_eq!(code[0].value, "api.acme.test");
    }

    #[test]
    fn body_templates_substitute_only_public_tokens() {
        let mut value = serde_json::json!({
            "domain": "{{target_domain}}",
            "cursor": "{{page_or_cursor}}",
            "secret": "unchanged"
        });
        substitute_body_template(
            &mut value,
            "acme.test",
            &PageRequest::Cursor(Some("next".to_owned())),
        );
        assert_eq!(value["domain"], "acme.test");
        assert_eq!(value["cursor"], "next");
        assert_eq!(value["secret"], "unchanged");
    }
}
