//! Reusable, secret-safe presentation resources for all FQDN Lens frontends.

use crate::app::ReportFormat;
use crate::config::{DisplayLanguage, ReportLanguage};
use crate::credentials::CredentialState;
use crate::domain::ScopeVerdict;
use crate::evidence::{RunMode, RunStatus};
use crate::production::ProductionSourceDefinition;
use crate::production::SourceHealthState;
use crate::source::{SourceState, SourceStatus};
use crate::store::ResultScope;
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageCode {
    TargetInvalid,
    TargetRootConfirmationRequired,
    UrlUserinfoDenied,
    SourceUnknown,
    SourceSelectionRequired,
    CredentialMissing,
    CredentialNotRequired,
    CredentialImportConfirmationRequired,
    CredentialRemoved,
    CredentialNotFound,
    AuthenticationFailed,
    RateLimited,
    UpstreamFailed,
    RunCancelled,
    RunNotCancellable,
    ExportDestinationDenied,
    ConfigurationInvalid,
    LabAcceptanceMismatch,
    InternalUnclassified,
}

impl MessageCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetInvalid => "target_invalid",
            Self::TargetRootConfirmationRequired => "target_root_confirmation_required",
            Self::UrlUserinfoDenied => "url_userinfo_denied",
            Self::SourceUnknown => "source_unknown",
            Self::SourceSelectionRequired => "source_selection_required",
            Self::CredentialMissing => "credential_missing",
            Self::CredentialNotRequired => "credential_not_required",
            Self::CredentialImportConfirmationRequired => "credential_import_confirmation_required",
            Self::CredentialRemoved => "credential_removed",
            Self::CredentialNotFound => "credential_not_found",
            Self::AuthenticationFailed => "authentication_failed",
            Self::RateLimited => "rate_limited",
            Self::UpstreamFailed => "upstream_failed",
            Self::RunCancelled => "run_cancelled",
            Self::RunNotCancellable => "run_not_cancellable",
            Self::ExportDestinationDenied => "export_destination_denied",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::LabAcceptanceMismatch => "lab_acceptance_mismatch",
            Self::InternalUnclassified => "internal_unclassified",
        }
    }
}

pub const REGISTERED_MESSAGE_CODES: &[MessageCode] = &[
    MessageCode::TargetInvalid,
    MessageCode::TargetRootConfirmationRequired,
    MessageCode::UrlUserinfoDenied,
    MessageCode::SourceUnknown,
    MessageCode::SourceSelectionRequired,
    MessageCode::CredentialMissing,
    MessageCode::CredentialNotRequired,
    MessageCode::CredentialImportConfirmationRequired,
    MessageCode::CredentialRemoved,
    MessageCode::CredentialNotFound,
    MessageCode::AuthenticationFailed,
    MessageCode::RateLimited,
    MessageCode::UpstreamFailed,
    MessageCode::RunCancelled,
    MessageCode::RunNotCancellable,
    MessageCode::ExportDestinationDenied,
    MessageCode::ConfigurationInvalid,
    MessageCode::LabAcceptanceMismatch,
    MessageCode::InternalUnclassified,
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageArgs {
    pub source_id: Option<String>,
    pub root_domain: Option<String>,
    pub run_id: Option<String>,
    pub path: Option<String>,
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalizedMessage {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[must_use]
pub fn message(
    language: DisplayLanguage,
    code: MessageCode,
    args: MessageArgs,
) -> LocalizedMessage {
    let source_id = args.source_id.as_deref().unwrap_or("source");
    let root_domain = args.root_domain.as_deref().unwrap_or("<root-domain>");
    let run_id = args.run_id.as_deref().unwrap_or("<run-id>");
    let path = args.path.as_deref().unwrap_or("<path>");
    let retry = args
        .retry_after_ms
        .map(|value| format!(" retry_after_ms={value}"))
        .unwrap_or_default();

    fn resource(
        severity: Severity,
        zh: impl Into<String>,
        en: impl Into<String>,
        zh_hint: impl Into<String>,
        en_hint: impl Into<String>,
    ) -> (Severity, String, String, String, String) {
        (
            severity,
            zh.into(),
            en.into(),
            zh_hint.into(),
            en_hint.into(),
        )
    }
    let (severity, zh, en, zh_hint, en_hint) = match code {
        MessageCode::TargetInvalid => resource(
            Severity::Error,
            "目标不是有效的 domain 或 HTTP(S) URL。",
            "The target is not a valid domain or HTTP(S) URL.",
            "示例：example.com 或 https://app.example.com/path。",
            "Example: example.com or https://app.example.com/path.",
        ),
        MessageCode::TargetRootConfirmationRequired => resource(
            Severity::Error,
            "目标会扩大到 root domain。",
            "The target expands to its registrable root domain.",
            format!("将查询 root domain `{root_domain}`；请使用 --confirm-root {root_domain}。"),
            format!(
                "The query will include root domain `{root_domain}`; use --confirm-root {root_domain}."
            ),
        ),
        MessageCode::UrlUserinfoDenied => resource(
            Severity::Error,
            "已安全拒绝包含 URL userinfo 的输入。",
            "The input containing URL userinfo was safely rejected.",
            "请移除用户名和密码后重试；path、query、fragment 不会被请求。",
            "Remove the username and password and retry; path, query, and fragment are never requested.",
        ),
        MessageCode::SourceUnknown => resource(
            Severity::Error,
            format!("未登记的 source ID：`{source_id}`。"),
            format!("The source ID is not registered: `{source_id}`."),
            "请先运行 source list 查看 allow-list。",
            "Run source list to view the registered allow-list.",
        ),
        MessageCode::SourceSelectionRequired => resource(
            Severity::Error,
            "未发出网络请求：必须显式选择 source。",
            "No network request was made: an explicit source selection is required.",
            "请使用 --source <source-id>，不会隐式启用全部 source。",
            "Use --source <source-id>; all sources are never enabled implicitly.",
        ),
        MessageCode::CredentialMissing => resource(
            Severity::Error,
            format!("source `{source_id}` 尚未配置 credential。"),
            format!("Source `{source_id}` has no configured credential."),
            "请使用 source configure-credential 或 source import-environment；本次 requests=0。",
            "Use source configure-credential or source import-environment; requests=0 for this attempt.",
        ),
        MessageCode::CredentialNotRequired => resource(
            Severity::Error,
            format!("source `{source_id}` 不需要 credential。"),
            format!("Source `{source_id}` does not require a credential."),
            "请改用 source list 查看需要 credential 的 source；不会保存无意义 secret。",
            "Use source list to find sources that require credentials; no meaningless secret is saved.",
        ),
        MessageCode::CredentialImportConfirmationRequired => resource(
            Severity::Error,
            "导入环境变量 credential 需要明确确认。",
            "Importing an environment credential requires explicit confirmation.",
            "请添加 --confirm；credential value 不会显示，也不会从环境变量删除。",
            "Add --confirm; the credential value is never displayed and the environment variable is not deleted.",
        ),
        MessageCode::CredentialRemoved => resource(
            Severity::Info,
            format!("已删除 source `{source_id}` 的 Lens-owned credential。"),
            format!("Removed the Lens-owned credential for source `{source_id}`."),
            "环境变量不会被删除。",
            "The environment variable was not removed.",
        ),
        MessageCode::CredentialNotFound => resource(
            Severity::Info,
            format!("未找到 source `{source_id}` 的 Lens-owned credential。"),
            format!("No Lens-owned credential was found for source `{source_id}`."),
            "环境变量不会被删除。",
            "The environment variable was not removed.",
        ),
        MessageCode::AuthenticationFailed => resource(
            Severity::Error,
            format!("source `{source_id}` 的 provider authentication failed。"),
            format!("Provider authentication failed for source `{source_id}`."),
            "请检查 secure credential 或环境变量配置；不要把 key 放入命令行参数。",
            "Check the secure credential or environment configuration; never put a key in command-line arguments.",
        ),
        MessageCode::RateLimited => resource(
            Severity::Warning,
            format!("source `{source_id}` 触发 rate limit。"),
            format!("Source `{source_id}` was rate limited."),
            format!("请等待 cooldown 后再试；保留当前结果与 stable status code。{retry}"),
            format!(
                "Wait for the cooldown before retrying; current results and stable status codes are retained.{retry}"
            ),
        ),
        MessageCode::UpstreamFailed => resource(
            Severity::Error,
            format!("source `{source_id}` 的 upstream 请求失败。"),
            format!("The upstream request for source `{source_id}` failed."),
            "该状态不等同于“未发现 FQDN”；请查看 source status 的 error code。",
            "This state does not mean “no FQDN found”; inspect the source status error code.",
        ),
        MessageCode::RunCancelled => resource(
            Severity::Info,
            format!("run `{run_id}` 已取消。"),
            format!("Run `{run_id}` was cancelled."),
            "请使用 runs show 查看最终状态。",
            "Use runs show to inspect the final state.",
        ),
        MessageCode::RunNotCancellable => resource(
            Severity::Error,
            format!("run `{run_id}` 当前不可取消。"),
            format!("Run `{run_id}` cannot be cancelled in its current state."),
            "只有当前本地 process 管理且未结束的 run 才能取消。",
            "Only an unfinished run managed by the current local process can be cancelled.",
        ),
        MessageCode::ExportDestinationDenied => resource(
            Severity::Error,
            "export destination 不在允许的目录内。",
            "The export destination is outside the allowed directory.",
            format!("请使用配置的 export directory；请求路径为 `{path}`。"),
            format!("Use the configured export directory; the requested path was `{path}`."),
        ),
        MessageCode::ConfigurationInvalid => resource(
            Severity::Error,
            "配置无效或无法读取。",
            "The configuration is invalid or could not be read.",
            format!("请检查配置路径 `{path}`，不要手工加入 secret 字段。"),
            format!("Check configuration path `{path}`; do not add secret fields manually."),
        ),
        MessageCode::LabAcceptanceMismatch => resource(
            Severity::Error,
            "Lab acceptance/verdict 未满足要求。",
            "The Lab acceptance/verdict did not satisfy the requested contract.",
            "请检查 Lab 参数、scenario 和 stable verification status。",
            "Check the Lab parameters, scenario, and stable verification status.",
        ),
        MessageCode::InternalUnclassified => resource(
            Severity::Error,
            "发生未分类的本地错误。",
            "An unclassified local error occurred.",
            "请使用受控诊断信息排查；输出不会包含 raw request、header、body 或 secret。",
            "Use controlled diagnostic information for troubleshooting; raw requests, headers, bodies, and secrets are not shown.",
        ),
    };
    LocalizedMessage {
        code: code.as_str().to_owned(),
        severity,
        message: match language {
            DisplayLanguage::ZhCn => zh,
            DisplayLanguage::EnUs => en,
        },
        hint: Some(match language {
            DisplayLanguage::ZhCn => zh_hint,
            DisplayLanguage::EnUs => en_hint,
        }),
    }
}

#[must_use]
pub fn localize_source(
    definition: ProductionSourceDefinition,
    language: DisplayLanguage,
) -> (String, String, String) {
    let zh = match definition.id {
        "ct-certspotter" => (
            "Cert Spotter".to_owned(),
            "被动查询证书透明度签发记录和 SAN 名称".to_owned(),
            "Certificate Transparency 签发记录查询；请遵守 provider 条款和限流。".to_owned(),
        ),
        "web-urlscan-search" => (
            "URLScan 搜索".to_owned(),
            "只读搜索已存在的公开扫描以提取 hostname 线索".to_owned(),
            "只读公开搜索；不会提交扫描，也不会访问结果 URL。".to_owned(),
        ),
        "ct-crtsh" => (
            "crt.sh".to_owned(),
            "低频 Certificate Transparency 后备查询".to_owned(),
            "低频公开后备来源；不承诺生产 SLA。".to_owned(),
        ),
        "archive-commoncrawl-cdxj" => (
            "Common Crawl CDXJ".to_owned(),
            "从历史网页索引中提取 hostname 线索".to_owned(),
            "有界历史索引查询；不会下载 WARC 或抓取网页。".to_owned(),
        ),
        _ => unreachable!("registry is fixed"),
    };
    let en = (
        definition.display_name.to_owned(),
        match definition.id {
            "ct-certspotter" => "Passive Certificate Transparency issuance and SAN lookup.",
            "web-urlscan-search" => "Read-only search of existing public scans for hostname leads.",
            "ct-crtsh" => "Low-frequency Certificate Transparency fallback lookup.",
            "archive-commoncrawl-cdxj" => "Historical web-index hostname lookup.",
            _ => unreachable!("registry is fixed"),
        }
        .to_owned(),
        definition.terms_notice.to_owned(),
    );
    match language {
        DisplayLanguage::ZhCn => zh,
        DisplayLanguage::EnUs => en,
    }
}

#[must_use]
pub fn display_language_code(language: DisplayLanguage) -> &'static str {
    match language {
        DisplayLanguage::ZhCn => "zh-cn",
        DisplayLanguage::EnUs => "en-us",
    }
}

#[must_use]
pub fn report_language_code(language: ReportLanguage) -> &'static str {
    match language {
        ReportLanguage::ZhCn => "zh-cn",
        ReportLanguage::EnUs => "en-us",
        ReportLanguage::Bilingual => "bilingual",
    }
}

#[must_use]
pub fn display_language_label(language: DisplayLanguage) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => "中文",
        DisplayLanguage::EnUs => "English",
    };
    format!("{label} ({})", display_language_code(language))
}

#[must_use]
pub fn report_language_label(language: DisplayLanguage, value: ReportLanguage) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match value {
            ReportLanguage::ZhCn => "中文报告",
            ReportLanguage::EnUs => "英文报告",
            ReportLanguage::Bilingual => "中英双语报告",
        },
        DisplayLanguage::EnUs => match value {
            ReportLanguage::ZhCn => "Chinese report",
            ReportLanguage::EnUs => "English report",
            ReportLanguage::Bilingual => "Bilingual report",
        },
    };
    format!("{label} ({})", report_language_code(value))
}

#[must_use]
pub fn boolean_label(language: DisplayLanguage, value: bool) -> String {
    let label = match (language, value) {
        (DisplayLanguage::ZhCn, true) => "是",
        (DisplayLanguage::ZhCn, false) => "否",
        (DisplayLanguage::EnUs, true) => "Yes",
        (DisplayLanguage::EnUs, false) => "No",
    };
    format!("{label} ({value})")
}

#[must_use]
pub fn result_scope_code(scope: &ResultScope) -> &'static str {
    match scope {
        ResultScope::Accepted => "accepted",
        ResultScope::Filtered => "filtered",
        ResultScope::All => "all",
    }
}

#[must_use]
pub fn result_scope_label(language: DisplayLanguage, scope: &ResultScope) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match scope {
            ResultScope::Accepted => "已接受",
            ResultScope::Filtered => "已过滤",
            ResultScope::All => "全部",
        },
        DisplayLanguage::EnUs => match scope {
            ResultScope::Accepted => "Accepted",
            ResultScope::Filtered => "Filtered",
            ResultScope::All => "All",
        },
    };
    format!("{label} ({})", result_scope_code(scope))
}

#[must_use]
pub fn scope_verdict_code(verdict: &ScopeVerdict) -> &'static str {
    match verdict {
        ScopeVerdict::Accepted => "accepted",
        ScopeVerdict::Root => "root",
        ScopeVerdict::Wildcard => "wildcard",
        ScopeVerdict::OutOfScope => "out_of_scope",
        ScopeVerdict::Invalid => "invalid",
    }
}

#[must_use]
pub fn scope_verdict_label(language: DisplayLanguage, verdict: &ScopeVerdict) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match verdict {
            ScopeVerdict::Accepted => "已接受",
            ScopeVerdict::Root => "根域名",
            ScopeVerdict::Wildcard => "通配符",
            ScopeVerdict::OutOfScope => "已过滤",
            ScopeVerdict::Invalid => "无效",
        },
        DisplayLanguage::EnUs => match verdict {
            ScopeVerdict::Accepted => "Accepted",
            ScopeVerdict::Root => "Root",
            ScopeVerdict::Wildcard => "Wildcard",
            ScopeVerdict::OutOfScope => "Filtered out of scope",
            ScopeVerdict::Invalid => "Invalid",
        },
    };
    format!("{label} ({})", scope_verdict_code(verdict))
}

#[must_use]
pub fn report_format_code(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Json => "json",
        ReportFormat::Markdown => "markdown",
        ReportFormat::Csv => "csv",
    }
}

#[must_use]
pub fn report_format_label(language: DisplayLanguage, format: ReportFormat) -> String {
    let label = match (language, format) {
        (DisplayLanguage::ZhCn, ReportFormat::Json) => "JSON",
        (DisplayLanguage::ZhCn, ReportFormat::Markdown) => "Markdown",
        (DisplayLanguage::ZhCn, ReportFormat::Csv) => "CSV",
        (DisplayLanguage::EnUs, ReportFormat::Json) => "JSON",
        (DisplayLanguage::EnUs, ReportFormat::Markdown) => "Markdown",
        (DisplayLanguage::EnUs, ReportFormat::Csv) => "CSV",
    };
    format!("{label} ({})", report_format_code(format))
}

#[must_use]
pub fn credential_state_code(state: CredentialState) -> &'static str {
    match state {
        CredentialState::NotRequired => "not_required",
        CredentialState::CredentialStore => "credential_store",
        CredentialState::Environment => "environment",
        CredentialState::SessionOnly => "session_only",
        CredentialState::Missing => "missing",
    }
}

#[must_use]
pub fn credential_state_label(language: DisplayLanguage, state: CredentialState) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match state {
            CredentialState::NotRequired => "不需要凭据",
            CredentialState::CredentialStore => "凭据库",
            CredentialState::Environment => "环境变量",
            CredentialState::SessionOnly => "仅本次会话",
            CredentialState::Missing => "缺少凭据",
        },
        DisplayLanguage::EnUs => match state {
            CredentialState::NotRequired => "Not required",
            CredentialState::CredentialStore => "Credential store",
            CredentialState::Environment => "Environment",
            CredentialState::SessionOnly => "Session only",
            CredentialState::Missing => "Missing credential",
        },
    };
    format!("{label} ({})", credential_state_code(state))
}

#[must_use]
pub fn source_state_code(state: &SourceState) -> &'static str {
    match state {
        SourceState::Succeeded => "succeeded",
        SourceState::Empty => "empty",
        SourceState::Failed => "failed",
        SourceState::Skipped => "skipped",
        SourceState::RateLimited => "rate_limited",
        SourceState::Cancelled => "cancelled",
    }
}

#[must_use]
pub fn source_state_label(language: DisplayLanguage, state: &SourceState) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match state {
            SourceState::Succeeded => "已成功",
            SourceState::Empty => "无结果",
            SourceState::Failed => "失败",
            SourceState::Skipped => "已跳过",
            SourceState::RateLimited => "触发 rate limit",
            SourceState::Cancelled => "已取消",
        },
        DisplayLanguage::EnUs => match state {
            SourceState::Succeeded => "Succeeded",
            SourceState::Empty => "Empty",
            SourceState::Failed => "Failed",
            SourceState::Skipped => "Skipped",
            SourceState::RateLimited => "Rate limited",
            SourceState::Cancelled => "Cancelled",
        },
    };
    format!("{label} ({})", source_state_code(state))
}

#[must_use]
pub fn source_state_label_code(language: DisplayLanguage, code: &str) -> String {
    let label = match (language, code) {
        (DisplayLanguage::ZhCn, "queued") => "排队中",
        (DisplayLanguage::ZhCn, "running") => "运行中",
        (DisplayLanguage::ZhCn, "succeeded") => "已成功",
        (DisplayLanguage::ZhCn, "empty") => "无结果",
        (DisplayLanguage::ZhCn, "failed") => "失败",
        (DisplayLanguage::ZhCn, "skipped") => "已跳过",
        (DisplayLanguage::ZhCn, "rate_limited") => "触发 rate limit",
        (DisplayLanguage::ZhCn, "cancelled") => "已取消",
        (DisplayLanguage::EnUs, "queued") => "Queued",
        (DisplayLanguage::EnUs, "running") => "Running",
        (DisplayLanguage::EnUs, "succeeded") => "Succeeded",
        (DisplayLanguage::EnUs, "empty") => "Empty",
        (DisplayLanguage::EnUs, "failed") => "Failed",
        (DisplayLanguage::EnUs, "skipped") => "Skipped",
        (DisplayLanguage::EnUs, "rate_limited") => "Rate limited",
        (DisplayLanguage::EnUs, "cancelled") => "Cancelled",
        (_, other) => return format!("{other} ({other})"),
    };
    format!("{label} ({code})")
}

#[must_use]
pub fn run_status_code(status: &RunStatus) -> &'static str {
    match status {
        RunStatus::Queued => "queued",
        RunStatus::Running => "running",
        RunStatus::Succeeded => "succeeded",
        RunStatus::Partial => "partial",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

#[must_use]
pub fn run_status_label(language: DisplayLanguage, status: &RunStatus) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match status {
            RunStatus::Queued => "排队中",
            RunStatus::Running => "运行中",
            RunStatus::Succeeded => "已成功",
            RunStatus::Partial => "部分成功",
            RunStatus::Failed => "失败",
            RunStatus::Cancelled => "已取消",
        },
        DisplayLanguage::EnUs => match status {
            RunStatus::Queued => "Queued",
            RunStatus::Running => "Running",
            RunStatus::Succeeded => "Succeeded",
            RunStatus::Partial => "Partial",
            RunStatus::Failed => "Failed",
            RunStatus::Cancelled => "Cancelled",
        },
    };
    format!("{label} ({})", run_status_code(status))
}

#[must_use]
pub fn run_status_label_code(language: DisplayLanguage, code: &str) -> String {
    let label = match (language, code) {
        (DisplayLanguage::ZhCn, "queued") => "排队中",
        (DisplayLanguage::ZhCn, "running") => "运行中",
        (DisplayLanguage::ZhCn, "succeeded") => "已成功",
        (DisplayLanguage::ZhCn, "partial") => "部分成功",
        (DisplayLanguage::ZhCn, "failed") => "失败",
        (DisplayLanguage::ZhCn, "cancelled") => "已取消",
        (DisplayLanguage::EnUs, "queued") => "Queued",
        (DisplayLanguage::EnUs, "running") => "Running",
        (DisplayLanguage::EnUs, "succeeded") => "Succeeded",
        (DisplayLanguage::EnUs, "partial") => "Partial",
        (DisplayLanguage::EnUs, "failed") => "Failed",
        (DisplayLanguage::EnUs, "cancelled") => "Cancelled",
        (_, other) => return format!("{other} ({other})"),
    };
    format!("{label} ({code})")
}

#[must_use]
pub fn source_health_code(health: &SourceHealthState) -> &'static str {
    match health {
        SourceHealthState::Succeeded => "succeeded",
        SourceHealthState::Empty => "empty",
        SourceHealthState::MissingCredentials => "missing_credentials",
        SourceHealthState::AuthenticationFailed => "authentication_failed",
        SourceHealthState::RateLimited => "rate_limited",
        SourceHealthState::UpstreamFailed => "upstream_failed",
        SourceHealthState::ParseFailed => "parse_failed",
        SourceHealthState::Cancelled => "cancelled",
        SourceHealthState::SecurityRejected => "security_rejected",
    }
}

#[must_use]
pub fn source_health_label(language: DisplayLanguage, health: &SourceHealthState) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match health {
            SourceHealthState::Succeeded => "已成功",
            SourceHealthState::Empty => "无结果",
            SourceHealthState::MissingCredentials => "缺少凭据",
            SourceHealthState::AuthenticationFailed => "认证失败",
            SourceHealthState::RateLimited => "触发 rate limit",
            SourceHealthState::UpstreamFailed => "上游失败",
            SourceHealthState::ParseFailed => "解析失败",
            SourceHealthState::Cancelled => "已取消",
            SourceHealthState::SecurityRejected => "安全策略拒绝",
        },
        DisplayLanguage::EnUs => match health {
            SourceHealthState::Succeeded => "Succeeded",
            SourceHealthState::Empty => "Empty",
            SourceHealthState::MissingCredentials => "Missing credentials",
            SourceHealthState::AuthenticationFailed => "Authentication failed",
            SourceHealthState::RateLimited => "Rate limited",
            SourceHealthState::UpstreamFailed => "Upstream failed",
            SourceHealthState::ParseFailed => "Parse failed",
            SourceHealthState::Cancelled => "Cancelled",
            SourceHealthState::SecurityRejected => "Security rejected",
        },
    };
    format!("{label} ({})", source_health_code(health))
}

#[must_use]
pub fn run_mode_code(mode: &RunMode) -> &'static str {
    match mode {
        RunMode::Lab => "lab",
        RunMode::LiveReserved => "live_reserved",
    }
}

#[must_use]
pub fn run_mode_label(language: DisplayLanguage, mode: &RunMode) -> String {
    let label = match language {
        DisplayLanguage::ZhCn => match mode {
            RunMode::Lab => "Lab",
            RunMode::LiveReserved => "生产保留模式",
        },
        DisplayLanguage::EnUs => match mode {
            RunMode::Lab => "Lab",
            RunMode::LiveReserved => "Live reserved",
        },
    };
    format!("{label} ({})", run_mode_code(mode))
}

#[must_use]
pub fn text(language: DisplayLanguage, key: &str) -> String {
    match (language, key) {
        (DisplayLanguage::ZhCn, "dashboard") => "仪表盘",
        (DisplayLanguage::EnUs, "dashboard") => "Dashboard",
        (DisplayLanguage::ZhCn, "quick_collect") => "快速采集",
        (DisplayLanguage::EnUs, "quick_collect") => "Quick Collect",
        (DisplayLanguage::ZhCn, "sources_credentials") => "Sources 与凭据",
        (DisplayLanguage::EnUs, "sources_credentials") => "Sources & Credentials",
        (DisplayLanguage::ZhCn, "run_monitor") => "运行监控",
        (DisplayLanguage::EnUs, "run_monitor") => "Run Monitor",
        (DisplayLanguage::ZhCn, "findings") => "发现",
        (DisplayLanguage::EnUs, "findings") => "Findings",
        (DisplayLanguage::ZhCn, "compare") => "比较",
        (DisplayLanguage::EnUs, "compare") => "Compare",
        (DisplayLanguage::ZhCn, "export") => "导出",
        (DisplayLanguage::EnUs, "export") => "Export",
        (DisplayLanguage::ZhCn, "settings") => "设置",
        (DisplayLanguage::EnUs, "settings") => "Settings",
        (DisplayLanguage::ZhCn, "help") => "帮助",
        (DisplayLanguage::EnUs, "help") => "Help",
        (DisplayLanguage::ZhCn, "target_input") => "目标输入",
        (DisplayLanguage::EnUs, "target_input") => "Target input",
        (DisplayLanguage::ZhCn, "target_preview") => "目标预览",
        (DisplayLanguage::EnUs, "target_preview") => "Target preview",
        (DisplayLanguage::ZhCn, "selected_sources") => "已选 source",
        (DisplayLanguage::EnUs, "selected_sources") => "Selected sources",
        (DisplayLanguage::ZhCn, "start_collection") => "开始 collection",
        (DisplayLanguage::EnUs, "start_collection") => "Start collection",
        (DisplayLanguage::ZhCn, "cancel_collection") => "取消 collection",
        (DisplayLanguage::EnUs, "cancel_collection") => "Cancel collection",
        (DisplayLanguage::ZhCn, "recent_runs") => "最近 run",
        (DisplayLanguage::EnUs, "recent_runs") => "Recent runs",
        (DisplayLanguage::ZhCn, "active_run") => "当前 run",
        (DisplayLanguage::EnUs, "active_run") => "Active run",
        (DisplayLanguage::ZhCn, "no_active_run") => "当前没有 active run。",
        (DisplayLanguage::EnUs, "no_active_run") => "No active run.",
        (DisplayLanguage::ZhCn, "no_runs") => "还没有本地 run。",
        (DisplayLanguage::EnUs, "no_runs") => "No local runs yet.",
        (DisplayLanguage::ZhCn, "confirm_action") => "确认操作",
        (DisplayLanguage::EnUs, "confirm_action") => "Confirm action",
        (DisplayLanguage::ZhCn, "save") => "保存",
        (DisplayLanguage::EnUs, "save") => "Save",
        (DisplayLanguage::ZhCn, "back") => "返回",
        (DisplayLanguage::EnUs, "back") => "Back",
        (DisplayLanguage::ZhCn, "yes") => "是",
        (DisplayLanguage::EnUs, "yes") => "Yes",
        (DisplayLanguage::ZhCn, "no") => "否",
        (DisplayLanguage::EnUs, "no") => "No",
        (DisplayLanguage::ZhCn, "credential_state") => "凭据状态",
        (DisplayLanguage::EnUs, "credential_state") => "Credential state",
        (DisplayLanguage::ZhCn, "source_health") => "Source 健康状态",
        (DisplayLanguage::EnUs, "source_health") => "Source health",
        (DisplayLanguage::ZhCn, "source_contribution") => "Source 贡献",
        (DisplayLanguage::EnUs, "source_contribution") => "Source contribution",
        (DisplayLanguage::ZhCn, "not_configured") => "未配置",
        (DisplayLanguage::EnUs, "not_configured") => "Not configured",
        (DisplayLanguage::ZhCn, "hidden_input") => "<隐藏；不会显示>",
        (DisplayLanguage::EnUs, "hidden_input") => "<hidden; never displayed>",
        (DisplayLanguage::ZhCn, "terminal_not_interactive") => "需要 interactive terminal；请改用 noninteractive CLI。",
        (DisplayLanguage::EnUs, "terminal_not_interactive") => "An interactive terminal is required; use the noninteractive CLI instead.",
        (DisplayLanguage::ZhCn, "network_after_confirm") => "只有确认开始 collection 后才会产生 provider request。",
        (DisplayLanguage::EnUs, "network_after_confirm") => "Provider requests are made only after Start collection is confirmed.",
        (DisplayLanguage::ZhCn, "api_txt_notice") => "TUI 不读取 api.txt；credential 只使用既有 secure store 或 environment resolution。",
        (DisplayLanguage::EnUs, "api_txt_notice") => "TUI never reads api.txt; credentials use the existing secure store or environment resolution.",
        (DisplayLanguage::ZhCn, "shortcuts") => "快捷键",
        (DisplayLanguage::EnUs, "shortcuts") => "Shortcuts",
        (DisplayLanguage::ZhCn, "pending_changes") => "有未保存的修改。",
        (DisplayLanguage::EnUs, "pending_changes") => "There are unsaved changes.",
        (DisplayLanguage::ZhCn, "scope_confirmation") => "此操作会扩大到 registrable root domain。",
        (DisplayLanguage::EnUs, "scope_confirmation") => "This action expands the scope to the registrable root domain.",
        (DisplayLanguage::ZhCn, "no_source_selected") => "必须明确选择至少一个 source。",
        (DisplayLanguage::EnUs, "no_source_selected") => "Select at least one source explicitly.",
        (DisplayLanguage::ZhCn, "project_id") => "项目 ID",
        (DisplayLanguage::EnUs, "project_id") => "Project ID",
        (DisplayLanguage::ZhCn, "root_domain") => "根域名",
        (DisplayLanguage::EnUs, "root_domain") => "Root domain",
        (DisplayLanguage::ZhCn, "policy") => "策略",
        (DisplayLanguage::EnUs, "policy") => "Policy",
        (DisplayLanguage::ZhCn, "run_id") => "Run ID",
        (DisplayLanguage::EnUs, "run_id") => "Run ID",
        (DisplayLanguage::ZhCn, "project") => "项目",
        (DisplayLanguage::EnUs, "project") => "Project",
        (DisplayLanguage::ZhCn, "target") => "目标",
        (DisplayLanguage::EnUs, "target") => "Target",
        (DisplayLanguage::ZhCn, "status") => "状态",
        (DisplayLanguage::EnUs, "status") => "Status",
        (DisplayLanguage::ZhCn, "mode") => "模式",
        (DisplayLanguage::EnUs, "mode") => "Mode",
        (DisplayLanguage::ZhCn, "started") => "开始时间",
        (DisplayLanguage::EnUs, "started") => "Started",
        (DisplayLanguage::ZhCn, "finished") => "结束时间",
        (DisplayLanguage::EnUs, "finished") => "Finished",
        (DisplayLanguage::ZhCn, "diagnostics") => "诊断摘要",
        (DisplayLanguage::EnUs, "diagnostics") => "Diagnostics",
        (DisplayLanguage::ZhCn, "added") => "新增",
        (DisplayLanguage::EnUs, "added") => "Added",
        (DisplayLanguage::ZhCn, "removed") => "移除",
        (DisplayLanguage::EnUs, "removed") => "Removed",
        (DisplayLanguage::ZhCn, "provenance_changed") => "来源证据变化",
        (DisplayLanguage::EnUs, "provenance_changed") => "Provenance changed",
        (DisplayLanguage::ZhCn, "evidence") => "证据",
        (DisplayLanguage::EnUs, "evidence") => "Evidence",
        (DisplayLanguage::ZhCn, "sources") => "来源",
        (DisplayLanguage::EnUs, "sources") => "Sources",
        (DisplayLanguage::ZhCn, "first_seen") => "首次发现",
        (DisplayLanguage::EnUs, "first_seen") => "First seen",
        (DisplayLanguage::ZhCn, "last_seen") => "最近发现",
        (DisplayLanguage::EnUs, "last_seen") => "Last seen",
        (DisplayLanguage::ZhCn, "source") => "Source",
        (DisplayLanguage::EnUs, "source") => "Source",
        (DisplayLanguage::ZhCn, "credential") => "凭据",
        (DisplayLanguage::EnUs, "credential") => "Credential",
        (DisplayLanguage::ZhCn, "observed") => "观察时间",
        (DisplayLanguage::EnUs, "observed") => "Observed",
        (DisplayLanguage::ZhCn, "fetched") => "抓取时间",
        (DisplayLanguage::EnUs, "fetched") => "Fetched",
        (DisplayLanguage::ZhCn, "response_digest") => "响应 digest",
        (DisplayLanguage::EnUs, "response_digest") => "Response digest",
        (DisplayLanguage::ZhCn, "record_digest") => "记录 digest",
        (DisplayLanguage::EnUs, "record_digest") => "Record digest",
        (DisplayLanguage::ZhCn, "reference") => "引用",
        (DisplayLanguage::EnUs, "reference") => "Reference",
        (DisplayLanguage::ZhCn, "verdict") => "范围 verdict",
        (DisplayLanguage::EnUs, "verdict") => "Scope verdict",
        (DisplayLanguage::ZhCn, "raw") => "原始值",
        (DisplayLanguage::EnUs, "raw") => "Raw value",
        (DisplayLanguage::ZhCn, "notes") => "规范化说明",
        (DisplayLanguage::EnUs, "notes") => "Normalization notes",
        (DisplayLanguage::ZhCn, "endpoint") => "Endpoint",
        (DisplayLanguage::EnUs, "endpoint") => "Endpoint",
        (DisplayLanguage::ZhCn, "latest_health") => "最近健康状态",
        (DisplayLanguage::EnUs, "latest_health") => "Latest health",
        (DisplayLanguage::ZhCn, "quota_limit") => "Quota limit",
        (DisplayLanguage::EnUs, "quota_limit") => "Quota limit",
        (DisplayLanguage::ZhCn, "cache_ttl_ms") => "Cache TTL (ms)",
        (DisplayLanguage::EnUs, "cache_ttl_ms") => "Cache TTL (ms)",
        (DisplayLanguage::ZhCn, "empty") => "没有符合筛选条件的结果。",
        (DisplayLanguage::EnUs, "empty") => "No results match the current filter.",
        (DisplayLanguage::ZhCn, "requests") => "Requests",
        (DisplayLanguage::EnUs, "requests") => "Requests",
        (DisplayLanguage::ZhCn, "pages") => "Pages",
        (DisplayLanguage::EnUs, "pages") => "Pages",
        (DisplayLanguage::ZhCn, "retries") => "Retries",
        (DisplayLanguage::EnUs, "retries") => "Retries",
        (DisplayLanguage::ZhCn, "cache") => "Cache",
        (DisplayLanguage::EnUs, "cache") => "Cache",
        (DisplayLanguage::ZhCn, "quota_rejections") => "Quota rejections",
        (DisplayLanguage::EnUs, "quota_rejections") => "Quota rejections",
        (DisplayLanguage::ZhCn, "received") => "Received",
        (DisplayLanguage::EnUs, "received") => "Received",
        (DisplayLanguage::ZhCn, "accepted") => "Accepted",
        (DisplayLanguage::EnUs, "accepted") => "Accepted",
        (DisplayLanguage::ZhCn, "filtered") => "Filtered",
        (DisplayLanguage::EnUs, "filtered") => "Filtered",
        (DisplayLanguage::ZhCn, "error_code") => "错误代码",
        (DisplayLanguage::EnUs, "error_code") => "Error code",
        (DisplayLanguage::ZhCn, "display_language") => "界面语言",
        (DisplayLanguage::EnUs, "display_language") => "Display language",
        (DisplayLanguage::ZhCn, "report_language") => "报告语言",
        (DisplayLanguage::EnUs, "report_language") => "Report language",
        (DisplayLanguage::ZhCn, "data_directory") => "数据目录",
        (DisplayLanguage::EnUs, "data_directory") => "Data directory",
        (DisplayLanguage::ZhCn, "config_file") => "配置文件",
        (DisplayLanguage::EnUs, "config_file") => "Config file",
        (DisplayLanguage::ZhCn, "database_file") => "数据库文件",
        (DisplayLanguage::EnUs, "database_file") => "Database file",
        (DisplayLanguage::ZhCn, "default_export_directory") => "默认导出目录",
        (DisplayLanguage::EnUs, "default_export_directory") => "Default export directory",
        (DisplayLanguage::ZhCn, "fallback_sources") => "显示低频后备 source",
        (DisplayLanguage::EnUs, "fallback_sources") => "Show low-frequency fallback sources",
        (DisplayLanguage::ZhCn, "persisted_enabled") => "持久化启用偏好",
        (DisplayLanguage::EnUs, "persisted_enabled") => "Persisted enabled preference",
        (DisplayLanguage::ZhCn, "effective_enabled") => "生效启用状态",
        (DisplayLanguage::EnUs, "effective_enabled") => "Effective enabled state",
        (DisplayLanguage::ZhCn, "default_enabled") => "默认启用状态",
        (DisplayLanguage::EnUs, "default_enabled") => "Default enabled state",
        (DisplayLanguage::ZhCn, "security_notice") => "凭据不会显示，也不保存在 config.toml。",
        (DisplayLanguage::EnUs, "security_notice") => {
            "Credentials are never displayed or stored in config.toml."
        }
        (DisplayLanguage::ZhCn, "configured") => "已配置",
        (DisplayLanguage::EnUs, "configured") => "Configured",
        (DisplayLanguage::ZhCn, "enabled") => "已启用",
        (DisplayLanguage::EnUs, "enabled") => "Enabled",
        (DisplayLanguage::ZhCn, "disabled") => "已禁用",
        (DisplayLanguage::EnUs, "disabled") => "Disabled",
        (DisplayLanguage::ZhCn, "exported") => "导出完成",
        (DisplayLanguage::EnUs, "exported") => "Export completed",
        (DisplayLanguage::ZhCn, "coverage_report") => "覆盖率报告",
        (DisplayLanguage::EnUs, "coverage_report") => "Coverage report",
        (DisplayLanguage::ZhCn, "verification_failed") => "验证失败",
        (DisplayLanguage::EnUs, "verification_failed") => "Verification failed",
        (DisplayLanguage::ZhCn, "global_hint") => {
            "Tab/Shift+Tab 聚焦｜方向键导航｜Enter 确认｜Space 切换｜Esc 返回｜? 帮助｜q 退出"
        }
        (DisplayLanguage::EnUs, "global_hint") => {
            "Tab/Shift+Tab focus | arrows navigate | Enter confirm | Space toggle | Esc back | ? help | q quit"
        }
        (DisplayLanguage::ZhCn, "minimum_terminal_warning") => {
            "警告：终端小于建议尺寸；请调整窗口，或按 q 退出。"
        }
        (DisplayLanguage::EnUs, "minimum_terminal_warning") => {
            "Warning: terminal is below the recommended size; resize or press q to quit."
        }
        (DisplayLanguage::ZhCn, "hint") => "提示",
        (DisplayLanguage::EnUs, "hint") => "Hint",
        (DisplayLanguage::ZhCn, "source_count") => "Source 数量",
        (DisplayLanguage::EnUs, "source_count") => "Source count",
        (DisplayLanguage::ZhCn, "health") => "健康状态",
        (DisplayLanguage::EnUs, "health") => "Health",
        (DisplayLanguage::ZhCn, "cache_retry_quota_summary") => {
            "cache / retry / quota 摘要：当前没有 active run；请打开运行监控查看有界计数器。"
        }
        (DisplayLanguage::EnUs, "cache_retry_quota_summary") => {
            "Cache / retry / quota summary: no active run; open Run Monitor for bounded counters."
        }
        (DisplayLanguage::ZhCn, "dashboard_hint") => {
            "c 快速采集｜s Sources 与凭据｜r 刷新本地视图｜? 帮助"
        }
        (DisplayLanguage::EnUs, "dashboard_hint") => {
            "c Quick Collect | s Sources & Credentials | r refresh local view | ? Help"
        }
        (DisplayLanguage::ZhCn, "hostname") => "hostname",
        (DisplayLanguage::EnUs, "hostname") => "Hostname",
        (DisplayLanguage::ZhCn, "requires_confirmation") => "需要确认",
        (DisplayLanguage::EnUs, "requires_confirmation") => "Requires confirmation",
        (DisplayLanguage::ZhCn, "include_root_domain") => "包含 root domain",
        (DisplayLanguage::EnUs, "include_root_domain") => "Include root domain",
        (DisplayLanguage::ZhCn, "passive") => "被动模式",
        (DisplayLanguage::EnUs, "passive") => "Passive",
        (DisplayLanguage::ZhCn, "start_enabled") => "可开始",
        (DisplayLanguage::EnUs, "start_enabled") => "Enabled",
        (DisplayLanguage::ZhCn, "start_disabled") => "不可开始：必须选择 source 并完成目标确认",
        (DisplayLanguage::EnUs, "start_disabled") => {
            "Disabled: source selection and target confirmation are required"
        }
        (DisplayLanguage::ZhCn, "cancel_behavior") => "取消后保留为 cancelled terminal status",
        (DisplayLanguage::EnUs, "cancel_behavior") => "Cancel keeps the run as a cancelled terminal status",
        (DisplayLanguage::ZhCn, "cancel_behavior_label") => "取消行为",
        (DisplayLanguage::EnUs, "cancel_behavior_label") => "Cancel behavior",
        (DisplayLanguage::ZhCn, "pending_run_event") => "等待 RunCreated event",
        (DisplayLanguage::EnUs, "pending_run_event") => "Waiting for the RunCreated event",
        (DisplayLanguage::ZhCn, "source_actions_hint") => {
            "k 配置 credential｜i 导入 environment｜x 删除 Lens-owned credential｜Space 启用/禁用"
        }
        (DisplayLanguage::EnUs, "source_actions_hint") => {
            "k configure credential | i import environment | x remove Lens-owned credential | Space enable/disable"
        }
        (DisplayLanguage::ZhCn, "quota") => "quota",
        (DisplayLanguage::EnUs, "quota") => "Quota",
        (DisplayLanguage::ZhCn, "run_actions_active") => "c 取消 active run（需要确认）",
        (DisplayLanguage::EnUs, "run_actions_active") => "c cancel active run (confirmation required)",
        (DisplayLanguage::ZhCn, "run_actions_terminal") => "f 发现｜v 证据｜d 比较｜e 导出",
        (DisplayLanguage::EnUs, "run_actions_terminal") => "f Findings | v Evidence | d Compare | e Export",
        (DisplayLanguage::ZhCn, "elapsed") => "耗时",
        (DisplayLanguage::EnUs, "elapsed") => "Elapsed",
        (DisplayLanguage::ZhCn, "accepted_findings") => "已接受 finding",
        (DisplayLanguage::EnUs, "accepted_findings") => "Accepted findings",
        (DisplayLanguage::ZhCn, "metric_requests") => "请求数",
        (DisplayLanguage::EnUs, "metric_requests") => "Requests",
        (DisplayLanguage::ZhCn, "metric_pages") => "页数",
        (DisplayLanguage::EnUs, "metric_pages") => "Pages",
        (DisplayLanguage::ZhCn, "metric_retries") => "重试数",
        (DisplayLanguage::EnUs, "metric_retries") => "Retries",
        (DisplayLanguage::ZhCn, "metric_cache") => "cache 命中/未命中",
        (DisplayLanguage::EnUs, "metric_cache") => "Cache hits/misses",
        (DisplayLanguage::ZhCn, "metric_quota_rejections") => "quota 拒绝数",
        (DisplayLanguage::EnUs, "metric_quota_rejections") => "Quota rejections",
        (DisplayLanguage::ZhCn, "metric_received") => "收到结果",
        (DisplayLanguage::EnUs, "metric_received") => "Received",
        (DisplayLanguage::ZhCn, "metric_accepted") => "已接受结果",
        (DisplayLanguage::EnUs, "metric_accepted") => "Accepted",
        (DisplayLanguage::ZhCn, "metric_filtered") => "已过滤结果",
        (DisplayLanguage::EnUs, "metric_filtered") => "Filtered",
        (DisplayLanguage::ZhCn, "metric_error") => "错误代码",
        (DisplayLanguage::EnUs, "metric_error") => "Error code",
        (DisplayLanguage::ZhCn, "findings_hint") => {
            "/ 搜索 FQDN｜p source filter｜a 范围｜s 排序｜n 下一页｜Enter 证据｜e 导出"
        }
        (DisplayLanguage::EnUs, "findings_hint") => {
            "/ search FQDN | p source filter | a scope | s sort | n next page | Enter evidence | e export"
        }
        (DisplayLanguage::ZhCn, "search") => "搜索",
        (DisplayLanguage::EnUs, "search") => "Search",
        (DisplayLanguage::ZhCn, "source_filter") => "Source 筛选",
        (DisplayLanguage::EnUs, "source_filter") => "Source filter",
        (DisplayLanguage::ZhCn, "scope_filter") => "范围筛选",
        (DisplayLanguage::EnUs, "scope_filter") => "Scope filter",
        (DisplayLanguage::ZhCn, "sort") => "排序",
        (DisplayLanguage::EnUs, "sort") => "Sort",
        (DisplayLanguage::ZhCn, "sort_fqdn") => "FQDN",
        (DisplayLanguage::EnUs, "sort_fqdn") => "FQDN",
        (DisplayLanguage::ZhCn, "sort_evidence_count") => "证据数量",
        (DisplayLanguage::EnUs, "sort_evidence_count") => "Evidence count",
        (DisplayLanguage::ZhCn, "sort_source_count") => "Source 数量",
        (DisplayLanguage::EnUs, "sort_source_count") => "Source count",
        (DisplayLanguage::ZhCn, "sort_first_seen") => "首次发现时间",
        (DisplayLanguage::EnUs, "sort_first_seen") => "First seen time",
        (DisplayLanguage::ZhCn, "sort_last_seen") => "最近发现时间（降序）",
        (DisplayLanguage::EnUs, "sort_last_seen") => "Last seen time (descending)",
        (DisplayLanguage::ZhCn, "page") => "页面",
        (DisplayLanguage::EnUs, "page") => "Page",
        (DisplayLanguage::ZhCn, "next_cursor") => "下一页 cursor",
        (DisplayLanguage::EnUs, "next_cursor") => "Next cursor",
        (DisplayLanguage::ZhCn, "local_only_notice") => "证据仅来自本地 redacted 数据；不会跟随 source URL。",
        (DisplayLanguage::EnUs, "local_only_notice") => "Evidence is local redacted data only; source URLs are never followed.",
        (DisplayLanguage::ZhCn, "kind") => "类型",
        (DisplayLanguage::EnUs, "kind") => "Kind",
        (DisplayLanguage::ZhCn, "select_compare_runs") => "[ / ] 选择左右 run｜Enter 比较｜Esc 返回",
        (DisplayLanguage::EnUs, "select_compare_runs") => "[ / ] select left/right run | Enter compare | Esc back",
        (DisplayLanguage::ZhCn, "left") => "左侧",
        (DisplayLanguage::EnUs, "left") => "Left",
        (DisplayLanguage::ZhCn, "right") => "右侧",
        (DisplayLanguage::EnUs, "right") => "Right",
        (DisplayLanguage::ZhCn, "compare_counts") => "新增={}｜移除={}｜来源证据变化={}",
        (DisplayLanguage::EnUs, "compare_counts") => "Added={} | Removed={} | Provenance changed={}",
        (DisplayLanguage::ZhCn, "export_hint") => "f 格式｜l 语言｜d 编辑 destination｜Enter 确认导出",
        (DisplayLanguage::EnUs, "export_hint") => "f format | l language | d edit destination | Enter confirm export",
        (DisplayLanguage::ZhCn, "format") => "格式",
        (DisplayLanguage::EnUs, "format") => "Format",
        (DisplayLanguage::ZhCn, "destination") => "目标路径",
        (DisplayLanguage::EnUs, "destination") => "Destination",
        (DisplayLanguage::ZhCn, "export_policy_notice") => {
            "Export policy 由 ApplicationService 强制执行；不会打开外部 browser/editor。"
        }
        (DisplayLanguage::EnUs, "export_policy_notice") => {
            "Export policy remains enforced by ApplicationService; external browser/editor is never opened."
        }
        (DisplayLanguage::ZhCn, "settings_hint") => "l 界面语言｜r 报告语言｜Enter 保存（需确认）｜Esc 取消",
        (DisplayLanguage::EnUs, "settings_hint") => "l display language | r report language | Enter Save (confirmation) | Esc Cancel",
        (DisplayLanguage::ZhCn, "pending") => "待保存",
        (DisplayLanguage::EnUs, "pending") => "Pending",
        (DisplayLanguage::ZhCn, "help_target") => "被动 target：支持 root domain、FQDN 或 HTTP(S) URL；不会请求 path/query/fragment。",
        (DisplayLanguage::EnUs, "help_target") => "Passive target input accepts a root domain, FQDN, or HTTP(S) URL; path/query/fragment are never requested.",
        (DisplayLanguage::ZhCn, "help_sources") => "Source selection 是显式 allow-list；root-domain expansion 和开始 collection 需要确认。",
        (DisplayLanguage::EnUs, "help_sources") => "Source selection is an explicit allow-list; root-domain expansion and Start collection require confirmation.",
        (DisplayLanguage::ZhCn, "help_credentials") => "Credential 使用 no-echo 输入，不显示，并在操作后清除。",
        (DisplayLanguage::EnUs, "help_credentials") => "Credential input uses no-echo mode, is never displayed, and is cleared after the operation.",
        (DisplayLanguage::ZhCn, "help_cancel_evidence") => "Cancel 会保留 cancelled run；Evidence 只读本地 redacted 数据，不跟随 source URL。",
        (DisplayLanguage::EnUs, "help_cancel_evidence") => "Cancel keeps a cancelled run; Evidence reads local redacted data only and never follows source URLs.",
        (DisplayLanguage::ZhCn, "help_keymap") => "Tab 聚焦｜方向键导航｜Enter 确认｜Space 切换｜Esc 返回｜?｜q｜c｜s｜r｜e｜l",
        (DisplayLanguage::EnUs, "help_keymap") => "Tab focus | arrows navigate | Enter confirm | Space toggle | Esc back | ? | q | c | s | r | e | l",
        (DisplayLanguage::ZhCn, "modal_quit") => "退出 TUI？",
        (DisplayLanguage::EnUs, "modal_quit") => "Quit TUI?",
        (DisplayLanguage::ZhCn, "modal_yes_no") => "Enter=是，Esc=否",
        (DisplayLanguage::EnUs, "modal_yes_no") => "Enter=yes, Esc=no",
        (DisplayLanguage::ZhCn, "modal_start_details") => "目标={}｜sources={}｜确认后才会产生 network request；不会写入 config 或 credential",
        (DisplayLanguage::EnUs, "modal_start_details") => "target={} | sources={} | network requests begin only after confirmation; config and credential writes are disabled",
        (DisplayLanguage::ZhCn, "modal_root_prompt") => "请在输入框中输入完全匹配的 root domain，然后按 Enter。",
        (DisplayLanguage::EnUs, "modal_root_prompt") => "Type the exact root domain in the input and press Enter.",
        (DisplayLanguage::ZhCn, "modal_cancel_details") => "run_id={}｜只发送取消动作；run 会保留为 cancelled terminal status",
        (DisplayLanguage::EnUs, "modal_cancel_details") => "run_id={} | only the cancel action is sent; the run is retained as a cancelled terminal status",
        (DisplayLanguage::ZhCn, "modal_credential_details") => "为 source={} 配置 credential｜endpoint={}｜写入 Lens-owned secure store；{}｜Enter=保存，Esc=取消",
        (DisplayLanguage::EnUs, "modal_credential_details") => "Configure credential for source={} | endpoint={} | writes to the Lens-owned secure store; {} | Enter=save, Esc=cancel",
        (DisplayLanguage::ZhCn, "modal_import") => "将 environment credential 导入 Lens-owned secure store？环境变量不会被删除。",
        (DisplayLanguage::EnUs, "modal_import") => "Import the environment credential into the Lens-owned secure store? The environment variable is not deleted.",
        (DisplayLanguage::ZhCn, "modal_remove") => "只删除 Lens-owned credential 条目？",
        (DisplayLanguage::EnUs, "modal_remove") => "Remove only the Lens-owned credential entry?",
        (DisplayLanguage::ZhCn, "modal_save_settings") => "{}｜config_path={}｜不会产生 network request",
        (DisplayLanguage::EnUs, "modal_save_settings") => "{} | config_path={} | no network request is made",
        (DisplayLanguage::ZhCn, "modal_export") => "run_id={}｜format={}｜language={}｜destination={}｜不会产生 network request；path policy 强制执行",
        (DisplayLanguage::EnUs, "modal_export") => "run_id={} | format={} | language={} | destination={} | no network request; path policy is enforced",
        _ => key,
    }
    .to_owned()
}

#[must_use]
pub fn source_status_summary(language: DisplayLanguage, status: &SourceStatus) -> String {
    format!(
        "{} ({})",
        source_state_label(language, &status.state),
        status.error_code.as_deref().unwrap_or("ok")
    )
}

#[must_use]
pub fn safe_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_message_has_both_locale_resources() {
        for code in REGISTERED_MESSAGE_CODES {
            let zh = message(DisplayLanguage::ZhCn, *code, MessageArgs::default());
            let en = message(DisplayLanguage::EnUs, *code, MessageArgs::default());
            assert!(
                !zh.message.is_empty(),
                "missing zh resource for {}",
                code.as_str()
            );
            assert!(
                !en.message.is_empty(),
                "missing en resource for {}",
                code.as_str()
            );
            assert_eq!(zh.code, en.code);
            assert!(zh.hint.is_some());
            assert!(en.hint.is_some());
        }
    }

    #[test]
    fn machine_state_is_kept_in_localized_labels() {
        assert_eq!(
            credential_state_label(DisplayLanguage::ZhCn, CredentialState::CredentialStore),
            "凭据库 (credential_store)"
        );
        assert_eq!(
            source_state_label(DisplayLanguage::EnUs, &SourceState::Succeeded),
            "Succeeded (succeeded)"
        );
    }

    #[test]
    fn presentation_mappers_keep_localized_labels_and_stable_codes() {
        assert_eq!(
            result_scope_label(DisplayLanguage::ZhCn, &ResultScope::Filtered),
            "已过滤 (filtered)"
        );
        assert_eq!(
            scope_verdict_label(DisplayLanguage::EnUs, &ScopeVerdict::OutOfScope),
            "Filtered out of scope (out_of_scope)"
        );
        assert_eq!(
            report_format_label(DisplayLanguage::ZhCn, ReportFormat::Markdown),
            "Markdown (markdown)"
        );
        assert_eq!(
            report_language_label(DisplayLanguage::EnUs, ReportLanguage::Bilingual),
            "Bilingual report (bilingual)"
        );
        assert_eq!(boolean_label(DisplayLanguage::ZhCn, true), "是 (true)");
        assert_eq!(
            run_status_label_code(DisplayLanguage::ZhCn, "cancelled"),
            "已取消 (cancelled)"
        );
    }

    #[test]
    fn every_required_static_resource_exists_in_both_locales() {
        let keys = [
            "global_hint",
            "minimum_terminal_warning",
            "dashboard_hint",
            "findings_hint",
            "local_only_notice",
            "export_policy_notice",
            "settings_hint",
            "help_target",
            "help_sources",
            "help_credentials",
            "help_cancel_evidence",
            "help_keymap",
            "modal_quit",
            "modal_start_details",
            "modal_root_prompt",
            "modal_cancel_details",
            "modal_credential_details",
            "modal_import",
            "modal_remove",
            "modal_save_settings",
            "modal_export",
        ];
        for key in keys {
            assert_ne!(
                text(DisplayLanguage::ZhCn, key),
                key,
                "missing zh resource: {key}"
            );
            assert_ne!(
                text(DisplayLanguage::EnUs, key),
                key,
                "missing en resource: {key}"
            );
        }
    }
}
