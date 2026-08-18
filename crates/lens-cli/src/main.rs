use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use lens_core::domain::normalize_root_domain;
use lens_core::i18n::{
    LocalizedMessage, MessageArgs, MessageCode, credential_state_code, credential_state_label,
    display_language_code, message, report_language_code, run_mode_label, run_status_label,
    safe_path, source_state_label, text,
};
use lens_core::{
    AppPaths, ApplicationError, ApplicationService, CollectOptions, DisplayLanguage, QueryService,
    ReportFormat, ReportLanguage, ResultScope, Store,
};
use lens_lab::{
    LabAcceptance, LabRunOptions,
    coverage::{
        VerificationProfile, planned_coverage_report, verify as verify_coverage,
        write_coverage_report,
    },
    run as run_lab,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "fqdn-lens",
    version,
    about = "被动 FQDN evidence 工具 / Strictly passive FQDN evidence explorer",
    long_about = "本地优先、严格 passive 的 FQDN evidence collection CLI。\nLocal-first, strictly passive FQDN evidence collection CLI.\n\nJSON stdout contains machine data only; localized human messages go to text output or stderr.",
    after_help = "稳定值代码 / Stable value codes:\n  display language: zh-cn / en-us\n  report language: zh-cn / en-us / bilingual\n  output format: text / json\n  export format: json / markdown / csv\n  result scope: accepted / filtered / all\n  Lab acceptance: forge-pass / lens-local-assertion\n  verification profile: direct-core / transport-quota / safe-rejection / lifecycle / resilience / full"
)]
struct Cli {
    /// SQLite evidence database；凭据和 Lab capability 永不存储于此 / Credentials and Lab capabilities are never stored here
    #[arg(long, global = true, default_value = "fqdn-lens.db")]
    database: PathBuf,
    /// 一次性界面语言覆盖，不修改 config.toml / One-shot display override; does not modify config.toml
    #[arg(long, global = true, value_enum)]
    language: Option<DisplayLanguageArg>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 管理 project / Manage projects
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// 查看和比较 runs / Inspect and compare runs
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// 查看 findings / Inspect findings
    Results {
        #[command(subcommand)]
        command: ResultsCommand,
    },
    /// 查看 redacted evidence / Inspect redacted evidence
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// 查看 per-source status / Inspect per-source status
    Sources {
        #[command(subcommand)]
        command: SourcesCommand,
    },
    /// 管理 registered source 和 credentials / Manage registered sources and credentials
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// 对显式选择的 registry source 执行 passive collection / Run passive collection against explicitly selected registry sources
    Collect(ProductionCollectArgs),
    /// 导出 report；文件 locale 独立于 display locale / Export a report; file locale is independent from display locale
    Export(ExportArgs),
    /// 运行离线 Lab / Run the offline Lab
    Lab {
        #[command(subcommand)]
        command: LabCommand,
    },
    /// 查看和持久化非秘密 preference / Inspect and persist non-secret preferences
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// 启动 terminal workbench / Start the terminal workbench
    Tui,
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// 创建 project / Create a project
    Create {
        /// 根域名 / Root domain
        #[arg(long)]
        domain: String,
    },
    /// 列出 projects / List projects
    List,
    /// 列出 project FQDN / List project FQDNs
    Fqdns {
        /// project UUID / project UUID
        #[arg(long)]
        project: Uuid,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
enum RunsCommand {
    /// 列出 runs / List runs
    List {
        /// project UUID / project UUID
        #[arg(long)]
        project: Uuid,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// 显示 run / Show a run
    Show {
        /// run UUID / run UUID
        run_id: Uuid,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// 比较 runs / Diff runs
    Diff {
        /// project UUID / project UUID
        #[arg(long)]
        project: Uuid,
        /// 左侧/源 run UUID / Left/source run UUID
        #[arg(long)]
        from: Uuid,
        /// 右侧/目标 run UUID / Right/target run UUID
        #[arg(long)]
        to: Uuid,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// replay 已保存的 Lens-local assertion / Replay a stored Lens-local assertion
    Replay {
        /// 已完成的 Lab run UUID / Completed Lab run UUID
        #[arg(long)]
        run: Uuid,
        /// replay 接受合同 / Accepted replay contract
        #[arg(long, value_enum)]
        acceptance: LabAcceptanceArg,
    },
}

#[derive(Subcommand)]
enum ResultsCommand {
    /// 列出 findings / List findings
    List {
        /// run UUID / run UUID
        #[arg(long)]
        run: Uuid,
        /// accepted、filtered 或 all findings / accepted, filtered, or all findings
        #[arg(long, value_enum, default_value_t = ResultScopeArg::Accepted)]
        scope: ResultScopeArg,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
enum EvidenceCommand {
    /// 显示 redacted evidence / Show redacted evidence
    Show {
        /// project UUID / project UUID
        #[arg(long)]
        project: Uuid,
        /// 要检查的精确 FQDN / Exact FQDN to inspect
        #[arg(long)]
        fqdn: String,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
enum SourcesCommand {
    /// 显示每个 source 的 status / Show status for each source
    Status {
        /// run UUID / run UUID
        #[arg(long)]
        run: Uuid,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// 列出 registered source / List registered sources
    List {
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// 检查 source credential、quota 和 health / Inspect source credentials, quota, and health
    Doctor {
        /// 可选 registered source ID；留空表示全部 source / Optional registered source IDs; empty means all sources
        #[arg(long = "source")]
        source_ids: Vec<String>,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// 将 environment credential 明确导入 Lens-owned secure store / Explicitly import an environment credential into the Lens-owned secure store
    ImportEnvironment {
        /// registered source ID / registered source ID
        source_id: String,
        /// 确认写入 secure store / Confirm the secure-store write
        #[arg(long)]
        confirm: bool,
    },
    /// 删除 Lens-owned credential，不删除 environment variable / Remove the Lens-owned credential without deleting the environment variable
    RemoveCredential {
        /// registered source ID / registered source ID
        source_id: String,
        /// 确认删除 Lens-owned entry / Confirm deletion of the Lens-owned entry
        #[arg(long)]
        confirm: bool,
    },
    /// 使用 no-echo prompt 或显式 stdin 安全配置 credential / Configure a credential through a no-echo prompt or explicit stdin
    ConfigureCredential {
        /// registered source ID / registered source ID
        #[arg(long = "source")]
        source_id: String,
        /// 从 stdin 读取一行 secret；否则使用 no-echo console input / Read one secret line from stdin; otherwise use no-echo console input
        #[arg(long)]
        stdin: bool,
        /// 确认写入 Lens-owned secure store / Confirm writing to the Lens-owned secure store
        #[arg(long)]
        confirm: bool,
    },
    /// 持久化 source enable preference；不访问网络 / Persist a source enable preference; does not access the network
    SetEnabled {
        /// registered source ID / registered source ID
        #[arg(long = "source")]
        source_id: String,
        /// 持久化 enabled 值：true 或 false / Persisted enabled value: true or false
        #[arg(long, value_parser = clap::value_parser!(bool))]
        enabled: bool,
    },
    /// 执行 passive collection / Run passive collection
    Collect(ProductionCollectArgs),
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// 查看非秘密设置和路径 / Show non-secret settings and paths
    Show {
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// 持久化界面语言 zh-cn|en-us / Persist display language zh-cn|en-us
    SetDisplayLanguage {
        /// zh-cn 或 en-us / zh-cn or en-us
        #[arg(long)]
        language: DisplayLanguageArg,
    },
    /// 持久化 report 语言 zh-cn|en-us|bilingual / Persist report language zh-cn|en-us|bilingual
    SetReportLanguage {
        /// zh-cn、en-us 或 bilingual / zh-cn, en-us, or bilingual
        #[arg(long)]
        language: ReportLanguageArg,
    },
}

#[derive(Args)]
struct ProductionCollectArgs {
    /// domain、FQDN 或 HTTP(S) URL；URL 只提取 hostname / domain, FQDN, or HTTP(S) URL; URLs contribute only their hostname
    #[arg(long)]
    domain: String,
    /// explicit source allow-list；不会隐式访问全部 source / explicit source allow-list; all sources are never selected implicitly
    #[arg(long = "source", required = true)]
    source_ids: Vec<String>,
    /// 包含 registrable root domain / Include the registrable root domain
    #[arg(long)]
    include_root: bool,
    /// 显式 root-domain confirmation / Explicit root-domain confirmation
    #[arg(long)]
    confirm_root: Option<String>,
    /// 文本或 JSON 输出 / Text or JSON output
    #[arg(long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Args)]
struct ExportArgs {
    /// run UUID / run UUID
    #[arg(long)]
    run: Uuid,
    /// report 文件格式 / Report file format
    #[arg(long)]
    format: ExportFormat,
    /// 安全 destination path / Safe destination path
    #[arg(long)]
    output: PathBuf,
    /// report file language；bilingual 仅适用于 report / report file language; bilingual applies only to reports
    #[arg(long, value_enum)]
    language: Option<ReportLanguageArg>,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum DisplayLanguageArg {
    ZhCn,
    EnUs,
}

impl From<DisplayLanguageArg> for DisplayLanguage {
    fn from(value: DisplayLanguageArg) -> Self {
        match value {
            DisplayLanguageArg::ZhCn => Self::ZhCn,
            DisplayLanguageArg::EnUs => Self::EnUs,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum ExportFormat {
    Json,
    Markdown,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum ReportLanguageArg {
    ZhCn,
    EnUs,
    Bilingual,
}

impl From<ReportLanguageArg> for ReportLanguage {
    fn from(value: ReportLanguageArg) -> Self {
        match value {
            ReportLanguageArg::ZhCn => Self::ZhCn,
            ReportLanguageArg::EnUs => Self::EnUs,
            ReportLanguageArg::Bilingual => Self::Bilingual,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum CoverageFormat {
    Json,
    Markdown,
}

impl CoverageFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum VerificationProfileArg {
    DirectCore,
    TransportQuota,
    SafeRejection,
    Lifecycle,
    Resilience,
    Full,
}

impl From<VerificationProfileArg> for VerificationProfile {
    fn from(value: VerificationProfileArg) -> Self {
        match value {
            VerificationProfileArg::DirectCore => Self::DirectCore,
            VerificationProfileArg::TransportQuota => Self::TransportQuota,
            VerificationProfileArg::SafeRejection => Self::SafeRejection,
            VerificationProfileArg::Lifecycle => Self::Lifecycle,
            VerificationProfileArg::Resilience => Self::Resilience,
            VerificationProfileArg::Full => Self::Full,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum LabAcceptanceArg {
    ForgePass,
    LensLocalAssertion,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum ResultScopeArg {
    Accepted,
    Filtered,
    All,
}

impl From<ResultScopeArg> for ResultScope {
    fn from(value: ResultScopeArg) -> Self {
        match value {
            ResultScopeArg::Accepted => Self::Accepted,
            ResultScopeArg::Filtered => Self::Filtered,
            ResultScopeArg::All => Self::All,
        }
    }
}

#[derive(Subcommand)]
enum LabCommand {
    /// 运行 Lab scenario / Run a Lab scenario
    Run {
        /// numeric loopback Forge base URL / numeric loopback Forge base URL
        #[arg(long)]
        base_url: String,
        /// Forge scenario ID / Forge scenario ID
        #[arg(long)]
        scenario: String,
        /// 确定性 Lab seed / Deterministic Lab seed
        #[arg(long)]
        seed: Option<u64>,
        /// 已存在的 project UUID / Existing project UUID
        #[arg(long)]
        project: Option<Uuid>,
        /// 创建 project，不使用 --project / Create a project instead of using --project
        #[arg(long)]
        create_project: bool,
        /// 文本或 JSON 输出 / Text or JSON output
        #[arg(long, default_value = "text")]
        format: OutputFormat,
        /// 必需的 acceptance contract / Required acceptance contract
        #[arg(long, value_enum, default_value = "forge-pass")]
        acceptance: LabAcceptanceArg,
    },
    /// 生成 coverage report / Generate a coverage report
    Coverage {
        /// JSON 或 Markdown 文件格式 / JSON or Markdown file format
        #[arg(long, value_enum)]
        format: CoverageFormat,
        /// report destination path / report destination path
        #[arg(long)]
        output: PathBuf,
    },
    /// 验证 Lens/Forge contract / Verify the Lens/Forge contract
    Verify {
        /// numeric loopback Forge base URL / numeric loopback Forge base URL
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        base_url: String,
        /// verification profile / verification profile
        #[arg(long, value_enum)]
        profile: VerificationProfileArg,
        /// repetition 次数 / Number of repetitions
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        /// 可选 report destination / Optional report destination
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Serialize)]
struct JsonEnvelope<T> {
    schema_version: &'static str,
    data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<LocalizedMessage>>,
}

#[derive(Serialize)]
struct JsonErrorEnvelope {
    schema_version: &'static str,
    error: LocalizedMessage,
}

const CLI_SCHEMA: &str = "fqdn-lens.cli.v1";

#[derive(Debug)]
struct LocalizedCliError {
    code: MessageCode,
    args: MessageArgs,
}

impl std::fmt::Display for LocalizedCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.code.as_str())
    }
}
impl std::error::Error for LocalizedCliError {}
fn cli_error(code: MessageCode, args: MessageArgs) -> anyhow::Error {
    anyhow::Error::new(LocalizedCliError { code, args })
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let requested_language = cli.language.map(Into::into);
    let output_format = command_output_format(&cli.command);
    let app_paths = match AppPaths::from_local_app_data() {
        Ok(paths) => paths.with_database_file(cli.database.clone()),
        Err(error) => {
            return finish_error(
                anyhow!(error),
                requested_language.unwrap_or_default(),
                output_format,
            );
        }
    };
    let mut application = match ApplicationService::open(app_paths) {
        Ok(application) => application,
        Err(error) => {
            return finish_error(
                anyhow!(error),
                requested_language.unwrap_or_default(),
                output_format,
            );
        }
    };
    let language = requested_language.unwrap_or(application.config().display_language);
    let store = match Store::open(&cli.database)
        .with_context(|| format!("could not open SQLite database {}", cli.database.display()))
    {
        Ok(store) => store,
        Err(error) => return finish_error(error, language, output_format),
    };
    match dispatch(cli.command, &mut application, &store, language).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => finish_error(error, language, output_format),
    }
}

async fn dispatch(
    command: Command,
    application: &mut ApplicationService,
    store: &Store,
    language: DisplayLanguage,
) -> Result<()> {
    let query = QueryService::new(store);
    match command {
        Command::Project { command } => match command {
            ProjectCommand::Create { domain } => {
                let domain = normalize_root_domain(&domain)
                    .map_err(|_| cli_error(MessageCode::TargetInvalid, MessageArgs::default()))?;
                let project = store.create_project(&domain)?;
                println!(
                    "{}: {}\n{}: {}\n{}: {}",
                    text(language, "project_id"),
                    project.id,
                    text(language, "root_domain"),
                    project.root_domain,
                    text(language, "policy"),
                    project.collection_policy
                );
            }
            ProjectCommand::List => {
                let projects = query.list_projects()?;
                if projects.is_empty() {
                    println!("{}", text(language, "empty"));
                } else {
                    for project in projects {
                        println!(
                            "{}={} {}={} {}={}",
                            text(language, "project_id"),
                            project.id,
                            text(language, "root_domain"),
                            project.root_domain,
                            text(language, "policy"),
                            project.collection_policy
                        );
                    }
                }
            }
            ProjectCommand::Fqdns { project, format } => {
                let fqdns = query.list_project_fqdns(project)?;
                match format {
                    OutputFormat::Json => print_json(fqdns)?,
                    OutputFormat::Text => {
                        if fqdns.is_empty() {
                            println!("{}", text(language, "empty"));
                        } else {
                            for fqdn in fqdns {
                                println!(
                                    "{}  {}={}  {}={}  {}={}  {}={}",
                                    fqdn.fqdn,
                                    text(language, "evidence"),
                                    fqdn.evidence_count,
                                    text(language, "sources"),
                                    fqdn.source_count,
                                    text(language, "first_seen"),
                                    fqdn.first_seen_at,
                                    text(language, "last_seen"),
                                    fqdn.last_seen_at
                                );
                            }
                        }
                    }
                }
            }
        },
        Command::Runs { command } => match command {
            RunsCommand::List { project, format } => {
                let runs = store.list_runs(project)?;
                match format {
                    OutputFormat::Json => print_json(runs)?,
                    OutputFormat::Text => {
                        if runs.is_empty() {
                            println!("{}", text(language, "empty"));
                        } else {
                            for run in runs {
                                println!(
                                    "{}={} {}={} {}={} {}={}",
                                    text(language, "run_id"),
                                    run.id,
                                    text(language, "mode"),
                                    run_mode_label(language, &run.mode),
                                    text(language, "status"),
                                    run_status_label(language, &run.status),
                                    text(language, "started"),
                                    run.started_at
                                );
                            }
                        }
                    }
                }
            }
            RunsCommand::Show { run_id, format } => {
                let run = query.get_run(run_id)?;
                match format {
                    OutputFormat::Json => print_json(run)?,
                    OutputFormat::Text => println!(
                        "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
                        text(language, "run_id"),
                        run.id,
                        text(language, "project"),
                        run.project_id,
                        text(language, "mode"),
                        run_mode_label(language, &run.mode),
                        text(language, "status"),
                        run_status_label(language, &run.status),
                        text(language, "started"),
                        run.started_at,
                        text(language, "finished"),
                        run.finished_at
                            .map(|value| value.to_rfc3339())
                            .unwrap_or_else(|| "-".to_owned()),
                        text(language, "diagnostics"),
                        run.diagnostics_summary.unwrap_or_else(|| "-".to_owned())
                    ),
                }
            }
            RunsCommand::Diff {
                project,
                from,
                to,
                format,
            } => {
                let diff = query.get_snapshot_diff(project, from, to)?;
                match format {
                    OutputFormat::Json => print_json(diff)?,
                    OutputFormat::Text => {
                        println!("{}:", text(language, "added"));
                        for record in diff.added {
                            println!("  {}", record.fqdn);
                        }
                        println!("{}:", text(language, "removed"));
                        for record in diff.removed {
                            println!("  {}", record.fqdn);
                        }
                        println!("{}:", text(language, "provenance_changed"));
                        for difference in diff.provenance_changed {
                            println!("  {}", difference.fqdn);
                        }
                    }
                }
            }
            RunsCommand::Replay { run, acceptance } => {
                let original = query.get_run(run)?;
                if !matches!(acceptance, LabAcceptanceArg::LensLocalAssertion) {
                    return Err(cli_error(
                        MessageCode::LabAcceptanceMismatch,
                        MessageArgs::default(),
                    ));
                }
                if original.mode != lens_core::evidence::RunMode::Lab
                    || original.finished_at.is_none()
                {
                    return Err(cli_error(
                        MessageCode::RunNotCancellable,
                        MessageArgs {
                            run_id: Some(original.id.to_string()),
                            ..MessageArgs::default()
                        },
                    ));
                }
                print_json(
                    serde_json::json!({"status":"lens_local_assertion","replayed_run_id":original.id,"project_id":original.project_id,"source_profile":original.source_profile,"note":"replay verifies persisted provenance and local assertions; no capability or remote request is retained"}),
                )?;
            }
        },
        Command::Results { command } => match command {
            ResultsCommand::List { run, scope, format } => {
                let results = query.list_run_results(run, scope.into())?;
                match format {
                    OutputFormat::Json => print_json(results)?,
                    OutputFormat::Text => {
                        if results.is_empty() {
                            println!("{}", text(language, "empty"));
                        } else {
                            for result in results {
                                println!(
                                    "{}  {}={}  {}={}  {}={}  {}={}",
                                    result.fqdn,
                                    text(language, "evidence"),
                                    result.evidence_count,
                                    text(language, "sources"),
                                    result.source_count,
                                    text(language, "first_seen"),
                                    result.first_seen_at,
                                    text(language, "last_seen"),
                                    result.last_seen_at
                                );
                            }
                        }
                    }
                }
            }
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::Show {
                project,
                fqdn,
                format,
            } => {
                let fqdn = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
                let evidence = query.get_fqdn_evidence(project, &fqdn)?;
                match format {
                    OutputFormat::Json => print_json(evidence)?,
                    OutputFormat::Text => {
                        if evidence.is_empty() {
                            println!("{}", text(language, "empty"));
                        } else {
                            for item in evidence {
                                println!(
                                    "{}={} {}={} ({}) {}={} {}={} {}={} {}={} {}={} {}={}\n  {}: {}\n  {}: {}",
                                    text(language, "evidence"),
                                    item.id,
                                    text(language, "source"),
                                    item.source_id,
                                    item.source_kind,
                                    text(language, "observed"),
                                    item.observed_at
                                        .map(|value| value.to_rfc3339())
                                        .unwrap_or_else(|| "-".to_owned()),
                                    text(language, "fetched"),
                                    item.fetched_at.to_rfc3339(),
                                    text(language, "response_digest"),
                                    item.response_digest,
                                    text(language, "record_digest"),
                                    item.record_digest.unwrap_or_else(|| "-".to_owned()),
                                    text(language, "reference"),
                                    item.raw_reference.unwrap_or_else(|| "-".to_owned()),
                                    text(language, "verdict"),
                                    serde_json::to_string(&item.scope_verdict)
                                        .unwrap_or_else(|_| "unknown".to_owned()),
                                    text(language, "raw"),
                                    item.raw_value,
                                    text(language, "notes"),
                                    item.normalization_notes.join(",")
                                );
                            }
                        }
                    }
                }
            }
        },
        Command::Sources { command } => match command {
            SourcesCommand::Status { run, format } => {
                let statuses = query.list_source_statuses(run)?;
                match format {
                    OutputFormat::Json => print_json(statuses)?,
                    OutputFormat::Text => {
                        if statuses.is_empty() {
                            println!("{}", text(language, "empty"));
                        } else {
                            for status in statuses {
                                print_source_status(language, &status);
                            }
                        }
                    }
                }
            }
        },
        Command::Source { command } => match command {
            SourceCommand::List { format } => {
                let sources = application.list_sources_for(language);
                match format {
                    OutputFormat::Json => print_json(sources)?,
                    OutputFormat::Text => {
                        for source in sources {
                            println!(
                                "{}  {}\n  {}\n  {}={}  {}={}\n  {}",
                                source.source_id,
                                source.display_name,
                                source.purpose,
                                text(language, "credential"),
                                credential_state_label(language, source.credential_state),
                                text(language, "endpoint"),
                                source.endpoint,
                                source.terms_notice
                            );
                        }
                    }
                }
            }
            SourceCommand::Doctor { source_ids, format } => {
                let reports = application.source_doctor_for(&source_ids, language)?;
                match format {
                    OutputFormat::Json => print_json(reports)?,
                    OutputFormat::Text => {
                        for report in reports {
                            println!(
                                "{}\n  {}={}  {}=registered_https  {}={}  {}={}",
                                report.source.source_id,
                                text(language, "credential"),
                                credential_state_label(language, report.source.credential_state),
                                text(language, "endpoint"),
                                text(language, "quota_limit"),
                                report.source.quota_limit,
                                text(language, "cache_ttl_ms"),
                                report.source.cache_ttl_ms
                            );
                            if let Some(latest) = report.latest_health {
                                println!(
                                    "  {}={} requests={} pages={} received={} error={}",
                                    text(language, "latest_health"),
                                    health_label(language, &latest.health),
                                    latest.requests,
                                    latest.pages,
                                    latest.results_received,
                                    latest.error_code.as_deref().unwrap_or("-")
                                );
                            } else {
                                println!("  {}=-", text(language, "latest_health"));
                            }
                        }
                    }
                }
            }
            SourceCommand::ImportEnvironment { source_id, confirm } => {
                if !confirm {
                    return Err(cli_error(
                        MessageCode::CredentialImportConfirmationRequired,
                        MessageArgs {
                            source_id: Some(source_id),
                            ..MessageArgs::default()
                        },
                    ));
                }
                application.import_environment_credential(&source_id, true)?;
                println!("{}: {source_id}", text(language, "configured"));
            }
            SourceCommand::RemoveCredential { source_id, confirm } => {
                if !confirm {
                    return Err(cli_error(
                        MessageCode::CredentialImportConfirmationRequired,
                        MessageArgs {
                            source_id: Some(source_id),
                            ..MessageArgs::default()
                        },
                    ));
                }
                let removed = application.remove_credential(&source_id)?;
                print_message(message(
                    language,
                    if removed {
                        MessageCode::CredentialRemoved
                    } else {
                        MessageCode::CredentialNotFound
                    },
                    MessageArgs {
                        source_id: Some(source_id),
                        ..MessageArgs::default()
                    },
                ));
            }
            SourceCommand::ConfigureCredential {
                source_id,
                stdin,
                confirm,
            } => {
                if !confirm {
                    return Err(cli_error(
                        MessageCode::CredentialImportConfirmationRequired,
                        MessageArgs {
                            source_id: Some(source_id),
                            ..MessageArgs::default()
                        },
                    ));
                }
                let value = if stdin {
                    read_secret_from_stdin()?
                } else {
                    read_secret_interactive(language, &source_id)?
                };
                application.configure_credential(&source_id, &value)?;
                println!("{}: {source_id}", text(language, "configured"));
            }
            SourceCommand::SetEnabled { source_id, enabled } => {
                application.set_source_enabled(&source_id, enabled)?;
                println!(
                    "source={} effective_enabled={} config_file={}",
                    source_id,
                    enabled,
                    safe_path(&application.paths().config_file)
                );
            }
            SourceCommand::Collect(args) => collect_production(application, args, language).await?,
        },
        Command::Collect(args) => collect_production(application, args, language).await?,
        Command::Export(args) => export(application, args, language)?,
        Command::Config { command } => match command {
            ConfigCommand::Show { format } => print_config(application, language, format)?,
            ConfigCommand::SetDisplayLanguage { language: value } => {
                let value: DisplayLanguage = value.into();
                application.set_display_language(value)?;
                println!(
                    "{}={} config_file={}",
                    text(language, "display_language"),
                    display_language_code(value),
                    safe_path(&application.paths().config_file)
                );
            }
            ConfigCommand::SetReportLanguage { language: value } => {
                let value: ReportLanguage = value.into();
                application.set_report_language(value)?;
                println!(
                    "{}={} config_file={}",
                    text(language, "report_language"),
                    report_language_code(value),
                    safe_path(&application.paths().config_file)
                );
            }
        },
        Command::Tui => lens_tui::run(application, language).await?,
        Command::Lab { command } => match command {
            LabCommand::Run {
                base_url,
                scenario,
                seed,
                project,
                create_project,
                format,
                acceptance,
            } => {
                if project.is_some() == create_project {
                    return Err(cli_error(
                        MessageCode::LabAcceptanceMismatch,
                        MessageArgs::default(),
                    ));
                }
                let mut options =
                    LabRunOptions::new(base_url, scenario, seed).create_project(create_project);
                options = options.acceptance(match acceptance {
                    LabAcceptanceArg::ForgePass => LabAcceptance::ForgePass,
                    LabAcceptanceArg::LensLocalAssertion => LabAcceptance::LensLocalAssertion,
                });
                if let Some(project) = project {
                    options = options.for_project(project);
                }
                let result = run_lab(store, options, CancellationToken::new()).await?;
                match format {
                    OutputFormat::Json => print_json(result.clone())?,
                    OutputFormat::Text => print_lab_text(&query, &result, language)?,
                }
                if matches!(acceptance, LabAcceptanceArg::ForgePass)
                    && result.verdict.as_deref() != Some("passed")
                {
                    return Err(cli_error(
                        MessageCode::LabAcceptanceMismatch,
                        MessageArgs::default(),
                    ));
                }
            }
            LabCommand::Coverage { format, output } => {
                let report = planned_coverage_report()?;
                write_coverage_report(&report, format.as_str(), &output)?;
                println!(
                    "{}: {}",
                    text(language, "coverage_report"),
                    output.display()
                );
            }
            LabCommand::Verify {
                base_url,
                profile,
                repeat,
                output,
            } => {
                let report = verify_coverage(
                    store,
                    base_url,
                    profile.into(),
                    repeat,
                    CancellationToken::new(),
                )
                .await?;
                if let Some(output) = output {
                    let format = output
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .map_or("json", |extension| {
                            if extension.eq_ignore_ascii_case("md") {
                                "markdown"
                            } else {
                                "json"
                            }
                        });
                    write_coverage_report(&report, format, &output)?;
                }
                print_json(&report)?;
                if report.status != "passed" {
                    return Err(cli_error(
                        MessageCode::LabAcceptanceMismatch,
                        MessageArgs::default(),
                    ));
                }
            }
        },
    }
    Ok(())
}

fn command_output_format(command: &Command) -> OutputFormat {
    match command {
        Command::Project { command } => match command {
            ProjectCommand::Fqdns { format, .. } => *format,
            _ => OutputFormat::Text,
        },
        Command::Runs { command } => match command {
            RunsCommand::List { format, .. }
            | RunsCommand::Show { format, .. }
            | RunsCommand::Diff { format, .. } => *format,
            RunsCommand::Replay { .. } => OutputFormat::Json,
        },
        Command::Results { command } => match command {
            ResultsCommand::List { format, .. } => *format,
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::Show { format, .. } => *format,
        },
        Command::Sources { command } => match command {
            SourcesCommand::Status { format, .. } => *format,
        },
        Command::Source { command } => match command {
            SourceCommand::List { format } | SourceCommand::Doctor { format, .. } => *format,
            _ => OutputFormat::Text,
        },
        Command::Collect(args) => args.format,
        Command::Export(_) => OutputFormat::Text,
        Command::Config { command } => match command {
            ConfigCommand::Show { format } => *format,
            _ => OutputFormat::Text,
        },
        Command::Tui => OutputFormat::Text,
        Command::Lab { command } => match command {
            LabCommand::Run { format, .. } => *format,
            LabCommand::Verify { .. } => OutputFormat::Json,
            LabCommand::Coverage { .. } => OutputFormat::Text,
        },
    }
}

fn finish_error(error: anyhow::Error, language: DisplayLanguage, output: OutputFormat) -> ExitCode {
    let (exit_code, localized) = classify_error(&error, language);
    match output {
        OutputFormat::Json => eprintln!("{}", serde_json::to_string_pretty(&JsonErrorEnvelope { schema_version: CLI_SCHEMA, error: localized }).unwrap_or_else(|_| "{\"schema_version\":\"fqdn-lens.cli.v1\",\"error\":{\"code\":\"internal_unclassified\"}}".to_owned())),
        OutputFormat::Text => { eprintln!("{}: {}", localized.code, localized.message); if let Some(hint) = localized.hint { eprintln!("hint: {hint}"); } }
    }
    ExitCode::from(exit_code)
}

fn classify_error(error: &anyhow::Error, language: DisplayLanguage) -> (u8, LocalizedMessage) {
    if let Some(localized) = error.downcast_ref::<LocalizedCliError>() {
        let exit_code = match localized.code {
            MessageCode::CredentialImportConfirmationRequired
            | MessageCode::LabAcceptanceMismatch => 3,
            _ => 2,
        };
        return (
            exit_code,
            message(language, localized.code, localized.args.clone()),
        );
    }
    if let Some(application_error) = error.downcast_ref::<ApplicationError>() {
        return classify_application_error(application_error, language);
    }
    (
        6,
        message(
            language,
            MessageCode::InternalUnclassified,
            MessageArgs::default(),
        ),
    )
}

fn classify_application_error(
    error: &ApplicationError,
    language: DisplayLanguage,
) -> (u8, LocalizedMessage) {
    let (exit_code, code, args) = match error {
        ApplicationError::InvalidTarget => (2, MessageCode::TargetInvalid, MessageArgs::default()),
        ApplicationError::UrlUserinfoDenied => {
            (2, MessageCode::UrlUserinfoDenied, MessageArgs::default())
        }
        ApplicationError::PublicSuffixOnly => {
            (2, MessageCode::TargetInvalid, MessageArgs::default())
        }
        ApplicationError::RootConfirmationRequired { root_domain }
        | ApplicationError::RootConfirmationMismatch { root_domain } => (
            3,
            MessageCode::TargetRootConfirmationRequired,
            MessageArgs {
                root_domain: Some(root_domain.clone()),
                ..MessageArgs::default()
            },
        ),
        ApplicationError::NoSelectedSources => (
            2,
            MessageCode::SourceSelectionRequired,
            MessageArgs::default(),
        ),
        ApplicationError::UnknownSource(source_id) => (
            2,
            MessageCode::SourceUnknown,
            MessageArgs {
                source_id: Some(source_id.clone()),
                ..MessageArgs::default()
            },
        ),
        ApplicationError::CredentialNotRequired(source_id) => (
            2,
            MessageCode::CredentialNotRequired,
            MessageArgs {
                source_id: Some(source_id.clone()),
                ..MessageArgs::default()
            },
        ),
        ApplicationError::RunNotCancellable(run_id) => (
            3,
            MessageCode::RunNotCancellable,
            MessageArgs {
                run_id: Some(run_id.to_string()),
                ..MessageArgs::default()
            },
        ),
        ApplicationError::ExportDestinationDenied => (
            3,
            MessageCode::ExportDestinationDenied,
            MessageArgs::default(),
        ),
        ApplicationError::Credential(_) => {
            (4, MessageCode::CredentialMissing, MessageArgs::default())
        }
        ApplicationError::Config(_) => {
            (6, MessageCode::ConfigurationInvalid, MessageArgs::default())
        }
        ApplicationError::Factory(_) => (5, MessageCode::UpstreamFailed, MessageArgs::default()),
        ApplicationError::Store(_)
        | ApplicationError::ExportIo(_)
        | ApplicationError::ExportJson(_)
        | ApplicationError::ExportCsv(_) => {
            (6, MessageCode::InternalUnclassified, MessageArgs::default())
        }
    };
    (exit_code, message(language, code, args))
}

fn print_json<T: Serialize>(data: T) -> Result<()> {
    print_json_with_messages(data, Vec::new())
}

fn print_json_with_messages<T: Serialize>(data: T, messages: Vec<LocalizedMessage>) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&JsonEnvelope {
            schema_version: CLI_SCHEMA,
            data,
            messages: (!messages.is_empty()).then_some(messages),
        })?
    );
    Ok(())
}

fn print_message(value: LocalizedMessage) {
    println!("{}: {}", value.code, value.message);
    if let Some(hint) = value.hint {
        println!("hint: {hint}");
    }
}

async fn collect_production(
    application: &ApplicationService,
    args: ProductionCollectArgs,
    language: DisplayLanguage,
) -> Result<()> {
    let report = application
        .collect(CollectOptions {
            target: args.domain,
            selected_sources: args.source_ids,
            include_root: args.include_root,
            confirmed_root_domain: args.confirm_root,
        })
        .await?;
    match args.format {
        OutputFormat::Json => {
            let messages = collection_messages(language, &report.statuses);
            print_json_with_messages(report, messages)?;
        }
        OutputFormat::Text => {
            println!(
                "{}: {}\n{}: {}\n{}: {}\n{}: {}\naccepted_findings={}\nevidence={}\nvirtual_waited_ms={}",
                text(language, "run_id"),
                report.run_id,
                text(language, "project"),
                report.project_id,
                text(language, "target"),
                report.target_domain,
                text(language, "status"),
                run_status_label(language, &report.status),
                report.accepted_findings,
                report.evidence_count,
                report.virtual_waited_ms
            );
            for status in report.statuses.values() {
                print_source_status(language, status);
                if let Some(value) = source_message(language, status) {
                    print_message(value);
                }
            }
        }
    }
    Ok(())
}

fn print_source_status(language: DisplayLanguage, status: &lens_core::SourceStatus) {
    println!(
        "source={} status={} requests={} pages={} retries={} cache_hits={} cache_misses={} quota_rejections={} received={} accepted={} filtered={} error={}{}",
        status.source_id,
        source_state_label(language, &status.state),
        status.requests,
        status.pages,
        status.retries,
        status.cache_hits,
        status.cache_misses,
        status.quota_rejections,
        status.results_received,
        status.results_accepted,
        status.results_filtered,
        status.error_code.as_deref().unwrap_or("-"),
        status
            .retry_after_ms
            .map(|value| format!(" retry_after_ms={value}"))
            .unwrap_or_default()
    );
}

fn source_message(
    language: DisplayLanguage,
    status: &lens_core::SourceStatus,
) -> Option<LocalizedMessage> {
    let code = status.error_code.as_deref()?;
    let args = MessageArgs {
        source_id: Some(status.source_id.clone()),
        retry_after_ms: status.retry_after_ms,
        ..MessageArgs::default()
    };
    Some(message(
        language,
        match code {
            "missing_credentials" => MessageCode::CredentialMissing,
            "authentication_failed" => MessageCode::AuthenticationFailed,
            "rate_limited" | "quota_exhausted" => MessageCode::RateLimited,
            _ => MessageCode::UpstreamFailed,
        },
        args,
    ))
}

fn collection_messages(
    language: DisplayLanguage,
    statuses: &std::collections::BTreeMap<String, lens_core::SourceStatus>,
) -> Vec<LocalizedMessage> {
    statuses
        .values()
        .filter_map(|status| source_message(language, status))
        .collect()
}

fn print_lab_text(
    query: &QueryService<'_>,
    result: &lens_lab::LabRunResult,
    language: DisplayLanguage,
) -> Result<()> {
    println!(
        "{}: {}\n{}: {}\n{}: {}\n{}: {}\nfound_fqdns={}\nevidence={}\nforge_verdict={}\nvirtual_waited_ms={}",
        text(language, "project"),
        result.project_id,
        text(language, "run_id"),
        result.run_id,
        text(language, "target"),
        result.target_domain,
        text(language, "status"),
        result.status,
        result.findings,
        result.evidence,
        result.verdict.as_deref().unwrap_or("unknown"),
        result.virtual_waited_ms
    );
    for source in query.list_source_statuses(result.run_id)? {
        print_source_status(language, &source);
    }
    println!(
        "{}",
        match language {
            DisplayLanguage::ZhCn => "诊断数据可通过 runs show 和 sources status 查看。",
            DisplayLanguage::EnUs => "Use runs show and sources status for local diagnostics.",
        }
    );
    Ok(())
}

fn print_config(
    application: &ApplicationService,
    language: DisplayLanguage,
    format: OutputFormat,
) -> Result<()> {
    #[derive(Serialize)]
    struct SourceConfigView {
        source_id: String,
        persisted_enabled: Option<bool>,
        default_enabled: bool,
        effective_enabled: bool,
        credential_state: &'static str,
    }
    #[derive(Serialize)]
    struct ConfigView {
        data_directory: String,
        config_file: String,
        database_file: String,
        default_export_directory: String,
        display_language: &'static str,
        report_language: &'static str,
        show_low_frequency_fallback_sources: bool,
        sources: Vec<SourceConfigView>,
        credential_notice: String,
    }
    let view = ConfigView {
        data_directory: safe_path(&application.paths().data_dir),
        config_file: safe_path(&application.paths().config_file),
        database_file: safe_path(&application.paths().database_file),
        default_export_directory: safe_path(
            application.config().export_directory(application.paths()),
        ),
        display_language: display_language_code(application.config().display_language),
        report_language: report_language_code(application.config().report_language),
        show_low_frequency_fallback_sources: application
            .config()
            .show_low_frequency_fallback_sources,
        sources: application
            .source_preferences()
            .into_iter()
            .map(|source| SourceConfigView {
                source_id: source.source_id,
                persisted_enabled: source.persisted_enabled,
                default_enabled: source.default_enabled,
                effective_enabled: source.effective_enabled,
                credential_state: credential_state_code(source.credential_state),
            })
            .collect(),
        credential_notice: text(language, "security_notice"),
    };
    match format {
        OutputFormat::Json => print_json(view),
        OutputFormat::Text => {
            println!(
                "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}={}\n{}={}\n{}={}\n{}",
                text(language, "data_directory"),
                view.data_directory,
                text(language, "config_file"),
                view.config_file,
                text(language, "database_file"),
                view.database_file,
                text(language, "default_export_directory"),
                view.default_export_directory,
                text(language, "display_language"),
                view.display_language,
                text(language, "report_language"),
                view.report_language,
                text(language, "fallback_sources"),
                view.show_low_frequency_fallback_sources,
                text(language, "security_notice")
            );
            for source in view.sources {
                println!(
                    "source={} persisted_enabled={} default_enabled={} effective_enabled={} credential_state={}",
                    source.source_id,
                    persisted_enabled_code(source.persisted_enabled),
                    source.default_enabled,
                    source.effective_enabled,
                    source.credential_state
                );
            }
            Ok(())
        }
    }
}

fn persisted_enabled_code(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unset",
    }
}

fn export(
    application: &ApplicationService,
    args: ExportArgs,
    language: DisplayLanguage,
) -> Result<()> {
    let format = match args.format {
        ExportFormat::Json => ReportFormat::Json,
        ExportFormat::Markdown => ReportFormat::Markdown,
        ExportFormat::Csv => ReportFormat::Csv,
    };
    let metadata = application.export_report(
        args.run,
        format,
        &args.output,
        args.language.map(Into::into),
        false,
    )?;
    println!(
        "{}: {}\nformat={} report_language={} findings={} evidence={}",
        text(language, "exported"),
        metadata.destination.display(),
        serde_json::to_string(&metadata.format).unwrap_or_else(|_| "unknown".to_owned()),
        report_language_code(metadata.report_language),
        metadata.findings,
        metadata.evidence
    );
    Ok(())
}

fn read_secret_from_stdin() -> Result<String> {
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    let value = trim_secret_line(&value);
    if value.trim().is_empty() {
        return Err(cli_error(
            MessageCode::CredentialMissing,
            MessageArgs::default(),
        ));
    }
    Ok(value.to_owned())
}

fn read_secret_interactive(language: DisplayLanguage, source_id: &str) -> Result<String> {
    let prompt = match language {
        DisplayLanguage::ZhCn => {
            format!("请输入 source `{source_id}` 的 credential（不会回显，Ctrl+C 可取消）： ")
        }
        DisplayLanguage::EnUs => {
            format!("Enter the credential for source `{source_id}` (hidden; Ctrl+C cancels): ")
        }
    };
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut value = String::new();
    read_line_no_echo(&mut value)?;
    eprintln!();
    let value = trim_secret_line(&value);
    if value.trim().is_empty() {
        return Err(cli_error(
            MessageCode::CredentialMissing,
            MessageArgs::default(),
        ));
    }
    Ok(value.to_owned())
}

fn trim_secret_line(value: &str) -> &str {
    value.trim_end_matches(['\r', '\n'])
}

fn read_line_no_echo(value: &mut String) -> io::Result<()> {
    #[cfg(windows)]
    {
        const STD_INPUT_HANDLE: i32 = -10;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        unsafe extern "system" {
            fn GetStdHandle(n_std_handle: i32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(console_handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
            fn SetConsoleMode(console_handle: *mut std::ffi::c_void, mode: u32) -> i32;
        }
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode = 0_u32;
        if !handle.is_null() && unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
            let changed = unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } != 0;
            let result = io::stdin().read_line(value).map(|_| ());
            if changed {
                let _ = unsafe { SetConsoleMode(handle, mode) };
            }
            return result;
        }
    }
    io::stdin().read_line(value).map(|_| ())
}

fn health_label(language: DisplayLanguage, health: &lens_core::SourceHealthState) -> String {
    let code = serde_json::to_string(health)
        .unwrap_or_else(|_| "\"unknown\"".to_owned())
        .trim_matches('"')
        .to_owned();
    let label = match (language, code.as_str()) {
        (DisplayLanguage::ZhCn, "succeeded") => "已成功",
        (DisplayLanguage::ZhCn, "empty") => "无结果",
        (DisplayLanguage::ZhCn, "missing_credentials") => "缺少 credential",
        (DisplayLanguage::ZhCn, "authentication_failed") => "authentication failed",
        (DisplayLanguage::ZhCn, "rate_limited") => "触发 rate limit",
        (DisplayLanguage::ZhCn, "parse_failed") => "解析失败",
        (DisplayLanguage::ZhCn, "security_rejected") => "安全策略拒绝",
        (DisplayLanguage::ZhCn, "cancelled") => "已取消",
        (DisplayLanguage::ZhCn, _) => "upstream 失败",
        (DisplayLanguage::EnUs, "succeeded") => "Succeeded",
        (DisplayLanguage::EnUs, "empty") => "Empty",
        (DisplayLanguage::EnUs, "missing_credentials") => "Missing credentials",
        (DisplayLanguage::EnUs, "authentication_failed") => "Authentication failed",
        (DisplayLanguage::EnUs, "rate_limited") => "Rate limited",
        (DisplayLanguage::EnUs, "parse_failed") => "Parse failed",
        (DisplayLanguage::EnUs, "security_rejected") => "Security rejected",
        (DisplayLanguage::EnUs, "cancelled") => "Cancelled",
        (DisplayLanguage::EnUs, _) => "Upstream failed",
    };
    format!("{label} ({code})")
}

#[cfg(test)]
fn bounded_diagnostic(value: &str) -> String {
    const LIMIT: usize = 512;
    let mut value = value.chars();
    let prefix = value.by_ref().take(LIMIT).collect::<String>();
    if value.next().is_some() {
        format!("{prefix}… [truncated]")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_diagnostic, trim_secret_line};
    #[test]
    fn diagnostic_output_is_bounded() {
        let diagnostic = bounded_diagnostic(&"x".repeat(513));
        assert!(diagnostic.ends_with("… [truncated]"));
        assert!(diagnostic.len() < 600);
    }
    #[test]
    fn secret_line_only_removes_terminal_line_endings() {
        assert_eq!(trim_secret_line(" secret \r\n"), " secret ");
        assert_eq!(trim_secret_line("secret"), "secret");
    }
}
