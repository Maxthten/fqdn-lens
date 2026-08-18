# FQDN Lens V0.4.2 — application service and TUI beta

FQDN Lens is a local-first, strictly passive FQDN evidence explorer. The
current V0.4.2 baseline freezes the shared Rust application service and the
terminal TUI, while retaining the V0.3 fixed-registry production path and the
FQDN Forge Lab path on `http://127.0.0.1:<port>` supplied by a run manifest.

中文摘要：FQDN Lens 是一个 local-first、strictly passive 的 FQDN evidence
explorer。当前 V0.4.2 已冻结 ApplicationService 与 TUI；MCP v0.1 仍处于
需求阶段，Desktop GUI 尚未开始。

The Rust workspace contains:

- `lens-core`: domain rules, evidence aggregation, bounded HTTP for Lab
  loopback and registered production HTTPS authorities, SQLite storage, and
  stable read queries; its `ApplicationService` owns production collection,
  credential status, findings/evidence paging, diff, cancellation and report
  export semantics;
- `lens-lab`: the public FQDN Forge external-collector bridge;
- `lens-cli`: the supported command-line interface.
- `lens-tui`: the interactive terminal workbench used by `fqdn-lens tui`.

The planned MCP v0.1 server and light-theme Desktop GUI are deliberately not
part of this workspace baseline yet. They must reuse `ApplicationService` when
implemented and must not add a second collection path.

## Open-source references and borrowed ideas

The local workspace keeps two reference projects under the sibling directory
`..\reference-projects\`: `amass` and `subfinder`. They are study references,
not runtime dependencies of FQDN Lens, and their source is not compiled into
this repository.

| Reference | Ideas used for study | Explicit boundary |
|---|---|---|
| ProjectDiscovery Subfinder | Passive source adapter organization, source authentication, aggregation, rate-limit/source status handling, and practical CLI ergonomics | FQDN Lens does not copy its implementation or add arbitrary third-party source behavior |
| OWASP Amass | Project/scope modeling, provenance and relationship-oriented evidence, and future visualization ideas | FQDN Lens does not enable active enumeration, DNS brute force, port scanning, or Amass-specific active workflows |

中文说明：本项目确实参考了 `Subfinder` 和 `Amass` 的设计思路，主要借鉴
passive source adapter、source status、scope/provenance、聚合和可视化方向；
没有直接复制它们的实现，也没有把它们作为运行时依赖。FQDN Lens 自己的
Rust ApplicationService、四个固定 production source、FQDN Forge contract、
secure credential model、双语 presentation 和 TUI 是本项目独立实现的部分。

后续如果需要移植具体代码，必须先核对对应项目的 license、文件来源和修改
记录；当前阶段只保留参考目录，不自动把参考项目代码合并进 FQDN Lens。

## Run locally

In one terminal, start FQDN Forge:

```powershell
Set-Location ..\fqdn-forge
cargo run -p lab-cli -- serve --port 18080
```

In another terminal:

```powershell
Set-Location ..\fqdn-lens
cargo run -p lens-cli -- lab run --create-project --base-url http://127.0.0.1:18080 --scenario 001-basic-certificate --seed 1
cargo run -p lens-cli -- lab run --project <project-id> --base-url http://127.0.0.1:18080 --scenario 001-basic-certificate --seed 1
cargo run -p lens-cli -- results list --run <run-id>
cargo run -p lens-cli -- results list --run <run-id> --scope all --format json
cargo run -p lens-cli -- export --run <run-id> --format json --output run.json
```

The Lab/Forge path rejects `localhost`, all non-loopback IPs, HTTPS, userinfo
URLs, redirects, environment proxies, and any source endpoint not provided as
a numeric `127.0.0.1` URL. The separate production path accepts only the
fixed HTTPS authorities registered below. Neither path performs DNS lookups or
connects to a root or discovered FQDN.

## V0.3 real passive sources

V0.3 adds an explicit production-source path. The four provider definitions
are fixed in `lens-core`; there is no user-supplied base URL:

- `ct-certspotter` — Cert Spotter CT issuance search, Bearer token;
- `web-urlscan-search` — URLScan read-only search, API key;
- `ct-crtsh` — low-frequency public CT fallback;
- `archive-commoncrawl-cdxj` — bounded Common Crawl index lookup.

Use the source list and doctor commands without exposing credentials:

```powershell
cargo run -p lens-cli -- source list
cargo run -p lens-cli -- source doctor
```

Credentials are read only from `FQDN_LENS_CERTSPOTTER_TOKEN` and
`FQDN_LENS_URLSCAN_API_KEY`. Missing credentials produce a skipped source and
zero network requests. Collection is always explicit and accepts only the
registered HTTPS authorities:

```powershell
cargo run -p lens-cli -- collect --domain <authorized-domain> --source ct-certspotter
cargo run -p lens-cli -- collect --domain <authorized-domain> --source web-urlscan-search --source ct-crtsh
```

The production path reuses the V0.2 project/run/evidence Store and scheduler.
URLScan never submits or follows scans/URLs; Common Crawl never downloads WARC
payloads or webpages. Live smoke tests are opt-in and must use a domain the
user is authorized to query; deterministic tests never require real keys.

## V0.4 application service, configuration, and credentials

The V0.4 service gives all later UI/MCP clients one source of truth for source
selection, target validation, egress policy, collection, findings, evidence,
run comparisons, cancellation and export. It does not add a provider or any
active reconnaissance capability.

Its normal Windows data layout is:

```text
%LOCALAPPDATA%\FQDN Lens\
  config.toml
  fqdn-lens.db
  exports\
  logs\
```

`config.toml` is non-secret only. It rejects unknown secret-shaped fields and
can contain language, source enablement, cache/concurrency preferences and an
export directory. Existing `--database <path>` automation remains supported.

Credentials resolve in this order:

```text
one-time session credential
  -> Lens-owned Windows Credential Manager entry
  -> compatible user environment variable
  -> Missing
```

`source doctor` reports only `credential_store`, `environment`,
`session_only`, `missing`, or `not_required`; it never emits a value, length,
prefix, suffix, or hash. The noninteractive CLI intentionally does not accept
secret values as flags. It can import an already-set environment variable only
after explicit confirmation, and deletion touches only the `FQDN Lens/<id>`
Credential Manager entry:

```powershell
cargo run -p lens-cli -- source import-environment ct-certspotter --confirm
cargo run -p lens-cli -- source remove-credential ct-certspotter --confirm
```

Collection accepts a root domain, FQDN, or HTTP(S) URL. A URL is never fetched:
Lens extracts only its host, rejects userinfo/IP literals, determines the
registrable root, and requires `--confirm-root` when an FQDN or URL expands
scope:

```powershell
cargo run -p lens-cli -- source collect `
  --domain https://app.example.com/login?session=ignored `
  --confirm-root example.com `
  --source ct-certspotter
```

Reports share the service contract and support JSON, Markdown, and CSV with
an explicit `zh-cn`, `en-us`, or `bilingual` human-readable language choice:

```powershell
cargo run -p lens-cli -- export --run <run-id> --format markdown `
  --language bilingual --output .\run-report.md
```

The TUI is now the first interactive client of this application-service
contract. MCP stdio and the light-theme Desktop GUI remain gated follow-up
surfaces; neither has been added yet.

## V0.4.2 TUI beta

The TUI provides a text-first local workbench for Dashboard, source and
credential status, Quick Collect, Run Monitor, Findings, Evidence, Compare,
Export, Settings, and Help. It uses the same source registry, credential
policy, target normalization, cancellation, evidence, and report semantics as
the CLI.

Start it from an interactive terminal:

```powershell
cargo run -p lens-cli -- tui
cargo run -p lens-cli -- --language en-us tui
```

The TUI does not read `api.txt`, accept credential values through the MCP/AI
path, follow evidence URLs, or perform active reconnaissance. Provider
requests begin only after an explicit collection confirmation.

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Strict local Forge acceptance matrix.
.\scripts\verify-forge.ps1 -Profile full -Repeat 1 -ForgePath ..\fqdn-forge
.\scripts\verify-forge.ps1 -Profile full -Repeat 2 -ForgePath ..\fqdn-forge
```

For the opt-in black-box integration test, leave FQDN Forge running and use:

```powershell
$env:FQDN_FORGE_BASE_URL = 'http://127.0.0.1:18080'
cargo test -p lens-lab --test external_forge
```

The release matrix is the authoritative acceptance entry: an unavailable
Forge, missing scenario, failed supported verdict, or failed local assertion
returns non-zero. Cases whose public submission contract cannot express
filtered/error evidence are labeled `Lens-local assertion`; unsupported
profiles are listed as explicit Deferred coverage rather than skipped.

## V0.4.1 CLI localization and safe preferences

Normal CLI text follows the persisted `display_language` (default `zh-cn`).
Use a one-shot override without changing configuration:

```powershell
cargo run -p lens-cli -- --language zh-cn source list
cargo run -p lens-cli -- --language en-us source doctor --source ct-certspotter
```

Non-secret preferences are managed through the application service:

```powershell
cargo run -p lens-cli -- config show --format text
cargo run -p lens-cli -- config show --format json
cargo run -p lens-cli -- config set-display-language --language en-us
cargo run -p lens-cli -- config set-report-language --language bilingual
cargo run -p lens-cli -- source set-enabled --source ct-certspotter --enabled true
```

Credential setup never accepts a secret as a command-line value. Interactive
setup uses a no-echo prompt; automation must explicitly opt into stdin:

```powershell
cargo run -p lens-cli -- source configure-credential --source ct-certspotter --confirm
Get-Content -Raw .\local-secret.txt | cargo run -p lens-cli -- source configure-credential --source ct-certspotter --stdin --confirm
```

JSON success keeps the `fqdn-lens.cli.v1` envelope and writes only JSON to
stdout. JSON errors use the same schema on stderr. Machine keys, source IDs,
status codes, and error codes remain English and stable; localized text is for
human-readable messages and hints. TUI is implemented and frozen at the V0.4.2
beta boundary; MCP v0.1 and Desktop GUI are not implemented yet.

## Local Git and generated files

This directory is maintained as its own local Git repository. Generated build
outputs, local databases, reports, artifacts, logs, `.env` files, temporary
credential input, and `api.txt` are intentionally ignored. Source code,
fixtures, tests, documentation, `Cargo.lock`, and release metadata remain
trackable. No remote push is performed automatically.
