# FQDN Lens V0.4.2.1 TUI presentation repair check

**Status:** complete; freeze gates passed on August 18, 2026.

## Scope

This repair is limited to TUI localization and presentation correctness. It
does not add product capability or change collection, source registry, network
egress, quota, cache, retry, scheduler, normalization, scope filtering,
evidence persistence, JSON/database/report schemas, or credential storage.

Changed areas:

- `crates/lens-core/src/i18n.rs`: controlled static resources and explicit
  localized-label/stable-code mappers for ResultScope, ScopeVerdict,
  ReportFormat, report/display language, boolean preferences, run/source
  status, source health, and TUI notices.
- `crates/lens-tui/src/lib.rs`: Dashboard, Collect, Sources, Run, Findings,
  Evidence, Compare, Export, Settings, Help, global shell, progress output,
  and all confirmation modals now use the controlled presentation contract.
- `docs/V0_4_2_TUI_BETA_CHECK.md`: corrected the earlier unsupported completion
  statement.

## Contract checks

- Default `zh-CN` output no longer emits complete hard-coded English UI
  sentences; professional terms and stable machine identifiers remain stable.
- `render_*` and `render_modal` contain no Rust `Debug` formatting and no
  JSON serialization used as user-facing status text.
- Scope, sort, verdict, format, run/source status, credential state, report
  language, and boolean preferences display a localized label plus stable
  machine code.
- Locale changes preserve source selection, run selection, findings filters,
  sort, and export destination.
- Credential values remain outside `AppState` and are not present in the
  renderer fixture, modal resources, notices, or test snapshots.
- Target userinfo, query, and fragment material is not rendered as a raw URL.
- The TUI continues to use `ApplicationService`; no direct `reqwest`, SQLite,
  Credential Manager, CLI subprocess, provider, MCP, GUI, or `api.txt` path
  was introduced.

## Automated coverage

Added deterministic checks for:

- zh-CN/en-US screen resource matrix with stable source/run/FQDN/cursor/digest
  values;
- no-`Debug`/no-JSON renderer source guard;
- fake-secret and URL-userinfo/query/fragment absence;
- localized-label/stable-code mapper coverage;
- locale-change selection preservation;
- empty source selection, target preview, progress terminal state, and
  cancellation behavior.

## Validation

Passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts\verify-forge.ps1 -Profile full -Repeat 1 -ForgePath E:\code\jnsec\fqdn-forge  passed (114/114)
scripts\verify-forge.ps1 -Profile full -Repeat 2 -ForgePath E:\code\jnsec\fqdn-forge  passed (228/228)
```

The workspace test run passed all existing tests plus the new core/TUI
presentation tests. No live provider smoke was run; no real credential was
read or authorized.

## Known limits

- The renderer remains intentionally text-first and does not add charts,
  themes, dark mode, AI summaries, or Desktop GUI behavior.
- Forge `full -Repeat 20` remains an optional long stress run and is not
  represented as part of this repair gate.
