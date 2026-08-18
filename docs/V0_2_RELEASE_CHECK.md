# FQDN Lens V0.2 release check

**Status:** `FROZEN` (release-close validation recorded on 2026-08-18)

V0.2 uses `docs/forge-coverage-matrix.yaml` as its versioned, machine-readable
Forge registry. It has exactly 114 entries: 101 Lens-covered cases, 12 strict
direct safe rejections, and one Forge-owned integrity result.

## Required commands

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
.\scripts\verify-forge.ps1 -Profile full -Repeat 1 -ForgePath E:\code\jnsec\fqdn-forge
.\scripts\verify-forge.ps1 -Profile full -Repeat 2 -ForgePath E:\code\jnsec\fqdn-forge
```

`full -Repeat 20` is an extended pre-release stress gate. It is required after
changes to SQLite, scheduler, cache, quota, lifecycle, or large-dataset
handling, but is not a routine V0.2 release-close regression command.

The script creates the ignored `artifacts/forge-coverage.json` and
`artifacts/forge-coverage.md` files. Each row records classification, seed,
runtime, Forge run ID, Lens run ID and the first bounded failure.

## V0.2 invariants

- Only numeric `http://127.0.0.1:<port>` manifest/control destinations are
  accepted. Redirects, proxies, CONNECT, LAN/public authorities, userinfo and
  system proxy settings are not used.
- Proxy/CONNECT manifests are rejected before source adapter creation, quota
  reservation or source request. The verification profile audits zero source,
  proxy and quota-side-effect records.
- Parser profile and source kind are distinct. The original source kind is
  persisted as evidence provenance; profile-specific parsers handle
  certificate, passive DNS, archive, URL/search, threat, code, organization,
  CSV/text, generic and custom REST shapes.
- Quota scope and run-local cache policy are explicit scheduler inputs. Cache
  fingerprints omit credentials, capability, cookies and request-body values.
- Run fingerprints and snapshot diffs retain redaction-safe request shape and
  provenance data. Lifecycle verification performs reset, stale-access denial
  and delete through Forge's public control API without persisting a capability.

## Public POST-body contract

The Lens implementation accepts the V0.2 optional
`request_body_template` / `request_body_content_type` manifest extension and
substitutes only `{{target_domain}}` and `{{page_or_cursor}}` under a bounded
body limit. It refuses a non-paginated POST with no public template instead of
guessing a body.

Forge's public `/api/runs/{id}/manifest` now exposes that extension for
`036-custom-rest-post`. The full profile verifies the scenario as `passed`
without Lens inferring a body from a scenario ID, report, fixture, or private
Forge file. A missing public template for a non-paginated POST remains a
strict safety rejection (`public_request_body_template_missing`), not a
deferred pass.

## Release-close record

The 2026-08-18 release-close patch removes the stale 036 dependency wording
from release-facing documents, stops emitting the historical deferred reason
in coverage reports, and aligns the versioned matrix with the public Forge
contract. It does not change the CLI, SQLite schema, evidence semantics,
manifest schema, source-adapter behavior, or network policy.

The file-level review and validation outcomes are recorded in
`docs/V0_2_PATCH_RECORD.md`. The next planned scope is defined separately in
`docs/V0_3_REAL_SOURCE_ADAPTER_PACK_REQUIREMENTS.md`.
