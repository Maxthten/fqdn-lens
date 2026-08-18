# FQDN Lens V0.2 core freeze

**Status:** `FROZEN` (release-close documentation and coverage metadata
reconciled on 2026-08-18)

## 1. Purpose and status

This document freezes the **V0.2 core** of FQDN Lens so that subsequent work
does not keep changing collection semantics while MCP, production source
adapters, and the GUI are being built.

V0.2 is a completed, Forge-validated local passive-collection core. It is not
yet a claim that Lens has the production source breadth, operational scale, or
user interface of mature enumeration tools.

The freeze decision is based on the following completed evidence:

- Forge coverage registry: 114 scenarios.
- Full verification, one round: 114/114 passed.
- Full verification, two rounds: 228/228 passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed.
- `cargo test --workspace --locked` passed.
- Forge now advertises the public POST body contract required by
  `036-custom-rest-post`.

The latest local verification artifacts are intentionally ignored by Git:

- `artifacts/forge-coverage.json`
- `artifacts/forge-coverage.md`

## 2. Frozen product boundary

### 2.1 Included in V0.2 core

The following behaviours are frozen and must remain compatible unless a
security fix requires a documented breaking change:

1. **Passive collection execution**
   - Manifest-defined HTTP source execution.
   - GET, POST, pagination, retries, response parsing, normalization,
     de-duplication, scope filtering, and evidence persistence.
   - Source kind remains provenance metadata; parser profile determines how a
     response is interpreted.

2. **Safety and network boundary**
   - Forge verification accepts only numeric `http://127.0.0.1:<port>`
     control and manifest endpoints.
   - No implicit system proxy, LAN, public address, redirect, CONNECT, or URL
     userinfo use.
   - Strict direct rejection must occur before creating adapters, reserving
     quota, or sending any source/proxy request.

3. **Source execution policy**
   - Explicit quota scope, retry policy, cache policy, source concurrency and
     cancellation.
   - Request fingerprints do not retain credentials, cookies, capabilities, or
     request-body values.
   - Request body templates are bounded and redacted outside the request path.

4. **Evidence, runs, and comparison**
   - SQLite-backed projects, runs, findings, evidence, lifecycle state, and
     reproducible metadata.
   - Redaction-safe fingerprints, run replay, snapshot diff, and provenance
     comparison.
   - Reset, stale-capability denial, cancellation, and deletion are supported
     by the Forge public control contract.

5. **CLI contract**
   - Existing `project`, `runs`, and `lab` commands remain the authoritative
     automation surface until MCP is introduced.
   - `lab coverage` and `lab verify` remain the machine-readable coverage
     entry points.

### 2.2 Explicitly outside V0.2

The following are not missing V0.2 core features and must not be added as
unplanned freeze-breaking work:

- Desktop GUI, visual graph, SpaceSniffer-style layout, or dashboard.
- MCP server, AI analysis, skills, agents, or autonomous scheduling.
- A broad pack of real Internet source integrations.
- Active DNS resolution, port scanning, screenshots, brute force, or any
  active reconnaissance behaviour.
- User accounts, cloud synchronization, shared workspaces, or telemetry.

V0.2 deliberately remains a passive, local-first core. Any active validation
must be designed as a separate opt-in capability in a future version.

## 3. Forge compatibility contract

`fqdn-lens` must use Forge only through its public loopback HTTP API. It must
never read Forge scenarios, truth files, assertions, fixtures, or repository
paths at runtime.

For sources that require a JSON request body, Forge may publish these optional
manifest fields:

```json
{
  "request_body_template": { "query": "subdomains", "mode": "strict" },
  "request_body_content_type": "application/json"
}
```

Lens performs only the documented public substitutions:

- `{{target_domain}}`
- `{{page_or_cursor}}`

Lens must refuse a non-paginated POST source with no public body template. It
must not infer a body from a scenario ID, response, report, fixture, or a
private Forge file.

The Forge-side compatibility patch is implemented in:

- `E:/code/jnsec/fqdn-forge/crates/lab-core/src/model.rs`
- `E:/code/jnsec/fqdn-forge/crates/lab-server/src/lib.rs`

## 4. Reference implementation boundaries

The frozen implementation is organized as follows:

| Area | Primary location | Freeze rule |
|---|---|---|
| Core models, sources, scheduling, evidence | `crates/lens-core` | Preserve persisted and request-execution semantics. |
| Forge adapter and coverage verification | `crates/lens-lab` | Preserve public-contract-only behaviour. |
| Command-line interface | `crates/lens-cli` | Do not silently rename or reinterpret established commands. |
| Versioned Forge matrix | `docs/forge-coverage-matrix.yaml` | Keep exactly 114 V0.2 entries unless a documented matrix revision is approved. |
| Verification wrapper | `scripts/verify-forge.ps1` | Keep loopback-only server start, artifact generation, and cleanup. |

When learning from existing open-source reconnaissance tools, reuse only
high-level ideas that fit Lens's passive, auditable model: source adapters,
per-source limits, structured output, provenance, and deterministic failure
handling. Do not copy source code or configuration contracts without checking
their license and compatibility.

## 5. Acceptance gates

### 5.1 Required developer gate

Run from `E:/code/jnsec/fqdn-lens`:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
.\scripts\verify-forge.ps1 -Profile full -Repeat 1
.\scripts\verify-forge.ps1 -Profile full -Repeat 2
```

The final two commands must produce a report with:

- `status: "passed"`
- zero scenario rows whose `status` is `failed`
- 114 results for `Repeat 1`
- 228 results for `Repeat 2`

### 5.2 Extended stress gate

The following is not a routine pre-commit check because it executes the full
matrix 20 times, including large-dataset and high-cardinality scenarios:

```powershell
.\scripts\verify-forge.ps1 -Profile full -Repeat 20
```

Use it before a tagged release, after changes to SQLite persistence, scheduler
concurrency, cache/quota behaviour, lifecycle cleanup, or large-dataset
handling. A long runtime by itself is not a functional failure: one full round
has historically taken roughly tens of seconds, and repeated runs accumulate
SQLite work and large-dataset processing.

If this gate is too expensive for day-to-day work, a future V0.3 task may add
an explicit `stress` profile or scenario filter. It must not weaken the
existing `full` definition silently.

### 5.3 Manual acceptance checks

Before declaring the freeze complete, inspect:

- The generated coverage JSON and Markdown artifacts.
- The first failed row, if any, including its Forge and Lens run IDs.
- The absence of public-network egress in the verification environment.
- The Git diff for unexpected API/schema changes.
- The CLI help output for accidental command breakage.

## 6. Known follow-up items

These items do not reopen the V0.2 execution core, but they should be tracked:

1. **Legacy 036 wording — resolved on 2026-08-18**
   - Forge supplies the public body-template contract and Lens passes
     `036-custom-rest-post` without inference.
   - Release-facing notes, versioned matrix notes, and generated coverage
     metadata no longer label that passed result as deferred.

2. **Long-running full repeat validation**
   - `full -Repeat 20` is an extended stress test, not a fast regression test.
   - Keep the full matrix intact; improve observability or introduce an
     explicit stress profile in a later version rather than weakening tests.

3. **Production-source breadth**
   - Forge validates the engine and public integration contract. It does not
     replace real API integration testing or establish production source
     coverage.

## 7. Allowed changes after freeze

Allowed V0.2 maintenance changes:

- Security fixes.
- Correctness fixes with regression tests.
- Test reliability, diagnostic clarity, documentation, and artifact cleanup.
- Backward-compatible Forge-contract fixes.
- Performance fixes that preserve observable CLI, manifest, database, and
  evidence semantics.

Changes requiring a new planned version, not an unreviewed V0.2 patch:

- New persistence schema or destructive migration.
- Changed finding/evidence semantics.
- Broadened network authority or active reconnaissance.
- New real source provider family.
- MCP methods, AI-specific execution paths, GUI state, or cloud behavior.
- Changes that invalidate the 114-entry coverage matrix meaning.

## 8. Exit criteria for V0.2 core freeze

V0.2 core freeze is complete only when all of the following are true:

- [x] Forge public POST-body contract is available and `036-custom-rest-post`
  passes without Lens inference.
- [x] Full Forge verification passes for one and two rounds.
- [x] Rust format, lint, and workspace tests pass.
- [x] The core remains local-first and passive by default.
- [x] Stale 036 dependency wording is removed from final release-facing notes.
- [x] The patch diff is reviewed and recorded in `docs/V0_2_PATCH_RECORD.md`.

## 9. Next version entry: V0.3 real source adapter pack

The immediate next planned work is **not GUI**. It is a small, auditable real
source-adapter pack that proves Lens can collect useful real-world data while
preserving the frozen V0.2 engine.

V0.3 must begin with a separate requirements document and should include:

1. Three to five representative passive source adapters:
   - a no-auth public source;
   - a public archive/history source;
   - an API-key source;
   - a custom JSON/REST source.
2. Per-source credentials, rate limits, cache policy, health state, and clear
   error classification.
3. Recorded or Forge-backed deterministic tests; live APIs must not be
   required for routine CI.
4. Evidence that identifies source, request shape, retrieval time, and
   normalized finding without persisting secrets.
5. No change to V0.2 scope, evidence, or safety semantics without an explicit
   compatibility review.

Only after V0.3 source adapters have stable commands and artifacts should the
project implement the MCP server. The later GUI must consume the same core
service/API rather than duplicating collection logic.
