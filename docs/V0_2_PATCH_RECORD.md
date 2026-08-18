# FQDN Lens V0.2 release-close patch record

**Recorded:** 2026-08-18  
**Scope:** `fqdn-lens` only  
**Status:** V0.2 `FROZEN`

## Purpose

This record closes the documentation and coverage-metadata work that remained
after Forge published the public POST-body contract required by
`036-custom-rest-post`. It documents the reviewed patch because the supplied
workspace is not a Git worktree and therefore cannot provide a repository
`git diff`.

## Reviewed file-level diff

| File | Change | Compatibility effect |
|---|---|---|
| `crates/lens-lab/src/coverage.rs` | Stops attaching a historical 036 deferred reason to current coverage results. | Keeps the serialized `deferred_reason` field; current 036 results now correctly use `null`. |
| `docs/forge-coverage-matrix.yaml` | Changes 036 from a pending-contract note to a public-contract consumption note. | Preserves the 114-entry matrix, scenario ID, owner, classifications, and assertions. |
| `docs/FQDN_FORGE_EXTERNAL_CONTRACT.md` | Records the public contract as available and the scenario as passed. | Preserves the strict rejection for a missing non-paginated POST template. |
| `docs/V0_2_RELEASE_CHECK.md` | Replaces stale release commands and the legacy 036 gap with the V0.2 release-close gates. | Does not alter any CLI command or runtime behavior. |
| `docs/V0_2_CORE_FREEZE.md` | Marks release-close documentation and metadata reconciliation complete. | Does not reopen or expand the frozen core. |
| `docs/V0_3_REAL_SOURCE_ADAPTER_PACK_REQUIREMENTS.md` | Adds the separately scoped next-version requirements entry. | Explicitly keeps V0.2 contracts frozen. |

## Validation record

The following commands are the release-close gates and must be run from the
`fqdn-lens` directory for this patch:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
.\scripts\verify-forge.ps1 -Profile full -Repeat 1 -ForgePath E:\code\jnsec\fqdn-forge
.\scripts\verify-forge.ps1 -Profile full -Repeat 2 -ForgePath E:\code\jnsec\fqdn-forge
```

### Executed results — 2026-08-18

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo test --workspace --locked`: passed (33 unit/integration tests; no
  failures).
- Forge `cargo fmt --all -- --check`, Clippy with warnings denied, and
  workspace tests: passed (50 executed tests; one explicitly ignored stress
  test; no failures).
- `full -Repeat 1`: passed with 114 results and zero failed scenarios.
- `full -Repeat 2`: passed with 228 results and zero failed scenarios.
- The generated repeat-2 report contains two `036-custom-rest-post` rows;
  both have `status: "passed"` and `deferred_reason: null`.
- CLI help still exposes the established `project`, `runs`, and `lab` command
  groups. No unexpected CLI rename was observed.

The Forge verification wrapper accepts only numeric `http://127.0.0.1:<port>`
without URL userinfo and all full-matrix runs completed through that loopback
endpoint. No public-network egress was introduced by this patch.

## Compatibility review

- No public-network egress, proxy, redirect, CONNECT, userinfo, LAN, or
  active-reconnaissance behavior was added.
- No database schema, evidence/finding semantics, manifest field, CLI command,
  source-provider family, or Forge private-file access was changed.
- The strict `public_request_body_template_missing` rejection still applies
  when a non-paginated POST source omits a public body template.
