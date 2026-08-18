# FQDN Lens V0.4 application-service stage check

**Scope:** V0.4 implementation step 2 from the root requirements document:
shared application service, non-secret local configuration, secure credential
resolution, target confirmation, unified report export, and CLI adaptation.

**Deliberately not claimed:** TUI beta, MCP v0.1, or desktop GUI beta. The
requirements explicitly sequence those after the application-service and
credential model are stable; this stage does not add parallel collection paths
or placeholder interfaces that would bypass that gate.

## Implemented contract

- `ApplicationService` is the production collection boundary for source list,
  doctor, credential configuration/removal, collect, run status, paged
  findings/evidence, comparison, cancellation, and JSON/Markdown/CSV export.
- It reuses the V0.2/V0.3 registry, egress allow-list, scheduler, cache,
  quota, cancellation token, normalization, scope filtering, Store, evidence,
  source status, and redaction semantics. It does not launch the CLI or add a
  source provider.
- Windows config lives beneath `%LOCALAPPDATA%\FQDN Lens`; its TOML schema has
  no secret fields and rejects unknown fields such as `api_key`.
- Credential resolution is `SessionOnly -> CredentialStore -> Environment ->
  Missing`. The Credential Manager target namespace is `FQDN Lens/<source-id>`
  and remove only deletes that Lens-owned generic credential. Values have no
  `Debug`, `Display`, or serialization implementation.
- `source doctor` uses stable machine states (`credential_store`,
  `environment`, `session_only`, `missing`, `not_required`) without exposing
  credential material.
- Collection input accepts domains, FQDNs, and HTTP(S) URLs. URL userinfo is
  rejected and only the hostname is retained. The registrable root is derived
  from the public suffix list; a FQDN/URL scope expansion requires explicit
  confirmation.
- Exports contain a stored target domain, source status, accepted findings and
  redacted evidence. Human-facing Markdown/CSV labels support `zh-CN`,
  `en-US`, and `bilingual`; JSON keeps stable English machine keys and adds a
  localized summary.

## Validation

Fixture/offline validation completed on **August 18, 2026**:

```text
cargo fmt --all -- --check                         passed
cargo clippy --workspace --all-targets --locked -- -D warnings  passed
cargo test --workspace --locked                    passed (45 lens-core tests)
scripts\verify-forge.ps1 -Profile full -Repeat 1  passed (114/114)
scripts\verify-forge.ps1 -Profile full -Repeat 2  passed (228/228)
```

The no-credential CLI smoke path was also run with an HTTP(S) URL input and
`ct-certspotter`: it produced `missing_credentials`, `requests=0`, and a
redacted/bilingual Markdown report. This was a fixture/safety validation, not
a live provider smoke test. No real API key, provider request, or authorized
target query was used.

The V0.2 Forge `full` repeat-1/repeat-2 release gates were run after this
change and passed. TUI/MCP/GUI work must add their own secret-redaction,
cancellation, multi-source isolation, export, and bilingual behavior tests
before moving this document's status beyond the application-service stage.

## V0.4.1 CLI localization follow-up

The CLI localization and usability follow-up is now implemented in
`docs/V0_4_1_CLI_LOCALIZATION_CHECK.md`. It completes the CLI presentation
surface only: reusable `zh-CN` / `en-US` resources, one-shot language
override, non-secret config commands, source enablement preference, secure
credential setup, stable JSON/error envelopes, and localized status/message
codes. This does not claim TUI, MCP, or Desktop GUI work; those remain future
stages and must continue to use `ApplicationService`.
