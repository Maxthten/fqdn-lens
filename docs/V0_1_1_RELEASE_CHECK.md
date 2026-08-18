# FQDN Lens V0.1.1 release check

This report records the V0.1.1 hardening surface implemented in `fqdn-lens`.
The Lens process remains strictly passive and only connects to numeric
`127.0.0.1` authorities and paths authorized by the current Forge manifest.

## Acceptance commands

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
.\scripts\verify-forge.ps1
```

`verify-forge.ps1` starts Forge only when the requested loopback port is not
already listening, gives each matrix case a fresh SQLite database and fresh
process cancellation scope, reports scenario/category/run/project/database
metadata, and removes its temporary directory in `finally`. It never reads
Forge scenario, truth, assertion, or fixture files.

## Matrix coverage

- Forge PASS: certificate, archive, generic JSON, generic HTML/Text/CSV, page,
  offset, cursor, POST-cursor, Link-header, Retry-After seconds/date/invalid,
  204 no-content, upstream failure, rate-limit retry, and direct loopback.
- Lens-local assertion: scope filtering, duplicate cursor loops,
  authentication/body-error classification, timeout/disconnect diagnostics,
  large-result bounds, and the 100,000-record high-unique profile.
- Deferred: the Forge public manifest currently does not expose the POST body
  template required by `036-custom-rest-post`; proxy/CONNECT profiles are not
  part of the direct Lab profile; filtered findings and some error evidence
  cannot be represented by the public `CollectorSubmission` schema.

## Core hardening

- `BoundedResponse` carries status, allow-listed headers, decoded bounded body,
  final URL and response SHA-256.
- Per-run egress pins numeric loopback authority and manifest path families;
  redirects are rejected regardless of `allow_redirect` metadata.
- Pagination is typed for query page/offset/cursor, POST page/cursor and Link
  headers, with repeated-state, reverse/invalid transition and max-page guards.
- `Clock` and `Waiter` are injected; Lab uses a fixed clock and virtual waiter.
- Evidence stores response and record digests, source references, filtered
  scope verdicts and sanitized raw values. `payload_digest` equals the bounded
  response digest for new records.
- Store migration versions are append-only (v1→v2→v3), and `finalize_run`
  commits statuses, evidence, project aggregates and terminal run state in a
  single transaction. Run results and project history are separate read
  models.
- CLI JSON has a schema envelope; exports contain stable non-sensitive fields,
  while credentials, capabilities, cookies, Authorization and URL userinfo
  are redacted before persistence or display.

The external Forge integration test remains an opt-in developer smoke test;
it is not release acceptance when its environment variable is absent.
