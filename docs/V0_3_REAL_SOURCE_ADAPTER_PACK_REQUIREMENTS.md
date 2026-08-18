# FQDN Lens V0.3 real source adapter pack — requirements

**Status:** proposed; not part of V0.2  
**Precondition:** V0.2 is frozen and its passive, local-first, evidence, CLI,
and Forge-public-contract semantics remain compatible.

## 1. Goal

V0.3 will add a small, auditable pack of real **passive** source adapters. Its
goal is to demonstrate useful real-world collection without introducing active
reconnaissance, weakening V0.2 safety controls, or creating a second execution
path outside the Lens core service layer.

## 2. Scope

The initial pack must contain three to five representative adapters:

1. One no-auth public passive source.
2. One public archive or historical source.
3. One API-key source.
4. One custom JSON/REST source.

An optional fifth adapter may be added only when it covers a distinct request
shape or reliability policy. Every adapter must declare its source identity,
credentials requirement, rate limit, cache policy, health state, parser
profile, and explicit error classification.

## 3. Compatibility and security requirements

- Reuse the V0.2 core service layer, scheduler, source adapter model,
  normalization, scope filtering, evidence persistence, and CLI semantics.
- Keep collection passive and local-first by default. Do not add DNS
  resolution, port scanning, screenshots, brute force, or any other active
  verification behavior.
- Keep existing egress protections and require explicit, source-specific
  authority for real external destinations; do not relax Forge loopback rules.
- Keep credentials in memory or user-approved local configuration. Never write
  secrets, cookies, raw authorization headers, or raw request-body values into
  fingerprints, evidence, artifacts, logs, or SQLite.
- Preserve the current request-body template limit and redaction behavior.
- Do not add or migrate a persistence schema unless a separately reviewed
  compatibility design requires it.

## 4. Adapter contract

Each adapter design must document:

- external endpoint ownership, terms/licensing constraints, and passive-use
  suitability;
- authentication type and the precise local credential lookup mechanism;
- target-domain request shape, pagination behavior, rate-limit policy, cache
  TTL, retryable failures, and cancellation behavior;
- parser profile, normalization rules, scope behavior, and duplicate handling;
- evidence fields identifying source, redacted request shape, retrieval time,
  normalization result, and error category;
- health checks that do not expand the adapter's network authority beyond its
  configured source endpoint.

## 5. Testing and acceptance gates

Routine CI must not depend on live external services. Each adapter requires
recorded fixtures or Forge-compatible deterministic responses that cover:

- successful collection and evidence provenance;
- pagination or cursor behavior where supported;
- authentication missing/invalid cases without exposing secrets;
- quota, retry, timeout, upstream failure, malformed response, and
  cancellation behavior;
- out-of-scope candidates, duplicate candidates, and redaction-safe request
  fingerprints;
- rejection of unauthorized destinations or unsafe redirects.

The V0.2 gates (`cargo fmt`, Clippy with warnings denied, workspace tests, and
full Forge verification for one and two rounds) remain mandatory. Live
integration checks, if used, must be explicit opt-in commands and must not
replace deterministic acceptance coverage.

## 6. Deliverables

- Source-specific configuration and credential documentation.
- Deterministic fixture/Forge tests and an adapter coverage matrix.
- Health and error-classification documentation.
- Release notes that state the tested passive-source coverage without claiming
  broad production parity with mature enumeration tools.
- A compatibility review confirming no V0.2 CLI, manifest, database, evidence,
  or safety contract was silently changed.

## 7. Explicit non-goals

V0.3 does not include an MCP server, AI execution path, GUI, cloud sync,
accounts, telemetry, active reconnaissance, or a large unreviewed provider
catalog. MCP may begin only after the source adapter pack is stable and must
call the same Lens core service layer rather than reimplement collection by
spawning the CLI.
