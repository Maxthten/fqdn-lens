# FQDN Forge external-collector contract notes

`lens-lab` talks only to the public loopback HTTP API. It never reads Forge
scenario, truth, assertion, or fixture files at runtime.

The public `CollectorSubmission` schema contains `findings` and
`source_statuses`, but no collection of filtered candidates or filter reasons.
FQDN Lens persists those locally as Evidence with `scope_verdict` and
normalization notes. Consequently, a Forge scenario whose verdict requires an
external client to submit a specific `pagination_loop`, `out_of_scope`, or
`blocked_egress` filtered value cannot be made to pass by a conforming external
submission alone: adding a `filtered` field is rejected by Forge's
`deny_unknown_fields` contract.

This is deliberately not worked around with scenario IDs, truth-file reads, or
invalid/out-of-scope findings. The exercised HTTP contract passes certificate,
archive, generic JSON/HTML, pagination-success, retry, upstream-failure, and
direct-loopback cases. The local SQLite evidence store remains the authoritative
record for accepted and filtered candidates.

Lens V0.2 recognizes the optional public `request_body_template` and
`request_body_content_type` fields. It performs only the documented
`{{target_domain}}` and `{{page_or_cursor}}` substitutions, bounds serialized
bodies and redacts body values everywhere outside the request. A
non-paginated POST without that public template is rejected before a source
request; Lens never infers fields from a scenario ID, report or fixture.

Forge's public run manifest now exposes this extension for
`036-custom-rest-post`. The V0.2 full profile therefore verifies that scenario
as passed without Lens inferring any request-body field. A non-paginated POST
that omits the public template remains a strict safety rejection, not a
deferred success.

Filtered Evidence and some local error diagnostics remain authoritative in the
Lens Store when `CollectorSubmission` cannot express them.
