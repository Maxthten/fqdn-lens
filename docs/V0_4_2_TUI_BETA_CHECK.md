# FQDN Lens V0.4.2 TUI beta check

**Status:** V0.4.2 structural implementation was completed, but its original
“implementation complete” statement is superseded by the V0.4.2.1
localization/presentation repair. TUI beta freeze is recorded in
`V0_4_2_1_TUI_PRESENTATION_REPAIR_CHECK.md` only after the repair gates pass.

## Delivered

- Added the independent `lens-tui` crate and `fqdn-lens tui` entrypoint.
- Added terminal interactivity checks, alternate-screen/raw-mode setup, cursor
  cleanup, panic cleanup, Ctrl+C handling, resize/minimum-size warning, and a
  text-first renderer that remains understandable without color.
- Added explicit pure state/reducer models for Dashboard, Collect, Sources &
  Credentials, Run, Findings, Evidence, Compare, Export, Settings, and Help.
- Reused `ApplicationService`, Store/query wrappers, credential provider,
  export policy, target normalization, source registry, scheduler policy,
  cancellation registry, and `lens-core::i18n`.
- Added bounded `CollectionProgressEvent` delivery. The TUI uses a capacity-64
  channel and `try_send`; intermediate events may be dropped under pressure,
  while the final `CollectionReport` and Store status remain authoritative.
- Added source/run progress counters, cancellation confirmation, findings
  search/source/scope/sort/pagination controls, evidence pagination, run diff,
  export policy enforcement, and pending Settings save confirmation.
- Added secure no-echo credential input without storing secret data in
  `AppState`; the controller clears its secret buffer on success, cancel,
  panic/unwind, and drop.
- Added core locale keys for TUI page labels and safety notices. Machine IDs,
  source IDs, run IDs, status codes, and report schemas remain English-stable.

## V0.4.2.1 status correction

The beta renderer found after this document was written still contained
hard-coded user-facing English, Rust `Debug` enum formatting, and JSON-derived
health text. Those gaps are not covered by the earlier structural checks, so
this document must not be read as evidence that the TUI presentation contract
was complete. See the repair check for the locale matrix, no-`Debug` guard,
secret-safety checks, and final freeze gates.

## Dependency decision

`crossterm 0.29.0` (MIT) is used only for terminal event input, raw mode,
alternate screen, cursor visibility, clear/redraw, and terminal size. It does
not contain collection or business logic and does not add a provider/network
capability. The remaining TUI dependencies are existing workspace libraries.

## V0.4.2 structural validation

Passed:

```text
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The TUI unit tests cover default Dashboard state, empty source selection,
language/machine-ID stability, target preview state, terminal progress, and
terminal cancellation state. Existing CLI contract tests and core redaction,
normalization, cancellation, Store, and source tests remain passing.

Manual PTY smoke also passed at 80x24: Dashboard rendered, `q` opened the
confirmation modal, Enter exited with code 0, and the final terminal cleanup
sequence restored the cursor and alternate screen.

Forge validation is run separately because this change extends `lens-core`
collection/scheduler progress contracts. Live provider smoke is intentionally
not run: no real credential or provider request was authorized.

Forge result:

```text
scripts\verify-forge.ps1 -Profile full -Repeat 1 -ForgePath E:\code\jnsec\fqdn-forge  passed (114/114)
scripts\verify-forge.ps1 -Profile full -Repeat 2 -ForgePath E:\code\jnsec\fqdn-forge  passed (228/228)
```

## Security and boundary review

- No `api.txt` read or discovery path exists.
- No TUI direct `reqwest`, SQLite/SQL, Credential Manager, CLI subprocess, or
  evidence URL follow exists.
- No active DNS, brute force, port scan, screenshot, crawler, link following,
  new source, provider, MCP, or Desktop GUI capability was added.
- Credential values are not rendered, serialized, logged, copied, included in
  progress events, or placed in `AppState`.
- Dashboard, Sources, and Settings use local ApplicationService reads only;
  provider requests begin only after the explicit Start collection confirmation.

## Known non-live limits

- Real-provider live smoke is not run by default and requires explicit user
  authorization plus a temporary credential.
- The terminal renderer is intentionally text-first; complex charts, AI
  summaries, risk scores, and Desktop GUI visualization remain out of scope.
- Progress events are bounded and may drop intermediate updates; the UI does
  not display a fabricated percentage and always reconciles with final Store
  status.
