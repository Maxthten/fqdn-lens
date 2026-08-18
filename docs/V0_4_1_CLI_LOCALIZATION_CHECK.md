# FQDN Lens V0.4.1 CLI localization check

**Status:** CLI implementation complete for offline acceptance on August 18, 2026.

## Delivered scope

- Added reusable `lens-core::i18n` resources for `zh-CN` / `en-US`, stable
  message codes, severity, localized source text, credential labels, source
  state labels, run state labels, and empty states.
- Added global one-shot `--language zh-cn|en-us`; it takes precedence over
  persisted `config.toml` language and does not write the config file.
- Added `config show`, `config set-display-language`,
  `config set-report-language`, and `source set-enabled`.
- Added secure `source configure-credential --confirm` with Windows no-echo
  interactive input and explicit `--stdin` input. Secret values are never
  accepted as command-line arguments.
- Replaced user-facing Rust `Debug` formatting with stable machine codes and
  localized labels. JSON success keeps `fqdn-lens.cli.v1` and may add localized
  `messages`; JSON errors are serialized on stderr without human banners.

## Offline validation

Passed:

```text
cargo fmt --all
cargo check --workspace --locked
cargo test --workspace --locked       47 lens-core + 2 lens-cli unit + 5 CLI contract + 5 lens-lab + 1 external test passed
```

The local CLI matrix also passed for:

- root and command help with bilingual descriptions;
- `--language zh-cn|en-us source list` with stable source IDs;
- `config show --format json` containing only non-secret fields;
- persisted display-language change and one-shot override behavior;
- source enable preference persistence and unknown-source rejection;
- URL userinfo rejection and root confirmation error envelopes;
- missing confirmation for stdin credential setup without secret persistence or
  echo;
- JSON stdout remaining parseable and free of text banners.

Not run:

- live provider smoke or real credential configuration;
- interactive secure-store write with a real user secret;
- Forge `full` repeat-1/repeat-2 gate in this CLI-localization pass.

## Stable output policy

- Exit `0`: request completed, including empty findings or recoverable source
  warnings.
- Exit `2`: validation or unknown source error.
- Exit `3`: confirmation or policy denial.
- Exit `4`: credential configuration/authentication problem.
- Exit `5`: upstream or transient source failure.
- Exit `6`: local configuration, storage, or internal failure.

TUI, MCP, and Desktop GUI remain out of scope and must reuse these core
resources and contracts in the later stages.
