# FQDN Lens V0.3 release check

This note records the implementation boundary for the V0.3 real passive
source adapter pack. It does not claim broad internet enumeration coverage.

Implemented in `lens-core`:

- fixed `ProductionSourceRegistry` for the four required provider IDs;
- environment-only `CredentialProvider` with redaction-safe status values;
- `ProductionSourceFactory` with missing-credential zero-request behavior;
- production HTTPS authority allow-list while preserving Lab loopback-only
  egress;
- provider parsers for Cert Spotter, URLScan Search, crt.sh, and Common Crawl
  CDXJ;
- recorded provider fixtures, malformed-response checks, Common Crawl corrupt
  line filtering, and zero-request missing-credential coverage;
- bounded provider cache TTLs, quotas, retries, cancellation, and diagnostics;
- Common Crawl metadata discovery followed by a bounded index query only;
- CLI `source list`, `source doctor`, and explicit `collect` commands.

Deterministic checks run without real credentials:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The Cert Spotter and URLScan live smoke checks remain explicit user-owned
actions. Before running them, the user must set the corresponding environment
variable and choose an authorized target domain; the agent must not receive or
persist either secret.

```powershell
cargo run -p lens-cli -- source doctor --source ct-certspotter
cargo run -p lens-cli -- collect --domain <authorized-domain> --source ct-certspotter
cargo run -p lens-cli -- source doctor --source web-urlscan-search
cargo run -p lens-cli -- collect --domain <authorized-domain> --source web-urlscan-search
```
