# Changelog

All notable changes to `aur-guard` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- GitHub Actions CI: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo build`, and `cargo test` on every push/PR.
- TL;DR section at the top of the README.
- Unit test coverage for `fetch_https_source`'s response handling
  (status, size limits, body write), previously untested since it
  performs real network I/O.

### Changed

- `src/rules.rs` split into `src/rules/{pkgbuild,text,line_rules}.rs`
  for maintainability. No behavior change.
- `run_audit` no longer relies on a runtime `.expect()` to enforce
  that `--pkgdir` and a package name are mutually exclusive; the
  invariant is now derived once via an exhaustive match.

## [0.1.0] - 2026-06-14

Initial release, forked and redesigned from `aur-sleuth`.

### Added

- Static PKGBUILD/.SRCINFO parser and deterministic rule-based
  scanner: remote-pipe-to-shell, obfuscated payload decoders,
  `chmod +x` + execute, privilege escalation, writes outside
  `$pkgdir`/`$srcdir`, shell profile/systemd/pacman hook
  modification, install scripts, skipped checksums, non-HTTPS and
  mutable VCS sources, suspicious `pkgver()`, git submodules and
  build-time fetches, language package manager network installs,
  dangerous commands (`rm -rf /`, `mkfs`, reverse shells, etc.).
- `audit` subcommand: audit an AUR package by name or a local
  directory.
- `wrapper` subcommand: gate `makepkg` invocations directly.
- Human, plain, and JSON report output; explicit PASS/WARN/FAIL
  status with a bounded, deterministic risk score.
- Fail-closed handling: unreadable, oversized, or otherwise
  uninspectable security-relevant input prevents a PASS.
- Optional OpenAI-compatible LLM review (off by default), with
  secret/path redaction before any prompt is sent.
- SSRF-hardened remote source fetching (`--fetch-remote-sources`):
  HTTPS-only, credential rejection, globally-routable-target
  validation on every redirect hop, size-limited downloads.
- TOML config at `~/.config/aur-guard/config.toml` with environment
  variable and CLI flag overrides.
- Arch packaging template (`packaging/PKGBUILD`) and `make install`.
