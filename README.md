# aur-guard

`aur-guard` is a fast, static AUR package security auditing CLI for Arch Linux.
It audits AUR package build files before any build or install step.

It is deliberately small:

- no GUI
- no daemon
- no telemetry
- no package database
- no automatic installation
- no execution of PKGBUILD or install script code
- optional LLM review, off by default

The tool is an assistant for manual review. A clean report means only that no
high-risk findings were detected by the implemented checks. It does not prove
that a package is safe.

## Install

From source:

```sh
cargo build --release --locked
```

Optional install target:

```sh
make install PREFIX="$HOME/.local"
```

An Arch packaging template is provided at `packaging/PKGBUILD`.

## Usage

Audit an AUR package by name:

```sh
aur-guard audit google-chrome
```

Audit a local directory containing `PKGBUILD`:

```sh
aur-guard audit --pkgdir ./some-package
```

Emit JSON:

```sh
aur-guard audit --json paru
```

Enable optional LLM review:

```sh
OPENAI_API_KEY=... aur-guard audit --llm paru
```

Use as a makepkg wrapper:

```sh
aur-guard wrapper -- makepkg -si
```

With AUR helpers that support a makepkg wrapper:

```sh
yay --makepkg "aur-guard wrapper -- makepkg" -S package-name
```

By default, WARN and FAIL reports exit non-zero. To report findings but continue:

```sh
aur-guard audit --warn-only package-name
aur-guard wrapper --warn-only -- makepkg -si
```

## Exit Codes

- `0`: pass, or warn/fail when `--warn-only` is set
- `1`: warn or fail under fail-closed policy
- `2`: tool error
- `3`: invalid usage

## Checks

Deterministic rules currently flag:

- `curl` or `wget` piped into shells/interpreters
- base64, hex, gzip, or encrypted-looking payload decoders
- `chmod +x` followed by execution
- `sudo`, `su`, or `doas`
- direct writes outside `$pkgdir` or `$srcdir`
- shell profile, systemd, and pacman/libalpm hook modifications
- install scripts
- `SKIP` checksums
- non-HTTPS sources
- mutable VCS sources
- suspicious `pkgver()` behavior
- git submodules and build-time git fetches
- `npm`, `pip`, `cargo`, `go`, `gem`, and bundler network install commands
- obfuscated shell, Python, Perl, Node, and Ruby snippets
- dangerous commands such as `rm -rf /`, `dd of=/dev/...`, `mkfs`, `chattr`,
  `setcap`, setuid chmods, `nc`, `socat`, reverse shells, and `/dev/tcp`

Unresolved dynamic shell behavior is treated as manual review material.

## Config

Config file:

```toml
# ~/.config/aur-guard/config.toml
output = "human"          # human, plain, json
warn_only = false
keep_tmp = false
include_vendored = false
fetch_remote_sources = false
max_file_bytes = 524288
max_files = 2000
git_timeout_secs = 45

[llm]
enabled = false
base_url = "https://api.openai.com/v1"
model = "gpt-5-mini"
token_budget = 8000
max_snippets = 12
timeout_secs = 45
```

Environment variables override the config file:

- `AUR_GUARD_OUTPUT`
- `AUR_GUARD_WARN_ONLY`
- `AUR_GUARD_KEEP_TMP`
- `AUR_GUARD_INCLUDE_VENDORED`
- `AUR_GUARD_FETCH_REMOTE_SOURCES`
- `AUR_GUARD_MAX_FILE_BYTES`
- `AUR_GUARD_MAX_FILES`
- `AUR_GUARD_LLM`
- `AUR_GUARD_OPENAI_API_KEY` or `OPENAI_API_KEY`
- `AUR_GUARD_OPENAI_BASE_URL` or `OPENAI_BASE_URL`
- `AUR_GUARD_OPENAI_MODEL` or `OPENAI_MODEL`
- `AUR_GUARD_LLM_TOKEN_BUDGET`
- `AUR_GUARD_LLM_MAX_SNIPPETS`
- `AUR_GUARD_LLM_TIMEOUT_SECS`

CLI flags override both environment and config.

## LLM Mode

LLM mode is optional and disabled by default. When enabled, `aur-guard` sends:

- the deterministic report
- snippets attached to findings
- if no findings exist, a capped `PKGBUILD` and `.SRCINFO` excerpt

It does not send entire repositories blindly. It redacts common secret shapes and
local paths before sending prompts. LLM output is advisory text only and cannot
downgrade deterministic FAIL findings.

## Source Handling

`aur-guard audit <package>` clones `https://aur.archlinux.org/<package>.git` into
a temporary directory with `git clone --depth 1`. It never runs `makepkg`,
`pkgver()`, `prepare()`, `build()`, `package()`, install scripts, hooks, or files
from the package.

Local sources referenced from the `source` array are scanned when present. Remote
source downloads are disabled by default. With `--fetch-remote-sources`, only small
HTTPS non-VCS files are fetched into a tempdir and scanned as inert bytes.

Large files, binary files, `.git`, `pkg`, `src`, `target`, and common vendored
directories are skipped by default.

## What Changed From aur-sleuth

Keep:

- audit by AUR package name
- audit local package directory
- makepkg wrapper workflow
- OpenAI-compatible optional analysis

Remove:

- mandatory LLM dependency
- Python and `uv` runtime
- rich TUI and UI/demo assets
- tracker database
- default `makepkg --printsrcinfo` and `makepkg --nobuild` execution
- agentic file selection as the primary trust path

Redesign:

- static deterministic checks first
- explicit PASS / WARN / FAIL report model
- JSON output for automation
- fail-closed wrapper mode with `--warn-only`
- TOML config at `~/.config/aur-guard/config.toml`
- bounded file reads and ignored large/vendored directories
