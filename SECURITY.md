# Security Policy

## Threat Model

`aur-guard` treats AUR package contents as hostile input. This includes:

- `PKGBUILD`
- `.SRCINFO`
- `.install` scripts
- patches
- hooks
- local files referenced by `source`
- scripts checked into the AUR package repository

The lightweight parser deliberately does not implement Bash. Unsupported or
ambiguous constructs such as command substitution, process substitution,
`eval`, here-documents, dynamic expansions, and unbalanced shell syntax are
reported for manual review and cannot produce a clean authorization result.

The tool is designed to inspect these files without building or installing the
package and without executing package-controlled code.

## Non-Goals

`aur-guard` does not prove that a package is safe. It does not replace manual
review, sandboxing, reproducible builds, maintainer reputation checks, or normal
Arch packaging hygiene.

It also does not fully evaluate shell. If a PKGBUILD computes behavior through
complex shell expansion, command substitution, environment-sensitive branches, or
generated scripts, the correct result is manual review.

## Execution Boundary

The audit path must not run package-controlled operations, including:

- `pkgver()`
- `prepare()`
- `build()`
- `check()`
- `package()`
- `.install` script functions
- package-provided hooks or scripts

Wrapper mode is the explicit exception at the process boundary: after a
successful audit it invokes `/usr/bin/makepkg`, which is expected to process
the package. The audit itself never invokes that package-controlled code.

Wrapper mode executes only `/usr/bin/makepkg` (with `makepkg` accepted as an
input alias). It audits before every package-processing invocation. Only
`--help`, `-h`, `--version`, and `-V` bypass the audit. Arbitrary commands are
rejected. The default wrapper policy blocks both deterministic findings and
security-relevant input that could not be inspected.

Expected ignored build/vendor directories are not treated as security
findings. In contrast, unreadable or unavailable `PKGBUILD`, `.SRCINFO`,
install scripts, referenced sources, fetched sources, and files skipped by
configured inspection limits are security-relevant and produce at least WARN.

For AUR package names it invokes `git clone` to fetch package metadata into a
temporary directory. Git clone is used only to retrieve the package repository;
tracked package files are still treated as untrusted data.

## LLM Boundary

LLM mode is off by default. When enabled:

- prompts are capped by a token budget
- local paths and common secret patterns are redacted
- only deterministic findings and small relevant snippets are sent
- LLM output is advisory and cannot downgrade deterministic findings

The LLM client uses the OpenAI-compatible chat completions protocol. OpenAI can
be used directly. Claude, Gemini, Mistral, Llama, local models, and other
providers require an endpoint or gateway that presents the same
`/chat/completions` API shape.

LLMs can produce false positives and false negatives. Treat LLM notes as review
hints, not as authorization to install.

Remote source fetching is opt-in. It accepts only small HTTPS non-VCS files,
does not allow URL credentials, follows at most three redirects, and validates
each redirect target. Literal or resolved loopback, private, link-local,
unspecified, multicast, and other obviously non-global addresses are rejected.
This is an egress safety boundary, not a complete guarantee against every DNS
rebinding or network-topology race.

## Reporting Vulnerabilities

For security issues in `aur-guard`, open a private advisory or contact the
maintainer out of band before publishing exploit details.

Useful reports include:

- exact command line
- package fixture or minimized reproducer
- expected versus actual finding
- whether package-controlled code was executed
- platform and `aur-guard --version`
