# Security Policy

## Current AUR Threat Context

Arch Linux reported a high volume of malicious AUR package adoptions and updates
on 12 June 2026. New-account registration was temporarily disabled and reopened
on 13 July 2026 with additional verification controls. Package submissions are
not categorically disabled, and AUR content remains untrusted.

See:

- [2026 AUR malicious-package incident](docs/incidents/2026-06-aur-malicious-packages.md)
- [Threat model](docs/threat-model.md)

During the incident, treat every AUR update as a new trust decision. A clean
snapshot scan is not sufficient to approve an update to an established package.
Compare the candidate revision with the exact previously trusted revision and
inspect ownership, sources, checksums, signing keys, patches, hooks, install
scripts, binary files, and newly introduced network behavior.

Native revision-aware auditing is tracked in issue #2.

## Threat Model

`aur-guard` treats AUR package contents as hostile input. This includes:

- `PKGBUILD`
- `.SRCINFO`
- `.install` scripts
- patches
- hooks
- local files referenced by `source`
- scripts checked into the AUR package repository

The tool is designed to inspect these files without building or installing the
package and without executing package-controlled code.

## Non-Goals

`aur-guard` does not prove that a package is safe. It does not replace manual
review, revision-to-revision comparison, sandboxing, reproducible builds,
maintainer and ownership checks, or normal Arch packaging hygiene.

It also does not fully evaluate shell. If a PKGBUILD computes behavior through
complex shell expansion, command substitution, environment-sensitive branches, or
generated scripts, the correct result is manual review.

Static analysis cannot establish that an upstream archive, compiler, dependency,
generated binary, or build toolchain is benign.

## Execution Boundary

`aur-guard` must not run:

- `makepkg`
- `pkgver()`
- `prepare()`
- `build()`
- `check()`
- `package()`
- `.install` script functions
- package-provided hooks or scripts

For AUR package names it invokes `git clone` to fetch package metadata into a
temporary directory. Git clone is used only to retrieve the package repository;
tracked package files are still treated as untrusted data.

For higher-risk packages, build as an unprivileged user in a disposable
environment with no personal secrets, no forwarded SSH/GPG agent, no writable
mount of the real home directory, and restricted network access.

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

## Reporting Vulnerabilities

For security issues in `aur-guard`, open a private advisory or contact the
maintainer out of band before publishing exploit details.

Useful reports include:

- exact command line
- package fixture or minimized reproducer
- expected versus actual finding
- whether package-controlled code was executed
- platform and `aur-guard --version`

## Reporting Malicious AUR Packages

Follow the process requested by Arch Linux staff. Validate scanner output
manually before reporting it. Include the package name, exact AUR commit,
affected files, and a concise technical explanation. Do not submit raw
LLM-generated accusations as authoritative findings.
