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

## LLM Boundary

LLM mode is off by default. When enabled:

- prompts are capped by a token budget
- local paths and common secret patterns are redacted
- only deterministic findings and small relevant snippets are sent
- LLM output is advisory and cannot downgrade deterministic findings

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
