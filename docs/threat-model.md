# Threat model

## Scope

`aur-guard` statically audits AUR packaging metadata and repository files before a build or installation. It is a review aid, not a sandbox, malware detector, reputation service, or proof of package safety.

The primary protected assets are:

- the user account running an AUR helper or `makepkg`
- credentials, browser data, SSH/GPG keys, wallets, and local source trees
- host integrity and persistence mechanisms
- package-manager trust and future update paths
- confidentiality of files reachable from the build user

## Current threat context

In June 2026, Arch Linux reported a high volume of malicious AUR package adoptions and updates. The incident demonstrates that reviewing only newly created packages is insufficient: an established package can become hostile after an account compromise, orphan adoption, maintainer change, or malicious update.

AUR account registration was temporarily disabled during remediation and was reopened on 13 July 2026 with mandatory email verification and disposable-address rejection. These controls reduce abusive registration; they do not make package contents trusted.

Authoritative references:

- https://archlinux.org/news/active-aur-malicious-packages-incident/
- https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/4JRS73YVTE7JUYHHE3ZDUIHXYHXZ3YQQ/

## Adversary capabilities

Assume an attacker can:

- publish a new malicious package
- adopt or take over an orphaned package
- compromise a maintainer account or SSH key
- introduce a malicious change into an otherwise legitimate update
- use delayed or conditional execution to evade simple signatures
- fetch second-stage payloads during build, install, first launch, or update
- hide behavior in install scripts, hooks, generated files, vendored code, patches, test fixtures, or upstream release artifacts
- exploit user habituation around popular or long-lived packages
- imitate legitimate packaging patterns and metadata

## Trust boundaries

The following are untrusted inputs:

- `PKGBUILD`, `.SRCINFO`, `.install`, hook files, patches, helper scripts, and vendored files
- remote source archives and VCS repositories
- upstream release artifacts and generated binaries
- AUR metadata, comments, popularity, votes, maintainer age, and package age
- optional LLM output

The following are not security boundaries:

- HTTPS alone
- checksums supplied by the same untrusted `PKGBUILD`
- a clean static scan
- prior benign package versions
- popularity or a familiar package name

## Detection objectives

`aur-guard` should detect or elevate for review:

1. direct command execution of remote or decoded content
2. undeclared network access during build or package stages
3. writes outside `$pkgdir` and `$srcdir`
4. privilege escalation, persistence, hooks, services, capabilities, or setuid behavior
5. obfuscation and generated executable content
6. mutable or insufficiently pinned sources
7. skipped or ineffective integrity verification
8. install-time or first-run execution paths
9. suspicious changes relative to the previously trusted package revision
10. maintainer, ownership, source-domain, signing-key, or upstream changes

Objectives 9 and 10 require historical and metadata-aware analysis. Snapshot-only scanning cannot satisfy them.

## Non-goals and residual risk

Static analysis cannot reliably determine whether:

- an upstream tarball is backdoored while the `PKGBUILD` is benign
- a compiler, dependency, or build toolchain is compromised
- generated code becomes malicious only for specific hosts, dates, locales, or environment variables
- a seemingly legitimate patch contains a subtle vulnerability
- a source repository rewrites mutable history after review

For higher-risk packages, build in an isolated, disposable environment with no personal secrets, no host SSH/GPG agents, no writable home-directory mounts, restricted network access, and explicit artifact inspection.

## Security invariants

- Never execute package-controlled code during analysis.
- Never call `makepkg --printsrcinfo`, `pkgver()`, build functions, install hooks, or package helper scripts to obtain metadata.
- Remote-source fetching remains opt-in, HTTPS-only, bounded, and treated as inert bytes.
- Deterministic findings cannot be downgraded by an LLM.
- Scanner errors and incomplete coverage must be visible and must not silently produce PASS.
- Wrapper mode fails closed unless the operator explicitly selects `--warn-only`.

## Update-review policy

During an active AUR supply-chain incident, users should treat every AUR update as a new trust decision.

Minimum review procedure:

1. retrieve the new AUR Git revision without executing package code
2. compare it with the exact previously installed or previously approved revision
3. inspect all changed packaging files, source URLs, checksums, install scripts, patches, hooks, and generated files
4. verify maintainer/ownership changes and unexpected upstream/domain changes
5. run `aur-guard` on the new revision
6. build only in a clean, unprivileged environment
7. inspect the package file list and package metadata before installation

Until `aur-guard` implements native revision comparison, the historical diff remains a mandatory manual control.