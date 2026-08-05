# 2026 AUR malicious-package incident

Status reviewed: 2026-08-05

## Verified situation

Arch Linux announced on 12 June 2026 that the AUR was experiencing a high volume of malicious package adoptions and updates. The project temporarily restricted several AUR operations while identifying malicious commits and developing mitigations.

New-account registration was temporarily disabled. It was reopened on 13 July 2026 after registration hardening, including mandatory email verification, time-limited verification tokens, rejection of disposable email addresses, and a cooldown around email changes.

This does **not** mean that AUR package submissions or updates are categorically disabled today. It also does not remove the supply-chain risk. Existing accounts, adopted packages, compromised credentials, and malicious updates remain relevant attack paths.

## Operational recommendation

For the duration of the incident and until Arch Linux publishes a clear resolution:

- do not auto-approve AUR updates
- inspect the Git diff from the previously trusted revision
- treat maintainer changes, orphan adoption, source-domain changes, new install scripts, hooks, binary blobs, and new build-time network access as high-risk
- run `aur-guard` before build, but do not treat PASS as authorization to install
- build as an unprivileged user in a disposable environment without personal credentials or writable access to the real home directory
- prefer official repository packages when the operational impact is acceptable
- postpone non-essential AUR updates when review effort exceeds the benefit

## Reporting

Suspicious AUR commits should be reported through the process requested by Arch Linux staff. Do not send unreviewed scanner or LLM output as an authoritative report. Validate the finding, provide the package name and exact commit, describe the observable behavior, and include a minimal reproducible explanation.

## Project implications

The incident changes the priority order for `aur-guard`:

1. revision-to-revision diff analysis
2. maintainer and package-ownership change awareness
3. source URL, domain, checksum, signing-key, and install-script change detection
4. explicit incomplete-scan reporting
5. isolated build guidance and machine-readable policy output

Snapshot-only signatures remain useful for obvious payloads, but they are not sufficient against a subtle malicious update to an established package.

## Sources

- Arch Linux news: https://archlinux.org/news/active-aur-malicious-packages-incident/
- Arch announce mirror: https://lists.archlinux.org/archives/list/arch-announce%40lists.archlinux.org/thread/FYVZMO3NVKG7FFB25FZQBMDDTZAU7WQF/
- AUR registration status thread: https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/4JRS73YVTE7JUYHHE3ZDUIHXYHXZ3YQQ/
