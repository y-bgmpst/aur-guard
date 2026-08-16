use crate::{
    pkgbuild_parser::{Pkgbuild, SourceLocation, SrcInfoEntry, is_remote_url, is_vcs_source},
    report::{Finding, Severity},
};

use super::{first_lines, re};

pub fn scan_pkgbuild_metadata(pkgbuild: &Pkgbuild) -> Vec<Finding> {
    let mut findings = Vec::new();

    for source in &pkgbuild.sources {
        if source.dynamic {
            findings.push(
                Finding::new(
                    "pkgbuild.dynamic-source",
                    Severity::High,
                    "PKGBUILD",
                    source.line,
                    "Dynamic source entry",
                    "The source array contains shell expansion or command substitution that cannot be resolved statically.",
                    "Manually expand and inspect the resolved source URL or file before building.",
                )
                .with_snippet(&source.raw),
            );
        }

        if let SourceLocation::Remote(url) = &source.location {
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("https://") || lower.starts_with("git+https://")) {
                findings.push(
                    Finding::new(
                        "source.non-https",
                        Severity::Medium,
                        "PKGBUILD",
                        source.line,
                        "Non-HTTPS source",
                        "A remote source is fetched without HTTPS transport integrity.",
                        "Prefer HTTPS sources or manually verify why this transport is required.",
                    )
                    .with_snippet(&source.raw),
                );
            }

            if is_vcs_source(url) {
                findings.push(
                    Finding::new(
                        "source.vcs",
                        Severity::Medium,
                        "PKGBUILD",
                        source.line,
                        "Mutable VCS source",
                        "VCS sources can move unless pinned to an immutable commit.",
                        "Check that the source is pinned and review the referenced upstream repository.",
                    )
                    .with_snippet(&source.raw),
                );
            }
        }
    }

    for checksum in &pkgbuild.checksums {
        if checksum.value.eq_ignore_ascii_case("SKIP") {
            findings.push(
                Finding::new(
                    "checksum.skip",
                    Severity::Medium,
                    "PKGBUILD",
                    checksum.line,
                    "Checksum verification skipped",
                    format!("{} contains SKIP, so makepkg will not verify that source.", checksum.algorithm),
                    "Require a real checksum for fixed sources, or manually justify the exception for VCS sources.",
                )
                .with_snippet("SKIP"),
            );
        }
    }

    if let Some(install) = &pkgbuild.install {
        if install.dynamic {
            findings.push(
                Finding::new(
                    "pkgbuild.dynamic-install",
                    Severity::High,
                    "PKGBUILD",
                    install.line,
                    "Dynamic install script path",
                    "The install script path contains shell expansion that cannot be resolved statically.",
                    "Resolve and inspect the install script path manually before building.",
                )
                .with_snippet(&install.raw),
            );
        }
        findings.push(
            Finding::new(
                "pkgbuild.install-script",
                Severity::Medium,
                "PKGBUILD",
                install.line,
                "Install script declared",
                "A .install script runs package lifecycle hooks as root on the user's system.",
                "Review every function in the install script before installing.",
            )
            .with_snippet(&install.raw),
        );
    }

    for function in &pkgbuild.functions {
        if function.name == "pkgver" {
            let suspicious = re(
                r"(?i)\b(curl|wget|fetch|git\s+clone|git\s+ls-remote|date|openssl\s+rand|/dev/urandom|sed\s+-i\s+PKGBUILD)\b",
            );
            let severity = if suspicious.is_match(&function.body) {
                Severity::High
            } else {
                Severity::Low
            };
            let message = if severity == Severity::High {
                "pkgver() performs network, randomness, timestamp, or self-modifying behavior."
            } else {
                "pkgver() is dynamic and should be checked because static analysis cannot prove its output."
            };
            findings.push(
                Finding::new(
                    "pkgbuild.dynamic-pkgver",
                    severity,
                    "PKGBUILD",
                    function.start_line,
                    "Dynamic pkgver()",
                    message,
                    "Inspect pkgver() manually and ensure it only derives a deterministic version from local sources.",
                )
                .with_snippet(first_lines(&function.body, 4)),
            );
        }
    }

    findings
}

pub fn scan_srcinfo(entries: &[SrcInfoEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in entries {
        if entry.key == "source" && is_remote_url(&entry.value) {
            let lower = entry.value.to_ascii_lowercase();
            if !(lower.starts_with("https://") || lower.starts_with("git+https://")) {
                findings.push(
                    Finding::new(
                        "srcinfo.non-https",
                        Severity::Medium,
                        ".SRCINFO",
                        entry.line,
                        "Non-HTTPS source in .SRCINFO",
                        "The generated source metadata contains a non-HTTPS source.",
                        "Compare .SRCINFO with PKGBUILD and prefer HTTPS sources.",
                    )
                    .with_snippet(&entry.value),
                );
            }
            if is_vcs_source(&entry.value) {
                findings.push(
                    Finding::new(
                        "srcinfo.vcs",
                        Severity::Medium,
                        ".SRCINFO",
                        entry.line,
                        "Mutable VCS source in .SRCINFO",
                        "The generated source metadata references mutable VCS content.",
                        "Check pinning and compare with the PKGBUILD source array.",
                    )
                    .with_snippet(&entry.value),
                );
            }
        }

        if is_checksum_key(&entry.key) && entry.value.eq_ignore_ascii_case("SKIP") {
            findings.push(
                Finding::new(
                    "srcinfo.checksum-skip",
                    Severity::Medium,
                    ".SRCINFO",
                    entry.line,
                    "Checksum SKIP in .SRCINFO",
                    "Generated package metadata shows skipped source verification.",
                    "Confirm this matches the PKGBUILD and manually justify the skipped checksum.",
                )
                .with_snippet(&entry.value),
            );
        }
    }
    findings
}

fn is_checksum_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "b2sums"
        || lower.starts_with("b2sums_")
        || lower == "md5sums"
        || lower.starts_with("md5sums_")
        || lower == "sha1sums"
        || lower.starts_with("sha1sums_")
        || lower == "sha224sums"
        || lower.starts_with("sha224sums_")
        || lower == "sha256sums"
        || lower.starts_with("sha256sums_")
        || lower == "sha384sums"
        || lower.starts_with("sha384sums_")
        || lower == "sha512sums"
        || lower.starts_with("sha512sums_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkgbuild_parser::parse_pkgbuild;

    #[test]
    fn detects_checksum_skip() {
        let pkgbuild = parse_pkgbuild("source=('x')\nsha256sums=('SKIP')\n");
        let findings = scan_pkgbuild_metadata(&pkgbuild);
        assert!(findings.iter().any(|f| f.rule_id == "checksum.skip"));
    }

    #[test]
    fn detects_non_https_source() {
        let pkgbuild = parse_pkgbuild("source=('http://example.invalid/x')\n");
        let findings = scan_pkgbuild_metadata(&pkgbuild);
        assert!(findings.iter().any(|f| f.rule_id == "source.non-https"));
    }
}
