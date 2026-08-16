use crate::report::{Finding, Severity};

use super::re;

pub(super) fn scan_line_rules(
    rel_path: &str,
    line_no: usize,
    line: &str,
    checksum_metadata: bool,
    findings: &mut Vec<Finding>,
) {
    let trimmed = line.trim();
    let command_text = strip_quoted_text(trimmed);

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

    if !checksum_metadata && re(r"[A-Za-z0-9+/]{120,}={0,2}").is_match(trimmed) {
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

    let assignment_with_hook_name =
        re(r"(?i)^\s*[A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)?\s*(?:\+?=).*\.hook\b")
            .is_match(trimmed);
    if re(r"(?i)(/etc/profile|\.bashrc|\.zshrc|\.profile|systemctl\b|/etc/systemd|/etc/pacman\.d/hooks|/usr/share/libalpm/hooks)")
        .is_match(trimmed)
        || (!assignment_with_hook_name && re(r"(?i)\.hook\b").is_match(trimmed))
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

    if re(r"(?i)\bgit\s+(clone|fetch|ls-remote|submodule\s+update)\b").is_match(&command_text) {
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

    if re(r#"(?i)\beval\b|\b(python|perl|node|ruby)\s+-e\b|\bexec\s*\(|\bcompile\s*\(|\btr\s+['"]?A-Za-z|__import__\(['"]base64['"]\)"#)
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

fn strip_quoted_text(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            out.push(' ');
            escaped = false;
        } else if !single && ch == '\\' {
            out.push(' ');
            escaped = true;
        } else if !double && ch == '\'' {
            single = !single;
            out.push(' ');
        } else if !single && ch == '"' {
            double = !double;
            out.push(' ');
        } else if single || double {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn writes_outside_pkgdir(line: &str) -> bool {
    if line.contains("$pkgdir")
        || line.contains("${pkgdir}")
        || line.contains("$srcdir")
        || line.contains("${srcdir}")
    {
        return false;
    }

    if let Some(destination) = ln_destination(line) {
        return re(r"^/(etc|usr|bin|sbin|home|root|var|boot|lib)(/|$)").is_match(&destination);
    }

    re(r#"(?i)\b(install|cp|mv|mkdir|touch|tee|sed)\b[^#\n]*([[:space:]"'=])/(etc|usr|bin|sbin|home|root|var|boot|lib)\b"#)
        .is_match(line)
}

fn ln_destination(line: &str) -> Option<String> {
    let words = shell_words(line);
    let command = words.iter().position(|word| word == "ln")?;
    let mut args = words.into_iter().skip(command + 1).peekable();
    let mut operands = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--" {
            operands.extend(args);
            break;
        }
        if arg.starts_with('-') {
            if arg == "-t" || arg == "--target-directory" {
                return args.next();
            }
            if let Some(value) = arg.strip_prefix("--target-directory=") {
                return Some(value.to_string());
            }
            continue;
        }
        operands.push(arg);
    }
    operands.get(1).cloned()
}

fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if !single && ch == '\\' {
            escaped = true;
        } else if !double && ch == '\'' {
            single = !single;
        } else if !single && ch == '"' {
            double = !double;
        } else if !single && !double && ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}
