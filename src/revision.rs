use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

use crate::report::{Finding, Severity};

pub fn audit_revision(root: &Path, baseline: &str) -> Result<Vec<Finding>> {
    validate_revision(baseline)?;
    ensure_git_repository(root)?;

    let baseline_commit = git_stdout(root, &["rev-parse", "--verify", &format!("{baseline}^{{commit}}")])
        .with_context(|| format!("baseline revision {baseline:?} is unavailable"))?;
    let baseline_commit = baseline_commit.trim();

    let head_commit = git_stdout(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let head_commit = head_commit.trim();

    if baseline_commit == head_commit {
        return Ok(Vec::new());
    }

    let ancestor = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", baseline_commit, head_commit])
        .status()
        .context("failed to run git merge-base")?;

    if !ancestor.success() {
        return Ok(vec![Finding::new(
            "revision.baseline-not-ancestor",
            Severity::Critical,
            ".git",
            1,
            "Baseline is not an ancestor of HEAD",
            format!(
                "The selected baseline {baseline_commit} is not an ancestor of {head_commit}; history may have been rewritten or the wrong trust anchor was supplied."
            ),
            "Do not install. Verify the trusted commit out of band and investigate force-push or repository replacement before continuing.",
        )]);
    }

    let range = format!("{baseline_commit}..{head_commit}");
    let name_status = git_stdout(
        root,
        &["diff", "--name-status", "--no-renames", &range, "--"],
    )?;
    let numstat = git_stdout(root, &["diff", "--numstat", &range, "--"])?;

    let binary_paths = numstat
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            let added = fields.next()?;
            let removed = fields.next()?;
            let path = fields.next()?;
            (added == "-" || removed == "-").then(|| path.to_string())
        })
        .collect::<std::collections::HashSet<_>>();

    let mut findings = Vec::new();
    for line in name_status.lines() {
        let mut fields = line.splitn(2, '\t');
        let status = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        if path.is_empty() {
            continue;
        }

        let change = match status.chars().next().unwrap_or('M') {
            'A' => "added",
            'D' => "removed",
            'T' => "changed type",
            _ => "modified",
        };

        let (rule_id, severity, title, action) = classify_change(path, binary_paths.contains(path));
        findings.push(
            Finding::new(
                rule_id,
                severity,
                path,
                1,
                title,
                format!(
                    "Security-relevant package content was {change} between trusted baseline {baseline_commit} and candidate {head_commit}."
                ),
                action,
            )
            .with_snippet(format!("{status}\t{path}")),
        );
    }

    if findings.is_empty() {
        findings.push(Finding::new(
            "revision.metadata-only",
            Severity::Info,
            ".git",
            1,
            "Revision changed without tracked file changes",
            format!("HEAD differs from baseline {baseline_commit}, but git reported no tracked file delta."),
            "Verify the selected revisions and repository state before relying on this result.",
        ));
    }

    Ok(findings)
}

fn classify_change(path: &str, binary: bool) -> (&'static str, Severity, &'static str, &'static str) {
    if binary {
        return (
            "revision.binary-change",
            Severity::High,
            "Binary package content changed",
            "Treat opaque binary additions or changes as untrusted. Obtain source provenance and independently verify or reproduce the artifact.",
        );
    }

    let file_name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(path);

    if file_name == "PKGBUILD" {
        return (
            "revision.pkgbuild-change",
            Severity::High,
            "PKGBUILD changed",
            "Review the exact PKGBUILD diff, especially sources, checksums, prepare/build/package functions, network access, and generated code.",
        );
    }
    if file_name == ".SRCINFO" {
        return (
            "revision.srcinfo-change",
            Severity::High,
            ".SRCINFO changed",
            "Compare .SRCINFO against PKGBUILD and confirm package metadata, sources, checksums, dependencies, and install script declarations match.",
        );
    }
    if path.ends_with(".install") {
        return (
            "revision.install-script-change",
            Severity::High,
            "Install script changed",
            "Review every lifecycle function. Install scripts execute during package transactions with elevated privileges.",
        );
    }
    if path.ends_with(".hook") {
        return (
            "revision.pacman-hook-change",
            Severity::High,
            "Pacman hook changed",
            "Review hook triggers and Exec commands; hooks can execute commands during unrelated package transactions.",
        );
    }
    if path.ends_with(".patch") || path.ends_with(".diff") {
        return (
            "revision.patch-change",
            Severity::Medium,
            "Patch content changed",
            "Inspect the full patch and verify it only implements the stated packaging change against the expected upstream source.",
        );
    }
    if matches!(
        Path::new(path).extension().and_then(|value| value.to_str()),
        Some("sh" | "bash" | "zsh" | "py" | "pl" | "rb" | "js")
    ) {
        return (
            "revision.script-change",
            Severity::High,
            "Executable script content changed",
            "Review the complete script delta and all call sites before building or installing the package.",
        );
    }

    (
        "revision.tracked-file-change",
        Severity::Low,
        "Tracked package file changed",
        "Confirm this file change is expected for the package update and inspect its complete diff before installation.",
    )
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.trim().is_empty() || revision.len() > 256 {
        bail!("baseline revision must contain 1 to 256 characters");
    }
    if revision.starts_with('-') || revision.contains(char::is_whitespace) {
        bail!("baseline revision contains unsafe characters");
    }
    Ok(())
}

fn ensure_git_repository(root: &Path) -> Result<()> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .context("failed to run git rev-parse")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "true" {
        bail!("{} is not a Git work tree", root.display());
    }
    Ok(())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("git output was not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_option_like_revision() {
        assert!(validate_revision("--output=/tmp/pwn").is_err());
    }

    #[test]
    fn classifies_pkgbuild_as_high_risk() {
        let (rule, severity, _, _) = classify_change("PKGBUILD", false);
        assert_eq!(rule, "revision.pkgbuild-change");
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn classifies_binary_as_high_risk() {
        let (rule, severity, _, _) = classify_change("payload.bin", true);
        assert_eq!(rule, "revision.binary-change");
        assert_eq!(severity, Severity::High);
    }
}
