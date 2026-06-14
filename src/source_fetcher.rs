use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use tempfile::TempDir;

use crate::{
    config::Config,
    pkgbuild_parser::{Pkgbuild, SourceLocation, is_vcs_source},
    report::SkippedFile,
};

#[derive(Debug)]
pub struct SourceFiles {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<SkippedFile>,
    _tempdir: Option<TempDir>,
}

impl SourceFiles {
    pub fn empty() -> Self {
        Self {
            files: Vec::new(),
            skipped: Vec::new(),
            _tempdir: None,
        }
    }
}

pub fn collect_referenced_sources(
    root: &Path,
    pkgbuild: &Pkgbuild,
    config: &Config,
) -> Result<SourceFiles> {
    let mut out = SourceFiles::empty();

    for source in &pkgbuild.sources {
        match &source.location {
            SourceLocation::Local(path) => {
                if source.dynamic {
                    out.skipped.push(SkippedFile {
                        file: source.raw.clone(),
                        reason: "dynamic local source path requires manual review".to_string(),
                    });
                    continue;
                }
                let candidate = root.join(path);
                if !candidate.exists() {
                    out.skipped.push(SkippedFile {
                        file: path.display().to_string(),
                        reason: "referenced local source file is not present".to_string(),
                    });
                    continue;
                }
                let Ok(canonical) = candidate.canonicalize() else {
                    out.skipped.push(SkippedFile {
                        file: candidate.display().to_string(),
                        reason: "failed to canonicalize referenced source".to_string(),
                    });
                    continue;
                };
                if !canonical.starts_with(root) {
                    out.skipped.push(SkippedFile {
                        file: candidate.display().to_string(),
                        reason: "referenced source resolves outside package directory".to_string(),
                    });
                    continue;
                }
                out.files.push(canonical);
            }
            SourceLocation::Remote(url) => {
                if !config.fetch_remote_sources {
                    continue;
                }
                if !url.starts_with("https://") || is_vcs_source(url) {
                    out.skipped.push(SkippedFile {
                        file: url.clone(),
                        reason: "remote source fetching only supports HTTPS non-VCS files"
                            .to_string(),
                    });
                    continue;
                }
                if out._tempdir.is_none() {
                    out._tempdir = Some(tempfile::Builder::new().prefix("sources-").tempdir()?);
                }
                let tempdir = out._tempdir.as_ref().expect("created above").path();
                match fetch_https_source(url, tempdir, config.max_file_bytes) {
                    Ok(path) => out.files.push(path),
                    Err(err) => out.skipped.push(SkippedFile {
                        file: url.clone(),
                        reason: format!("failed to fetch remote source: {err}"),
                    }),
                }
            }
        }
    }

    out.files.sort();
    out.files.dedup();
    Ok(out)
}

fn fetch_https_source(url: &str, tempdir: &Path, max_file_bytes: u64) -> Result<PathBuf> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;
    let mut response = client.get(url).send().context("request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("HTTP {}", response.status());
    }
    if let Some(length) = response.content_length()
        && length > max_file_bytes
    {
        anyhow::bail!("remote file exceeds max_file_bytes");
    }

    let mut bytes = Vec::new();
    let mut limited = response.by_ref().take(max_file_bytes + 1);
    limited
        .read_to_end(&mut bytes)
        .context("failed to read response body")?;
    if bytes.len() as u64 > max_file_bytes {
        anyhow::bail!("remote file exceeds max_file_bytes");
    }

    let filename = safe_filename(url);
    let path = tempdir.join(filename);
    let mut file =
        fs::File::create(&path).with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn safe_filename(url: &str) -> String {
    let last = url
        .split('/')
        .next_back()
        .filter(|part| !part.is_empty())
        .unwrap_or("source");
    last.chars()
        .map(|ch| match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_removes_path_separators() {
        assert_eq!(safe_filename("https://example.invalid/a/b?x=1"), "b_x_1");
    }
}
