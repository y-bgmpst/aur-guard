use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use tempfile::TempDir;
use url::Url;

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

    for (source_index, source) in pkgbuild.sources.iter().enumerate() {
        match &source.location {
            SourceLocation::Local(path) => {
                if source.dynamic {
                    out.skipped.push(SkippedFile::security_relevant(
                        source.raw.clone(),
                        "dynamic local source path requires manual review",
                    ));
                    continue;
                }
                let candidate = root.join(path);
                if !candidate.exists() {
                    out.skipped.push(SkippedFile::security_relevant(
                        path.display().to_string(),
                        "referenced local source file is not present",
                    ));
                    continue;
                }
                let Ok(canonical) = candidate.canonicalize() else {
                    out.skipped.push(SkippedFile::security_relevant(
                        candidate.display().to_string(),
                        "failed to canonicalize referenced source",
                    ));
                    continue;
                };
                if !canonical.starts_with(root) {
                    out.skipped.push(SkippedFile::security_relevant(
                        candidate.display().to_string(),
                        "referenced source resolves outside package directory",
                    ));
                    continue;
                }
                out.files.push(canonical);
            }
            SourceLocation::Remote(url) => {
                if !config.fetch_remote_sources {
                    out.skipped.push(SkippedFile::security_relevant(
                        safe_url_label(url),
                        "remote source fetching is disabled",
                    ));
                    continue;
                }
                if !url.starts_with("https://") || is_vcs_source(url) {
                    out.skipped.push(SkippedFile::security_relevant(
                        safe_url_label(url),
                        "remote source was not safely fetched (HTTPS non-VCS required)",
                    ));
                    continue;
                }
                if out._tempdir.is_none() {
                    out._tempdir = Some(tempfile::Builder::new().prefix("sources-").tempdir()?);
                }
                let tempdir = out._tempdir.as_ref().expect("created above").path();
                match fetch_https_source(url, tempdir, config.max_file_bytes, source_index) {
                    Ok(path) => out.files.push(path),
                    Err(err) => out.skipped.push(SkippedFile::security_relevant(
                        safe_url_label(url),
                        format!("failed to fetch remote source: {err}"),
                    )),
                }
            }
        }
    }

    out.files.sort();
    out.files.dedup();
    Ok(out)
}

fn fetch_https_source(
    url: &str,
    tempdir: &Path,
    max_file_bytes: u64,
    source_index: usize,
) -> Result<PathBuf> {
    let mut current = validate_fetch_url(url)?;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")?;

    let mut response = None;
    for _ in 0..=3 {
        let candidate = validate_fetch_url(current.as_str())?;
        let next = client
            .get(candidate.clone())
            .send()
            .context("request failed")?;
        if next.status().is_redirection() {
            let Some(location) = next.headers().get(reqwest::header::LOCATION) else {
                anyhow::bail!("redirect response did not include a location");
            };
            let location = location
                .to_str()
                .context("redirect location was not valid UTF-8")?;
            current = next_redirect_url(&candidate, location)?;
            continue;
        }
        response = Some(next);
        break;
    }
    let mut response = response.ok_or_else(|| anyhow::anyhow!("too many redirects"))?;
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

    let filename = format!("{source_index:04}-{}", safe_filename(url));
    let path = tempdir.join(filename);
    let mut file =
        fs::File::create(&path).with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn next_redirect_url(current: &Url, location: &str) -> Result<Url> {
    let next = current
        .join(location)
        .context("redirect location was not a valid URL")?;
    validate_fetch_url(next.as_str())
}

fn validate_fetch_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("source URL was invalid")?;
    if url.scheme() != "https" {
        anyhow::bail!("remote source must use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("source URL credentials are not allowed");
    }

    let host = url.host_str().context("source URL has no host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = match host.parse::<IpAddr>() {
        Ok(address) => vec![address],
        Err(_) => format!("{host}:{port}")
            .to_socket_addrs()
            .context("source hostname could not be resolved")?
            .map(|address| address.ip())
            .collect::<Vec<_>>(),
    };
    if addresses.is_empty() || addresses.iter().any(is_non_global_ip) {
        anyhow::bail!("source target is not a globally routable address");
    }
    Ok(url)
}

fn is_non_global_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.octets()[0] == 0
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
                || (ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip
                    .to_ipv4()
                    .is_some_and(|ip| is_non_global_ip(&IpAddr::V4(ip)))
        }
    }
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

fn safe_url_label(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<invalid-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_removes_path_separators() {
        assert_eq!(safe_filename("https://example.invalid/a/b?x=1"), "b_x_1");
    }

    #[test]
    fn fetched_source_names_are_unique_per_source() {
        let first = format!("{:04}-{}", 0, safe_filename("https://a.example/payload"));
        let second = format!("{:04}-{}", 1, safe_filename("https://b.example/payload"));
        assert_ne!(first, second);
        assert!(first.ends_with("-payload"));
        assert!(second.ends_with("-payload"));
    }

    #[test]
    fn rejects_non_https_and_non_global_targets() {
        for url in [
            "http://example.com/source",
            "https://127.0.0.1/source",
            "https://10.0.0.1/source",
            "https://169.254.169.254/source",
            "https://[::1]/source",
            "https://[fe80::1]/source",
        ] {
            assert!(validate_fetch_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn accepts_a_public_literal_address() {
        assert!(validate_fetch_url("https://1.1.1.1/source").is_ok());
    }

    #[test]
    fn rejects_private_redirect_targets() {
        let current = validate_fetch_url("https://1.1.1.1/source").unwrap();
        assert!(next_redirect_url(&current, "https://127.0.0.1/metadata").is_err());
    }

    #[test]
    fn redacts_url_credentials_in_report_labels() {
        assert_eq!(
            safe_url_label("https://user:password@example.com/source"),
            "https://example.com/source"
        );
    }
}
