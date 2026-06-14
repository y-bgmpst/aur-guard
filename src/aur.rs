use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use tempfile::TempDir;
use wait_timeout::ChildExt;

use crate::config::Config;

#[derive(Debug)]
pub struct PreparedTarget {
    name: String,
    root: PathBuf,
    tempdir: Option<TempDir>,
}

impl PreparedTarget {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_temp(&self) -> bool {
        self.tempdir.is_some()
    }

    pub fn keep(self) {
        if let Some(tempdir) = self.tempdir {
            let _ = tempdir.keep();
        }
    }
}

pub fn prepare_local(pkgdir: &Path) -> Result<PreparedTarget> {
    let root = pkgdir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", pkgdir.display()))?;
    if !root.join("PKGBUILD").is_file() {
        bail!("{} does not contain a PKGBUILD", root.display());
    }

    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("local-package")
        .to_string();

    Ok(PreparedTarget {
        name,
        root,
        tempdir: None,
    })
}

pub fn clone_package(
    package: &str,
    clone_url: Option<&str>,
    config: &Config,
) -> Result<PreparedTarget> {
    validate_package_name(package)?;

    let parent = std::env::temp_dir().join("aur-guard");
    fs::create_dir_all(&parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let tempdir = tempfile::Builder::new()
        .prefix("pkg-")
        .tempdir_in(parent)
        .context("failed to create temporary audit directory")?;
    let root = tempdir.path().to_path_buf();
    let url = clone_url
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("https://aur.archlinux.org/{package}.git"));

    run_git_clone(&url, &root, config)?;

    if !root.join("PKGBUILD").is_file() {
        bail!("cloned repository does not contain a PKGBUILD");
    }

    Ok(PreparedTarget {
        name: package.to_string(),
        root,
        tempdir: Some(tempdir),
    })
}

fn run_git_clone(url: &str, root: &Path, config: &Config) -> Result<()> {
    let mut child = Command::new("git")
        .args(["clone", "--depth", "1", "--no-tags", "--"])
        .arg(url)
        .arg(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run git clone")?;

    let stdout = child
        .stdout
        .take()
        .context("failed to capture git stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture git stderr")?;
    let stdout_reader = read_pipe(stdout);
    let stderr_reader = read_pipe(stderr);

    let status = match child.wait_timeout(config.git_timeout)? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = join_reader(stderr_reader)?;
            let _ = join_reader(stdout_reader);
            bail!(
                "git clone timed out after {} seconds: {}",
                config.git_timeout.as_secs(),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
    };

    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;

    if !status.success() {
        bail!(
            "git clone failed for {url}: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }

    let _ = stdout;
    Ok(())
}

fn read_pipe<R>(mut reader: R) -> thread::JoinHandle<Result<Vec<u8>, std::io::Error>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    })
}

fn join_reader(handle: thread::JoinHandle<Result<Vec<u8>, std::io::Error>>) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| anyhow!("failed to join git output reader"))?
        .context("failed to read git output")
}

fn validate_package_name(package: &str) -> Result<()> {
    if package.is_empty() || package.len() > 128 {
        bail!("invalid AUR package name length");
    }
    let valid = Regex::new(r"^[A-Za-z0-9@._+-]+$").map_err(|err| anyhow!(err))?;
    if !valid.is_match(package) {
        bail!("invalid AUR package name: {package}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_package_names_with_slashes() {
        assert!(validate_package_name("../bad").is_err());
    }
}
