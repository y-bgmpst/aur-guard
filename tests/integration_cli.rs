use std::{fs, path::Path, process::Command as StdCommand};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = StdCommand::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("git must be available for revision audit tests");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn benign_fixture_passes() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.args(["audit", "--pkgdir", &fixture("benign"), "--plain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("status: PASS"))
        .stdout(predicate::str::contains(
            "No high-risk findings detected by deterministic checks.",
        ));
}

#[test]
fn malicious_fixture_fails_closed() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.args(["audit", "--pkgdir", &fixture("malicious-pipe"), "--plain"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("status: FAIL"))
        .stdout(predicate::str::contains("shell.remote-pipe"))
        .stdout(predicate::str::contains("dangerous.command"));
}

#[test]
fn revision_audit_flags_pkgbuild_delta() {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    git(repo.path(), &["config", "user.name", "aur-guard test"]);
    git(repo.path(), &["config", "user.email", "aur-guard@example.invalid"]);

    fs::write(
        repo.path().join("PKGBUILD"),
        "pkgname=fixture\npkgver=1\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\npackage() { :; }\n",
    )
    .unwrap();
    git(repo.path(), &["add", "PKGBUILD"]);
    git(repo.path(), &["commit", "--quiet", "-m", "trusted baseline"]);
    let baseline = git(repo.path(), &["rev-parse", "HEAD"]);

    fs::write(
        repo.path().join("PKGBUILD"),
        "pkgname=fixture\npkgver=2\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\npackage() { :; }\n",
    )
    .unwrap();
    git(repo.path(), &["add", "PKGBUILD"]);
    git(repo.path(), &["commit", "--quiet", "-m", "candidate update"]);

    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.args([
        "audit",
        "--pkgdir",
        repo.path().to_str().unwrap(),
        "--since",
        &baseline,
        "--plain",
    ])
    .assert()
    .failure()
    .code(1)
    .stdout(predicate::str::contains("status: FAIL"))
    .stdout(predicate::str::contains("revision.pkgbuild-change"));
}

#[test]
fn missing_revision_is_a_tool_error_not_a_pass() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.args([
        "audit",
        "--pkgdir",
        &fixture("benign"),
        "--since",
        "definitely-not-a-revision",
        "--plain",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicate::str::contains("baseline revision"));
}

#[test]
fn warn_only_returns_zero_but_preserves_fail_report() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.args([
        "audit",
        "--pkgdir",
        &fixture("malicious-pipe"),
        "--plain",
        "--warn-only",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("status: FAIL"));
}

#[test]
fn json_output_is_machine_readable() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    let output = cmd
        .args(["audit", "--pkgdir", &fixture("malicious-pipe"), "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "fail");
    assert!(json["findings"].as_array().unwrap().len() >= 3);
}

#[test]
fn invalid_usage_exits_three() {
    let mut cmd = Command::cargo_bin("aur-guard").unwrap();
    cmd.arg("audit").assert().code(3);
}
