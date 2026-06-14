use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
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
