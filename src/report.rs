use std::{collections::BTreeMap, fmt};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn score(self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 3,
            Self::Medium => 7,
            Self::High => 30,
            Self::Critical => 70,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Pass,
    Warn,
    Fail,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub title: String,
    pub message: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        severity: Severity,
        file: impl Into<String>,
        line: usize,
        title: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            severity,
            file: file.into(),
            line,
            title: title.into(),
            message: message.into(),
            action: action.into(),
            snippet: None,
        }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        let snippet = snippet.into();
        if !snippet.trim().is_empty() {
            self.snippet = Some(snippet);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedFile {
    pub file: String,
    pub reason: String,
    pub classification: SkipClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipClassification {
    Expected,
    SecurityRelevant,
}

impl SkippedFile {
    pub fn expected(file: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            reason: reason.into(),
            classification: SkipClassification::Expected,
        }
    }

    pub fn security_relevant(file: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            reason: reason.into(),
            classification: SkipClassification::SecurityRelevant,
        }
    }

    pub fn is_security_relevant(&self) -> bool {
        self.classification == SkipClassification::SecurityRelevant
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub target: String,
    pub status: AuditStatus,
    pub risk_score: u16,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_notes: Option<String>,
}

impl AuditReport {
    pub fn new(
        target: impl Into<String>,
        mut findings: Vec<Finding>,
        skipped: Vec<SkippedFile>,
    ) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        let risk_score = calculate_risk_score(&findings);

        let status = if findings
            .iter()
            .any(|finding| finding.severity >= Severity::High)
        {
            AuditStatus::Fail
        } else if findings
            .iter()
            .any(|finding| finding.severity >= Severity::Low)
            || skipped.iter().any(SkippedFile::is_security_relevant)
        {
            AuditStatus::Warn
        } else {
            AuditStatus::Pass
        };

        Self {
            target: target.into(),
            status,
            risk_score,
            findings,
            skipped,
            llm_notes: None,
        }
    }

    pub fn with_llm_notes(mut self, notes: Option<String>) -> Self {
        self.llm_notes = notes.filter(|note| !note.trim().is_empty());
        self
    }

    pub fn to_text(&self, plain: bool) -> String {
        let mut out = String::new();
        out.push_str("aur-guard audit report\n");
        out.push_str(&format!("target: {}\n", self.target));
        out.push_str(&format!("status: {}\n", self.status));
        out.push_str(&format!("risk_score: {}/100\n", self.risk_score));
        out.push('\n');

        if self.findings.is_empty() {
            out.push_str("No high-risk findings detected by deterministic checks.\n");
        } else {
            out.push_str("Findings:\n");
            if plain {
                for finding in &self.findings {
                    render_finding(&mut out, finding);
                }
            } else {
                let mut manual = BTreeMap::<(String, String, String), Vec<&Finding>>::new();
                for finding in &self.findings {
                    if finding.rule_id.starts_with("manual-review.") {
                        manual
                            .entry((
                                finding.rule_id.to_string(),
                                finding.file.clone(),
                                finding.title.clone(),
                            ))
                            .or_default()
                            .push(finding);
                    } else {
                        render_finding(&mut out, finding);
                    }
                }
                for ((rule_id, file, title), findings) in manual {
                    let first = findings[0];
                    out.push_str(&format!(
                        "\n[{}] {} {}\n  rule: {}\n  why: {}\n  review: {}\n  occurrences: {}\n  examples:\n",
                        first.severity,
                        file,
                        title,
                        rule_id,
                        first.message,
                        first.action,
                        findings.len()
                    ));
                    for finding in findings.iter().take(3) {
                        out.push_str(&format!(
                            "    line {}: {}\n",
                            finding.line,
                            finding.snippet.as_deref().unwrap_or("")
                        ));
                    }
                }
            }
        }

        if !self.skipped.is_empty() {
            out.push_str("\nSkipped files:\n");
            for skipped in &self.skipped {
                out.push_str(&format!(
                    "  {} [{}]: {}\n",
                    skipped.file,
                    match skipped.classification {
                        SkipClassification::Expected => "expected",
                        SkipClassification::SecurityRelevant => "security-relevant",
                    },
                    skipped.reason
                ));
            }
        }

        if let Some(notes) = &self.llm_notes {
            out.push_str("\nLLM notes:\n");
            out.push_str(notes.trim());
            out.push('\n');
        }

        out
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn calculate_risk_score(findings: &[Finding]) -> u16 {
    let mut groups = BTreeMap::<&'static str, Vec<Severity>>::new();
    for finding in findings {
        groups
            .entry(finding.rule_id)
            .or_default()
            .push(finding.severity);
    }

    let total = groups
        .values_mut()
        .map(|severities| {
            severities.sort_by(|left, right| right.cmp(left));
            let base = severities[0].score();
            let contribution = severities
                .iter()
                .enumerate()
                .map(|(index, severity)| {
                    let weight = severity.score();
                    match index {
                        0 => weight,
                        1 => weight / 2,
                        2 => weight / 4,
                        _ => weight / 8,
                    }
                })
                .sum::<u32>();
            contribution.min(base * 2)
        })
        .sum::<u32>();

    total.min(100) as u16
}

fn render_finding(out: &mut String, finding: &Finding) {
    out.push_str(&format!(
        "\n[{}] {}:{} {}\n",
        finding.severity, finding.file, finding.line, finding.title
    ));
    out.push_str(&format!("  rule: {}\n", finding.rule_id));
    out.push_str(&format!("  why: {}\n", finding.message));
    out.push_str(&format!("  review: {}\n", finding.action));
    if let Some(snippet) = &finding.snippet {
        out.push_str("  snippet:\n");
        for line in snippet.lines().take(4) {
            out.push_str(&format!("    {}\n", line.trim_end()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_text_snapshot() {
        let report = AuditReport::new(
            "fixture",
            vec![Finding::new(
                "test.rule",
                Severity::High,
                "PKGBUILD",
                7,
                "Suspicious command",
                "A command would fetch remote code and execute it.",
                "Inspect the command before running makepkg.",
            )],
            vec![],
        );

        insta::assert_snapshot!(report.to_text(true), @r"
aur-guard audit report
target: fixture
status: FAIL
risk_score: 30/100

Findings:

[HIGH] PKGBUILD:7 Suspicious command
  rule: test.rule
  why: A command would fetch remote code and execute it.
  review: Inspect the command before running makepkg.
        ");
    }

    #[test]
    fn security_relevant_skips_warn_without_overriding_failures() {
        let report = AuditReport::new(
            "fixture",
            vec![],
            vec![SkippedFile::security_relevant("payload.sh", "size limit")],
        );
        assert_eq!(report.status, AuditStatus::Warn);
        assert!(report.to_text(false).contains("security-relevant"));
    }

    #[test]
    fn human_output_aggregates_manual_review_without_changing_status() {
        let findings = (1..=5)
            .map(|line| {
                Finding::new(
                    "manual-review.unsupported-shell",
                    Severity::Medium,
                    "PKGBUILD",
                    line,
                    "Shell construct requires manual review",
                    "Unsupported shell syntax",
                    "Inspect the construct",
                )
                .with_snippet(format!("line {line}"))
            })
            .collect();
        let report = AuditReport::new("fixture", findings, vec![]);
        let text = report.to_text(false);
        assert_eq!(report.findings.len(), 5);
        assert_eq!(report.status, AuditStatus::Warn);
        assert!(text.contains("occurrences: 5"));
        assert_eq!(text.matches("occurrences:").count(), 1);
        assert!(text.contains("line 1: line 1"));
        assert!(text.contains("line 3: line 3"));
    }

    fn finding(rule_id: &'static str, severity: Severity) -> Finding {
        Finding::new(rule_id, severity, "PKGBUILD", 1, "test", "test", "test")
    }

    #[test]
    fn risk_score_is_zero_without_findings() {
        assert_eq!(calculate_risk_score(&[]), 0);
    }

    #[test]
    fn risk_score_preserves_severity_order() {
        assert!(
            calculate_risk_score(&[finding("low", Severity::Low)])
                < calculate_risk_score(&[finding("medium", Severity::Medium)])
        );
        assert!(
            calculate_risk_score(&[finding("medium", Severity::Medium)])
                < calculate_risk_score(&[finding("high", Severity::High)])
        );
        assert!(
            calculate_risk_score(&[finding("high", Severity::High)])
                < calculate_risk_score(&[finding("critical", Severity::Critical)])
        );
    }

    #[test]
    fn repeated_findings_are_damped() {
        let one = vec![finding("same", Severity::Medium)];
        let five = (0..5)
            .map(|_| finding("same", Severity::Medium))
            .collect::<Vec<_>>();
        assert!(calculate_risk_score(&five) > calculate_risk_score(&one));
        assert!(calculate_risk_score(&five) < calculate_risk_score(&one) * 5);
        assert!(
            calculate_risk_score(
                &(0..100)
                    .map(|_| finding("same", Severity::Medium))
                    .collect::<Vec<_>>()
            ) < 100
        );
    }

    #[test]
    fn distinct_groups_outweigh_repetition_of_one_group() {
        let repeated = (0..5)
            .map(|_| finding("same", Severity::Medium))
            .collect::<Vec<_>>();
        let distinct = ["one", "two", "three", "four", "five"]
            .into_iter()
            .map(|rule| finding(rule, Severity::Medium))
            .collect::<Vec<_>>();
        assert!(calculate_risk_score(&distinct) > calculate_risk_score(&repeated));
    }

    #[test]
    fn mixed_severity_adds_to_the_score() {
        let critical = vec![finding("critical", Severity::Critical)];
        let mixed = vec![
            finding("critical", Severity::Critical),
            finding("high", Severity::High),
            finding("medium", Severity::Medium),
        ];
        assert!(calculate_risk_score(&mixed) > calculate_risk_score(&critical));
    }

    #[test]
    fn score_is_bounded_and_status_is_independent() {
        let findings = (0..100)
            .map(|_| finding("same", Severity::High))
            .collect::<Vec<_>>();
        assert_eq!(calculate_risk_score(&findings), 60);

        let low = AuditReport::new("warn", vec![finding("low", Severity::Low)], vec![]);
        let high = AuditReport::new("fail", vec![finding("high", Severity::High)], vec![]);
        assert_eq!(low.status, AuditStatus::Warn);
        assert_eq!(high.status, AuditStatus::Fail);
        assert_ne!(low.risk_score, high.risk_score);
    }

    #[test]
    fn adversarial_counts_remain_deterministic_and_safe() {
        let same_low = (0..100)
            .map(|_| finding("low", Severity::Low))
            .collect::<Vec<_>>();
        let same_medium = (0..100)
            .map(|_| finding("medium", Severity::Medium))
            .collect::<Vec<_>>();
        let same_high = (0..100)
            .map(|_| finding("high", Severity::High))
            .collect::<Vec<_>>();
        let distinct_low = (0..100)
            .map(|index| {
                finding(
                    Box::leak(format!("low-{index}").into_boxed_str()),
                    Severity::Low,
                )
            })
            .collect::<Vec<_>>();
        let distinct_medium = (0..10)
            .map(|index| {
                finding(
                    Box::leak(format!("medium-{index}").into_boxed_str()),
                    Severity::Medium,
                )
            })
            .collect::<Vec<_>>();
        let distinct_high = (0..5)
            .map(|index| {
                finding(
                    Box::leak(format!("high-{index}").into_boxed_str()),
                    Severity::High,
                )
            })
            .collect::<Vec<_>>();

        for findings in [
            &same_low,
            &same_medium,
            &same_high,
            &distinct_low,
            &distinct_medium,
            &distinct_high,
        ] {
            assert!(calculate_risk_score(findings) <= 100);
        }
        assert!(calculate_risk_score(&distinct_low) > calculate_risk_score(&same_low));
        assert!(calculate_risk_score(&distinct_medium) > calculate_risk_score(&same_medium));
        assert!(calculate_risk_score(&distinct_high) > calculate_risk_score(&same_high));
    }
}
