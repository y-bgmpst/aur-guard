use std::fmt;

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
    pub fn score(self) -> u16 {
        match self {
            Self::Info => 1,
            Self::Low => 5,
            Self::Medium => 15,
            Self::High => 30,
            Self::Critical => 50,
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

        let risk_score = findings
            .iter()
            .map(|finding| finding.severity.score())
            .sum::<u16>()
            .min(100);

        let status = if findings
            .iter()
            .any(|finding| finding.severity >= Severity::High)
        {
            AuditStatus::Fail
        } else if findings
            .iter()
            .any(|finding| finding.severity >= Severity::Low)
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
        let _ = plain;
        out.push_str("aur-guard audit report\n");
        out.push_str(&format!("target: {}\n", self.target));
        out.push_str(&format!("status: {}\n", self.status));
        out.push_str(&format!("risk_score: {}/100\n", self.risk_score));
        out.push('\n');

        if self.findings.is_empty() {
            out.push_str("No high-risk findings detected by deterministic checks.\n");
        } else {
            out.push_str("Findings:\n");
            for finding in &self.findings {
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
        }

        if !self.skipped.is_empty() {
            out.push_str("\nSkipped files:\n");
            for skipped in &self.skipped {
                out.push_str(&format!("  {}: {}\n", skipped.file, skipped.reason));
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
}
