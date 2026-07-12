//! Security audit report generator.
//!
//! Takes a slice of [`CheckResult`] and produces a structured Markdown report
//! or a one-line summary.  Also supports JSON output.

use crate::scanner::{CheckResult, Severity};
use serde::Serialize;

// ─── Recommendation ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    Approve,
    BlockMerge,
    RequestChanges,
    Comment,
}

impl Recommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Recommendation::Approve => "APPROVE",
            Recommendation::BlockMerge => "BLOCK_MERGE",
            Recommendation::RequestChanges => "REQUEST_CHANGES",
            Recommendation::Comment => "COMMENT",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Recommendation::Approve => "✅",
            Recommendation::BlockMerge => "🚫",
            Recommendation::RequestChanges => "⚠️",
            Recommendation::Comment => "💬",
        }
    }
}

impl std::fmt::Display for Recommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

fn recommendation(results: &[CheckResult]) -> Recommendation {
    let failing: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();
    if failing.is_empty() {
        return Recommendation::Approve;
    }
    if failing.iter().any(|r| r.severity == Severity::Critical) {
        return Recommendation::BlockMerge;
    }
    if failing.iter().any(|r| r.severity == Severity::Error) {
        return Recommendation::RequestChanges;
    }
    Recommendation::Comment
}

// ─── Risk level ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::None => "NONE",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    pub fn badge(self) -> &'static str {
        match self {
            RiskLevel::Critical => "🔴 **CRITICAL**",
            RiskLevel::High => "🟠 **HIGH**",
            RiskLevel::Medium => "🟡 **MEDIUM**",
            RiskLevel::Low => "🔵 **LOW**",
            RiskLevel::None => "🟢 **NONE**",
        }
    }
}

fn risk_level(results: &[CheckResult]) -> RiskLevel {
    let failing: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();
    if failing.is_empty() {
        return RiskLevel::None;
    }
    if failing.iter().any(|r| r.severity == Severity::Critical) {
        return RiskLevel::Critical;
    }
    if failing.iter().any(|r| r.severity == Severity::Error) {
        return RiskLevel::High;
    }
    if failing.iter().any(|r| r.severity == Severity::Warning) {
        return RiskLevel::Medium;
    }
    RiskLevel::Low
}

// ─── Icon helper ────────────────────────────────────────────

fn icon_for(result: &CheckResult) -> &'static str {
    if result.passed {
        "✅"
    } else {
        result.severity.icon()
    }
}

// ─── Markdown report ────────────────────────────────────────

/// Generate a full Markdown security audit report.
///
/// # Arguments
/// * `results` - Slice of `CheckResult` from `run_all_checks`.
/// * `repo` - Repository name (e.g. `"owner/repo"`).
/// * `pr_number` - PR number for the header.
/// * `author` - PR author for the header.
pub fn generate_report(
    results: &[CheckResult],
    repo: Option<&str>,
    pr_number: Option<u32>,
    author: Option<&str>,
) -> String {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    let rec = recommendation(results);
    let risk = risk_level(results);

    let mut lines: Vec<String> = Vec::new();

    // ── Header ──────────────────────────────────────────────
    lines.push("## 🔒 PLATO Security Audit Report\n".to_string());

    if repo.is_some() || pr_number.is_some() || author.is_some() {
        let mut header_parts = Vec::new();
        if let Some(r) = repo {
            header_parts.push(format!("**Repo:** `{r}`"));
        }
        if let Some(n) = pr_number {
            header_parts.push(format!("**PR:** #{n}"));
        }
        if let Some(a) = author {
            header_parts.push(format!("**Author:** @{a}"));
        }
        lines.push(header_parts.join(" | "));
        lines.push(String::new());
    }

    // ── Risk badge ───────────────────────────────────────────
    lines.push(format!("**Risk Level:** {}\n", risk.badge()));

    // ── Summary ─────────────────────────────────────────────
    lines.push("### Summary\n".to_string());
    lines.push("| Metric | Value |".to_string());
    lines.push("|--------|-------|".to_string());
    lines.push(format!("| Checks Run | {total} |"));
    lines.push(format!("| Passed | {passed} ✅ |"));
    lines.push(format!("| Failed | {failed} ❌ |"));
    lines.push(format!("| Risk Level | {} |", risk.as_str()));
    lines.push(format!(
        "| Recommendation | {} **{}** |",
        rec.icon(),
        rec.as_str()
    ));
    lines.push(String::new());

    // ── Findings by severity ─────────────────────────────────
    let failing: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();
    if !failing.is_empty() {
        lines.push("### Findings by Severity\n".to_string());

        for &severity in &[Severity::Critical, Severity::Error, Severity::Warning, Severity::Info] {
            let sev_findings: Vec<&&CheckResult> =
                failing.iter().filter(|r| r.severity == severity).collect();
            if !sev_findings.is_empty() {
                let icon = severity.icon();
                lines.push(format!("#### {icon} {}\n", severity.to_string().to_uppercase()));
                for r in &sev_findings {
                    let cwe_str = if r.cwe.is_empty() {
                        String::new()
                    } else {
                        format!(" `{}`", r.cwe)
                    };
                    lines.push(format!("- **{}**{cwe_str}: {}", r.name, r.message));
                    if !r.file_hints.is_empty() {
                        let hint_list: Vec<String> =
                            r.file_hints.iter().map(|h| format!("`{h}`")).collect();
                        lines.push(format!("  - Files: {}", hint_list.join(", ")));
                    }
                }
                lines.push(String::new());
            }
        }
    }

    // ── Detailed Results ────────────────────────────────────
    lines.push("### Detailed Results\n".to_string());

    let mut sorted: Vec<&CheckResult> = results.iter().collect();
    sorted.sort_by(|a, b| {
        // Failing first, then by severity weight (descending)
        match (a.passed, b.passed) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            _ => b.severity.weight().cmp(&a.severity.weight()),
        }
    });

    for r in &sorted {
        let icon = icon_for(r);
        lines.push(format!("#### {icon} {}\n", r.name));
        lines.push(format!("- **Check ID:** `{}`", r.check_id));
        lines.push(format!(
            "- **Status:** {}",
            if r.passed { "PASSED" } else { "FAILED" }
        ));
        lines.push(format!("- **Severity:** `{}`", r.severity));
        if !r.cwe.is_empty() {
            lines.push(format!("- **CWE:** `{}`", r.cwe));
        }
        lines.push(format!("- **Message:** {}", r.message));
        if !r.file_hints.is_empty() {
            let hint_list: Vec<String> =
                r.file_hints.iter().map(|h| format!("`{h}`")).collect();
            lines.push(format!("- **Files:** {}", hint_list.join(", ")));
        }
        lines.push(String::new());
    }

    // ── Footer ──────────────────────────────────────────────
    lines.push("---".to_string());
    lines.push(
        "_Generated by [PLATO Security Audit Room (Rust)](https://github.com/SuperInstance/plato-room-security-audit-rs)_"
            .to_string(),
    );

    lines.join("\n")
}

/// Generate a one-line summary suitable for PR status checks.
///
/// Example: `"PLATO Security: 10/12 checks passed — BLOCK_MERGE"`
pub fn generate_short_summary(results: &[CheckResult]) -> String {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let rec = recommendation(results);
    format!("PLATO Security: {passed}/{total} checks passed — {rec}")
}

// ─── JSON report ────────────────────────────────────────────

/// JSON-serializable report structure.
#[derive(Debug, Serialize)]
pub struct JsonReport {
    pub summary: JsonSummary,
    pub findings: Vec<JsonFinding>,
    pub checks: Vec<JsonCheck>,
}

#[derive(Debug, Serialize)]
pub struct JsonSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub risk_level: String,
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct JsonFinding {
    pub check_id: String,
    pub name: String,
    pub severity: String,
    pub message: String,
    pub cwe: String,
    pub file_hints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonCheck {
    pub check_id: String,
    pub name: String,
    pub passed: bool,
    pub severity: String,
    pub message: String,
    pub cwe: String,
    pub file_hints: Vec<String>,
}

/// Generate a JSON security report.
///
/// # Arguments
/// * `results` - Slice of `CheckResult` from `run_all_checks`.
/// * `repo` - Repository name.
/// * `pr_number` - PR number.
/// * `author` - PR author.
pub fn generate_json_report(
    results: &[CheckResult],
    repo: Option<&str>,
    pr_number: Option<u32>,
    author: Option<&str>,
) -> String {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    let rec = recommendation(results);
    let risk = risk_level(results);

    let failing: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();

    let findings: Vec<JsonFinding> = failing
        .iter()
        .map(|r| JsonFinding {
            check_id: r.check_id.clone(),
            name: r.name.clone(),
            severity: r.severity.to_string(),
            message: r.message.clone(),
            cwe: r.cwe.clone(),
            file_hints: r.file_hints.clone(),
        })
        .collect();

    let checks: Vec<JsonCheck> = results
        .iter()
        .map(|r| JsonCheck {
            check_id: r.check_id.clone(),
            name: r.name.clone(),
            passed: r.passed,
            severity: r.severity.to_string(),
            message: r.message.clone(),
            cwe: r.cwe.clone(),
            file_hints: r.file_hints.clone(),
        })
        .collect();

    let mut json = serde_json::json!({
        "summary": JsonSummary {
            total,
            passed,
            failed,
            risk_level: risk.as_str().to_string(),
            recommendation: rec.as_str().to_string(),
        },
        "findings": findings,
        "checks": checks,
    });

    if let Some(r) = repo {
        json["repo"] = serde_json::Value::String(r.to_string());
    }
    if let Some(n) = pr_number {
        json["pr_number"] = serde_json::Value::Number(n.into());
    }
    if let Some(a) = author {
        json["author"] = serde_json::Value::String(a.to_string());
    }

    serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
}
