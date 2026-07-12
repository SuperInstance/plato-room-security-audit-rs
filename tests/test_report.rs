mod common;

use si_security_audit_room::scanner::*;
use si_security_audit_room::report::*;

// ─── Report generation tests ────────────────────────────────

#[test]
fn test_report_returns_string() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(!report.is_empty());
}

#[test]
fn test_report_contains_header() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("PLATO Security Audit Report"));
}

#[test]
fn test_report_contains_summary() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("Summary"));
    assert!(report.contains("Checks Run"));
}

#[test]
fn test_report_risk_critical_on_vulnerable() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("Risk Level"));
    assert!(report.contains("CRITICAL"));
}

#[test]
fn test_report_risk_none_on_clean() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("NONE"));
}

#[test]
fn test_report_block_merge_on_critical() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("BLOCK_MERGE"));
}

#[test]
fn test_report_approve_on_clean() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("APPROVE"));
}

#[test]
fn test_report_contains_cwe() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("CWE-89"));
    assert!(report.contains("CWE-798"));
}

#[test]
fn test_report_contains_file_hints() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("app/auth.py"));
}

#[test]
fn test_report_includes_repo_and_pr_info() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, Some("owner/repo"), Some(42), Some("alice"));
    assert!(report.contains("owner/repo"));
    assert!(report.contains("#42"));
    assert!(report.contains("@alice"));
}

#[test]
fn test_report_empty_results_dont_crash() {
    let report = generate_report(&[], None, None, None);
    assert!(!report.is_empty());
}

#[test]
fn test_report_failing_sorted_before_passing() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let report = generate_report(&results, None, None, None);
    let pos_sql = report.find("SQL Injection").unwrap_or(usize::MAX);
    let pos_random = report.find("Insecure Random").unwrap_or(0);
    // SQL Injection (failing) should appear before Insecure Random (passing)
    assert!(pos_sql < pos_random);
}

#[test]
fn test_report_contains_footer() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let report = generate_report(&results, None, None, None);
    assert!(report.contains("PLATO Security Audit Room"));
    assert!(report.contains("SuperInstance"));
}

// ─── Short summary tests ────────────────────────────────────

#[test]
fn test_summary_all_passed() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let summary = generate_short_summary(&results);
    assert!(summary.contains("APPROVE"));
}

#[test]
fn test_summary_with_critical() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let summary = generate_short_summary(&results);
    assert!(summary.contains("BLOCK_MERGE"));
}

#[test]
fn test_summary_empty_results() {
    let summary = generate_short_summary(&[]);
    assert!(summary.contains("0/0"));
}

// ─── JSON report tests ──────────────────────────────────────

#[test]
fn test_json_report_valid() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let json_str = generate_json_report(&results, Some("owner/repo"), Some(42), Some("alice"));
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("invalid JSON");
    assert_eq!(parsed["summary"]["recommendation"], "BLOCK_MERGE");
    assert_eq!(parsed["repo"], "owner/repo");
}

#[test]
fn test_json_report_has_findings() {
    let results = run_all_checks(common::VULNERABLE_DIFF);
    let json_str = generate_json_report(&results, None, None, None);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
}

#[test]
fn test_json_report_clean_no_findings() {
    let results = run_all_checks(common::CLEAN_DIFF);
    let json_str = generate_json_report(&results, None, None, None);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.is_empty());
}
