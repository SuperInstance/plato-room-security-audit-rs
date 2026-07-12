mod common;

use si_security_audit_room::scanner::*;

#[test]
fn test_path_traversal_detects_dot_dot() {
    let result = check_path_traversal(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
    assert_eq!(result.cwe, "CWE-22");
}

#[test]
fn test_path_traversal_clean_ok() {
    let result = check_path_traversal(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_path_traversal_detects_etc_passwd() {
    let diff = "+data = open(\"../../etc/passwd\").read()\n";
    let result = check_path_traversal(diff);
    assert!(!result.passed);
}

#[test]
fn test_path_traversal_detects_etc_shadow() {
    let diff = "+f = open(\"../../etc/shadow\")\n";
    let result = check_path_traversal(diff);
    assert!(!result.passed);
}
