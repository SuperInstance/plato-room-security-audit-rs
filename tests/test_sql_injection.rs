mod common;

use si_security_audit_room::scanner::*;

#[test]
fn test_sql_injection_detects_string_concat() {
    let result = check_sql_injection(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
    assert_eq!(result.cwe, "CWE-89");
}

#[test]
fn test_sql_injection_clean_ok() {
    let result = check_sql_injection(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_sql_injection_empty_ok() {
    let result = check_sql_injection(common::EMPTY_DIFF);
    assert!(result.passed);
}

#[test]
fn test_sql_injection_detects_fstring_query() {
    let diff = "+cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n";
    let result = check_sql_injection(diff);
    assert!(!result.passed);
}

#[test]
fn test_sql_injection_detects_insert_concat() {
    let diff = "+query = \"INSERT INTO users VALUES(\" + data + \")\"\n";
    let result = check_sql_injection(diff);
    assert!(!result.passed);
}
