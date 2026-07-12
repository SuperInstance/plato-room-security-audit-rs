mod common;

use si_security_audit_room::scanner::*;

#[test]
fn test_xss_detects_innerhtml() {
    let result = check_xss(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
    assert_eq!(result.cwe, "CWE-79");
}

#[test]
fn test_xss_clean_ok() {
    let result = check_xss(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_xss_detects_dangerously_set_inner_html() {
    let diff = "+<div dangerouslySetInnerHTML={{__html: rawHtml}} />\n";
    let result = check_xss(diff);
    assert!(!result.passed);
}

#[test]
fn test_xss_detects_document_write() {
    let diff = "+document.write(userInput);\n";
    let result = check_xss(diff);
    assert!(!result.passed);
}

#[test]
fn test_xss_detects_insert_adjacent_html() {
    let diff = "+el.insertAdjacentHTML('beforeend', userData);\n";
    let result = check_xss(diff);
    assert!(!result.passed);
}
