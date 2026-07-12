mod common;

use si_security_audit_room::scanner::*;

#[test]
fn test_secrets_detects_api_key() {
    let result = check_hardcoded_secrets(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
}

#[test]
fn test_secrets_clean_ok() {
    let result = check_hardcoded_secrets(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_secrets_detects_aws_key() {
    let diff = "+key = 'AKIAIOSFODNN7EXAMPLE'\n";
    let result = check_hardcoded_secrets(diff);
    assert!(!result.passed);
}

#[test]
fn test_secrets_detects_private_key() {
    let diff = "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA...\n";
    let result = check_hardcoded_secrets(diff);
    assert!(!result.passed);
}

#[test]
fn test_secrets_detects_github_token() {
    let diff = "+token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz1234'\n";
    let result = check_hardcoded_secrets(diff);
    assert!(!result.passed);
}

#[test]
fn test_secrets_detects_jwt() {
    let diff = "+jwt = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"\n";
    let result = check_hardcoded_secrets(diff);
    assert!(!result.passed);
}
