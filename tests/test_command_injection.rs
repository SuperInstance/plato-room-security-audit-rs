mod common;

use si_security_audit_room::scanner::*;

#[test]
fn test_cmd_injection_detects_os_system_concat() {
    let result = check_command_injection(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
    assert_eq!(result.cwe, "CWE-78");
}

#[test]
fn test_cmd_injection_clean_ok() {
    let result = check_command_injection(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_cmd_injection_detects_shell_true() {
    let diff = "+subprocess.run(cmd, shell=True)\n";
    let result = check_command_injection(diff);
    assert!(!result.passed);
}

#[test]
fn test_cmd_injection_detects_popen_shell_true() {
    let diff = "+p = Popen(cmd, shell=True)\n";
    let result = check_command_injection(diff);
    assert!(!result.passed);
}

#[test]
fn test_eval_detects_input() {
    let result = check_critical_eval(common::VULNERABLE_DIFF);
    assert!(!result.passed);
    assert_eq!(result.severity, Severity::Critical);
    assert_eq!(result.cwe, "CWE-95");
}

#[test]
fn test_eval_clean_ok() {
    let result = check_critical_eval(common::CLEAN_DIFF);
    assert!(result.passed);
}

#[test]
fn test_eval_alone_is_ok() {
    let diff = "+result = eval('1 + 1')\n";
    let result = check_critical_eval(diff);
    assert!(result.passed);
}

#[test]
fn test_exec_detects_input() {
    let diff = "+exec(user_input)\n";
    let result = check_critical_eval(diff);
    assert!(!result.passed);
}
