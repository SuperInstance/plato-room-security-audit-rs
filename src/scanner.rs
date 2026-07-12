//! Vulnerability pattern scanner for the PLATO Security Audit Room.
//!
//! Each check is a pure function that takes diff text and returns a
//! [`CheckResult`].  Checks are intentionally heuristic — no AST parsing,
//! no LLM — they catch the 80% of security issues that pattern matching
//! handles well.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// ─── CheckResult ────────────────────────────────────────────

/// Severity levels, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Severity {
    pub fn weight(self) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Error => 3,
            Severity::Critical => 4,
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Severity::Critical => "🔴",
            Severity::Error => "🟠",
            Severity::Warning => "🟡",
            Severity::Info => "🔵",
        }
    }
}

/// Result of a single security check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub severity: Severity,
    pub file_hints: Vec<String>,
    pub cwe: String,
}

impl CheckResult {
    /// Create a passing result.
    pub fn pass(check_id: &str, name: &str, message: &str) -> Self {
        Self {
            check_id: check_id.to_string(),
            name: name.to_string(),
            passed: true,
            message: message.to_string(),
            severity: Severity::Info,
            file_hints: Vec::new(),
            cwe: String::new(),
        }
    }

    /// Create a failing result.
    pub fn fail(
        check_id: &str,
        name: &str,
        message: &str,
        severity: Severity,
        file_hints: Vec<String>,
        cwe: &str,
    ) -> Self {
        Self {
            check_id: check_id.to_string(),
            name: name.to_string(),
            passed: false,
            message: message.to_string(),
            severity,
            file_hints,
            cwe: cwe.to_string(),
        }
    }
}

// ─── Pattern helpers ────────────────────────────────────────

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex")
}

// ─── Vulnerability patterns ─────────────────────────────────
// All patterns use r#"..."# to safely include both ' and " inside the regex.

fn sql_injection_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        re(r#"(?i)execute\s*\(\s*['\"].*\+.*['\"]\s*\)"#),
        re(r#"(?i)execute\s*\(\s*f['\"]"#),
        re(r"(?i)%\s*\(.*\)\s*.*execute"),
        re(r"(?i)cursor\.execute.*\+.*request"),
        re(r#"(?i)query\s*=\s*['\"].*select.*\+.*['\"]"#),
        re(r#"(?i)query\s*=\s*['\"].*insert.*\+.*['\"]"#),
        re(r#"(?i)query\s*=\s*['\"].*update.*\+.*['\"]"#),
        re(r#"(?i)query\s*=\s*['\"].*delete.*\+.*['\"]"#),
    ])
}

fn xss_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        re(r#"(?i)innerHTML\s*=\s*['\"]?\s*[{(]"#),
        re(r"(?i)innerHTML\s*=\s*.*\+"),
        re(r"(?i)document\.write\s*\("),
        re(r"(?i)eval\s*\(\s*.*request"),
        re(r"(?i)dangerouslySetInnerHTML"),
        re(r"(?i)\{\{.*\|.*safe\s*\}\}"),
        re(r"(?i)<script.*>.*\{.*\}"),
        re(r"(?i)outerHTML\s*="),
        re(r"(?i)insertAdjacentHTML\s*\("),
    ])
}

fn path_traversal_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)\.\./\.\./",
        r"(?i)\.\.\\\.\.\\",
        r"(?i)open\s*\(\s*.*request\.",
        r"(?i)open\s*\(\s*.*input\.",
        r"(?i)open\s*\(\s*.*\+",
        r"(?i)read_file\s*\(\s*.*request\.",
        r"(?i)os\.path\.join\s*\(\s*.*request\.",
        r"(?i)\.\./.*passwd",
        r"(?i)\.\./.*shadow",
        r"(?i)\.\./.*etc/",
    ].iter().map(|p| re(p)).collect())
}

fn command_injection_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)os\.system\s*\(.*\+",
        r"(?i)os\.system\s*\(.*request\.",
        r"(?i)os\.system\s*\(.*input",
        r#"(?i)os\.system\s*\(.*f['\"]"#,
        r"(?i)subprocess\..*shell\s*=\s*True",
        r"(?i)subprocess\.call\s*\(.*\+",
        r"(?i)subprocess\.run\s*\(.*\+",
        r"(?i)Popen\s*\(.*shell\s*=\s*True",
        r"(?i)commands\.getoutput\s*\(",
        r"(?i)popen\s*\(.*\+",
    ].iter().map(|p| re(p)).collect())
}

fn eval_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)\beval\s*\(\s*.*request\.",
        r"(?i)\beval\s*\(\s*.*input",
        r#"(?i)\beval\s*\(\s*[^'"]*\+"#,
        r"(?i)\bexec\s*\(\s*.*request\.",
        r"(?i)\bexec\s*\(\s*.*input",
        r"(?i)\bexec\s*\(\s*.*\+",
        r"(?i)\beval\s*\(\s*open\s*\(",
    ].iter().map(|p| re(p)).collect())
}

/// (pattern, label, cwe)
fn secret_patterns() -> &'static [(Regex, &'static str, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        (re(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "CWE-798"),
        (re(r#"(?i)aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]"#), "AWS Secret Key", "CWE-798"),
        (re(r#"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"][-A-Za-z0-9_/+=]{16,}['"]"#), "API Key / Token", "CWE-798"),
        (re(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key block", "CWE-321"),
        (re(r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"), "DB connection string with credentials", "CWE-798"),
        (re(r"xox[bpoa]-[0-9A-Za-z-]{10,48}"), "Slack token", "CWE-798"),
        (re(r"gh[pousr]_[A-Za-z0-9]{36,255}"), "GitHub token", "CWE-798"),
        (re(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT token", "CWE-798"),
        (re(r#"(?i)password\s*[:=]\s*['"][^\s'"]{6,}['"]"#), "Hardcoded password", "CWE-259"),
        (re(r#"(?i)secret\s*[:=]\s*['"][^\s'"]{6,}['"]"#), "Hardcoded secret", "CWE-798"),
    ])
}

fn insecure_crypto_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)hashlib\.md5\s*\(",
        r"(?i)hashlib\.sha1\s*\(",
        r"(?i)\bDES\b.*encrypt",
        r"(?i)\bECB\b.*mode",
        r"(?i)Cipher.*DES",
        r"(?i)random\.random\s*\(\s*\).*token",
        r"(?i)\brandom\b.*password",
        r"(?i)\brandom\b.*secret",
        r"(?i)\brandom\b.*key",
    ].iter().map(|p| re(p)).collect())
}

fn insecure_random_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)\brandom\.random\b",
        r"(?i)\brandom\.randint\b",
        r"(?i)\brandom\.choice\b",
        r"(?i)Math\.random",
    ].iter().map(|p| re(p)).collect())
}

fn debug_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)DEBUG\s*=\s*True",
        r"(?i)app\.debug\s*=\s*True",
        r"(?i)app\.run\s*\(.*debug\s*=\s*True",
    ].iter().map(|p| re(p)).collect())
}

fn http_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        re(r#"(?i)http://[^\s'"]+"#),
    ])
}

/// Check if an HTTP URL is to a local/example host that's safe.
fn is_safe_http_host(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://0.0.0.0")
        || lower.starts_with("http://example.com")
}

fn disabled_security_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)#\s*noqa.*security",
        r"(?i)#\s*type:\s*ignore",
        r"(?i)@SuppressWarnings",
        r"(?i)#\s*pylint:\s*disable=.*security",
        r"(?i)#\s*bandit:\s*disable",
        r"(?i)#\s*nosec",
        r"(?i)#\s*nosecB\d+",
    ].iter().map(|p| re(p)).collect())
}

fn weak_hash_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        r"(?i)hashlib\.md5\s*\(.*password",
        r"(?i)hashlib\.sha1\s*\(.*password",
        r"(?i)\.crypt\s*\(",
        r"(?i)crypt\.crypt\s*\(",
    ].iter().map(|p| re(p)).collect())
}

const SENSITIVE_FILES: &[&str] = &[
    ".env", "secrets", "id_rsa", "id_ed25519", ".pem", ".key",
    ".crt", ".p12", ".pfx", "credentials", "password", "token",
    ".htpasswd", "shadow", "sudoers",
];

// ─── Diff parsing helpers ───────────────────────────────────

/// Extract the filename from a `diff --git` line.
fn get_current_file(line: &str, current: &str) -> String {
    if line.starts_with("diff --git") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            return parts.last().unwrap().trim_start_matches('b').trim_start_matches('/').to_string();
        }
    }
    current.to_string()
}

/// Iterate over added lines in a diff, calling `f` with (content, current_file).
fn for_added_lines<F>(diff: &str, mut f: F)
where
    F: FnMut(&str, &str),
{
    let mut current_file = String::new();
    for line in diff.lines() {
        current_file = get_current_file(line, &current_file);
        if line.starts_with('+') && !line.starts_with("+++") {
            let content = &line[1..];
            f(content, &current_file);
        }
    }
}

/// Check if any pattern matches the content and collect file hints.
fn scan_added_lines(diff: &str, patterns: &[Regex]) -> Vec<String> {
    let mut findings = Vec::new();
    for_added_lines(diff, |content, file| {
        for p in patterns {
            if p.is_match(content) {
                findings.push(file.to_string());
                break;
            }
        }
    });
    findings
}

// ─── Individual checks ──────────────────────────────────────

/// Detect SQL injection vulnerabilities (CWE-89).
pub fn check_sql_injection(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, sql_injection_patterns());
    if findings.is_empty() {
        return CheckResult::pass("sql_injection", "SQL Injection", "No SQL injection patterns detected.");
    }
    CheckResult::fail(
        "sql_injection",
        "SQL Injection",
        &format!("{} SQL injection pattern(s) detected. Use parameterized queries instead of string concatenation.", findings.len()),
        Severity::Critical,
        dedup_hints(&findings),
        "CWE-89",
    )
}

/// Detect Cross-Site Scripting (XSS) vulnerabilities (CWE-79).
pub fn check_xss(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, xss_patterns());
    if findings.is_empty() {
        return CheckResult::pass("xss", "Cross-Site Scripting (XSS)", "No XSS patterns detected.");
    }
    CheckResult::fail(
        "xss",
        "Cross-Site Scripting (XSS)",
        &format!("{} XSS pattern(s) detected. Sanitize/escape user input before rendering.", findings.len()),
        Severity::Critical,
        dedup_hints(&findings),
        "CWE-79",
    )
}

/// Detect path traversal vulnerabilities (CWE-22).
pub fn check_path_traversal(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, path_traversal_patterns());
    if findings.is_empty() {
        return CheckResult::pass("path_traversal", "Path Traversal", "No path traversal patterns detected.");
    }
    CheckResult::fail(
        "path_traversal",
        "Path Traversal",
        &format!("{} path traversal pattern(s) detected. Validate and sanitize file paths.", findings.len()),
        Severity::Critical,
        dedup_hints(&findings),
        "CWE-22",
    )
}

/// Detect hardcoded secrets and credentials (CWE-798).
pub fn check_hardcoded_secrets(diff: &str) -> CheckResult {
    let mut files = Vec::new();
    let mut labels = Vec::new();
    for_added_lines(diff, |content, file| {
        for (pattern, label, _cwe) in secret_patterns() {
            if pattern.is_match(content) {
                files.push(file.to_string());
                labels.push(*label);
            }
        }
    });
    if files.is_empty() {
        return CheckResult::pass("hardcoded_secrets", "Hardcoded Secrets", "No secret-like patterns detected.");
    }
    let unique_labels: Vec<&str> = {
        let mut seen = std::collections::HashSet::new();
        labels.iter().copied().filter(|l| seen.insert(*l)).collect()
    };
    CheckResult::fail(
        "hardcoded_secrets",
        "Hardcoded Secrets",
        &format!("Potential secrets detected ({}). Use environment variables or a secrets manager.", unique_labels.join(", ")),
        Severity::Critical,
        dedup_hints(&files),
        "CWE-798",
    )
}

/// Detect command injection vulnerabilities (CWE-78).
pub fn check_command_injection(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, command_injection_patterns());
    if findings.is_empty() {
        return CheckResult::pass("command_injection", "Command Injection", "No command injection patterns detected.");
    }
    CheckResult::fail(
        "command_injection",
        "Command Injection",
        &format!("{} command injection pattern(s) detected. Avoid os.system/shell=True with user input.", findings.len()),
        Severity::Critical,
        dedup_hints(&findings),
        "CWE-78",
    )
}

/// Detect critical eval()/exec() usage with user input (CWE-95).
pub fn check_critical_eval(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, eval_patterns());
    if findings.is_empty() {
        return CheckResult::pass("critical_eval", "Critical eval()/exec() Usage", "No dangerous eval/exec patterns detected.");
    }
    CheckResult::fail(
        "critical_eval",
        "Critical eval()/exec() Usage",
        &format!("{} dangerous eval/exec pattern(s) detected. eval() and exec() with user input enable arbitrary code execution.", findings.len()),
        Severity::Critical,
        dedup_hints(&findings),
        "CWE-95",
    )
}

/// Detect insecure random in security contexts (CWE-330).
pub fn check_insecure_random(diff: &str) -> CheckResult {
    let mut findings = Vec::new();
    for_added_lines(diff, |content, file| {
        let lower = content.to_lowercase();
        let is_security_context = [
            "token", "password", "secret", "key", "session",
            "csrf", "auth", "nonce", "salt",
        ].iter().any(|kw| lower.contains(kw));
        if is_security_context && insecure_random_patterns().iter().any(|p| p.is_match(content)) {
            findings.push(file.to_string());
        }
    });
    if findings.is_empty() {
        return CheckResult::pass("insecure_random", "Insecure Random Number Generator", "No insecure random usage in security contexts.");
    }
    CheckResult::fail(
        "insecure_random",
        "Insecure Random Number Generator",
        &format!("{} insecure random usage in security context. Use `secrets` module or `os.urandom()`.", findings.len()),
        Severity::Error,
        dedup_hints(&findings),
        "CWE-330",
    )
}

/// Detect insecure crypto (CWE-327).
pub fn check_insecure_crypto(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, insecure_crypto_patterns());
    if findings.is_empty() {
        return CheckResult::pass("insecure_crypto", "Insecure Cryptography", "No insecure crypto patterns detected.");
    }
    CheckResult::fail(
        "insecure_crypto",
        "Insecure Cryptography",
        &format!("{} insecure crypto pattern(s) detected. Use SHA-256+, AES-GCM, and `secrets` for security-sensitive operations.", findings.len()),
        Severity::Error,
        dedup_hints(&findings),
        "CWE-327",
    )
}

/// Detect DEBUG=True in settings (CWE-489).
pub fn check_debug_enabled(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, debug_patterns());
    if findings.is_empty() {
        return CheckResult::pass("debug_enabled", "Debug Mode Enabled", "No debug mode patterns detected.");
    }
    CheckResult::fail(
        "debug_enabled",
        "Debug Mode Enabled",
        &format!("{} DEBUG=True pattern(s) detected. Disable debug in production.", findings.len()),
        Severity::Warning,
        dedup_hints(&findings),
        "CWE-489",
    )
}

/// Detect HTTP URLs that should use HTTPS (CWE-319).
pub fn check_http_not_https(diff: &str) -> CheckResult {
    let mut findings = Vec::new();
    for_added_lines(diff, |content, file| {
        let stripped = content.trim();
        if stripped.starts_with('#') || stripped.starts_with("//") {
            return;
        }
        for p in http_patterns() {
            for m in p.find_iter(content) {
                let url = m.as_str();
                if !is_safe_http_host(url) {
                    findings.push(file.to_string());
                }
            }
        }
    });
    if findings.is_empty() {
        return CheckResult::pass("http_not_https", "HTTP Instead of HTTPS", "No insecure HTTP URLs detected.");
    }
    CheckResult::fail(
        "http_not_https",
        "HTTP Instead of HTTPS",
        &format!("{} insecure HTTP URL(s) detected. Use HTTPS for production endpoints.", findings.len()),
        Severity::Warning,
        dedup_hints(&findings),
        "CWE-319",
    )
}

/// Detect disabled security controls (CWE-693).
pub fn check_disabled_security(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, disabled_security_patterns());
    if findings.is_empty() {
        return CheckResult::pass("disabled_security", "Disabled Security Controls", "No security control suppressions detected.");
    }
    CheckResult::fail(
        "disabled_security",
        "Disabled Security Controls",
        &format!("{} security control suppression(s) detected. Review whether suppression is justified.", findings.len()),
        Severity::Warning,
        dedup_hints(&findings),
        "CWE-693",
    )
}

/// Detect sensitive file exposure (CWE-200).
pub fn check_sensitive_file_exposure(diff: &str) -> CheckResult {
    let mut touched = Vec::new();
    for line in diff.lines() {
        if line.starts_with("diff --git") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let raw = parts.last().unwrap();
                let fname = raw.trim_start_matches('b').trim_start_matches('/').to_lowercase();
                for sensitive in SENSITIVE_FILES {
                    if fname.contains(sensitive) {
                        touched.push(raw.trim_start_matches('b').trim_start_matches('/').to_string());
                        break;
                    }
                }
            }
        }
    }
    if touched.is_empty() {
        return CheckResult::pass("sensitive_file_exposure", "Sensitive File Exposure", "No sensitive files in diff.");
    }
    CheckResult::fail(
        "sensitive_file_exposure",
        "Sensitive File Exposure",
        &format!("Sensitive file(s) modified: {}. Ensure no secrets are committed.", touched.join(", ")),
        Severity::Error,
        dedup_hints(&touched),
        "CWE-200",
    )
}

/// Detect weak password hashing (CWE-916).
pub fn check_weak_password_hash(diff: &str) -> CheckResult {
    let findings = scan_added_lines(diff, weak_hash_patterns());
    if findings.is_empty() {
        return CheckResult::pass("weak_password_hash", "Weak Password Hashing", "No weak password hashing detected.");
    }
    CheckResult::fail(
        "weak_password_hash",
        "Weak Password Hashing",
        &format!("{} weak hash pattern(s) for passwords. Use bcrypt, scrypt, or Argon2.", findings.len()),
        Severity::Error,
        dedup_hints(&findings),
        "CWE-916",
    )
}

// ─── Dedup helper ───────────────────────────────────────────

fn dedup_hints(hints: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    hints.iter().map(|h| h.clone()).filter(|h| seen.insert(h.clone())).take(5).collect()
}

// ─── Orchestration ──────────────────────────────────────────

/// Run all registered security checks and return results.
pub fn run_all_checks(diff: &str) -> Vec<CheckResult> {
    vec![
        check_sql_injection(diff),
        check_xss(diff),
        check_path_traversal(diff),
        check_hardcoded_secrets(diff),
        check_command_injection(diff),
        check_critical_eval(diff),
        check_insecure_random(diff),
        check_insecure_crypto(diff),
        check_debug_enabled(diff),
        check_http_not_https(diff),
        check_disabled_security(diff),
        check_sensitive_file_exposure(diff),
        check_weak_password_hash(diff),
    ]
}

/// Run a single check by ID. Returns `None` if the check_id is unknown.
pub fn run_check(check_id: &str, diff: &str) -> Option<CheckResult> {
    run_all_checks(diff).into_iter().find(|r| r.check_id == check_id)
}
