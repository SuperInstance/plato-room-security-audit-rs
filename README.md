# 🔒 PLATO Security Audit Room (Rust)

![Crates.io](https://img.shields.io/crates/v/si-security-audit-room)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![Tests](https://img.shields.io/badge/tests-64%2B-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> Automated security auditing as a **PLATO engine block** — heuristic vulnerability scanning of code diffs, packaged as a Room with sensors, actuators, and alarms.

A Rust implementation of the PLATO Security Audit Room. Scans code diffs for 13 vulnerability classes using fast, deterministic, pattern-based heuristics. No LLM, no AST parsing, no network calls required. Includes a full PLATO room protocol implementation with JSON wire format.

Rust port of the [Python plato-room-security-audit](https://github.com/SuperInstance/plato-room-security-audit).

---

## Philosophy

Part of [Working Animal Architecture](https://github.com/SuperInstance/AI-Writings), where **γ + η = C** (genome + nurture = capability). The security audit room is the **guard dog** — a working animal that patrols the fence. It doesn't need to understand the whole codebase; it just needs to recognize the patterns of intrusion. Fast, tireless, and consistent.

> *The guard dog doesn't need to be smart. It needs to be awake.*

## What Is This?

A Rust library that combines:

- **Heuristic security scanner** — SQL injection, XSS, path traversal, hardcoded secrets, command injection, and 8 more
- **PLATO room protocol** — sensors, alarms, actuators, tick loop, and JSON wire protocol
- **Report generation** — Markdown and JSON security audit reports with severity ratings (CWE-mapped)
- **Zero external services** — No LLM, no AST parsing, no network calls required

## Installation

```bash
cargo add si-security-audit-room
```

Or in `Cargo.toml`:

```toml
[dependencies]
si-security-audit-room = "0.1"
```

## Quick Start

### Scan a diff

```rust
use si_security_audit_room::scanner::run_all_checks;
use si_security_audit_room::report::generate_report;

let diff = r#"
diff --git a/app.py b/app.py
+++ b/app.py
+query = "SELECT * FROM users WHERE id='" + user_input + "'"
+cursor.execute(query)
"#;

let results = run_all_checks(diff);
let report = generate_report(&results, Some("owner/repo"), Some(42), Some("alice"));
println!("{report}");
```

### Use the PLATO room protocol

```rust
use si_security_audit_room::SecurityAuditRoom;

let mut room = SecurityAuditRoom::new(diff, "0.0.0.0", 1235);

// Process a tick — sensors read, alarms evaluate
let sensor_data = room.tick();

// Handle protocol commands
let response = room.handle_command("alarm list");
println!("{response}");

// Check triggered alarms
room.process_alarms();
```

### Generate a JSON report

```rust
use si_security_audit_room::{run_all_checks, generate_json_report};

let results = run_all_checks(diff);
let json = generate_json_report(&results, Some("owner/repo"), Some(42), None);
```

## Security Checks

All checks are **heuristic** (pattern-based) — fast, deterministic, and auditable. No false negatives from AST parsing failures, no API rate limits.

| Check | What It Catches | Severity | CWE |
|-------|----------------|----------|-----|
| `sql_injection` | String concatenation in SQL execute() calls, f-string queries | **critical** | CWE-89 |
| `xss` | Unescaped output in templates, `innerHTML` with variables | **critical** | CWE-79 |
| `path_traversal` | `../` patterns in file paths, unsanitized `open()` calls | **critical** | CWE-22 |
| `hardcoded_secrets` | AWS keys, API keys, private keys, JWTs, Slack tokens, DB URLs | **critical** | CWE-798 |
| `command_injection` | `os.system()`, `subprocess` with `shell=True`, `eval()` with user input | **critical** | CWE-78 |
| `critical_eval` | `eval()`/`exec()` with user input | **critical** | CWE-95 |
| `insecure_random` | `random` module for security-sensitive contexts | error | CWE-330 |
| `insecure_crypto` | MD5, SHA1, DES, ECB mode for crypto operations | error | CWE-327 |
| `debug_enabled` | `DEBUG = True` in settings files | warning | CWE-489 |
| `http_not_https` | HTTP (not HTTPS) URLs in source code | warning | CWE-319 |
| `disabled_security` | Comments disabling security checks, `# noqa`, `@SuppressWarnings` | warning | CWE-693 |
| `sensitive_file_exposure` | Changes to `.env`, secrets files, key files | error | CWE-200 |
| `weak_password_hash` | `hashlib.md5`/`sha1` for password hashing | error | CWE-916 |

### Severity Levels

| Level | Meaning |
|-------|---------|
| **critical** | Exploitable vulnerability — block merge immediately |
| **error** | Security weakness — should fix before merge |
| **warning** | Best-practice violation — review recommended |
| **info** | Informational — no action required |

## API Reference

### `scanner` Module

| Function | Description |
|----------|-------------|
| `run_all_checks(diff)` | Run all 13 security checks on a diff |
| `run_check(check_id, diff)` | Run a single named check |
| `check_sql_injection(diff)` | Individual check functions for each CWE |
| `check_xss(diff)` | ... |
| `check_path_traversal(diff)` | ... |

**Types:**

| Type | Fields |
|------|--------|
| `CheckResult` | `check_id`, `severity`, `findings: Vec<Finding>`, `count` |
| `Severity` | `Critical`, `Error`, `Warning`, `Info` |

### `report` Module

| Function | Description |
|----------|-------------|
| `generate_report(results, repo, pr, author)` | Full Markdown security report |
| `generate_short_summary(results)` | One-line summary (for PR comments) |
| `generate_json_report(results, repo, pr, author)` | JSON report for API consumption |

### `SecurityAuditRoom`

| Method | Description |
|--------|-------------|
| `new(diff, host, port)` | Create room with a diff to monitor |
| `empty()` | Create room with no diff (sensors return zeros) |
| `tick()` | Execute one sensor sweep |
| `handle_command(line)` | Handle a PLATO wire protocol command |
| `process_alarms()` | Evaluate alarms, dispatch actuators |

### Room Sensors

| Sensor | What It Measures |
|--------|-----------------|
| `vuln_patterns` | Count of vulnerability findings |
| `secret_scan` | Count of hardcoded secrets detected |
| `risk_score` | Aggregate risk score (0–100) |

### Room Alarms

| Alarm | Condition | Cooldown |
|-------|-----------|----------|
| `sql_injection` | vuln_patterns > 0 (SQL injection class) | 30s |
| `xss_detected` | vuln_patterns > 0 (XSS class) | 30s |
| `path_traversal` | vuln_patterns > 0 (path traversal class) | 30s |
| `hardcoded_secrets` | secret_scan > 0 | 60s |
| `command_injection` | vuln_patterns > 0 (command injection class) | 30s |
| `critical_eval` | vuln_patterns > 0 (eval/exec class) | 30s |

### Room Actuators

| Actuator | Action |
|----------|--------|
| `post_audit` | Post audit report as PR comment |
| `block_merge` | Block the pull request merge |
| `apply_label` | Apply a security label to the PR |

## Architecture

```
                    PLATO Wire Protocol
                    (JSON over TCP)
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     tick command     alarm list      actuator cmd
          │                │                │
          ▼                ▼                ▼
    ┌─────────────────────────────────────────────┐
    │        SecurityAuditRoom (Rust)              │
    │                                             │
    │  Sensors              Actuators             │
    │  ├─ vuln_patterns     ├─ post_audit         │
    │  ├─ secret_scan       ├─ block_merge        │
    │  └─ risk_score        └─ apply_label        │
    │                                             │
    │  Alarms                                    │
    │  ├─ sql_injection (count > 0)              │
    │  ├─ xss_detected (count > 0)               │
    │  ├─ path_traversal (count > 0)             │
    │  ├─ hardcoded_secrets (count > 0)          │
    │  ├─ command_injection (count > 0)          │
    │  └─ critical_eval (count > 0)              │
    │                                             │
    │  History (1000-tick ring buffer)            │
    └─────────────────────────────────────────────┘
```

## PLATO Wire Protocol

The room implements the standard PLATO wire protocol:

| Command | Description |
|---------|-------------|
| `tick` | Execute one sensor sweep, evaluate alarms |
| `history N` | Show last N tick records |
| `alarm list` | List all alarms and their states |
| `alarm set ID SENSOR OP THRESH COOLDOWN` | Register a new alarm |
| `actuator NAME [VALUE]` | Trigger an actuator |
| `subscribe` / `unsubscribe` | Subscribe to tick notifications |
| `help` | Show available commands |
| `quit` | Disconnect |

Full spec: [PLATO_WIRE_PROTOCOL.md](https://github.com/SuperInstance/AI-Writings/blob/main/PLATO_WIRE_PROTOCOL.md)

## Testing

```bash
# Run all 64 tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run scanner tests only
cargo test scanner::

# Run report tests only
cargo test report::
```

All tests use simulated diff data — no GitHub API calls or network access needed.

## Differences from Python Version

| Aspect | Python | Rust |
|--------|--------|------|
| Transport | Built-in TCP server | **Library-only** (bring your own transport) |
| GitHub client | Included (`github_client.py`) | Bring your own (`octocrab`, `reqwest`, etc.) |
| Regex engine | Python `re` (supports lookahead) | Rust `regex` crate (no lookahead — post-filter for HTTP check) |
| Concurrency | `threading` + `socketserver` | Single-threaded tick, easy to wrap in `tokio` |
| FLUX policies | Loaded from `.flx` files | Hardcoded alarm definitions |
| Checks | Same 13 patterns | Same 13 patterns, same heuristics |

The Rust version is designed as a library crate, not a standalone server. This lets you embed it in CI pipelines, GitHub Actions, or async servers with your choice of runtime.

## Cross-Implementation

| Aspect | Python | Rust |
|--------|--------|------|
| Package | (source) | `cargo add si-security-audit-room` |
| Repo | [plato-room-security-audit](https://github.com/SuperInstance/plato-room-security-audit) | [plato-room-security-audit-rs](https://github.com/SuperInstance/plato-room-security-audit-rs) (this) |
| Check compatibility | 13 checks | Same 13 checks, same patterns |
| Report format | Markdown + JSON | Markdown + JSON (same structure) |

## Ecosystem

### PLATO Protocol
- [plato-core-rs](https://github.com/SuperInstance/plato-core-rs) — Core protocol types (Room, Sensor, Actuator, Alarm)
- **plato-room-security-audit-rs** — This room (security scanning)

### FLUX Policy Layer
- [conservation-enforcer-rs](https://github.com/SuperInstance/conservation-enforcer-rs) — Conservation-law enforcement
- [flux-registry-rs](https://github.com/SuperInstance/flux-registry-rs) — Policy registry CLI
- [flux-policy-tester-rs](https://github.com/SuperInstance/flux-policy-tester-rs) — Policy testing framework

### Cognitive Layer
- [exocortex-rs](https://github.com/SuperInstance/exocortex-rs) — Multi-agent cognitive substrate

### Theory
- [AI-Writings](https://github.com/SuperInstance/AI-Writings) — Paradigm essays and protocol specs

## License

MIT — see [LICENSE](LICENSE)
