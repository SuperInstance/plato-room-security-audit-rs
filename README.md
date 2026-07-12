# PLATO Security Audit Room (Rust)

> Automated security auditing as a **PLATO engine block** — Rust port of the [Python plato-room-security-audit](https://github.com/SuperInstance/plato-room-security-audit).

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What is this?

A Rust implementation of the PLATO Security Audit Room that scans code diffs for vulnerability patterns. It provides:

- **Heuristic security scanner** — SQL injection, XSS, path traversal, hardcoded secrets, command injection, and more
- **PLATO room protocol** — sensors, alarms, actuators, tick loop, and JSON wire protocol
- **Report generation** — Markdown and JSON security audit reports with severity ratings
- **Zero external services** — No LLM, no AST parsing, no network calls required

## Quick Start

### Add to your project

```toml
[dependencies]
si-security-audit-room = "0.1"
```

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

### Use the room protocol

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

All checks are **heuristic** (pattern-based) — fast, deterministic, and auditable.

| Check | What it catches | Severity | CWE |
|-------|----------------|----------|-----|
| `sql_injection` | String concatenation in SQL execute() calls, f-string queries | critical | CWE-89 |
| `xss` | Unescaped output in templates, `innerHTML` with variables | critical | CWE-79 |
| `path_traversal` | `../` patterns in file paths, unsanitized `open()` calls | critical | CWE-22 |
| `hardcoded_secrets` | AWS keys, API keys, private keys, JWTs, Slack tokens, DB URLs | critical | CWE-798 |
| `command_injection` | `os.system()`, `subprocess` with `shell=True`, `eval()` with user input | critical | CWE-78 |
| `critical_eval` | `eval()`/`exec()` with user input | critical | CWE-95 |
| `insecure_random` | `random` module for security-sensitive contexts | error | CWE-330 |
| `insecure_crypto` | MD5, SHA1, DES, ECB mode for crypto operations | error | CWE-327 |
| `debug_enabled` | `DEBUG = True` in settings files | warning | CWE-489 |
| `http_not_https` | HTTP (not HTTPS) URLs in source code | warning | CWE-319 |
| `disabled_security` | Comments disabling security checks, `# noqa`, `@SuppressWarnings` | warning | CWE-693 |
| `sensitive_file_exposure` | Changes to `.env`, secrets files, key files | error | CWE-200 |
| `weak_password_hash` | `hashlib.md5`/`sha1` for password hashing | error | CWE-916 |

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

## PLATO Room Protocol

The room implements the standard PLATO wire protocol:

| Command | Description |
|---------|-------------|
| `tick` | Execute one sensor sweep, evaluate alarms |
| `history N` | Show last N tick records |
| `alarm list` | List all alarms and their states |
| `alarm set ID SENSOR,OP,THRESH COOLDOWN` | Register a new alarm |
| `actuator NAME [VALUE]` | Trigger an actuator |
| `subscribe` / `unsubscribe` | Subscribe to tick notifications |
| `help` | Show available commands |
| `quit` | Disconnect |

## API Reference

### `scanner` module

- `run_all_checks(diff: &str) -> Vec<CheckResult>` — Run all security checks
- `run_check(check_id: &str, diff: &str) -> Option<CheckResult>` — Run a single check
- Individual checks: `check_sql_injection`, `check_xss`, `check_path_traversal`, `check_hardcoded_secrets`, `check_command_injection`, `check_critical_eval`, etc.

### `report` module

- `generate_report(results, repo, pr_number, author) -> String` — Full Markdown report
- `generate_short_summary(results) -> String` — One-line summary
- `generate_json_report(results, repo, pr_number, author) -> String` — JSON report

### `SecurityAuditRoom`

- `new(diff, host, port)` — Create room with a diff to monitor
- `empty()` — Create room with no diff (sensors return zeros)
- `tick()` — Execute one tick
- `handle_command(line)` — Handle protocol command
- `process_alarms()` — Process triggered alarms (actuator dispatch)

## Testing

```bash
cargo test
```

All 64 tests use simulated data — no GitHub API calls needed.

## Differences from Python version

| Aspect | Python | Rust |
|--------|--------|------|
| Transport | Built-in TCP server | Library-only (bring your own transport) |
| GitHub client | Included (`github_client.py`) | Bring your own (use `octocrab`, `reqwest`, etc.) |
| Regex engine | Python `re` (supports lookahead) | Rust `regex` crate (no lookahead — uses post-filter for HTTP check) |
| Concurrency | `threading` + `socketserver` | Single-threaded tick, easy to wrap in `tokio` |
| FLUX policies | Loaded from `.flx` files | Hardcoded alarm definitions |

## License

MIT — see [LICENSE](LICENSE).

## Part of

[SuperInstance](https://github.com/SuperInstance) — the PLATO ecosystem.

### Related

- **[plato-room-security-audit](https://github.com/SuperInstance/plato-room-security-audit)** — Original Python implementation
