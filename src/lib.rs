//! # PLATO Security Audit Room (Rust)
//!
//! A Rust port of the [Python plato-room-security-audit](https://github.com/SuperInstance/plato-room-security-audit).
//!
//! Provides heuristic security scanning of code diffs and a PLATO room protocol
//! implementation with sensors, alarms, actuators, and a tick-loop core.
//!
//! ## Quick start
//!
//! ```rust
//! use si_security_audit_room::scanner::run_all_checks;
//! use si_security_audit_room::report::generate_report;
//!
//! let diff = r#"
//! diff --git a/app.py b/app.py
//! +++ b/app.py
//! +query = "SELECT * FROM users WHERE id='" + user_input + "'"
//! +cursor.execute(query)
//! "#;
//!
//! let results = run_all_checks(diff);
//! let report = generate_report(&results, None, None, None);
//! println!("{report}");
//! ```

pub mod scanner;
pub mod report;

pub use scanner::{CheckResult, Severity, run_all_checks, run_check};
pub use report::{generate_report, generate_short_summary, generate_json_report};

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Protocol constants ─────────────────────────────────────

pub const PROTOCOL_VERSION: &str = "0.1";

// ─── Alarm ──────────────────────────────────────────────────

/// A declarative alarm that fires when a sensor crosses a threshold.
#[derive(Debug, Clone)]
pub struct AlarmDef {
    pub alarm_id: String,
    pub condition: String,
    pub sensor: String,
    pub operator: String,
    pub threshold: f64,
    pub cooldown_sec: u64,
    pub last_triggered: f64,
    pub state: AlarmState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmState {
    Idle,
    Triggered,
    Cooling,
}

impl AlarmDef {
    pub fn new(
        alarm_id: impl Into<String>,
        sensor: impl Into<String>,
        operator: impl Into<String>,
        threshold: f64,
        cooldown_sec: u64,
    ) -> Self {
        let sensor = sensor.into();
        let operator = operator.into();
        let condition = format!("{sensor} {operator} {threshold}");
        Self {
            alarm_id: alarm_id.into(),
            condition,
            sensor,
            operator,
            threshold,
            cooldown_sec,
            last_triggered: 0.0,
            state: AlarmState::Idle,
        }
    }

    /// Evaluate the alarm against current sensor values.
    pub fn evaluate(&self, values: &HashMap<String, f64>) -> bool {
        let Some(&val) = values.get(&self.sensor) else {
            return false;
        };
        match self.operator.as_str() {
            "<" => val < self.threshold,
            ">" => val > self.threshold,
            "<=" => val <= self.threshold,
            ">=" => val >= self.threshold,
            "==" => val == self.threshold,
            "!=" => val != self.threshold,
            _ => false,
        }
    }
}

// ─── Tick record ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TickRecord {
    pub t: f64,
    pub seq: u64,
    pub data: HashMap<String, f64>,
}

// ─── Sensor and actuator function types ─────────────────────

/// A sensor function reads room state and returns named metric values.
pub type SensorFn = Box<dyn Fn(&BaseRoom) -> HashMap<String, f64> + Send + Sync>;

/// An actuator function performs a side-effect.
/// Receives a mutable reference to a metadata map so actuators can record outcomes.
pub type ActuatorFn = Box<dyn Fn(&mut ActuatorCtx, f64) + Send + Sync>;

/// Context passed to actuators so they can record results without needing
/// access to the full room state.
#[derive(Debug, Default)]
pub struct ActuatorCtx {
    pub metadata: HashMap<String, String>,
}

impl ActuatorCtx {
    pub fn set(&mut self, key: &str, value: String) {
        self.metadata.insert(key.to_string(), value);
    }
}

// ─── BaseRoom ───────────────────────────────────────────────

/// Base PLATO room — implements the wire protocol tick loop.
///
/// Subclasses (e.g. `SecurityAuditRoom`) register sensors, actuators,
/// and alarms in their constructor.
pub struct BaseRoom {
    pub room_id: String,
    pub tick_hz: f64,
    pub host: String,
    pub port: u16,

    pub sensors: Vec<(String, SensorFn)>,
    pub actuators: Vec<(String, ActuatorFn)>,
    pub alarms: HashMap<String, AlarmDef>,
    pub history: Vec<TickRecord>,
    history_cap: usize,

    pub seq: u64,
    pub latest: HashMap<String, f64>,
    pub actuator_ctx: ActuatorCtx,
}

impl BaseRoom {
    pub fn new(room_id: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            room_id: room_id.into(),
            tick_hz: 0.2,
            host: host.into(),
            port,
            sensors: Vec::new(),
            actuators: Vec::new(),
            alarms: HashMap::new(),
            history: Vec::new(),
            history_cap: 1000,
            seq: 0,
            latest: HashMap::new(),
            actuator_ctx: ActuatorCtx::default(),
        }
    }

    pub fn register_sensor<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&BaseRoom) -> HashMap<String, f64> + Send + Sync + 'static,
    {
        self.sensors.push((name.into(), Box::new(func)));
    }

    pub fn register_actuator<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut ActuatorCtx, f64) + Send + Sync + 'static,
    {
        self.actuators.push((name.into(), Box::new(func)));
    }

    pub fn register_alarm(
        &mut self,
        alarm_id: impl Into<String>,
        sensor: impl Into<String>,
        operator: impl Into<String>,
        threshold: f64,
        cooldown_sec: u64,
    ) {
        let alarm = AlarmDef::new(alarm_id, sensor, operator, threshold, cooldown_sec);
        self.alarms.insert(alarm.alarm_id.clone(), alarm);
    }

    /// Execute one tick: read all sensors, evaluate alarms, record history.
    pub fn tick(&mut self) -> HashMap<String, f64> {
        self.seq += 1;
        let mut values = HashMap::new();

        for (_name, func) in &self.sensors {
            let result = func(self);
            values.extend(result);
        }

        self.latest = values.clone();
        let t = now_secs();
        let tick_record = TickRecord {
            t,
            seq: self.seq,
            data: values.clone(),
        };

        // ring-buffer history
        if self.history.len() >= self.history_cap {
            self.history.remove(0);
        }
        self.history.push(tick_record);

        // evaluate alarms and collect triggered IDs
        let mut triggered_ids: Vec<String> = Vec::new();
        for alarm in self.alarms.values_mut() {
            if alarm.evaluate(&values) {
                let since = t - alarm.last_triggered;
                if since >= alarm.cooldown_sec as f64 {
                    alarm.last_triggered = t;
                    alarm.state = AlarmState::Triggered;
                    triggered_ids.push(alarm.alarm_id.clone());
                } else {
                    alarm.state = AlarmState::Cooling;
                }
            } else {
                alarm.state = AlarmState::Idle;
            }
        }

        values
    }

    /// Trigger the actuator with the given name.
    pub fn actuate(&mut self, name: &str, value: f64) {
        // Find the index first to avoid borrow conflicts
        let idx = self.actuators.iter().position(|(n, _)| n == name);
        if let Some(i) = idx {
            let func = &self.actuators[i].1;
            func(&mut self.actuator_ctx, value);
        } else {
            eprintln!("unknown actuator: {name}");
        }
    }

    /// Handle a protocol command line and return a JSON response string.
    pub fn handle_command(&mut self, line: &str) -> String {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            return serde_json::json!({"type": "error", "message": "empty command"}).to_string();
        }

        match parts[0] {
            "tick" => {
                let data = self.tick();
                serde_json::json!({
                    "type": "tick",
                    "t": now_secs(),
                    "seq": self.seq,
                    "data": data,
                })
                .to_string()
            }
            "history" => {
                let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                let start = self.history.len().saturating_sub(n);
                let ticks: Vec<&TickRecord> = self.history[start..].iter().collect();
                serde_json::json!({
                    "type": "history",
                    "count": ticks.len(),
                    "ticks": ticks.iter().map(|t| serde_json::json!({
                        "t": t.t, "seq": t.seq, "data": t.data
                    })).collect::<Vec<_>>()
                }).to_string()
            }
            "actuator" => {
                if parts.len() < 2 {
                    return serde_json::json!({"type": "error", "message": "missing actuator name"}).to_string();
                }
                let name = parts[1];
                let value: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
                self.actuate(name, value);
                serde_json::json!({"type": "ack", "command": "actuator", "name": name, "value": value})
                    .to_string()
            }
            "alarm" => {
                if parts.len() < 2 {
                    return serde_json::json!({"type": "error", "message": "missing alarm subcommand"}).to_string();
                }
                match parts[1] {
                    "list" => {
                        let alarms: Vec<serde_json::Value> = self.alarms.values().map(|a| {
                            serde_json::json!({
                                "id": a.alarm_id,
                                "condition": a.condition,
                                "cooldown_sec": a.cooldown_sec,
                                "last_triggered": a.last_triggered,
                                "state": match a.state {
                                    AlarmState::Idle => "idle",
                                    AlarmState::Triggered => "triggered",
                                    AlarmState::Cooling => "cooling",
                                }
                            })
                        }).collect();
                        serde_json::json!({"type": "alarm_list", "alarms": alarms}).to_string()
                    }
                    "set" => {
                        if parts.len() < 5 {
                            return serde_json::json!({"type": "error", "message": "alarm set needs ID CONDITION COOLDOWN"}).to_string();
                        }
                        let aid = parts[2];
                        let condition = parts[3];
                        let cooldown: u64 = parts[4].parse().unwrap_or(300);
                        let tokens: Vec<&str> = condition.split(',').collect();
                        if tokens.len() == 3 {
                            self.register_alarm(aid, tokens[0], tokens[1], tokens[2].parse().unwrap_or(0.0), cooldown);
                        }
                        serde_json::json!({"type": "ack", "command": "alarm set", "id": aid}).to_string()
                    }
                    _ => serde_json::json!({"type": "error", "message": "unknown alarm subcommand"}).to_string(),
                }
            }
            "subscribe" => {
                serde_json::json!({"type": "subscribed", "tick_hz": self.tick_hz}).to_string()
            }
            "unsubscribe" => {
                serde_json::json!({"type": "unsubscribed"}).to_string()
            }
            "help" => {
                serde_json::json!({"type": "help", "commands": [
                    "tick", "history N", "actuator NAME [VALUE]",
                    "alarm list", "alarm set ID SENSOR,OP,THRESH COOLDOWN",
                    "subscribe", "unsubscribe", "help", "quit"
                ]}).to_string()
            }
            "quit" => serde_json::json!({"type": "bye"}).to_string(),
            cmd => serde_json::json!({"type": "error", "message": format!("unknown command: {cmd}")}).to_string(),
        }
    }

    /// Generate the welcome message sent on new client connections.
    pub fn welcome(&self) -> String {
        let sensor_names: Vec<&str> = self.sensors.iter().map(|(n, _)| n.as_str()).collect();
        serde_json::json!({
            "type": "welcome",
            "room_id": self.room_id,
            "tick_hz": self.tick_hz,
            "sensors": sensor_names,
            "format": "json",
            "protocol_version": PROTOCOL_VERSION,
        })
        .to_string()
    }

    /// Returns the last triggered alarm IDs after a tick.
    pub fn triggered_alarms(&self) -> Vec<String> {
        self.alarms
            .values()
            .filter(|a| a.state == AlarmState::Triggered)
            .map(|a| a.alarm_id.clone())
            .collect()
    }
}

// ─── SecurityAuditRoom ──────────────────────────────────────

/// A PLATO room that runs security audits on code diffs.
///
/// # Sensors
///
/// | Sensor | Metrics |
/// |--------|---------|
/// | `vuln_patterns` | `sql_injection_count`, `xss_count`, `traversal_count`, `cmd_injection_count`, `eval_count` |
/// | `secret_scan` | `secret_count`, `sensitive_file_count` |
/// | `risk_score` | `risk_score`, `critical_count`, `error_count` |
///
/// # Alarms
///
/// | Alarm | Condition |
/// |-------|-----------|
/// | `sql_injection` | `sql_injection_count > 0` |
/// | `xss_detected` | `xss_count > 0` |
/// | `path_traversal` | `traversal_count > 0` |
/// | `hardcoded_secrets` | `secret_count > 0` |
/// | `command_injection` | `cmd_injection_count > 0` |
/// | `critical_eval` | `eval_count > 0` |
pub struct SecurityAuditRoom {
    pub base: BaseRoom,
    pub diff: String,
}

impl SecurityAuditRoom {
    /// Create a new SecurityAuditRoom with the given diff text.
    ///
    /// In production the diff would come from the GitHub API; here we pass it
    /// directly so the room is transport-agnostic.
    pub fn new(diff: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        let mut base = BaseRoom::new("security-audit-room", host, port);
        base.tick_hz = 0.1; // every 10 seconds

        let diff_text = diff.into();
        let diff_for_sensors = diff_text.clone();

        // ── Sensors ─────────────────────────────────────────
        base.register_sensor("vuln_patterns", move |_| {
            let results = run_all_checks(&diff_for_sensors);
            let mut counts = HashMap::new();
            let mapping = [
                ("sql_injection", "sql_injection_count"),
                ("xss", "xss_count"),
                ("path_traversal", "traversal_count"),
                ("command_injection", "cmd_injection_count"),
                ("critical_eval", "eval_count"),
            ];
            for (check_id, sensor_name) in &mapping {
                let count = results
                    .iter()
                    .filter(|r| r.check_id == *check_id && !r.passed)
                    .count() as f64;
                counts.insert(sensor_name.to_string(), count);
            }
            counts
        });

        let diff_for_secrets = diff_text.clone();
        base.register_sensor("secret_scan", move |_| {
            let results = run_all_checks(&diff_for_secrets);
            let secret_count = results
                .iter()
                .filter(|r| r.check_id == "hardcoded_secrets" && !r.passed)
                .count() as f64;
            let sensitive_files = results
                .iter()
                .filter(|r| r.check_id == "sensitive_file_exposure" && !r.passed)
                .count() as f64;
            let mut m = HashMap::new();
            m.insert("secret_count".to_string(), secret_count);
            m.insert("sensitive_file_count".to_string(), sensitive_files);
            m
        });

        let diff_for_risk = diff_text.clone();
        base.register_sensor("risk_score", move |_| {
            let results = run_all_checks(&diff_for_risk);
            let failing: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();
            let critical = failing.iter().filter(|r| r.severity == Severity::Critical).count();
            let error = failing.iter().filter(|r| r.severity == Severity::Error).count();
            let warning = failing.iter().filter(|r| r.severity == Severity::Warning).count();
            let info = failing.iter().filter(|r| r.severity == Severity::Info).count();
            let score = (critical * 30 + error * 15 + warning * 5 + info).min(100);
            let mut m = HashMap::new();
            m.insert("risk_score".to_string(), score as f64);
            m.insert("critical_count".to_string(), critical as f64);
            m.insert("error_count".to_string(), error as f64);
            m
        });

        // ── Actuators ───────────────────────────────────────
        // Actuators store their output in the shared actuator_ctx metadata map.
        base.register_actuator("post_audit", |ctx, value| {
            let event = match value as u8 {
                2 => "REQUEST_CHANGES",
                3 => "APPROVE",
                _ => "COMMENT",
            };
            ctx.set("last_event", format!("post_audit:{event}"));
        });

        base.register_actuator("block_merge", |ctx, _value| {
            ctx.set("last_event", "block_merge:REQUEST_CHANGES".to_string());
        });

        base.register_actuator("apply_label", |ctx, value| {
            let label = match value as u8 {
                1 => "needs-security-review",
                2 => "security-critical",
                3 => "secrets-detected",
                4 => "vulnerability-detected",
                _ => "security-review",
            };
            ctx.set("last_event", format!("apply_label:{label}"));
        });

        // ── Alarms ──────────────────────────────────────────
        base.register_alarm("sql_injection", "sql_injection_count", ">", 0.0, 60);
        base.register_alarm("xss_detected", "xss_count", ">", 0.0, 60);
        base.register_alarm("path_traversal", "traversal_count", ">", 0.0, 60);
        base.register_alarm("hardcoded_secrets", "secret_count", ">", 0.0, 60);
        base.register_alarm("command_injection", "cmd_injection_count", ">", 0.0, 60);
        base.register_alarm("critical_eval", "eval_count", ">", 0.0, 60);

        Self {
            base,
            diff: diff_text,
        }
    }

    /// Create a room with no diff (sensors return zeros).
    pub fn empty() -> Self {
        Self::new("", "0.0.0.0", 1235)
    }

    /// Convenience: run a tick and return the data.
    pub fn tick(&mut self) -> HashMap<String, f64> {
        self.base.tick()
    }

    /// Process triggered alarms after a tick.
    pub fn process_alarms(&mut self) {
        let triggered = self.base.triggered_alarms();
        for id in triggered {
            match id.as_str() {
                "sql_injection" | "command_injection" | "critical_eval" | "hardcoded_secrets" => {
                    self.base.actuate("block_merge", 2.0);
                }
                "xss_detected" | "path_traversal" => {
                    self.base.actuate("post_audit", 1.0);
                }
                _ => {
                    self.base.actuate("apply_label", 5.0);
                }
            }
        }
    }

    /// Handle a protocol command (delegates to base room, then processes alarms).
    pub fn handle_command(&mut self, line: &str) -> String {
        let resp = self.base.handle_command(line);
        // after a tick, check for triggered alarms
        if line.trim_start().starts_with("tick") {
            self.process_alarms();
        }
        resp
    }

    /// Welcome message for new clients.
    pub fn welcome(&self) -> String {
        self.base.welcome()
    }
}

// ─── Helpers ────────────────────────────────────────────────

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
