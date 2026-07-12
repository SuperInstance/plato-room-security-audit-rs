use si_security_audit_room::*;

#[test]
fn test_room_id() {
    let room = SecurityAuditRoom::empty();
    assert_eq!(room.base.room_id, "security-audit-room");
}

#[test]
fn test_room_tick_hz() {
    let room = SecurityAuditRoom::empty();
    assert!((room.base.tick_hz - 0.1).abs() < 0.001);
}

#[test]
fn test_room_has_sensors() {
    let room = SecurityAuditRoom::empty();
    assert_eq!(room.base.sensors.len(), 3);
}

#[test]
fn test_room_has_actuators() {
    let room = SecurityAuditRoom::empty();
    assert_eq!(room.base.actuators.len(), 3);
}

#[test]
fn test_room_has_alarms() {
    let room = SecurityAuditRoom::empty();
    assert!(room.base.alarms.contains_key("sql_injection"));
    assert!(room.base.alarms.contains_key("xss_detected"));
    assert!(room.base.alarms.contains_key("path_traversal"));
    assert!(room.base.alarms.contains_key("hardcoded_secrets"));
    assert!(room.base.alarms.contains_key("command_injection"));
    assert!(room.base.alarms.contains_key("critical_eval"));
}

#[test]
fn test_room_tick_empty_returns_zeros() {
    let mut room = SecurityAuditRoom::empty();
    let data = room.tick();
    assert_eq!(data.get("sql_injection_count"), Some(&0.0));
    assert_eq!(data.get("secret_count"), Some(&0.0));
    assert_eq!(data.get("risk_score"), Some(&0.0));
}

#[test]
fn test_room_tick_with_vulnerable_diff() {
    let vuln = "\
diff --git a/app.py b/app.py
+++ b/app.py
+query = \"SELECT * FROM users WHERE name='\" + user + \"'\"
+cursor.execute(query)
+API_KEY = \"sk-1234567890abcdef1234567890abcdef\"
+os.system(\"echo \" + user_input)
+eval(user_input)
";
    let mut room = SecurityAuditRoom::new(vuln, "0.0.0.0", 0);
    let data = room.tick();
    assert!(data["sql_injection_count"] > 0.0);
    assert!(data["secret_count"] > 0.0);
    assert!(data["cmd_injection_count"] > 0.0);
    assert!(data["eval_count"] > 0.0);
    assert!(data["risk_score"] > 0.0);
}

#[test]
fn test_room_tick_fires_alarms() {
    let vuln = "\
diff --git a/app.py b/app.py
+++ b/app.py
+query = \"SELECT * FROM users WHERE name='\" + user + \"'\"
+cursor.execute(query)
";
    let mut room = SecurityAuditRoom::new(vuln, "0.0.0.0", 0);
    room.tick();
    assert_eq!(room.base.alarms["sql_injection"].state, AlarmState::Triggered);
}

#[test]
fn test_room_handle_tick_command() {
    let mut room = SecurityAuditRoom::empty();
    let resp = room.handle_command("tick");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["type"], "tick");
}

#[test]
fn test_room_handle_help_command() {
    let mut room = SecurityAuditRoom::empty();
    let resp = room.base.handle_command("help");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["type"], "help");
    let commands = parsed["commands"].as_array().unwrap();
    assert!(commands.iter().any(|c| c == "tick"));
    assert!(commands.iter().any(|c| c == "alarm list"));
}

#[test]
fn test_room_handle_alarm_list_command() {
    let mut room = SecurityAuditRoom::empty();
    let resp = room.base.handle_command("alarm list");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["type"], "alarm_list");
    let alarms = parsed["alarms"].as_array().unwrap();
    assert!(!alarms.is_empty());
}

#[test]
fn test_room_handle_history_command() {
    let mut room = SecurityAuditRoom::empty();
    room.tick();
    room.tick();
    let resp = room.base.handle_command("history 2");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["type"], "history");
    assert_eq!(parsed["count"].as_u64().unwrap(), 2);
}

#[test]
fn test_room_handle_actuator_command() {
    let mut room = SecurityAuditRoom::empty();
    let resp = room.base.handle_command("actuator post_audit 1");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(parsed["type"], "ack");
}

#[test]
fn test_room_welcome_message() {
    let room = SecurityAuditRoom::empty();
    let welcome = room.welcome();
    let parsed: serde_json::Value = serde_json::from_str(&welcome).unwrap();
    assert_eq!(parsed["type"], "welcome");
    assert_eq!(parsed["room_id"], "security-audit-room");
}

#[test]
fn test_base_room_alarm_evaluation() {
    let alarm = AlarmDef::new("test", "val", ">", 5.0, 300);
    let mut values = std::collections::HashMap::new();

    values.insert("val".to_string(), 10.0);
    assert!(alarm.evaluate(&values));

    values.insert("val".to_string(), 3.0);
    assert!(!alarm.evaluate(&values));

    values.clear();
    assert!(!alarm.evaluate(&values));
}

#[test]
fn test_base_room_alarm_operators() {
    let cases: &[(&str, f64, f64, bool)] = &[
        ("<", 3.0, 5.0, true),
        ("<", 7.0, 5.0, false),
        (">", 7.0, 5.0, true),
        (">", 3.0, 5.0, false),
        ("<=", 5.0, 5.0, true),
        (">=", 5.0, 5.0, true),
        ("==", 5.0, 5.0, true),
        ("!=", 5.0, 5.0, false),
    ];
    for (op, val, threshold, expected) in cases {
        let alarm = AlarmDef::new("t", "v", *op, *threshold, 0);
        let mut values = std::collections::HashMap::new();
        values.insert("v".to_string(), *val);
        assert_eq!(alarm.evaluate(&values), *expected, "failed: {op} {val} {threshold}");
    }
}
