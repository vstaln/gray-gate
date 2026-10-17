//! gray-confirm — confirmation gate for dangerous bash commands.
//!
//! `tool/before` on `bash` scans the command for dangerous
//! patterns (rm -rf, sudo, chmod 777, dd, mkfs, shred, > /dev/, kill -9 1,
//! git push --force, git reset --hard, plus user regexes from
//! ~/.gray/confirm/patterns.json) and, on a match, asks the user through
//! `host/ask` (capability `host.ask`). Empty/timeout/error answers deny —
//! the gate fails closed.
//!
//! Timed confirm is a config object here:
//! ~/.gray/confirm/config.json = {"timeout_secs": N, "default": "deny"|"allow"}.
//! `timeout_secs` 0 (the default) means "host default": the sidecar waits
//! up to its internal 300s TTL and the host's own ask TTL applies. A timeout
//! resolves to `default` (normally "deny"). `GRAY_CONFIRM_TIMEOUT_SECS`
//! overrides `timeout_secs`.
//!
//! `/confirm` status · `/confirm list` shows active patterns ·
//! `/confirm on|off` toggles the gate (state: ~/.gray/confirm/disabled).

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

/// Plugin name claimed in `plugin/manifest`.
const PLUGIN_NAME: &str = "confirm";
/// Internal cap on `host/ask` waits — under the host's 330s outer TTL.
const ASK_TTL: Duration = Duration::from_secs(300);
const QUESTION_ID: &str = "confirm-dangerous";
const LABEL_YES: &str = "Yes";
const LABEL_NO: &str = "No";

/// Built-in dangerous patterns (pi permission-gate's list plus the rest of
/// the port spec's destructive commands).
const BUILTIN_PATTERNS: &[&str] = &[
    r"\brm\s+(-[a-zA-Z]*r|--recursive)",  // rm -rf / rm -r / rm --recursive
    r"\bsudo\b",                        // sudo
    r"\b(chmod|chown)\b[^|&;]*\b777\b", // chmod/chown 777
    r"\bdd\b\s",                        // dd if=… of=…
    r"\bmkfs[.\w-]*\b",                 // mkfs, mkfs.ext4, …
    r"\bshred\b",                       // shred
    r">\s*/dev/",                       // > /dev/sda etc.
    r"\bkill\s+-9\s+1\b",               // kill -9 1 (init)
    r"\bgit\s+push\b[^|&;]*(--force\b|-f\b)", // git push --force / -f
    r"\bgit\s+reset\b[^|&;]*--hard\b",  // git reset --hard
];

pub type Pending = Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>>;

fn manifest_confirm() -> Value {
    json!({
        "name": PLUGIN_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": ["/confirm"],
        "hooks": ["tool/before"],
        "capabilities": ["host.ask"],
    })
}

fn gray_home() -> PathBuf {
    std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn state_dir() -> PathBuf {
    gray_home().join("confirm")
}

fn enabled() -> bool {
    !state_dir().join("disabled").exists()
}

/// Timed-confirm port: how long to wait on `host/ask` and what a timeout
/// means. `timeout_secs == 0` → host default (use the internal TTL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmConfig {
    timeout_secs: u64,
    /// true = allow on timeout, false = deny on timeout.
    default_allow: bool,
}

pub fn load_config() -> ConfirmConfig {
    let mut cfg = ConfirmConfig {
        timeout_secs: 0,
        default_allow: false,
    };
    if let Ok(raw) = std::fs::read_to_string(state_dir().join("config.json"))
        && let Ok(v) = serde_json::from_str::<Value>(&raw)
    {
        if let Some(n) = v.get("timeout_secs").and_then(Value::as_u64) {
            cfg.timeout_secs = n;
        }
        if v.get("default").and_then(Value::as_str) == Some("allow") {
            cfg.default_allow = true;
        }
    }
    if let Ok(s) = std::env::var("GRAY_CONFIRM_TIMEOUT_SECS")
        && let Ok(n) = s.trim().parse::<u64>()
    {
        cfg.timeout_secs = n;
    }
    cfg
}

/// All active patterns: builtins + user regexes from patterns.json.
/// Bad user regexes are skipped and returned so `/confirm list` can say so.
pub fn load_patterns() -> (Vec<regex::Regex>, Vec<String>) {
    let mut out = Vec::new();
    for p in BUILTIN_PATTERNS {
        if let Ok(r) = regex::Regex::new(p) {
            out.push(r);
        }
    }
    let mut bad = Vec::new();
    if let Ok(raw) = std::fs::read_to_string(state_dir().join("patterns.json"))
        && let Ok(v) = serde_json::from_str::<Value>(&raw)
        && let Some(list) = v.get("patterns").and_then(Value::as_array)
    {
        for item in list {
            let Some(s) = item.as_str() else { continue };
            match regex::Regex::new(s) {
                Ok(r) => out.push(r),
                Err(_) => bad.push(s.to_string()),
            }
        }
    }
    (out, bad)
}

/// What `tool/before` should do for this call.
enum Verdict {
    Allow,
    Ask { command: String, matched: String },
}

fn classify(name: &str, args: &Value, patterns: &[regex::Regex], on: bool) -> Verdict {
    if !on || name != "bash" {
        return Verdict::Allow;
    }
    let command = args.get("command").and_then(Value::as_str).unwrap_or("");
    for p in patterns {
        if p.is_match(command) {
            return Verdict::Ask {
                command: command.to_string(),
                matched: p.as_str().to_string(),
            };
        }
    }
    Verdict::Allow
}

fn ask_question(command: &str, matched: &str) -> Value {
    json!({
        "id": QUESTION_ID,
        "header": "Dangerous command",
        "question": format!("⚠️ Dangerous command (matched `{matched}`):\n\n  {command}\n\nRun it?"),
        "options": [
            {"label": LABEL_YES, "description": "run the command once"},
            {"label": LABEL_NO, "description": "block it"},
        ],
    })
}

/// Interpret a `host/ask` result. Returns the user's Yes/No, or None on
/// error/timeout/empty (the caller then applies the configured default).
fn answers_picked(result: &Value) -> Option<bool> {
    if result.get("error").is_some() {
        return None;
    }
    let picked: Vec<&str> = result
        .get("answers")
        .and_then(|a| a.get(QUESTION_ID))
        .and_then(|e| e.get("answers"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    match picked.first() {
        Some(&LABEL_YES) => Some(true),
        Some(_) => Some(false),
        None => None,
    }
}

fn next_id(counter: &Mutex<u64>) -> String {
    let mut n = counter.lock().expect("id counter");
    *n += 1;
    format!("q{n}")
}

/// `tool/before` with the host/ask round-trip. Fails closed: no ask
/// channel, an error reply, or a timeout all deny.
pub fn tool_before(
    out: &Mutex<std::io::Stdout>,
    pending: &Pending,
    counter: &Mutex<u64>,
    patterns: &[regex::Regex],
    cfg: &ConfirmConfig,
    params: &Value,
) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("args").cloned().unwrap_or(json!({}));
    let Verdict::Ask { command, matched } = classify(name, &args, patterns, enabled()) else {
        return json!({"decision": "allow"});
    };

    let id = next_id(counter);
    let (tx, rx) = mpsc::channel();
    pending.lock().expect("pending").insert(id.clone(), tx);
    let req = json!({
        "id": id,
        "method": "host/ask",
        "params": {
            "questions": [ask_question(&command, &matched)],
            "blocking": true,
        },
    });
    {
        let mut o = out.lock().expect("stdout");
        let _ = writeln!(o, "{req}");
        let _ = o.flush();
    }
    let ttl = if cfg.timeout_secs == 0 {
        ASK_TTL
    } else {
        Duration::from_secs(cfg.timeout_secs)
    };
    let reply = rx.recv_timeout(ttl).ok();
    pending.lock().expect("pending").remove(&id);
    match reply.and_then(|r| answers_picked(&r)) {
        Some(true) => json!({"decision": "allow"}),
        Some(false) => json!({
            "decision": "deny",
            "reason": "dangerous command declined by user — do NOT retry via a workaround; ask the user instead"
        }),
        None => {
            if cfg.default_allow {
                json!({"decision": "allow"})
            } else {
                json!({
                    "decision": "deny",
                    "reason": "no confirmation channel or timed out (dangerous commands require confirmation)"
                })
            }
        }
    }
}

/// `/confirm …` — `argv` excludes the command name.
pub fn run_command(argv: &[&str], patterns: &[regex::Regex], bad: &[String], cfg: &ConfirmConfig) -> String {
    match argv.first().copied() {
        Some("list") => {
            let mut lines = vec![format!("{} patterns active:", patterns.len())];
            for p in patterns {
                lines.push(format!("  {p}"));
            }
            for b in bad {
                lines.push(format!("  (skipped, invalid regex) {b}"));
            }
            lines.join("\n")
        }
        Some("on") | Some("off") => {
            let dir = state_dir();
            let flag = dir.join("disabled");
            let res = if argv[0] == "off" {
                std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&flag, b""))
            } else {
                std::fs::remove_file(&flag).or_else(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
            };
            match res {
                Ok(()) => format!("confirm gate {}", if argv[0] == "off" { "off" } else { "on" }),
                Err(e) => format!("couldn't flip state: {e}"),
            }
        }
        _ => format!(
            "gray-confirm {} — {} · {} patterns · timeout {}s (0 = host default, times out {}) · \
             /confirm list · /confirm on|off",
            env!("CARGO_PKG_VERSION"),
            if enabled() { "on" } else { "off" },
            patterns.len(),
            cfg.timeout_secs,
            if cfg.default_allow { "allow" } else { "deny" },
        ),
    }
}

fn main_confirm() {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest_confirm());
        return;
    }
    let (patterns, bad_patterns) = load_patterns();
    let cfg = load_config();
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let counter = Mutex::new(0u64);

    // Reader thread: host answers (string ids) go to `pending`; requests
    // (numeric ids) go to the work channel.
    let (work_tx, work_rx) = mpsc::channel::<Value>();
    let reader_pending = pending.clone();
    let _reader = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(id) = v.get("id").and_then(Value::as_str)
                && v.get("method").is_none()
                && let Some(tx) = reader_pending.lock().expect("pending").remove(id)
            {
                let _ = tx.send(v.get("result").cloned().unwrap_or(Value::Null));
                continue;
            }
            let shutdown = v.get("method").and_then(Value::as_str) == Some("plugin/shutdown");
            if (v.get("id").is_some() || shutdown) && work_tx.send(v).is_err() {
                break;
            }
        }
    });

    for req in work_rx {
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(json!(0));
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "plugin/manifest" => manifest_confirm(),
            "tool/before" => tool_before(&stdout, &pending, &counter, &patterns, &cfg, &params),
            "command/run" => {
                let argv: Vec<String> = params
                    .get("argv")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_default();
                let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
                json!({ "text": run_command(&argv, &patterns, &bad_patterns, &cfg) })
            }
            "plugin/shutdown" => {
                let reply = json!({ "id": id, "result": {} });
                let mut o = stdout.lock().expect("stdout");
                let _ = writeln!(o, "{reply}");
                let _ = o.flush();
                break;
            }
            "tool/call" => json!({ "content": "confirm has no tools", "is_error": true }),
            other => {
                let reply = json!({ "id": id, "error": { "code": -32601, "message": format!("method not found: {other}") } });
                let mut o = stdout.lock().expect("stdout");
                let _ = writeln!(o, "{reply}");
                let _ = o.flush();
                continue;
            }
        };
        let reply = json!({ "id": id, "result": result });
        let mut o = stdout.lock().expect("stdout");
        let _ = writeln!(o, "{reply}");
        let _ = o.flush();
    }
    // The reader thread is a detached stdin pump; returning from main
    // ends the process with it, so there is nothing to join.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats() -> Vec<regex::Regex> {
        BUILTIN_PATTERNS
            .iter()
            .map(|p| regex::Regex::new(p).unwrap())
            .collect()
    }

    fn classify_cmd(cmd: &str) -> Verdict {
        classify("bash", &json!({"command": cmd}), &pats(), true)
    }

    #[test]
    fn manifest_shape() {
        let m = manifest_confirm();
        assert_eq!(m["name"], "confirm");
        assert_eq!(m["protocol"], "2.0");
        assert_eq!(m["hooks"], json!(["tool/before"]));
        assert_eq!(m["capabilities"], json!(["host.ask"]));
        assert_eq!(m["commands"], json!(["/confirm"]));
    }

    #[test]
    fn dangerous_commands_ask() {
        for cmd in [
            "rm -rf /tmp/x",
            "rm -r build",
            "sudo apt update",
            "chmod 777 /etc",
            "chown 777 f",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "shred secret",
            "cat x > /dev/sda",
            "kill -9 1",
            "git push --force origin main",
            "git push -f",
            "git reset --hard HEAD~1",
        ] {
            assert!(
                matches!(classify_cmd(cmd), Verdict::Ask { .. }),
                "should ask: {cmd}"
            );
        }
    }

    #[test]
    fn safe_commands_allow() {
        for cmd in [
            "ls -la",
            "cargo test",
            "rm file.txt",
            "git push origin main",
            "git reset --soft HEAD~1",
            "chmod 644 f",
            "cat /dev/null",
        ] {
            assert!(matches!(classify_cmd(cmd), Verdict::Allow), "should allow: {cmd}");
        }
    }

    #[test]
    fn non_bash_and_disabled_allow() {
        assert!(matches!(
            classify("write", &json!({"path": "x", "content": "sudo rm -rf /"}), &pats(), true),
            Verdict::Allow
        ));
        assert!(matches!(
            classify("bash", &json!({"command": "sudo rm -rf /"}), &pats(), false),
            Verdict::Allow
        ));
    }

    #[test]
    fn answers_interpretation() {
        let yes = json!({"answers": {QUESTION_ID: {"answers": ["Yes"]}}});
        let no = json!({"answers": {QUESTION_ID: {"answers": ["No"]}}});
        let empty = json!({"answers": {}});
        let err = json!({"error": {"message": "no handler"}});
        assert_eq!(answers_picked(&yes), Some(true));
        assert_eq!(answers_picked(&no), Some(false));
        assert_eq!(answers_picked(&empty), None);
        assert_eq!(answers_picked(&err), None);
    }
}
