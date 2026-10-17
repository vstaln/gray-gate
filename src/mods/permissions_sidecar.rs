//! `permissions` sidecar: approval gate over the gray wire v1. No tools;
//! claims `tool/before` + `/permissions` (+ `/perms`, `/access` aliases).
//! Asking goes through `host/ask` (same contract as `gray-questions`):
//! empty/timeout answers deny (fail closed).
//!
//! Mode persistence: `$GRAY_HOME/permissions-mode.json`, seeded from
//! `GRAY_PERMISSION`/`GRAY_PERMISSIONS` when no file exists. Session
//! memory is in-process (a respawned child starts unremembered).

use crate::permissions::{
    APPROVAL_QUESTION_ID, ApprovalGate, Decision, LABEL_NO, approval_question, call_label,
    decide_from_answers, manifest_permissions, run_permissions_command,
};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// How long `tool/before` waits for a `host/ask` reply. Must sit under
/// the host's ask-gated outer deadline (330s).
const ASK_TTL: Duration = Duration::from_secs(300);

pub type Pending = Arc<Mutex<HashMap<String, mpsc::Sender<serde_json::Value>>>>;

fn gray_home() -> Option<PathBuf> {
    std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
}

fn mode_path() -> Option<PathBuf> {
    gray_home().map(|h| h.join("permissions-mode.json"))
}

pub fn load_mode() -> String {
    if let Some(path) = mode_path()
        && let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(mode) = v.get("mode").and_then(|m| m.as_str())
        && crate::permissions::normalize_mode(mode).is_some()
    {
        return mode.to_string();
    }
    for key in ["GRAY_PERMISSION", "GRAY_PERMISSIONS"] {
        if let Ok(v) = std::env::var(key)
            && !v.trim().is_empty()
        {
            return v;
        }
    }
    crate::permissions::MODE_AUTO.to_string()
}

pub fn save_mode(mode: &str) {
    let Some(path) = mode_path() else { return };
    if path
        .parent()
        .is_some_and(|p| std::fs::create_dir_all(p).is_err())
    {
        return;
    }
    let _ = std::fs::write(&path, format!("{{\"mode\":{mode:?}}}\n"));
}

fn next_id(counter: &Arc<Mutex<u64>>) -> String {
    let mut n = counter.lock().expect("id counter");
    *n += 1;
    format!("p{n}")
}

pub fn tool_before(
    out: &Arc<Mutex<std::io::Stdout>>,
    pending: &Pending,
    counter: &Arc<Mutex<u64>>,
    gate: &ApprovalGate,
    params: &serde_json::Value,
) -> serde_json::Value {
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params.get("args").cloned().unwrap_or(serde_json::json!({}));
    let cwd = params
        .get("session")
        .and_then(|s| s.get("cwd"))
        .and_then(|c| c.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if name.is_empty() {
        return serde_json::json!({"decision": "deny", "reason": "empty tool name"});
    }
    match gate.check_cached(name, &args, &cwd) {
        Ok(true) => return serde_json::json!({"decision": "allow"}),
        Err(reason) => return serde_json::json!({"decision": "deny", "reason": reason}),
        Ok(false) => {}
    }
    let label = call_label(name, &args);
    let q = approval_question(name, &label, &cwd);
    let id = next_id(counter);
    let (tx, rx) = mpsc::channel();
    pending.lock().expect("pending").insert(id.clone(), tx);
    let req = serde_json::json!({
        "id": id,
        "method": "host/ask",
        "params": {
            "questions": [{
                "id": q.id,
                "header": q.header,
                "question": q.question,
                "options": q.options,
            }],
            "blocking": true,
        },
    });
    {
        let mut o = out.lock().expect("stdout");
        let _ = writeln!(o, "{req}");
        let _ = o.flush();
    }
    let picked: Vec<String> = match rx.recv_timeout(ASK_TTL) {
        Ok(result) => {
            if result.get("error").and_then(|e| e.as_str()).is_some() {
                return serde_json::json!({"decision": "deny", "reason": "approval prompt unavailable"});
            }
            result
                .get("answers")
                .and_then(|a| a.get(APPROVAL_QUESTION_ID))
                .and_then(|e| e.get("answers"))
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        }
        Err(_) => {
            return serde_json::json!({"decision": "deny", "reason": "approval timed out"});
        }
    };
    match decide_from_answers(&picked) {
        Decision::Accept => serde_json::json!({"decision": "allow"}),
        Decision::AcceptForSession => {
            gate.remember(name, &args, &cwd);
            serde_json::json!({"decision": "allow"})
        }
        Decision::Decline | Decision::Cancel => serde_json::json!({
            "decision": "deny",
            "reason": format!("{name} declined by user ({LABEL_NO}) — do NOT re-attempt via write/edit/bash workarounds; ask the user instead"),
        }),
    }
}

fn main_permissions() {
    let gate = ApprovalGate::new(&load_mode());
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let counter = Arc::new(Mutex::new(0u64));

    let (work_tx, work_rx) = mpsc::channel::<serde_json::Value>();
    let reader_pending = pending.clone();
    let reader = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            // `plugin/shutdown` is a notification (no id): stop reading so
            // the work channel closes and the main loop exits. See
            // gray-questions for the TTL rationale.
            if v.get("method").and_then(|m| m.as_str()) == Some("plugin/shutdown") {
                break;
            }
            if let Some(id) = v.get("id").and_then(|i| i.as_str())
                && v.get("method").is_none()
                && let Some(tx) = reader_pending.lock().expect("pending").remove(id)
            {
                let _ = tx.send(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
                continue;
            }
            let Some(id) = v.get("id").and_then(|i| i.as_u64()) else {
                continue;
            };
            let _ = id;
            if work_tx.send(v).is_err() {
                break;
            }
        }
    });

    for req in work_rx {
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(serde_json::json!(0));
        let params = req
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let result = match method {
            "plugin/manifest" => manifest_permissions(),
            "tool/before" => tool_before(&stdout, &pending, &counter, &gate, &params),
            "command/run" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if crate::permissions::COMMANDS.contains(&name) {
                    let argv: Vec<String> = params
                        .get("argv")
                        .and_then(|a| a.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|e| e.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let text = run_permissions_command(&gate, &argv);
                    save_mode(&gate.mode());
                    serde_json::json!({ "text": text })
                } else {
                    continue;
                }
            }
            _ => continue, // unknown methods/lines are ignored
        };
        let reply = serde_json::json!({ "id": id, "result": result });
        let mut o = stdout.lock().expect("stdout");
        let _ = writeln!(o, "{reply}");
        let _ = o.flush();
    }
    let _ = reader.join();
}
