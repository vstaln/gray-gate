//! gray-gate — one sidecar for every tool-call policy plugin.
//!
//! Merges gray-permissions, gray-confirm, gray-tool-gate, gray-guard and
//! gray-repguard. Each source lives nearly verbatim in `mods/` with its own
//! state files and slash commands — only the wire plumbing is shared.
//!
//! Hook fan-out:
//! - `tool/before` → ALL five modules; verdicts combine strictest-wins
//!   (`deny` > `modify` > `allow`), deny reasons are concatenated. Order:
//!   tool-gate, guard, repguard (cheap, non-interactive — always run so their
//!   bookkeeping stays exact), then permissions and confirm (may block on a
//!   `host/ask` prompt). Once the verdict is already `deny`, the interactive
//!   modules are not asked — the outcome can't change, so no pointless prompt.
//! - `tool/after`  → guard then repguard, chained: guard's rewritten
//!   `content` is fed to repguard, so both appendices survive.
//! - `command/run` → routed by `params.name` to the owning module.
//!   `/gate` is both tool-gate's command and this plugin's meta command:
//!   `deny|allow|list|clear` go to tool-gate, anything else prints the
//!   merged overview plus tool-gate's usage.
//!
//! permissions + confirm ask the user via `host/ask`, so the wire loop is a
//! reader thread (host replies → pending map, requests → work queue) as in
//! the originals. Their id prefixes (`p…` / `q…`) never collide.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};

#[allow(dead_code)]
#[path = "mods/confirm.rs"]
mod confirm;
#[allow(dead_code)]
#[path = "mods/guard.rs"]
mod guard;
#[allow(dead_code)]
#[path = "mods/permissions.rs"]
mod permissions;
#[allow(dead_code)]
#[path = "mods/permissions_sidecar.rs"]
mod permissions_sidecar;
#[allow(dead_code)]
#[path = "mods/repguard.rs"]
mod repguard;
#[allow(dead_code)]
#[path = "mods/tool_gate.rs"]
mod tool_gate;

fn manifest() -> Value {
    json!({
        "name": "gate",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": [
            "/gate", "/permissions", "/perms", "/access", "/confirm", "/repguard",
        ],
        "hooks": ["tool/before", "tool/after"],
        "capabilities": ["host.ask"],
    })
}

/// Everything the merged loop holds across requests.
struct Gate {
    out: Arc<Mutex<std::io::Stdout>>,
    pending: Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>>,
    counter: Arc<Mutex<u64>>,
    perm: permissions::ApprovalGate,
    confirm_patterns: Vec<regex::Regex>,
    confirm_bad: Vec<String>,
    confirm_cfg: confirm::ConfirmConfig,
    repguard: repguard::State,
}

/// Pull `result` out of a module's `(reply, exit)` pair.
fn result_of(pair: (Option<Value>, bool)) -> Value {
    pair.0
        .and_then(|r| r.get("result").cloned())
        .unwrap_or_else(|| json!({}))
}

/// Strictest-wins accumulator for `tool/before` verdicts.
#[derive(Default)]
struct Verdicts {
    denied: bool,
    modified: Option<Value>,
    reasons: Vec<String>,
    messages: Vec<String>,
}

impl Verdicts {
    fn add(&mut self, r: &Value) {
        match r.get("decision").and_then(Value::as_str) {
            Some("deny") => {
                self.denied = true;
                if let Some(reason) = r.get("reason").and_then(Value::as_str)
                    && !reason.trim().is_empty()
                {
                    self.reasons.push(reason.trim_end().to_string());
                }
            }
            Some("modify") => {
                if let Some(a) = r.get("args") {
                    self.modified = Some(a.clone());
                }
            }
            _ => {}
        }
        for k in ["message", "text", "nudge"] {
            if let Some(m) = r.get(k).and_then(Value::as_str)
                && !m.trim().is_empty()
            {
                self.messages.push(m.trim_end().to_string());
            }
        }
    }

    fn finish(self) -> Value {
        let mut out = if self.denied {
            let mut v = json!({ "decision": "deny" });
            if !self.reasons.is_empty() {
                v["reason"] = json!(self.reasons.join("\n\n"));
            }
            v
        } else if let Some(args) = self.modified {
            json!({ "decision": "modify", "args": args })
        } else {
            json!({ "decision": "allow" })
        };
        if !self.messages.is_empty() {
            out["message"] = json!(self.messages.join("\n\n"));
        }
        out
    }
}

/// `tool/before` fan-out — every owner runs; deny wins.
fn tool_before(g: &Gate, req: &Value) -> Value {
    let mut req = req.clone();
    let mut v = Verdicts::default();
    // Re-point later modules at modified args, if an earlier one rewrote them.
    let step = |r: Value, req: &mut Value, v: &mut Verdicts| {
        v.add(&r);
        if r.get("decision").and_then(Value::as_str) == Some("modify")
            && let Some(a) = r.get("args")
        {
            req["params"]["args"] = a.clone();
        }
    };
    let r = result_of(tool_gate::handle_tool_gate(&req));
    step(r, &mut req, &mut v);
    let r = result_of(guard::handle_guard(&req));
    step(r, &mut req, &mut v);
    let r = result_of(repguard::handle_repguard(&req, &g.repguard));
    step(r, &mut req, &mut v);
    if !v.denied {
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let r = permissions_sidecar::tool_before(&g.out, &g.pending, &g.counter, &g.perm, &params);
        step(r, &mut req, &mut v);
    }
    if !v.denied {
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let r = confirm::tool_before(
            &g.out,
            &g.pending,
            &g.counter,
            &g.confirm_patterns,
            &g.confirm_cfg,
            &params,
        );
        step(r, &mut req, &mut v);
    }
    v.finish()
}

/// `tool/after` chain — guard then repguard; each sees the previous
/// module's rewritten fields (`content`, `is_error`), so both appendices
/// survive. `{}` when nobody rewrote anything.
fn tool_after(g: &Gate, req: &Value) -> Value {
    let mut req = req.clone();
    let mut changed = serde_json::Map::new();
    let mut apply = |r: Value, req: &mut Value| {
        if let Some(obj) = r.as_object() {
            for (k, val) in obj {
                changed.insert(k.clone(), val.clone());
                req["params"][k] = val.clone();
            }
        }
    };
    let r = result_of(guard::handle_guard(&req));
    apply(r, &mut req);
    let r = result_of(repguard::handle_repguard(&req, &g.repguard));
    apply(r, &mut req);
    Value::Object(changed)
}

fn argv_of(params: &Value) -> Vec<String> {
    params
        .get("argv")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// `/gate` with no tool-gate subcommand — merged-plugin overview.
fn gate_overview(req: &Value) -> String {
    let tg = result_of(tool_gate::handle_tool_gate(req));
    let tg = tg.get("text").and_then(Value::as_str).unwrap_or("");
    format!(
        "gray-gate {} — one sidecar, five tool-call policies (strictest verdict wins):\n\
         \x20 /permissions (/perms, /access)  approval mode read-only|auto|full + host prompts\n\
         \x20 /confirm    confirm dangerous bash commands (on|off|list)\n\
         \x20 /gate       persisted tool deny-list (deny|allow|list|clear <glob>)\n\
         \x20 guard       security warnings on risky file writes (no command)\n\
         \x20 /repguard   nudge out of identical-call loops\n\n{tg}",
        env!("CARGO_PKG_VERSION")
    )
}

fn command_run(g: &Gate, req: &Value) -> Value {
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let argv = argv_of(&params);
    match name {
        "/gate" => match argv.first().map(String::as_str) {
            Some("deny" | "allow" | "list" | "clear") => {
                result_of(tool_gate::handle_tool_gate(req))
            }
            _ => json!({ "text": gate_overview(req) }),
        },
        "/permissions" | "/perms" | "/access" => {
            let text = permissions::run_permissions_command(&g.perm, &argv);
            permissions_sidecar::save_mode(&g.perm.mode());
            json!({ "text": text })
        }
        "/confirm" => {
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            json!({ "text": confirm::run_command(&argv, &g.confirm_patterns, &g.confirm_bad, &g.confirm_cfg) })
        }
        "/repguard" => result_of(repguard::handle_repguard(req, &g.repguard)),
        _ => json!({ "text": format!("unknown command {name} — try /gate") }),
    }
}

fn handle(g: &Gate, req: &Value) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest(),
        "tool/before" => tool_before(g, req),
        "tool/after" => tool_after(g, req),
        "command/run" => command_run(g, req),
        "tool/call" => json!({ "content": "gate has no tools", "is_error": true }),
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest());
        return;
    }
    let (confirm_patterns, confirm_bad) = confirm::load_patterns();
    let g = Gate {
        out: Arc::new(Mutex::new(std::io::stdout())),
        pending: Arc::new(Mutex::new(HashMap::new())),
        counter: Arc::new(Mutex::new(0u64)),
        perm: permissions::ApprovalGate::new(&permissions_sidecar::load_mode()),
        confirm_patterns,
        confirm_bad,
        confirm_cfg: confirm::load_config(),
        repguard: Mutex::new(HashMap::new()),
    };

    // Reader thread: host answers (string id, no method) resolve `pending`;
    // requests and the shutdown notification go to the work queue.
    let (work_tx, work_rx) = mpsc::channel::<Value>();
    let reader_pending = g.pending.clone();
    let _reader = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(id) = v.get("id").and_then(Value::as_str)
                && v.get("method").is_none()
            {
                if let Some(tx) = reader_pending.lock().expect("pending").remove(id) {
                    let _ = tx.send(v.get("result").cloned().unwrap_or(Value::Null));
                }
                continue;
            }
            let shutdown = v.get("method").and_then(Value::as_str) == Some("plugin/shutdown");
            if (v.get("id").is_some() || shutdown) && work_tx.send(v).is_err() {
                break;
            }
            if shutdown {
                break;
            }
        }
    });

    for req in work_rx {
        let (reply, exit) = handle(&g, &req);
        if let Some(reply) = reply {
            let mut o = g.out.lock().expect("stdout");
            let _ = writeln!(o, "{reply}");
            let _ = o.flush();
        }
        if exit {
            break;
        }
    }
    // The reader is a detached stdin pump; returning ends the process.
}
