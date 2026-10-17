//! gray-tool-gate — a persisted deny-list for tools.
//!
//! Port of pi's `tools.ts` (MIT), flattened to a sidecar: instead of an
//! interactive TUI selector, `tool/before` checks every tool call's `name`
//! against ~/.gray/tool-gate/deny.txt — one pattern per line, `#` comments,
//! `*`/`?` globs (`git-*` matches `git-foo`). A match answers
//! `{decision:"deny"}` with a pointer at `/gate allow`.
//!
//! `/gate deny <pat> | allow <pat> | list | clear` edits the file.
//!
//! This is a GUARD: it fails closed only on an explicit match. A missing
//! file denies nothing; any read error is logged to stderr and allows.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

fn manifest_tool_gate() -> Value {
    json!({
        "name": "tool-gate",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": ["/gate"],
        "hooks": ["tool/before"],
    })
}

fn state_dir() -> PathBuf {
    std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tool-gate")
}

fn deny_file() -> PathBuf {
    state_dir().join("deny.txt")
}

/// Deny patterns from deny.txt. Missing file → empty list (nothing denied);
/// a read error is logged and treated as empty (fail open for non-matches).
fn deny_list() -> Vec<String> {
    match std::fs::read_to_string(deny_file()) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect(),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("gray-tool-gate: can't read {}: {e}", deny_file().display());
            }
            Vec::new()
        }
    }
}

fn write_deny_list(list: &[String]) -> std::io::Result<()> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(deny_file(), list.join("\n") + if list.is_empty() { "" } else { "\n" })
}

/// Glob match: `*` any run, `?` one char, everything else literal.
fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn tool_before(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    for pat in deny_list() {
        if glob_match(&pat, name) {
            return json!({
                "decision": "deny",
                "reason": format!("{name} denied by tool-gate (/gate allow {pat} to re-enable)")
            });
        }
    }
    json!({"decision": "allow"})
}

/// `/gate …` — `argv` excludes the command name.
fn run_command(argv: &[&str]) -> String {
    match argv.first().copied() {
        Some("deny") => match argv.get(1) {
            Some(pat) => {
                let mut list = deny_list();
                if list.iter().any(|p| p == pat) {
                    format!("{pat} already denied")
                } else {
                    list.push(pat.to_string());
                    match write_deny_list(&list) {
                        Ok(()) => format!("denied {pat}"),
                        Err(e) => format!("couldn't write {}: {e}", deny_file().display()),
                    }
                }
            }
            None => "usage: /gate deny <tool-or-glob>".into(),
        },
        Some("allow") => match argv.get(1) {
            Some(pat) => {
                let mut list = deny_list();
                let before = list.len();
                list.retain(|p| p != pat);
                if list.len() == before {
                    format!("{pat} wasn't denied")
                } else {
                    match write_deny_list(&list) {
                        Ok(()) => format!("allowed {pat}"),
                        Err(e) => format!("couldn't write {}: {e}", deny_file().display()),
                    }
                }
            }
            None => "usage: /gate allow <tool-or-glob>".into(),
        },
        Some("list") => {
            let list = deny_list();
            if list.is_empty() {
                "no denied tools".into()
            } else {
                format!("denied: {}", list.join(", "))
            }
        }
        Some("clear") => match write_deny_list(&[]) {
            Ok(()) => "deny list cleared".into(),
            Err(e) => format!("couldn't write {}: {e}", deny_file().display()),
        },
        _ => format!(
            "gray-tool-gate {} — persisted tool deny-list in {}. \
             /gate deny <pat> | allow <pat> | list | clear (globs: *, ?)",
            env!("CARGO_PKG_VERSION"),
            deny_file().display()
        ),
    }
}

/// One request → `Some(reply)`, or `None` for notifications. The bool asks
/// the loop to exit after writing the reply.
pub fn handle_tool_gate(req: &Value) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest_tool_gate(),
        "tool/before" => tool_before(&params),
        "command/run" => {
            let argv: Vec<&str> = params
                .get("argv")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            json!({ "text": run_command(&argv) })
        }
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

fn main_tool_gate() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest_tool_gate());
        return Ok(());
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let (reply, exit) = handle_tool_gate(&req);
        if let Some(reply) = reply {
            writeln!(stdout, "{reply}")?;
            stdout.flush()?;
        }
        if exit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(method: &str, params: Value) -> Value {
        handle_tool_gate(&json!({ "id": 1, "method": method, "params": params }))
            .0
            .unwrap()
    }

    #[test]
    fn manifest_shape() {
        let m = manifest_tool_gate();
        assert_eq!(m["name"], "tool-gate");
        assert_eq!(m["hooks"], json!(["tool/before"]));
        assert_eq!(m["commands"], json!(["/gate"]));
    }

    /// Serializes tests that mutate the process-wide GRAY_HOME env var.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn glob_matcher() {
        assert!(glob_match("git-*", "git-foo"));
        assert!(glob_match("git-*", "git-"));
        assert!(glob_match("ba?h", "bash"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("bash", "bash"));
        assert!(!glob_match("git-*", "gitx"));
        assert!(!glob_match("bash", "bashful"));
        assert!(!glob_match("ba?", "bash"));
    }

    #[test]
    fn deny_allow_roundtrip() {
        // Use a scratch GRAY_HOME so the test never touches the real list.
        let _env = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("gray-gate-test-{}", std::process::id()));
        unsafe { std::env::set_var("GRAY_HOME", &dir) };

        let r = call("command/run", json!({"name": "/gate", "argv": ["deny", "rm-*"]}));
        assert!(r["result"]["text"].as_str().unwrap().contains("denied rm-*"));

        let r = call("tool/before", json!({"name": "rm-tmp", "args": {}, "session": {}}));
        assert_eq!(r["result"]["decision"], "deny");
        assert!(r["result"]["reason"].as_str().unwrap().contains("/gate allow rm-*"));

        // non-matching tools still pass
        let r = call("tool/before", json!({"name": "bash", "args": {}, "session": {}}));
        assert_eq!(r["result"]["decision"], "allow");

        let r = call("command/run", json!({"name": "/gate", "argv": ["allow", "rm-*"]}));
        assert!(r["result"]["text"].as_str().unwrap().contains("allowed"));
        let r = call("tool/before", json!({"name": "rm-tmp", "args": {}, "session": {}}));
        assert_eq!(r["result"]["decision"], "allow");

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("GRAY_HOME") };
    }

    #[test]
    fn missing_file_denies_nothing() {
        let _env = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("gray-gate-empty-{}", std::process::id()));
        unsafe { std::env::set_var("GRAY_HOME", &dir) };
        let r = call("tool/before", json!({"name": "bash", "args": {}, "session": {}}));
        assert_eq!(r["result"]["decision"], "allow");
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("GRAY_HOME") };
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let _env = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("gray-gate-cfg-{}", std::process::id()));
        unsafe { std::env::set_var("GRAY_HOME", &dir) };
        std::fs::create_dir_all(dir.join("tool-gate")).unwrap();
        std::fs::write(dir.join("tool-gate/deny.txt"), "# comment\n\n  web_fetch  \n").unwrap();
        assert_eq!(deny_list(), vec!["web_fetch".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("GRAY_HOME") };
    }

    #[test]
    fn shutdown_replies_then_exits() {
        let (reply, exit) = handle_tool_gate(&json!({ "id": 2, "method": "plugin/shutdown" }));
        assert!(reply.is_some() && exit);
    }
}
