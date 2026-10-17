//! `gray_permissions` shared core: approval modes, static verdicts, and the
//! `/permissions` command model. The sidecar binary (`src/main.rs`) and any
//! host-side helpers must agree on these; this lib is the single definition.
//!
//! History: reshaped from gray's former `crates/gray-core/src/approvals.rs`
//! as a sidecar: the plugin owns policy, the host owns user I/O via
//! `host/ask` (owned by the `gray-questions` contract).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Codex approval preset ids, reused as gray's on-disk mode strings.
pub const MODE_READ_ONLY: &str = "read-only";
pub const MODE_AUTO: &str = "auto";
pub const MODE_FULL: &str = "full";

/// Plugin name claimed in `plugin/manifest`.
pub const PLUGIN_NAME: &str = "permissions";
/// Protocol version claimed in `plugin/manifest`.
pub const PROTOCOL: &str = "1.1";
/// Slash commands claimed in `plugin/manifest`.
pub const COMMANDS: &[&str] = &["/permissions", "/perms", "/access"];
/// Hook claimed in `plugin/manifest`.
pub const HOOK_TOOL_BEFORE: &str = "tool/before";

/// Per-call verdict the gate can return without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(&'static str),
    Ask,
}

/// User decision on an asked call (codex decision subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    AcceptForSession,
    Decline,
    Cancel,
}

/// One question row sent to `host/ask` for an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskQuestion {
    pub id: String,
    pub header: String,
    pub question: String,
    pub options: Vec<AskOption>,
}

/// One option row sent to `host/ask` for an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskOption {
    pub label: String,
    pub description: String,
}

/// Exact labels rendered above (display text is untrusted input:
/// substring matching once escalated any note containing "always" into
/// session-wide memory — kept from the original).
pub const LABEL_ONCE: &str = "Yes (Recommended)";
pub const LABEL_SESSION: &str = "Yes, for session";
pub const LABEL_NO: &str = "No";

pub const APPROVAL_QUESTION_ID: &str = "tool-approval";

/// Session-scoped memory of accepted calls (codex `with_cached_approval`).
#[derive(Debug, Default)]
pub struct ApprovalCache {
    paths: Mutex<HashSet<PathBuf>>,
    commands: Mutex<HashSet<String>>,
}

impl ApprovalCache {
    pub fn remember_path(&self, path: PathBuf) {
        let _ = self.paths.lock().map(|mut g| g.insert(path));
    }

    pub fn remembered_path(&self, path: &Path) -> bool {
        self.paths.lock().map(|g| g.contains(path)).unwrap_or(false)
    }

    /// Raw command bytes are the cache identity: any normalization risks
    /// approving a different shell program. Different bytes re-ask.
    pub fn remember_command(&self, command: String) {
        let _ = self.commands.lock().map(|mut g| g.insert(command));
    }

    pub fn remembered_command(&self, command: &str) -> bool {
        self.commands
            .lock()
            .map(|g| g.contains(command))
            .unwrap_or(false)
    }
}

/// Approval mode + session memory. `Clone` shares both across calls.
#[derive(Debug, Clone)]
pub struct ApprovalGate {
    mode: Arc<Mutex<String>>,
    cache: Arc<ApprovalCache>,
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new(MODE_AUTO.to_string())),
            cache: Arc::new(ApprovalCache::default()),
        }
    }
}

impl ApprovalGate {
    pub fn new(mode: &str) -> Self {
        let gate = Self::default();
        gate.set_mode(mode);
        gate
    }

    pub fn mode(&self) -> String {
        self.mode
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Sets the mode; unknown values fall back to `auto` (fail safe).
    pub fn set_mode(&self, mode: &str) {
        let clean = normalize_mode(mode).unwrap_or(MODE_AUTO);
        if let Ok(mut g) = self.mode.lock() {
            *g = clean.to_string();
        }
    }

    /// Static verdict + session memory, without asking. `Ok(true)` = run,
    /// `Ok(false)` = must ask, `Err(msg)` = deny.
    pub fn check_cached(
        &self,
        tool: &str,
        args: &serde_json::Value,
        cwd: &Path,
    ) -> Result<bool, String> {
        match verdict(&self.mode(), tool, args, cwd) {
            Verdict::Allow => Ok(true),
            Verdict::Deny(msg) => Err(msg.to_string()),
            Verdict::Ask => {
                if (tool == "write" || tool == "edit")
                    && let Some(p) = tool_path(args)
                {
                    let full = if Path::new(&p).is_absolute() {
                        PathBuf::from(&p)
                    } else {
                        cwd.join(&p)
                    };
                    if self.cache.remembered_path(&full) {
                        return Ok(true);
                    }
                }
                if tool == "bash"
                    && let Some(cmd) = args.get("command").and_then(|v| v.as_str())
                    && self.cache.remembered_command(cmd)
                {
                    return Ok(true);
                }
                Ok(false)
            }
        }
    }

    /// Remember an accepted call for the rest of the session.
    pub fn remember(&self, tool: &str, args: &serde_json::Value, cwd: &Path) {
        if (tool == "write" || tool == "edit")
            && let Some(p) = tool_path(args)
        {
            let full = if Path::new(&p).is_absolute() {
                PathBuf::from(&p)
            } else {
                cwd.join(&p)
            };
            self.cache.remember_path(full);
        }
        if tool == "bash"
            && let Some(cmd) = args.get("command").and_then(|v| v.as_str())
        {
            self.cache.remember_command(cmd.to_string());
        }
    }
}

/// Parses a mode string; `None` when unknown.
pub fn normalize_mode(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().replace(' ', "-").as_str() {
        "read-only" | "readonly" | "read_only" | "ro" => Some(MODE_READ_ONLY),
        "auto" | "ask" | "default" | "ask-for-approval" | "workspace" => Some(MODE_AUTO),
        "full" | "full-access" | "full_access" | "never" | "yolo" => Some(MODE_FULL),
        _ => None,
    }
}

/// One row of the `/permissions` picker: (mode id, label, description),
/// mirroring codex's preset label + description copy.
pub fn permission_modes() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            MODE_AUTO,
            "Ask for approval",
            "Read and edit files in the workspace. Every command and anything outside the workspace asks for approval.",
        ),
        (
            MODE_FULL,
            "Full Access",
            "No approval prompts: edits and commands run unattended. Exercise caution.",
        ),
        (
            MODE_READ_ONLY,
            "Read Only",
            "Read-only tools only: edits, commands, and network access are denied.",
        ),
    ]
}

/// Extracts the target path from tool args (same alias set the tools use).
pub fn tool_path(args: &serde_json::Value) -> Option<String> {
    args.get("path")
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("file"))
        .or_else(|| args.get("filename"))
        .or_else(|| args.get("target"))
        .or_else(|| args.get("destination"))
        .or_else(|| args.get("target_file"))
        .or_else(|| args.get("targetFile"))
        .or_else(|| args.get("TargetFile"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// True when `path` resolves inside `cwd` (nearest-existing-ancestor walk
/// with symlink resolution; unresolvable returns false — uncertainty asks).
pub fn path_in_cwd(cwd: &Path, path: &str) -> bool {
    use std::ffi::OsString;
    let joined: PathBuf = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };
    let Ok(root) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let mut ancestor: &Path = &joined;
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        if ancestor.exists() {
            break;
        }
        match ancestor.file_name() {
            Some(name) => {
                missing.push(name.to_os_string());
                match ancestor.parent() {
                    Some(parent) => ancestor = parent,
                    None => return false,
                }
            }
            None => return false,
        }
    }
    let Ok(mut target) = std::fs::canonicalize(ancestor) else {
        return false;
    };
    for comp in missing.iter().rev() {
        let p = Path::new(comp);
        if p.components().count() != 1
            || !matches!(p.components().next(), Some(std::path::Component::Normal(_)))
        {
            return false;
        }
        target.push(comp);
    }
    target.starts_with(root)
}

/// Static verdict for a tool call: no asking, no session memory yet.
pub fn verdict(mode: &str, tool: &str, args: &serde_json::Value, cwd: &Path) -> Verdict {
    match normalize_mode(mode).unwrap_or(MODE_AUTO) {
        MODE_FULL => Verdict::Allow,
        MODE_READ_ONLY => match tool {
            "read" | "ls" | "find" | "grep" | "skill" | "request_user_input" => Verdict::Allow,
            _ => Verdict::Deny("read-only mode: mutating tools are disabled"),
        },
        _ => match tool {
            "read" | "ls" | "find" | "grep" | "skill" | "request_user_input" => Verdict::Allow,
            "write" | "edit" => match tool_path(args) {
                Some(p) if path_in_cwd(cwd, &p) => Verdict::Allow,
                Some(_) => Verdict::Ask,
                None => Verdict::Ask,
            },
            "bash" => Verdict::Ask,
            // Fail closed: unknown/sidecar tools prompt, never silent Allow.
            _ => Verdict::Ask,
        },
    }
}

/// Build the `host/ask` question for an approval. Full target, no
/// truncation: a prompt hiding the tail of a command approves something
/// the user did not see.
pub fn approval_question(tool: &str, label: &str, cwd: &Path) -> AskQuestion {
    AskQuestion {
        id: APPROVAL_QUESTION_ID.to_string(),
        header: "Allow?".to_string(),
        question: format!(
            "Allow {tool}?\n{label}\nWorking directory: {}",
            cwd.display()
        ),
        options: vec![
            AskOption {
                label: LABEL_ONCE.to_string(),
                description: "Run this once.".to_string(),
            },
            AskOption {
                label: LABEL_SESSION.to_string(),
                description: "Run this and remember for the rest of the session.".to_string(),
            },
            AskOption {
                label: LABEL_NO.to_string(),
                description: "Skip it; the turn continues.".to_string(),
            },
        ],
    }
}

/// Map a `host/ask` result to a [`Decision`]. Fail-closed: anything but an
/// explicit accept denies (Esc always cancels, like codex).
pub fn decide_from_answers(answers: &[String]) -> Decision {
    // Exact matches on the labels rendered above.
    if answers.iter().any(|a| a == LABEL_SESSION) {
        Decision::AcceptForSession
    } else if answers.iter().any(|a| a == LABEL_ONCE) {
        Decision::Accept
    } else {
        Decision::Decline
    }
}

/// Short human label for a tool call (command or path), for the ask prompt.
pub fn call_label(tool: &str, args: &serde_json::Value) -> String {
    if tool == "bash" {
        return args
            .get("command")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("(empty command)")
            .to_string();
    }
    tool_path(args).unwrap_or_else(|| args.to_string())
}

/// Handle `/permissions` argv: `[]` prints mode + usage; `[mode]` sets it.
pub fn run_permissions_command(gate: &ApprovalGate, argv: &[String]) -> String {
    match argv.first().map(|s| s.as_str()) {
        None => {
            let mut out = format!("permissions: {}\n", gate.mode());
            out.push_str("usage: /permissions <read-only|auto|full>\n");
            for (id, label, desc) in permission_modes() {
                out.push_str(&format!("  {id} — {label}: {desc}\n"));
            }
            out
        }
        Some(mode) => match normalize_mode(mode) {
            Some(clean) => {
                gate.set_mode(clean);
                format!("permissions: {clean}")
            }
            None => format!("unknown mode {mode:?} — usage: /permissions <read-only|auto|full>"),
        },
    }
}

/// The `plugin/manifest` result value.
pub fn manifest_permissions() -> serde_json::Value {
    serde_json::json!({
        "name": PLUGIN_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": PROTOCOL,
        "tools": [],
        "commands": COMMANDS,
        "hooks": [HOOK_TOOL_BEFORE],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cwd() -> PathBuf {
        PathBuf::from("/work/proj")
    }

    #[test]
    fn normalize_accepts_aliases_and_rejects_unknown() {
        assert_eq!(normalize_mode("read-only"), Some(MODE_READ_ONLY));
        assert_eq!(normalize_mode("RO"), Some(MODE_READ_ONLY));
        assert_eq!(normalize_mode("auto"), Some(MODE_AUTO));
        assert_eq!(normalize_mode("Full Access"), Some(MODE_FULL));
        assert_eq!(normalize_mode("yolo"), Some(MODE_FULL));
        assert_eq!(normalize_mode("bogus"), None);
    }

    #[test]
    fn full_allows_everything() {
        for tool in ["read", "write", "edit", "bash", "schedule_task", "whatever"] {
            assert_eq!(
                verdict("full", tool, &json!({}), &cwd()),
                Verdict::Allow,
                "{tool}"
            );
        }
    }

    #[test]
    fn read_only_denies_mutations_but_allows_reads() {
        for tool in ["read", "ls", "find", "grep", "skill", "request_user_input"] {
            assert_eq!(
                verdict("read-only", tool, &json!({}), &cwd()),
                Verdict::Allow,
                "{tool}"
            );
        }
        for tool in ["write", "edit", "bash", "schedule_task"] {
            assert!(
                matches!(
                    verdict("read-only", tool, &json!({}), &cwd()),
                    Verdict::Deny(_)
                ),
                "{tool}"
            );
        }
    }

    #[test]
    fn auto_verdict_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let existing = work.join("a.rs");
        std::fs::write(&existing, "x").unwrap();
        assert_eq!(verdict("auto", "read", &json!({}), &work), Verdict::Allow);
        assert_eq!(
            verdict("auto", "write", &json!({"path": "a.rs"}), &work),
            Verdict::Allow
        );
        assert_eq!(
            verdict("auto", "bash", &json!({"command": "ls"}), &cwd()),
            Verdict::Ask
        );
        assert_eq!(verdict("auto", "write", &json!({}), &work), Verdict::Ask);
        assert_eq!(
            verdict("auto", "write", &json!({"path": "/etc/passwd"}), &work),
            Verdict::Ask
        );
        assert_eq!(
            verdict("auto", "schedule_task", &json!({}), &cwd()),
            Verdict::Ask
        );
    }

    #[test]
    fn unknown_tools_fail_closed_in_auto() {
        for tool in ["whatever", "sidecar_plugin_tool", "schedule_task", ""] {
            assert_eq!(
                verdict("auto", tool, &json!({}), &cwd()),
                Verdict::Ask,
                "{tool} must prompt, never silent Allow"
            );
        }
    }

    #[test]
    fn cached_gate_remembers_session_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let gate = ApprovalGate::new("auto");
        // bash always asks the first time…
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls"}), &work),
            Ok(false)
        );
        // …until remembered.
        gate.remember("bash", &json!({"command": "ls"}), &work);
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls"}), &work),
            Ok(true)
        );
        // Different bytes re-ask.
        assert_eq!(
            gate.check_cached("bash", &json!({"command": "ls  "}), &work),
            Ok(false)
        );
    }

    #[test]
    fn decide_exact_labels_only() {
        assert_eq!(
            decide_from_answers(&[LABEL_SESSION.into()]),
            Decision::AcceptForSession
        );
        assert_eq!(decide_from_answers(&[LABEL_ONCE.into()]), Decision::Accept);
        // Substring must NOT escalate (the old "always" bug class).
        assert_eq!(
            decide_from_answers(&["user_note: always do this".into()]),
            Decision::Decline
        );
        assert_eq!(decide_from_answers(&[]), Decision::Decline);
    }

    #[test]
    fn manifest_shape() {
        let m = manifest_permissions();
        assert_eq!(m["name"], "permissions");
        assert_eq!(m["protocol"], "1.1");
        assert!(
            m["commands"]
                .as_array()
                .unwrap()
                .contains(&json!("/permissions"))
        );
        assert_eq!(m["hooks"], json!(["tool/before"]));
    }

    #[test]
    fn permissions_command_sets_and_prints() {
        let gate = ApprovalGate::new("auto");
        assert!(run_permissions_command(&gate, &[]).contains("auto"));
        assert_eq!(
            run_permissions_command(&gate, &["full".to_string()]),
            "permissions: full"
        );
        assert_eq!(gate.mode(), "full");
        assert!(run_permissions_command(&gate, &["bogus".to_string()]).contains("unknown mode"));
    }
}
