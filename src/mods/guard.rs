//! gray-guard — pattern-matched security warnings on file writes.
//!
//! Scans the content written by write/edit/patch-shaped tools — and
//! bash heredoc writes — for ~25 dangerous-code patterns (eval(, pickle.load,
//! yaml.load sans SafeLoader, os.system, subprocess shell=True,
//! dangerouslySetInnerHTML, verify=False, ECB, XXE parsers,
//! ${{ github.event.* }} injection, torch.load sans weights_only, …).
//!
//! `post_tool`/`tool/after` carries no args, so `tool/before` stashes the
//! last write's (path, content) per (session, tool) in memory and
//! `tool/after` appends a `⚠️ Security warning:` block to the result —
//! non-blocking, the file is already written; the model self-corrects.
//! `SECURITY_GUIDANCE_BLOCK=1` instead denies in `tool/before`.
//! `SECURITY_GUIDANCE_DISABLE=1` turns the plugin off.
//! Scan cap: 256 KiB per string arg.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::{LazyLock, Mutex};

use serde_json::{Value, json};

/// Above this we skip — pattern matching a huge blob has poor
/// signal-to-noise and would slow the agent loop.
const MAX_SCAN_BYTES: usize = 256 * 1024;

/// Write-shaped tools whose args carry code being written to disk.
const WRITE_TOOLS: &[&str] = &[
    "write", "edit", "patch", "write_file", "apply_patch", "multi_edit", "notebook_edit",
];

const JS_EXTS: &[&str] = &[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"];
const PY_EXTS: &[&str] = &[".py", ".pyi", ".ipynb"];
const DOC_EXTS: &[&str] = &[".md", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml"];

const UNSAFE_DESERIALIZATION_REMINDER: &str = "Loading pickle data (or equivalents: cPickle, cloudpickle, dill, marshal, shelve, joblib, pandas.read_pickle, numpy with allow_pickle=True) from untrusted sources allows arbitrary code execution.\n\nFor simple data, prefer JSON or msgspec. For typed objects, prefer a schema-validated deserializer (msgspec.Struct, pydantic, marshmallow) that constructs only declared types.\n\nIf this is safe or is explicitly needed, briefly document that in a comment before continuing.";

const UNSAFE_YAML_LOAD_REMINDER: &str = "yaml.load() / yaml.unsafe_load() execute arbitrary Python via !!python/object tags.\n\nUse yaml.safe_load() if the file only contains simple data structures (dicts, lists, strings, numbers). If you need typed objects, parse with safe_load and validate the result against a schema (pydantic, msgspec, marshmallow) — never use a custom Loader that constructs arbitrary types.";

const UNSAFE_TORCH_LOAD_REMINDER: &str = "torch.load() deserializes with pickle under the hood — a malicious .pt/.pth/.ckpt file executes arbitrary code.\n\nIf the file only contains tensors and simple data structures, pass weights_only=True (or set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1).";

const GITHUB_WORKFLOW_REMINDER: &str = "You are editing a GitHub Actions workflow file. Be aware of these security risks:\n\n1. **Command Injection**: Never use untrusted input (like issue titles, PR descriptions, commit messages) directly in run: commands without proper escaping\n2. **Use environment variables**: Instead of ${{ github.event.issue.title }}, use env: with proper quoting\n3. **Review the guide**: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/\n\nExample of UNSAFE pattern to avoid:\nrun: echo \"${{ github.event.issue.title }}\"\n\nExample of SAFE pattern:\nenv:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"$TITLE\"\n\nOther risky inputs to be careful with: github.event.issue.body, pull_request.title/body, comment.body, review.body, review_comment.body, pages.*.page_name, commits.*.message, head_commit.message/author.*, commits.*.author.*, pull_request.head.ref/label/repo.default_branch, client_payload.*, github.head_ref\n\n4. **Ref injection**: Never use untrusted input in `ref:` parameters of `actions/checkout`. For `client_payload.pr_number`, validate it matches `^[0-9]+$` before using in `ref: refs/pull/${{ ... }}/head`";

const CHILD_PROCESS_EXEC_REMINDER: &str = "Using child_process.exec() can lead to command injection vulnerabilities.\n\nexec() runs the command string through a shell, so any user input interpolated into it can inject arbitrary commands. Prefer child_process.execFile() (or spawn()) with an argument array instead of building a shell string.\n\nInstead of:\n  exec(`command ${userInput}`)\n\nUse:\n  import { execFile } from 'node:child_process'\n  execFile('command', [userInput], callback)\n\nWhy execFile/spawn with an argument array is safer:\n- No shell is involved, so shell metacharacters in arguments are not interpreted\n- Arguments are passed directly to the program rather than interpolated into a command string\n\nOnly use exec() if you absolutely need shell features and the input is guaranteed to be safe.";

const SUBPROCESS_SHELL_REMINDER: &str = "Using subprocess with shell=True enables command injection.\n\nUNSAFE:\n  subprocess.run(f\"ls {user_input}\", shell=True)\n  subprocess.call(\"grep \" + pattern, shell=True)\n\nSAFE - pass arguments as a list without shell:\n  subprocess.run([\"ls\", user_input])\n  subprocess.call([\"grep\", pattern])\n\nWhen arguments are passed as a list without shell=True, special characters cannot be interpreted as shell metacharacters.";

const GO_EXEC_SHELL_REMINDER: &str = "Using exec.Command with a shell interpreter (sh/bash) enables command injection.\n\nUNSAFE:\n  exec.Command(\"sh\", \"-c\", \"ping -c 1 \" + host)\n  exec.Command(\"bash\", \"-c\", fmt.Sprintf(\"df -h %s\", path))\n\nSAFE - pass arguments directly without a shell:\n  exec.Command(\"ping\", \"-c\", \"1\", host)\n  exec.Command(\"df\", \"-h\", path)\n\nWhen arguments are passed directly (not through a shell), special characters in user input cannot be interpreted as shell metacharacters. This prevents command injection entirely.\n\nAdditionally, validate user inputs:\n- For hostnames/IPs: use net.ParseIP() or a hostname regex\n- For file paths: use filepath.Clean() and verify the result is within an allowed directory\n- For numeric values: parse to int/float first";

/// Which paths a rule applies to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathFilter {
    Any,
    JsOnly,
    PyOnly,
    NotDoc,
    /// Fires purely on the path (no content scan) — GitHub workflows.
    GithubWorkflow,
}

struct Rule {
    name: &'static str,
    reminder: &'static str,
    filter: PathFilter,
    substrings: &'static [&'static str],
    regex: Option<&'static str>,
}

const RULES: &[Rule] = &[
    Rule { name: "github_actions_workflow", reminder: GITHUB_WORKFLOW_REMINDER, filter: PathFilter::GithubWorkflow, substrings: &[], regex: None },
    Rule { name: "child_process_exec", reminder: CHILD_PROCESS_EXEC_REMINDER, filter: PathFilter::JsOnly,
        substrings: &["child_process.exec", "execSync("],
        regex: Some(r"(?<![a-zA-Z0-9_\.])exec\(") },
    Rule { name: "new_function_injection",
        reminder: "new Function() is equivalent to eval() and can execute arbitrary code. To access properties use obj[key] or array.reduce((o, k) => o[k], root); for computation use a safe expression parser. NEVER interpolate untrusted strings into new Function() bodies.",
        filter: PathFilter::Any, substrings: &["new Function"], regex: None },
    Rule { name: "eval_injection",
        reminder: "eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data, ast.literal_eval() for Python literals, or a safe expression parser. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
        filter: PathFilter::NotDoc, substrings: &[],
        regex: Some(r"(?<![a-zA-Z0-9_\.])eval\(") },
    Rule { name: "react_dangerously_set_html",
        reminder: "dangerouslySetInnerHTML can lead to XSS vulnerabilities if used with untrusted content. Ensure all content is properly sanitized using an HTML sanitizer library like DOMPurify, or use safe alternatives.",
        filter: PathFilter::Any, substrings: &["dangerouslySetInnerHTML"], regex: None },
    Rule { name: "document_write_xss",
        reminder: "document.write() can be exploited for XSS attacks and has performance issues. Use DOM manipulation methods like createElement() and appendChild() instead.",
        filter: PathFilter::Any, substrings: &["document.write"], regex: None },
    Rule { name: "innerHTML_xss",
        reminder: "Setting innerHTML with untrusted content can lead to XSS vulnerabilities. Use textContent for plain text or safe DOM methods for HTML content. If you need HTML support, consider using an HTML sanitizer library such as DOMPurify.",
        filter: PathFilter::Any, substrings: &[".innerHTML =", ".innerHTML="], regex: None },
    Rule { name: "pickle_deserialization", reminder: UNSAFE_DESERIALIZATION_REMINDER, filter: PathFilter::PyOnly, substrings: &[],
        regex: Some(r"(?<![a-zA-Z0-9_])pickle\.(loads?|Unpickler)\b|(?<![a-zA-Z0-9_])pkl_load\(") },
    Rule { name: "os_system_injection",
        reminder: "os.system() runs a shell and is a command-injection sink. Use subprocess.run([...]) with a list of arguments instead. If this is safe or is explicitly needed, briefly document that in a comment before continuing.",
        filter: PathFilter::PyOnly, substrings: &["from os import system"],
        regex: Some(r"\bos\.system\s*\(") },
    Rule { name: "python_subprocess_shell", reminder: SUBPROCESS_SHELL_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"subprocess\.(?:run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True") },
    Rule { name: "go_exec_shell_injection", reminder: GO_EXEC_SHELL_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r#"exec\.Command\(\s*"(?:sh|bash|/bin/sh|/bin/bash)""#) },
    Rule { name: "unsafe_yaml_load", reminder: UNSAFE_YAML_LOAD_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\byaml\.load\s*\((?![^)\n]{0,80}\bSafe)") },
    Rule { name: "node_createcipher_no_iv",
        reminder: "Use crypto.createCipheriv() / createDecipheriv(). createCipher was removed in Node 22 and derives the key insecurely (no IV, MD5-based KDF).",
        filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\bcrypto\.(createCipher|createDecipher)\b") },
    Rule { name: "aes_ecb_mode",
        reminder: "Use AES-GCM or AES-CBC with HMAC. ECB mode leaks plaintext structure (identical blocks encrypt to identical ciphertext).",
        filter: PathFilter::Any, substrings: &[],
        regex: Some(r#"\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(|[\x22\x27]aes-\d+-ecb[\x22\x27]"#) },
    Rule { name: "tls_verification_disabled",
        reminder: "Don't disable TLS verification. This allows MITM attacks. For self-signed dev certs, add the CA to your trust store or use a properly-issued cert.",
        filter: PathFilter::Any, substrings: &[],
        regex: Some(r#"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x22\x27]?0|ssl\._create_unverified_context|check_hostname\s*=\s*False"#) },
    Rule { name: "marshal_loads", reminder: UNSAFE_DESERIALIZATION_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\bmarshal\.loads?\s*\(") },
    Rule { name: "shelve_open", reminder: UNSAFE_DESERIALIZATION_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\bshelve\.open\s*\(") },
    Rule { name: "xml_unsafe_parse",
        reminder: "Use defusedxml.ElementTree. Python's stdlib XML parsers are vulnerable to XXE (external entity) and billion-laughs attacks by default.",
        filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\b(xml\.etree\.ElementTree|ElementTree|ET)\.(parse|fromstring|XML)\s*\(|\bminidom\.(parse|parseString)\s*\(|\bxml\.sax\.(parse|make_parser)\b") },
    Rule { name: "pickle_variants_load", reminder: UNSAFE_DESERIALIZATION_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\b(cPickle|cloudpickle|dill)\.(load|loads)\s*\(") },
    Rule { name: "outerHTML_xss",
        reminder: "Use textContent or sanitize with DOMPurify. outerHTML assignment is an XSS sink equivalent to innerHTML.",
        filter: PathFilter::Any, substrings: &[".outerHTML =", ".outerHTML="], regex: None },
    Rule { name: "insertAdjacentHTML_xss",
        reminder: "Use insertAdjacentText() or sanitize with DOMPurify. insertAdjacentHTML is an XSS sink.",
        filter: PathFilter::Any, substrings: &[".insertAdjacentHTML("], regex: None },
    Rule { name: "script_src_without_sri",
        reminder: "Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to external script tags. Loading scripts without Subresource Integrity exposes you to CDN compromise.",
        filter: PathFilter::Any, substrings: &[],
        regex: Some(r#"<script\s+(?![^>]{0,400}integrity\s*=)[^>]{0,200}src\s*=\s*[\x22\x27](?:https?:)?//[^\x22\x27]{1,300}[\x22\x27][^>]{0,100}>"#) },
    Rule { name: "torch_unsafe_load", reminder: UNSAFE_TORCH_LOAD_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"(?:\btorch\.load|\.torch_load)\s*\((?![^)\n]{0,200}weights_only\s*=\s*True)") },
    Rule { name: "yaml_unsafe_load_variants", reminder: UNSAFE_YAML_LOAD_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"(?:\byaml\.unsafe_load|\.yaml_unsafe_load)\s*\(") },
    Rule { name: "pickle_wrapper_load", reminder: UNSAFE_DESERIALIZATION_REMINDER, filter: PathFilter::Any, substrings: &[],
        regex: Some(r"\bjoblib\.load\s*\(|\b(?:pd|pandas)\.read_pickle\s*\(|\.cloudpickle_load\s*\(|\b(?:np|numpy)\.load\s*\([^)\n]{0,200}allow_pickle\s*=\s*True") },
];

struct CompiledRule {
    rule: &'static Rule,
    regex: Option<fancy_regex::Regex>,
}

static COMPILED: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|r| CompiledRule {
            rule: r,
            regex: r.regex.and_then(|src| fancy_regex::Regex::new(src).ok()),
        })
        .collect()
});

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn path_filter_ok(filter: PathFilter, path: &str) -> bool {
    match filter {
        PathFilter::Any => true,
        PathFilter::JsOnly => JS_EXTS.iter().any(|e| path.ends_with(e)),
        PathFilter::PyOnly => PY_EXTS.iter().any(|e| path.ends_with(e)),
        PathFilter::NotDoc => !DOC_EXTS.iter().any(|e| path.ends_with(e)),
        PathFilter::GithubWorkflow => {
            path.contains(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml"))
        }
    }
}

/// Every (ruleName, reminder) hit for one (path, content) pair. Each rule
/// fires at most once.
fn scan_content(path: &str, content: &str) -> Vec<(&'static str, &'static str)> {
    if content.is_empty() || content.len() > MAX_SCAN_BYTES {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for entry in COMPILED.iter() {
        let rule = entry.rule;
        if !path_filter_ok(rule.filter, path) {
            continue;
        }
        if rule.filter == PathFilter::GithubWorkflow {
            hits.push((rule.name, rule.reminder));
            continue;
        }
        let matched = rule.substrings.iter().any(|s| content.contains(s))
            || entry
                .regex
                .as_ref()
                .is_some_and(|r| r.find(content).ok().flatten().is_some());
        if matched {
            hits.push((rule.name, rule.reminder));
        }
    }
    hits
}

/// Strip a redundant leading "⚠️ Security Warning[:]" the rule
/// reminders carry — the block already leads with the warning marker.
fn strip_marker(reminder: &str) -> &str {
    reminder
        .trim_start_matches("⚠️ Security Warning:")
        .trim_start_matches("⚠️ Security Warning")
        .trim_start_matches([':', ' '])
}

fn format_warning_block(findings: &[(&str, &str)]) -> String {
    let names: Vec<&str> = findings.iter().map(|f| f.0).collect();
    let mut out = format!(
        "\n\n---\n⚠️ Security guidance — {} pattern{} matched ({})\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        names.join(", ")
    );
    for (name, reminder) in findings {
        out.push_str(&format!("\n⚠️ Security warning: {name} — {}\n", strip_marker(reminder)));
    }
    out.push_str(
        "\nPattern matches can be false positives. If the construct is safe in this \
         context, briefly document why in a code comment and continue. Otherwise, \
         fix the code before moving on.",
    );
    out
}

/// Recursively collect string values from tool args (content to scan) and
/// pick the path arg (first of `path`, `file_path`, or any `*path*` key).
fn extract_args(args: &Value) -> (String, Vec<String>) {
    let mut path = String::new();
    for key in ["path", "file_path"] {
        if let Some(p) = args.get(key).and_then(Value::as_str) {
            path = p.to_string();
            break;
        }
    }
    let mut strings = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            Value::Object(m) => m.values().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    walk(args, &mut strings);
    (path, strings)
}

fn is_bash_heredoc(command: &str) -> bool {
    command.contains("<<")
}

/// Best-effort path for a heredoc write: the first `>`/`>>` redirect
/// target, so path-filtered rules (Python-only, doc-skip, workflows) see
/// the real extension.
fn heredoc_target(command: &str) -> Option<String> {
    static REDIRECT: LazyLock<Option<regex::Regex>> =
        LazyLock::new(|| regex::Regex::new(r">+\s*([^\s|&;><]+)").ok());
    REDIRECT
        .as_ref()?
        .captures(command)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// (session, tool) → (path, content strings) stashed by tool/before for
/// tool/after to scan (post_tool events carry no args).
type Stash = Mutex<HashMap<(String, String), (String, Vec<String>)>>;
static STASH: LazyLock<Stash> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn session_key(params: &Value) -> (String, String) {
    let sid = params
        .get("session")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let name = params.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    (sid, name)
}

fn tool_before(params: &Value) -> Value {
    if env_flag("SECURITY_GUIDANCE_DISABLE") {
        return json!({"decision": "allow"});
    }
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("args").cloned().unwrap_or(json!({}));
    let (path, strings) = if WRITE_TOOLS.contains(&name) {
        extract_args(&args)
    } else if name == "bash" {
        let command = args.get("command").and_then(Value::as_str).unwrap_or("");
        if is_bash_heredoc(command) {
            (heredoc_target(command).unwrap_or_default(), vec![command.to_string()])
        } else {
            (String::new(), Vec::new())
        }
    } else {
        return json!({"decision": "allow"});
    };
    if strings.is_empty() {
        return json!({"decision": "allow"});
    }

    if env_flag("SECURITY_GUIDANCE_BLOCK") {
        let findings: Vec<(&str, &str)> = strings
            .iter()
            .flat_map(|c| scan_content(&path, c))
            .collect();
        if !findings.is_empty() {
            return json!({
                "decision": "deny",
                "reason": format!("security-guidance refused this write:{}\n\nTo override, unset SECURITY_GUIDANCE_BLOCK and retry.", format_warning_block(&findings))
            });
        }
        return json!({"decision": "allow"});
    }

    STASH
        .lock()
        .expect("stash")
        .insert(session_key(params), (path, strings));
    json!({"decision": "allow"})
}

fn tool_after(params: &Value) -> Value {
    if env_flag("SECURITY_GUIDANCE_DISABLE") || env_flag("SECURITY_GUIDANCE_BLOCK") {
        return json!({});
    }
    let key = session_key(params);
    let Some((path, strings)) = STASH.lock().expect("stash").remove(&key) else {
        return json!({});
    };
    if params.get("is_error").and_then(Value::as_bool) == Some(true) {
        return json!({});
    }
    let mut findings: Vec<(&str, &str)> = Vec::new();
    for c in &strings {
        for hit in scan_content(&path, c) {
            if !findings.iter().any(|f| f.0 == hit.0) {
                findings.push(hit);
            }
        }
    }
    if findings.is_empty() {
        return json!({});
    }
    let content = params.get("content").and_then(Value::as_str).unwrap_or("");
    json!({ "content": format!("{content}{}", format_warning_block(&findings)) })
}

fn manifest_guard() -> Value {
    json!({
        "name": "guard",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": [],
        "hooks": ["tool/before", "tool/after"],
    })
}

/// One request → `Some(reply)`, or `None` for notifications. The bool asks
/// the loop to exit after writing the reply.
pub fn handle_guard(req: &Value) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest_guard(),
        "tool/before" => tool_before(&params),
        "tool/after" => tool_after(&params),
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

fn main_guard() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest_guard());
        return Ok(());
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let (reply, exit) = handle_guard(&req);
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
        handle_guard(&json!({ "id": 1, "method": method, "params": params }))
            .0
            .unwrap()
    }

    #[test]
    fn manifest_shape() {
        let m = manifest_guard();
        assert_eq!(m["name"], "guard");
        assert_eq!(m["protocol"], "2.0");
        assert_eq!(m["hooks"], json!(["tool/before", "tool/after"]));
    }

    #[test]
    fn all_rules_compile() {
        assert_eq!(COMPILED.len(), RULES.len());
        assert_eq!(RULES.len(), 25);
        for c in COMPILED.iter() {
            if let Some(src) = c.rule.regex {
                assert!(c.regex.is_some(), "rule {} failed to compile: {src}", c.rule.name);
            }
        }
    }

    #[test]
    fn known_patterns_hit() {
        let cases: &[(&str, &str, &str)] = &[
            ("x.py", "import pickle\npickle.load(f)", "pickle_deserialization"),
            ("x.py", "os.system('ls')", "os_system_injection"),
            ("x.py", "yaml.load(data)", "unsafe_yaml_load"),
            ("x.py", "torch.load('m.pt')", "torch_unsafe_load"),
            ("x.ts", "eval(code)", "eval_injection"),
            ("x.tsx", "dangerouslySetInnerHTML={{__html: d}}", "react_dangerously_set_html"),
            ("x.js", "el.innerHTML = s", "innerHTML_xss"),
            ("x.js", "crypto.createCipher('aes-256', k)", "node_createcipher_no_iv"),
            ("x.py", "requests.get(u, verify=False)", "tls_verification_disabled"),
            ("x.py", "subprocess.run(c, shell=True)", "python_subprocess_shell"),
            ("x.py", "pickle.loads(b)", "pickle_deserialization"),
            ("x.py", "joblib.load('m.pkl')", "pickle_wrapper_load"),
        ];
        for (path, content, rule) in cases {
            let hits = scan_content(path, content);
            assert!(
                hits.iter().any(|h| h.0 == *rule),
                "expected {rule} to hit on {path} — got {hits:?}"
            );
        }
    }

    #[test]
    fn safe_constructs_dont_hit() {
        assert!(scan_content("x.py", "yaml.load(d, Loader=yaml.SafeLoader)")
            .iter().all(|h| h.0 != "unsafe_yaml_load"));
        assert!(scan_content("x.py", "torch.load('m.pt', weights_only=True)")
            .iter().all(|h| h.0 != "torch_unsafe_load"));
        assert!(scan_content("x.py", "model.eval()").iter().all(|h| h.0 != "eval_injection"));
        assert!(scan_content("x.md", "eval(code)").is_empty());
        assert!(scan_content("x.js", "eval(code)").iter().all(|h| h.0 != "eval_injection") == false);
    }

    #[test]
    fn workflow_path_fires_on_path_alone() {
        let hits = scan_content(".github/workflows/ci.yml", "name: ci");
        assert!(hits.iter().any(|h| h.0 == "github_actions_workflow"));
        assert!(scan_content("ci.yml", "name: ci").iter().all(|h| h.0 != "github_actions_workflow"));
    }

    #[test]
    fn scan_cap_respected() {
        let big = "a".repeat(MAX_SCAN_BYTES + 1);
        assert!(scan_content("x.py", &big).is_empty());
        assert!(scan_content("x.py", "").is_empty());
    }

    #[test]
    fn before_then_after_appends_warning() {
        let before = call(
            "tool/before",
            json!({"name": "write", "args": {"path": "x.py", "content": "import os\nos.system('ls')"},
                   "session": {"id": "s1", "cwd": "/tmp"}}),
        );
        assert_eq!(before["result"]["decision"], "allow");
        let after = call(
            "tool/after",
            json!({"name": "write", "content": "ok", "is_error": false,
                   "session": {"id": "s1", "cwd": "/tmp"}}),
        );
        let content = after["result"]["content"].as_str().unwrap_or("");
        assert!(content.contains("Security warning: os_system_injection"), "got: {content}");
    }

    #[test]
    fn after_without_stash_keeps_result() {
        let after = call(
            "tool/after",
            json!({"name": "write", "content": "ok", "is_error": false,
                   "session": {"id": "other", "cwd": "/tmp"}}),
        );
        assert_eq!(after["result"], json!({}));
    }

    #[test]
    fn bash_heredoc_is_scanned() {
        let cmd = "cat > /tmp/x.py <<'PY'\nimport pickle\npickle.load(f)\nPY";
        let before = call(
            "tool/before",
            json!({"name": "bash", "args": {"command": cmd}, "session": {"id": "s2"}}),
        );
        assert_eq!(before["result"]["decision"], "allow");
        let after = call(
            "tool/after",
            json!({"name": "bash", "content": "", "is_error": false, "session": {"id": "s2"}}),
        );
        assert!(after["result"]["content"].as_str().unwrap_or("").contains("pickle_deserialization"));
    }

    #[test]
    fn non_write_tools_pass() {
        let r = call("tool/before", json!({"name": "read", "args": {"path": "x"}, "session": {}}));
        assert_eq!(r["result"]["decision"], "allow");
    }
}
