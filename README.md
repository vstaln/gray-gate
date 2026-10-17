<div align="center">
  <img alt="gray-gate" src="assets/icon.svg" width="120" height="120" />
  <h1>gray-gate</h1>
  <p><strong>One sidecar for every tool-call policy plugin. The strictest verdict wins.</strong></p>
  <p>
    <a href="https://gray.alignment.id">Website</a> ·
    <a href="https://github.com/vstaln/gray-gate">Source</a> ·
    <a href="https://github.com/vstaln/gray">gray</a>
  </p>
  <p>
    <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-1c1c20?style=flat-square&labelColor=0a0a0b" /></a>
    <a href="https://www.rust-lang.org"><img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-rust-1c1c20?style=flat-square&labelColor=0a0a0b&logo=rust&logoColor=d4a373" /></a>
    <img alt="gray plugin" src="https://img.shields.io/badge/gray-plugin-1c1c20?style=flat-square&labelColor=0a0a0b&color=7aa2f7" />
  </p>
</div>

<br/>

```bash
gray plugin install gate
```

`gray-gate` combines five plugins that all check tool calls into one sidecar
process. Each module still reads its own state files
(`~/.gray/permissions-mode.json`, `~/.gray/confirm/`, `~/.gray/tool-gate/`)
and env vars, and keeps its own slash commands. If you already use the
standalone plugins, your setup carries over when you uninstall them.

## Replaces

| Module | Former plugin | Hooks | Commands | State / config |
|---|---|---|---|---|
| permissions | `gray-permissions` | `tool/before` | `/permissions` `/perms` `/access` | `~/.gray/permissions-mode.json`, `GRAY_PERMISSION(S)` |
| confirm | `gray-confirm` | `tool/before` | `/confirm` | `~/.gray/confirm/{patterns.json,config.json,disabled}`, `GRAY_CONFIRM_TIMEOUT_SECS` |
| tool_gate | `gray-tool-gate` | `tool/before` | `/gate` | `~/.gray/tool-gate/deny.txt` |
| guard | `gray-guard` | `tool/before` `tool/after` | — | `SECURITY_GUIDANCE_BLOCK`, `SECURITY_GUIDANCE_DISABLE` |
| repguard | `gray-repguard` | `tool/before` `tool/after` | `/repguard` | `REPGUARD_MAX_REPEATS`, `REPGUARD_WINDOW_SECS` |

None of the modules adds tools. The plugin declares the `host.ask` capability
because permissions and confirm both ask the user to approve calls.

## How verdicts combine

- **`tool/before`**: every module gets a say. A `deny` from any module beats
  `modify`, and `modify` beats `allow`. If several modules deny, their reasons
  are joined together. The non-interactive modules run first and always run:
  tool-gate, guard, then repguard. Repguard has to see every call to count
  repeats correctly. Permissions and confirm, the modules that prompt the
  user, run last. Once the call is already denied they are skipped, because a
  prompt can't change the outcome.
- **`tool/after`**: guard runs first, then repguard. Repguard receives the
  output with guard's security warning already added, so the result keeps
  both guard's warning and repguard's loop nudge.

## `/gate`

`/gate deny|allow|list|clear <glob>` works as it did in `gray-tool-gate`.
`/gate` without a subcommand prints an overview of all five modules, followed
by tool-gate's usage line.

## Build from source

```sh
cargo build --release
gray plugin check ./target/release/gate
```

## License

MIT
