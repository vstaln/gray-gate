#!/bin/sh
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sys="$(uname -s)"
case "$sys" in
MINGW* | MSYS* | CYGWIN*) rel="x86_64-pc-windows-msvc/gate.exe" ;;
Darwin*)
    case "$(uname -m)" in
    arm64) rel="aarch64-apple-darwin/gate" ;;
    *) rel="x86_64-apple-darwin/gate" ;;
    esac ;;
*)
    case "$(uname -m)" in
    aarch64 | arm64) rel="aarch64-unknown-linux-musl/gate" ;;
    *) rel="x86_64-unknown-linux-musl/gate" ;;
    esac ;;
esac
if [ -x "$here/$rel" ]; then exec "$here/$rel" "$@"; fi
for cand in "$here/target/release/gate.exe" "$here/target/release/gate" "$here/target/debug/gate.exe" "$here/target/debug/gate"; do
    if [ -x "$cand" ]; then exec "$cand" "$@"; fi
done
echo "gate binary not found in $here" >&2
exit 1
