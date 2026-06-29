#!/bin/sh
# computermoney one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
#
# Installs the `cm` binary (which includes the `cm mcp` MCP server) by compiling
# from source with cargo, then prints how to register the MCP server with your
# AI client. No secrets are written — you supply the wallet unlock yourself.
set -eu

REPO="https://github.com/xodn348/computermoney"
BIN_NAME="cm"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- prerequisites ---------------------------------------------------------
command -v cargo >/dev/null 2>&1 || err \
  "Rust toolchain not found. Install it, then re-run:  curl https://sh.rustup.rs -sSf | sh"
command -v cc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || err \
  "A C compiler is required (ring builds C). macOS: xcode-select --install. Linux: install gcc."

# --- build + install -------------------------------------------------------
say "Compiling $BIN_NAME from $REPO (from source; this can take a few minutes)…"
cargo install --git "$REPO" --bin "$BIN_NAME" --locked

BIN="$(command -v "$BIN_NAME" 2>/dev/null || echo "${CARGO_HOME:-$HOME/.cargo}/bin/$BIN_NAME")"
say "Installed: $BIN"
case ":${PATH}:" in
  *":$(dirname "$BIN"):"*) : ;;
  *) say "Note: $(dirname "$BIN") is not on your PATH — add it to use \`$BIN_NAME\` directly." ;;
esac

# --- next steps: register the MCP server -----------------------------------
# The server needs the wallet unlock (CM_MNEMONIC for the demo, or CM_PASSPHRASE
# for a sealed mainnet seed) and the network — these are yours to provide, so we
# print the command instead of baking a placeholder secret.
printf '\n' >&2
if command -v claude >/dev/null 2>&1; then
  say "Claude Code detected. Register the MCP server (signet demo) with your own mnemonic:"
  printf '\n  claude mcp add computermoney \\\n    -e CM_NETWORK=signet \\\n    -e CM_MNEMONIC="<your 12-word mnemonic>" \\\n    -- "%s" mcp\n\n' "$BIN" >&2
else
  say "Add this to your MCP client config (.mcp.json or claude_desktop_config.json):"
  printf '\n  "computermoney": { "command": "%s", "args": ["mcp"],\n    "env": { "CM_NETWORK": "signet", "CM_MNEMONIC": "<your 12-word mnemonic>" } }\n\n' "$BIN" >&2
fi
say "For mainnet, set CM_PASSPHRASE (sealed seed) + a CM_POLICY spend cap — see $REPO#mcp-server--natural-language-payments"
