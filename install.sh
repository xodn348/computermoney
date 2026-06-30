#!/bin/sh
# computermoney one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
#
# Takes a fresh machine to a working natural-language Bitcoin payment agent in
# one line: installs the `cm` binary, and — if Claude Code is present — registers
# the `cm mcp` server on a throwaway *signet* demo wallet (zero secrets to type).
# Real-money mainnet is a deliberate opt-in (see the README), never auto-wired.
set -eu

REPO="https://github.com/xodn348/computermoney"
BIN_NAME="cm"
SERVER_NAME="computermoney"

say() { printf '\033[1;36m==>\033[0m %s\n' "$1" >&2; }
err() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

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

# --- one-line MCP setup: register cm mcp with Claude Code (signet demo) -----
# The server needs a wallet unlock + a network. For the demo we generate a
# throwaway signet wallet (worthless coins) and bake it into the registration,
# so there is nothing to type. Mainnet is handled separately, on purpose.
if command -v claude >/dev/null 2>&1; then
  if claude mcp list 2>/dev/null | grep -q "^${SERVER_NAME}:"; then
    say "MCP server '${SERVER_NAME}' is already registered with Claude Code — left untouched."
  else
    say "Registering the MCP server with Claude Code (throwaway signet demo wallet)…"
    INIT_OUT="$(env -u CM_PASSPHRASE CM_NETWORK=signet "$BIN" init 2>/dev/null || true)"
    MNEMONIC="$(printf '%s\n' "$INIT_OUT" | grep -F 'mnemonic: ' | cut -d' ' -f2-)"
    ADDR="$(printf '%s\n' "$INIT_OUT" | grep -F 'address[0]: ' | cut -d' ' -f2-)"
    [ -n "$MNEMONIC" ] || err \
      "demo-wallet generation failed; register manually — see $REPO#mcp-server--natural-language-payments"
    claude mcp add -s user "$SERVER_NAME" \
      -e CM_NETWORK=signet -e CM_MNEMONIC="$MNEMONIC" -- "$BIN" mcp >&2
    say "Done — restart Claude Code, then just say:  \"send 5000 sats to <address>\""
    say "This is a signet demo wallet (worthless coins). Fund it to try a real send:"
    printf '\n  address: %s\n  faucet:  https://faucet.mutinynet.com/\n\n' "$ADDR" >&2
  fi
else
  say "Claude Code CLI not found. Add this to your MCP client config (.mcp.json / claude_desktop_config.json):"
  printf '\n  "computermoney": { "command": "%s", "args": ["mcp"],\n    "env": { "CM_NETWORK": "signet", "CM_MNEMONIC": "<your 12-word mnemonic>" } }\n\n' "$BIN" >&2
fi

# --- mainnet is deliberate -------------------------------------------------
say "Mainnet (real BTC) is opt-in: seal a seed (CM_PASSPHRASE) + set a CM_POLICY spend cap,"
say "then register with CM_NETWORK=mainnet. See $REPO#mcp-server--natural-language-payments"
