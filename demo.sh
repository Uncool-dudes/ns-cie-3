#!/usr/bin/env bash
# demo.sh — launch p2p-chat demo in a tmux session
#
# Usage:
#   ./demo.sh                  # default: full DH encryption
#   ./demo.sh --no-diffie      # naive key exchange (key sniffable)
#   ./demo.sh --no-encrypt     # plaintext (no encryption)
#
# Layout:
#   ┌──────────────────┬──────────────────┐
#   │  Alice (listen)  │   Bob (connect)  │
#   ├──────────────────┼──────────────────┤
#   │    tcpdump       │    log viewer    │
#   └──────────────────┴──────────────────┘

set -euo pipefail

# ── config ────────────────────────────────────────────────────────────────────
SESSION="p2p-demo"
PORT=4242
MODE_FLAG="${1:-}"          # --no-diffie | --no-encrypt | (empty = default)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── validate mode flag ────────────────────────────────────────────────────────
case "$MODE_FLAG" in
  ""|"--no-diffie"|"--no-encrypt") ;;
  *)
    echo "error: unknown flag '$MODE_FLAG'"
    echo "usage: $0 [--no-diffie | --no-encrypt]"
    exit 1
    ;;
esac

# ── label for the session title ───────────────────────────────────────────────
case "$MODE_FLAG" in
  "--no-diffie")  MODE_LABEL="naive-key" ;;
  "--no-encrypt") MODE_LABEL="plaintext" ;;
  *)              MODE_LABEL="encrypted" ;;
esac

# ── check dependencies ────────────────────────────────────────────────────────
for cmd in tmux go tcpdump; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: '$cmd' not found — please install it first"
    exit 1
  fi
done

# ── kill any existing session with the same name ─────────────────────────────
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Killing existing tmux session '$SESSION' ..."
  tmux kill-session -t "$SESSION"
fi

# ── build binaries ────────────────────────────────────────────────────────────
echo "Building p2p-chat ..."
(cd "$SCRIPT_DIR" && go build -o p2p-chat .)

echo "Building relay-server ..."
(cd "$SCRIPT_DIR" && go build -o relay/relay-server ./relay)

echo "Done. Starting tmux session '$SESSION' (mode: $MODE_LABEL) ..."

# ── detect loopback interface for tcpdump ────────────────────────────────────
if [[ "$(uname)" == "Darwin" ]]; then
  LOOPBACK="lo0"
else
  LOOPBACK="lo"
fi

# ── helper: wait for the log directory to have at least one file ─────────────
LOG_WAIT_CMD='i=0; while [ $(ls '"$SCRIPT_DIR"'/logs/conn_*.log 2>/dev/null | wc -l) -lt 1 ] && [ $i -lt 30 ]; do sleep 0.5; i=$((i+1)); done'

# ── cache sudo credentials now so tcpdump doesn't prompt inside tmux ─────────
echo "Caching sudo credentials for tcpdump ..."
sudo -v

# ── create tmux session (start detached, no default window command) ───────────
tmux new-session -d -s "$SESSION" -x 220 -y 50
tmux rename-window -t "$SESSION:0" "p2p-$MODE_LABEL"

# Capture pane IDs immediately after each split — indices shift when panes are
# inserted mid-list, so IDs are the only reliable targeting mechanism.

# Pane: Alice (top-left)
ALICE=$(tmux display-message -t "$SESSION:0" -p '#{pane_id}')
tmux send-keys -t "$ALICE" \
  "cd '$SCRIPT_DIR' && echo '=== Alice (listener) ===' && ./p2p-chat --listen :$PORT --name Alice $MODE_FLAG" \
  Enter

# Pane: Bob (top-right) — horizontal split from Alice's pane
BOB=$(tmux split-window -t "$ALICE" -h -P -F '#{pane_id}')
tmux send-keys -t "$BOB" \
  "cd '$SCRIPT_DIR' && sleep 1 && echo '=== Bob (dialer) ===' && ./p2p-chat --connect localhost:$PORT --name Bob $MODE_FLAG" \
  Enter

# Pane: tcpdump (bottom-left) — vertical split from Alice's pane
TCPDUMP=$(tmux split-window -t "$ALICE" -v -P -F '#{pane_id}')
tmux send-keys -t "$TCPDUMP" \
  "echo '=== tcpdump on $LOOPBACK port $PORT ===' && sudo tcpdump -i $LOOPBACK -nn -X tcp port $PORT" \
  Enter

# Pane: log viewer (bottom-right) — vertical split from Bob's pane
LOG=$(tmux split-window -t "$BOB" -v -P -F '#{pane_id}')
tmux send-keys -t "$LOG" \
  "cd '$SCRIPT_DIR' && echo '=== waiting for log files ===' && $LOG_WAIT_CMD && tail -f \$(ls -t logs/*.log | head -1) | hl -P" \
  Enter

# ── even out the pane sizes ───────────────────────────────────────────────────
tmux select-layout -t "$SESSION:0" tiled

# ── focus Alice's pane so the user can start typing ──────────────────────────
tmux select-pane -t "$ALICE"

# ── attach ───────────────────────────────────────────────────────────────────
tmux attach-session -t "$SESSION"
