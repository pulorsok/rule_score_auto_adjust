#!/usr/bin/env bash
# =============================================================================
#  start.sh — Start the Rule Score Auto Adjust web server
#
#  Usage:
#    ./start.sh             # default: port 9527
#    PORT=8080 ./start.sh   # custom port
#    DEV=true ./start.sh    # enable auto-reload (development only)
#
#  WARNING: Do NOT use DEV=true during long-running training jobs.
#           uvicorn --reload will restart the server on any .py file change,
#           causing "分析中斷" and loss of in-flight training state.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-9527}"
DEV="${DEV:-false}"

# ── Preflight checks ──────────────────────────────────────────────────────────
if ! command -v uv &>/dev/null; then
    # Try common install locations before giving up
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
if ! command -v uv &>/dev/null; then
    echo "[✗] uv not found."
    echo "    Fix: source ~/.bashrc  (or open a new terminal)"
    echo "    If uv is not installed yet, run: ./install.sh"
    exit 1
fi

if [[ ! -f ".env" ]]; then
    echo "[!] .env not found — copying from .env.template"
    cp .env.template .env
    echo "[!] Please edit .env and add your API keys, then re-run ./start.sh"
    exit 1
fi

# Load .env so PYTHONPATH etc. are set for this process
set -a; source .env; set +a

# ── Start ─────────────────────────────────────────────────────────────────────
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║  Rule Score Auto Adjust — Web UI      ║"
echo "  ║  http://localhost:${PORT}               ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""

RELOAD_FLAG=""
if [[ "$DEV" == "true" ]]; then
    RELOAD_FLAG="--reload"
    echo "  [dev] Auto-reload enabled (DEV=true)"
    echo "        Do NOT run long training jobs in this mode."
    echo ""
fi

exec uv run uvicorn web.app:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    $RELOAD_FLAG \
    --log-level info
