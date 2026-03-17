#!/usr/bin/env bash
# =============================================================================
#  start.sh — Start the Rule Score Auto Adjust web server
#
#  Usage:
#    ./start.sh             # default: port 9527
#    PORT=8080 ./start.sh   # custom port
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-9527}"

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

exec uv run uvicorn web.app:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --reload \
    --log-level info
