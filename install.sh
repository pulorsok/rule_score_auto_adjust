#!/usr/bin/env bash
# =============================================================================
#  install.sh — One-click setup for rule_score_auto_adjust on Ubuntu
#
#  Usage:
#    chmod +x install.sh
#    ./install.sh
#
#  What this does:
#    1. Install system dependencies (git, curl, build-essential)
#    2. Install uv (fast Python package manager)
#    3. Use uv to install Python 3.13 (no system Python required)
#    4. Clone quark-engine sibling repo (required by pyproject.toml)
#    5. Install all Python dependencies via uv sync
#    6. Create .env from .env.template (if not already present)
#    7. Create local data directories
# =============================================================================
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[•]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Sanity check ─────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]] || error "This script is for Linux (Ubuntu) only."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
info "Project root: $SCRIPT_DIR"

# ── 1. System dependencies ────────────────────────────────────────────────────
header "Step 1: System dependencies"

PACKAGES=()
command -v git   &>/dev/null || PACKAGES+=(git)
command -v curl  &>/dev/null || PACKAGES+=(curl)
dpkg -s build-essential &>/dev/null 2>&1 || PACKAGES+=(build-essential)
# Required for uv-managed Python builds
dpkg -s libssl-dev &>/dev/null 2>&1  || PACKAGES+=(libssl-dev)
dpkg -s zlib1g-dev &>/dev/null 2>&1  || PACKAGES+=(zlib1g-dev)
dpkg -s libbz2-dev &>/dev/null 2>&1  || PACKAGES+=(libbz2-dev)
dpkg -s libffi-dev &>/dev/null 2>&1  || PACKAGES+=(libffi-dev)

if [[ ${#PACKAGES[@]} -gt 0 ]]; then
    info "Installing: ${PACKAGES[*]}"
    sudo apt-get update -q
    sudo apt-get install -y -q "${PACKAGES[@]}"
else
    success "System packages already present"
fi

# Docker Compose (for optional Prefect server)
if ! command -v docker &>/dev/null; then
    warn "Docker not found — Prefect server (service/prefect/compose.yaml) won't start."
    warn "Install Docker later if needed: https://docs.docker.com/engine/install/ubuntu/"
fi

# ── 2. Install uv ─────────────────────────────────────────────────────────────
header "Step 2: uv (Python package manager)"

if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Make uv available in the current shell
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
    command -v uv &>/dev/null || error "uv installation failed — please add ~/.local/bin to PATH and retry"
    success "uv installed: $(uv --version)"
else
    success "uv already installed: $(uv --version)"
fi

# ── 3. Python 3.13 ────────────────────────────────────────────────────────────
header "Step 3: Python 3.13"

if ! uv python list --only-installed 2>/dev/null | grep -q "3\.13"; then
    info "Installing Python 3.13 via uv..."
    uv python install 3.13
    success "Python 3.13 installed"
else
    success "Python 3.13 already available"
fi

# ── 4. quark-engine sibling ───────────────────────────────────────────────────
header "Step 4: quark-engine (sibling repo)"

QUARK_DIR="$(dirname "$SCRIPT_DIR")/quark-engine"
QUARK_REPO="https://github.com/haeter525/quark-engine.git"
QUARK_BRANCH="for_rule_adjust"

if [[ -d "$QUARK_DIR/.git" ]]; then
    success "quark-engine already present at $QUARK_DIR"
    info "Pulling latest changes..."
    git -C "$QUARK_DIR" pull --ff-only --quiet || warn "git pull skipped (local changes?)"
else
    info "Cloning quark-engine → $QUARK_DIR"
    git clone --depth 1 --branch "$QUARK_BRANCH" "$QUARK_REPO" "$QUARK_DIR"
    success "quark-engine cloned"
fi

# ── 5. Python dependencies ────────────────────────────────────────────────────
header "Step 5: Python dependencies (uv sync)"

info "This installs torch, ray, prefect, quark-engine, etc. — may take a few minutes."
uv sync
success "All Python dependencies installed"

# ── 6. .env file ─────────────────────────────────────────────────────────────
header "Step 6: Environment file (.env)"

if [[ -f ".env" ]]; then
    success ".env already exists — skipping (edit manually to set API keys)"
else
    cp .env.template .env
    # Replace /mnt/storage paths with local ./data paths for Ubuntu convenience
    sed -i 's|/mnt/storage/data/cache|'"$SCRIPT_DIR"'/data/cache|g'         .env
    sed -i 's|/mnt/storage/data/apks|'"$SCRIPT_DIR"'/data/apks|g'           .env
    sed -i 's|/mnt/storage/data/generated_rules|'"$SCRIPT_DIR"'/data/generated_rules|g' .env
    sed -i 's|/mnt/storage/data/analysis_results|'"$SCRIPT_DIR"'/data/analysis_results|g' .env
    success ".env created from .env.template (paths updated to ./data/)"
    warn "Edit .env and fill in your API keys before running the app:"
    echo   "    ANDROZOO_API_KEY=..."
    echo   "    MALWAREBAZAAR_API_KEY=..."
    echo   "    OPENAI_API_KEY=..."
fi

# ── 7. Data directories ───────────────────────────────────────────────────────
header "Step 7: Data directories"

# Read paths from .env (fallback to defaults)
_env_val() { grep -E "^$1=" .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" || echo ""; }

DATA_DIRS=(
    "$SCRIPT_DIR/data/apks"
    "$SCRIPT_DIR/data/generated_rules"
    "$SCRIPT_DIR/data/rules"
    "$SCRIPT_DIR/data/lists/family"
    "$SCRIPT_DIR/data/cache"
    "$SCRIPT_DIR/data/analysis_results"
    "$SCRIPT_DIR/data/dataset"
)

for d in "${DATA_DIRS[@]}"; do
    mkdir -p "$d"
done
success "Data directories ready"

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}✓ Installation complete!${RESET}\n"
echo -e "Next steps:"
echo -e "  ${BOLD}1.${RESET} Fill in API keys in ${CYAN}.env${RESET}"
echo -e "  ${BOLD}2.${RESET} Start the web UI:   ${CYAN}./start.sh${RESET}"
echo -e "  ${BOLD}3.${RESET} Open browser:        ${CYAN}http://localhost:9527${RESET}"
echo -e ""
echo -e "Optional — start Prefect server (requires Docker):"
echo -e "  ${CYAN}docker compose -f service/prefect/compose.yaml up -d${RESET}"
echo -e ""
