#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info "AutoPwn installer starting..."
echo ""

# ─── Privilege check ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  warn "Not running as root. Some install steps may fail."
  warn "Re-run with: sudo bash install.sh"
fi

# ─── System dependencies ───────────────────────────────────────
info "Updating apt package lists..."
apt-get update -qq

info "Installing system packages..."
apt-get install -y -qq \
  nmap gobuster ffuf nikto hydra sqlmap \
  enum4linux enum4linux-ng smbclient crackmapexec \
  exploitdb metasploit-framework \
  python3 python3-pip python3-venv python3-weasyprint \
  curl wget git build-essential golang-go ruby ruby-dev \
  sshpass evil-winrm \
  >/dev/null 2>&1 && ok "System packages installed"

# ─── Python venv ───────────────────────────────────────────────
info "Setting up Python virtual environment..."
if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

info "Installing Python backend dependencies..."
pip install -q --upgrade pip
pip install -q -r backend/requirements.txt
ok "Python dependencies installed"

# ─── Go scanner ────────────────────────────────────────────────
info "Building Go scanner service..."
mkdir -p scanner/bin
cd scanner
if go mod tidy && go build -o bin/scanner ./cmd/scanner/; then
  ok "Go scanner built → scanner/bin/scanner"
else
  warn "Go build failed. Install Go 1.22+ and retry."
fi
cd "$SCRIPT_DIR"

# ─── Frontend ──────────────────────────────────────────────────
info "Installing frontend dependencies..."
cd frontend
if command -v npm &>/dev/null; then
  npm install --silent
  info "Building React frontend..."
  npm run build --silent
  ok "Frontend built → frontend/dist/"
else
  warn "npm not found. Install Node.js 18+ then run: cd frontend && npm install && npm run build"
fi
cd "$SCRIPT_DIR"

# ─── Pip extras ────────────────────────────────────────────────
# pymetasploit3 is not in apt — install via pip into the venv.
# python-libnmap and slowapi/python-dotenv are already in requirements.txt.
info "Installing pymetasploit3..."
pip install -q pymetasploit3
ok "pymetasploit3 installed"

# ─── enum4linux-ng fallback ────────────────────────────────────
# Installed via apt above; if it failed (older distro), clone from GitHub.
if ! command -v enum4linux-ng &>/dev/null; then
  warn "enum4linux-ng not found via apt — trying GitHub install..."
  git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng \
    && pip install -q -r /opt/enum4linux-ng/requirements.txt \
    && ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng \
    && chmod +x /opt/enum4linux-ng/enum4linux-ng.py \
    && ok "enum4linux-ng installed from GitHub" \
    || warn "enum4linux-ng install failed — SMB enumeration will fall back to enum4linux"
fi

# ─── Download loot tools ───────────────────────────────────────
LOOT_DIR="/opt/autopwn/loot"
mkdir -p "$LOOT_DIR"

info "Downloading linpeas..."
curl -fsSL "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" \
  -o "$LOOT_DIR/linpeas.sh" && chmod +x "$LOOT_DIR/linpeas.sh" && ok "linpeas downloaded"

info "Downloading winpeas..."
curl -fsSL "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" \
  -o "$LOOT_DIR/winpeas.exe" && ok "winpeas downloaded"

info "Downloading pspy64..."
curl -fsSL "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
  -o "$LOOT_DIR/pspy64" && chmod +x "$LOOT_DIR/pspy64" && ok "pspy64 downloaded"

# ─── Sudoers ───────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
  info "Configuring sudoers for autopwn tools..."
  SUDOERS_FILE="/etc/sudoers.d/autopwn"
  cat > "$SUDOERS_FILE" <<EOF
# AutoPwn tool permissions — allows running specific tools without password
%sudo ALL=(ALL) NOPASSWD: /usr/bin/nmap
%sudo ALL=(ALL) NOPASSWD: /usr/bin/hydra
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/iptables
EOF
  chmod 440 "$SUDOERS_FILE"
  ok "Sudoers configured at $SUDOERS_FILE"
fi

# ─── Data directories ──────────────────────────────────────────
info "Creating data directories..."
mkdir -p data/reports data/loot

# Symlink wordlists if seclists is installed
if [[ -d /usr/share/seclists ]]; then
  ln -sfn /usr/share/seclists data/wordlists/seclists 2>/dev/null || true
  ok "Symlinked /usr/share/seclists → data/wordlists/seclists"
fi
if [[ -d /usr/share/wordlists ]]; then
  ln -sfn /usr/share/wordlists data/wordlists/wordlists 2>/dev/null || true
  ok "Symlinked /usr/share/wordlists → data/wordlists/wordlists"
fi

echo ""
ok "Installation complete!"
echo ""
echo -e "${CYAN}First-time setup:${NC}"
echo "  0. Create your .env file (required for auth):"
echo "       cp .env.example .env"
echo "       # Edit .env and set AUTOPWN_API_TOKEN and MSF_PASSWORD"
echo "       cp .env.example frontend/.env.local"
echo "       # Edit frontend/.env.local and set VITE_API_TOKEN to match AUTOPWN_API_TOKEN"
echo "       cd frontend && npm run build && cd .."
echo "       # Rebuild frontend after setting VITE_API_TOKEN (bakes token into the bundle)"
echo ""
echo -e "${CYAN}To start AutoPwn:${NC}"
echo "  1. Connect to HTB VPN:  sudo openvpn <your.ovpn>"
echo "  2. Activate venv:       source .venv/bin/activate"
echo "  3. Start backend:       python -m backend.main"
echo "  4. Open browser:        http://localhost:8000"
echo ""
echo -e "${YELLOW}For development (hot reload):${NC}"
echo "  Backend:  uvicorn backend.main:app --reload --port 8000"
echo "  Frontend: cd frontend && npm run dev"
