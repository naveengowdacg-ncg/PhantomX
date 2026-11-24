#!/usr/bin/env bash
#
# PhantomX Kali Linux Installer
#
# Idempotent installer for the PhantomX cybersecurity reconnaissance framework.
# Sets up a fresh Kali machine with all system prerequisites, Python environment,
# and scanner tools. Does not run scans or require root beyond APT operations.
#
# Usage:
#   ./install_phantomx_kali.sh          # Normal install
#   ./install_phantomx_kali.sh --dry-run  # Show planned actions without changes
#   ./install_phantomx_kali.sh --help     # Show this help
#
# Requirements:
# - Run as normal user (not root)
# - Kali Linux (detected via /etc/os-release)
# - Internet access for Git, APT, and vendor downloads
#
# Exit codes:
#   0 = success
#   1 = usage / argument error
#   2 = OS/user check failed
#   4 = Git clone/update failed
#   5 = Python/venv setup failed
#   6 = Requirements install failed
#   7 = Verification failed
#   8 = Local changes prevent safe update

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Configuration & Constants
# ──────────────────────────────────────────────────────────────────────

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly REPO_URL="https://github.com/naveengowdacg-ncg/PhantomX.git"
readonly REPO_DIR="${HOME}/PhantomX"
readonly VENV_DIR="${REPO_DIR}/.venv"
readonly BRANCH="main"

# Colors for output (only if stdout is a TTY)
if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[1;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_CYAN='\033[0;36m'
else
    readonly C_RESET=''
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BLUE=''
    readonly C_CYAN=''
fi

# State tracking
DRY_RUN=false
APT_PACKAGES_TO_INSTALL=()
SCANNERS_AVAILABLE=()
SCANNERS_UNAVAILABLE=()
TEMP_DIRS=()

# ──────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────

log_info()    { printf "${C_CYAN}[INFO]${C_RESET} %s\n" "$*"; }
log_success() { printf "${C_GREEN}[OK]${C_RESET} %s\n" "$*"; }
log_warn()    { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$*"; }
log_error()   { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }
log_step()    { printf "\n${C_BLUE}▶${C_RESET} %s\n" "$*"; }

# Dry-run aware command runner - NO eval, uses argument arrays
run_cmd() {
    if [[ "${DRY_RUN}" == true ]]; then
        printf "${C_YELLOW}[DRY-RUN]${C_RESET} %s\n" "$*"
        return 0
    fi
    log_info "Running: $*"
    "$@"
}

# Sudo-aware apt wrapper
apt_install() {
    local packages=("$@")
    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi
    log_step "Installing APT packages: ${packages[*]}"
    run_cmd sudo apt-get update -y
    run_cmd sudo apt-get install -y --no-install-recommends "${packages[@]}"
}

# Cleanup on exit
cleanup() {
    local exit_code=$?
    for d in "${TEMP_DIRS[@]}"; do
        [[ -d "$d" ]] && rm -rf "$d"
    done
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Register temp directory for cleanup
register_temp_dir() {
    TEMP_DIRS+=("$1")
}

# ──────────────────────────────────────────────────────────────────────
# Help / Usage
# ──────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
${SCRIPT_NAME} - PhantomX Kali Linux Installer

Usage: ${SCRIPT_NAME} [OPTIONS]

Options:
  --dry-run    Show planned actions without making changes
  --help       Show this help and exit

Examples:
  ${SCRIPT_NAME}           # Full installation
  ${SCRIPT_NAME} --dry-run # Preview what would be done

Exit codes:
  0 = success
  1 = usage / argument error
  2 = OS/user check failed
  4 = Git clone/update failed
  5 = Python/venv setup failed
  6 = Requirements install failed
  7 = Verification failed
  8 = Local changes prevent safe update
EOF
    exit 0
}

# ──────────────────────────────────────────────────────────────────────
# Argument Parsing
# ──────────────────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) DRY_RUN=true; shift ;;
            --help) usage ;;
            *) log_error "Unknown option: $1"; usage ;;
        esac
    done
}

# ──────────────────────────────────────────────────────────────────────
# Pre-flight Checks
# ──────────────────────────────────────────────────────────────────────

check_os() {
    log_step "Verifying OS is Kali Linux"
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS: /etc/os-release missing"
        exit 2
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID,,}" != "kali" ]]; then
        log_error "This installer is for Kali Linux only. Detected: ${PRETTY_NAME:-${ID}}"
        exit 2
    fi
    log_success "OS verified: ${PRETTY_NAME}"
}

check_user() {
    log_step "Verifying user context"
    if [[ $EUID -eq 0 ]]; then
        log_error "Do not run as root. Run as a normal user; sudo will be used for APT only."
        exit 2
    fi
    if ! sudo -n true 2>/dev/null; then
        log_warn "Sudo access required for APT operations. You may be prompted for your password."
        sudo -v || { log_error "Sudo authentication failed"; exit 2; }
    fi
    log_success "Running as user: $(whoami)"
}

check_internet() {
    log_step "Checking internet connectivity"
    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Would check internet connectivity"
        return 0
    fi
    if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log_warn "No internet connectivity detected. Git/APT operations may fail."
    else
        log_success "Internet reachable"
    fi
}

# ──────────────────────────────────────────────────────────────────────
# APT Package Installation
# ──────────────────────────────────────────────────────────────────────

install_system_prerequisites() {
    log_step "Installing system prerequisites via APT"

    # Core packages needed for PhantomX + build deps for Python packages
    local core_packages=(
        git
        python3
        python3-venv
        python3-pip
        python3-tk          # Tkinter for GUI
        python3-dev         # Headers for building wheels
        build-essential     # Compiler toolchain
        libssl-dev          # OpenSSL dev headers
        libffi-dev          # libffi dev headers
        curl
        ca-certificates
        gnupg
        lsb-release
        unzip               # For Subfinder extraction
    )

    # Scanner tools available in official Kali repositories
    # Using correct Kali package names
    local scanner_packages=(
        nmap
        whatweb
        nikto
        nuclei
        gobuster
        dnsx
        httpx-toolkit       # Kali package name is httpx-toolkit
        katana
        testssl.sh          # Kali package name is testssl.sh
    )

    APT_PACKAGES_TO_INSTALL=("${core_packages[@]}" "${scanner_packages[@]}")

    if [[ "${DRY_RUN}" == true ]]; then
        log_step "DRY-RUN: Would install APT packages:"
        printf '  %s\n' "${APT_PACKAGES_TO_INSTALL[@]}"
        return 0
    fi

    log_info "Updating package index..."
    run_cmd sudo apt-get update -y

    log_info "Installing ${#APT_PACKAGES_TO_INSTALL[@]} packages..."
    run_cmd sudo apt-get install -y --no-install-recommends "${APT_PACKAGES_TO_INSTALL[@]}"

    log_success "APT packages installed"
}

# ──────────────────────────────────────────────────────────────────────
# Scanner Tools - Additional Installation (Non-APT)
# ──────────────────────────────────────────────────────────────────────

install_subfinder() {
    log_step "Installing Subfinder (official vendor release)"

    if command -v subfinder >/dev/null 2>&1; then
        log_success "Subfinder already installed: $(subfinder -version 2>&1 | head -1)"
        SCANNERS_AVAILABLE+=("subfinder")
        return 0
    fi

    local tmpdir version url archive expected_sha256 actual_sha256
    tmpdir=$(mktemp -d)
    register_temp_dir "$tmpdir"

    # Fetch latest version from GitHub API
    log_info "Fetching latest Subfinder version..."
    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Would fetch latest Subfinder version from GitHub API"
        return 0
    fi

    version=$(curl -sL "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest" \
        | grep -Po '"tag_name":\s*"\K[^"]+' | head -1)
    if [[ -z "$version" ]]; then
        log_error "Failed to determine latest Subfinder version"
        SCANNERS_UNAVAILABLE+=("subfinder")
        return 1
    fi
    log_info "Latest version: $version"

    # Download and verify
    url="https://github.com/projectdiscovery/subfinder/releases/download/${version}/subfinder_${version#v}_linux_amd64.zip"
    archive="${tmpdir}/subfinder.zip"

    log_info "Downloading: $url"
    if ! run_cmd curl -sL -o "$archive" "$url"; then
        log_error "Failed to download Subfinder"
        SCANNERS_UNAVAILABLE+=("subfinder")
        return 1
    fi

    # Verify checksum (SHA256 from release page) - MANDATORY
    log_info "Verifying checksum..."
    local sha256_url="https://github.com/projectdiscovery/subfinder/releases/download/${version}/subfinder_${version#v}_checksums.txt"
    local expected_sha256
    expected_sha256=$(curl -sL "$sha256_url" | grep "linux_amd64.zip" | awk '{print $1}')
    if [[ -z "$expected_sha256" ]]; then
        log_error "Could not retrieve expected SHA256 checksum for Subfinder"
        SCANNERS_UNAVAILABLE+=("subfinder")
        return 1
    fi
    actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        log_error "Checksum mismatch for Subfinder archive (expected: $expected_sha256, got: $actual_sha256)"
        SCANNERS_UNAVAILABLE+=("subfinder")
        return 1
    fi
    log_success "Checksum verified"

    log_info "Installing to /usr/local/bin..."
    run_cmd sudo unzip -o -q "$archive" -d "$tmpdir"
    run_cmd sudo install -m 0755 "$tmpdir/subfinder" /usr/local/bin/subfinder

    if command -v subfinder >/dev/null 2>&1; then
        log_success "Subfinder installed: $(subfinder -version 2>&1 | head -1)"
        SCANNERS_AVAILABLE+=("subfinder")
    else
        log_error "Subfinder installation failed"
        SCANNERS_UNAVAILABLE+=("subfinder")
        return 1
    fi
}

install_optional_scanners() {
    log_step "Installing optional scanners not in APT"

    # Subfinder (no Kali package)
    install_subfinder || true
}

# ──────────────────────────────────────────────────────────────────────
# Git Repository Management
# ──────────────────────────────────────────────────────────────────────

clone_or_update_repo() {
    log_step "Managing PhantomX repository"

    if [[ ! -d "$REPO_DIR" ]]; then
        log_info "Cloning repository to $REPO_DIR..."
        run_cmd git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
        log_success "Repository cloned"
        return 0
    fi

    log_info "Repository exists at $REPO_DIR. Verifying..."

    # Verify it's the correct remote
    local remote_url
    remote_url=$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || echo "")
    if [[ "$remote_url" != "$REPO_URL" ]]; then
        log_error "Existing directory $REPO_DIR has different remote: $remote_url"
        log_error "Expected: $REPO_URL"
        log_error "Please rename or remove the directory and re-run."
        exit 4
    fi

    # Check for local changes (tracked AND untracked)
    if ! git -C "$REPO_DIR" diff --quiet 2>/dev/null || \
       ! git -C "$REPO_DIR" diff --cached --quiet 2>/dev/null || \
       [[ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ]]; then
        log_error "Local changes detected in $REPO_DIR. Refusing to overwrite."
        log_error "Commit or stash your changes, then re-run."
        exit 8
    fi

    # Fetch and fast-forward
    log_info "Fetching latest changes from origin..."
    run_cmd git -C "$REPO_DIR" fetch origin

    local local_rev remote_rev
    local_rev=$(git -C "$REPO_DIR" rev-parse HEAD)
    remote_rev=$(git -C "$REPO_DIR" rev-parse "origin/$BRANCH")

    if [[ "$local_rev" == "$remote_rev" ]]; then
        log_success "Repository already up to date"
        return 0
    fi

    # Check if fast-forward possible
    if git -C "$REPO_DIR" merge-base --is-ancestor "$local_rev" "origin/$BRANCH" 2>/dev/null; then
        log_info "Fast-forwarding to latest $BRANCH..."
        run_cmd git -C "$REPO_DIR" merge --ff-only "origin/$BRANCH"
        log_success "Repository updated"
    else
        log_error "Local branch has diverged from origin/$BRANCH."
        log_error "Cannot safely update. Manual intervention required."
        exit 4
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Python Virtual Environment & Requirements
# ──────────────────────────────────────────────────────────────────────

setup_python_environment() {
    log_step "Setting up Python virtual environment"

    # Check Python version
    local py_version
    py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_info "System Python: $py_version"

    # Check minimum version (3.10+)
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
        log_error "Python 3.10+ required. Found: $py_version"
        exit 5
    fi
    log_success "Python version OK: $py_version"

    # Create/reuse virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
        log_info "Creating virtual environment at $VENV_DIR..."
        run_cmd python3 -m venv "$VENV_DIR"
    else
        log_info "Reusing existing virtual environment at $VENV_DIR"
    fi

    # Activate and upgrade pip
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    run_cmd pip install --upgrade pip setuptools wheel

    # Install requirements
    local req_file="${REPO_DIR}/requirements.txt"
    if [[ ! -f "$req_file" ]]; then
        log_warn "No requirements.txt found at $req_file"
        if [[ -f "${REPO_DIR}/pyproject.toml" ]]; then
            log_info "Found pyproject.toml, installing from it..."
            run_cmd pip install -e "${REPO_DIR}"
        else
            log_warn "No pyproject.toml either; skipping Python deps"
        fi
    else
        log_info "Installing Python requirements from $req_file..."
        run_cmd pip install -r "$req_file"
    fi

    log_success "Python environment ready"
}

# ──────────────────────────────────────────────────────────────────────
# Verification
# ──────────────────────────────────────────────────────────────────────

verify_installation() {
    log_step "Verifying installation"

    # Ensure venv is activated
    source "$VENV_DIR/bin/activate"

    # Core imports
    log_info "Testing core imports..."
    run_cmd python3 -c "
import sys
import json
import sqlite3
import ssl
import tkinter
import tkinter.ttk
print('Core imports OK')
"

    # PhantomX imports
    log_info "Testing PhantomX imports..."
    run_cmd python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from core.models import Session, ToolResult, Finding
from core.scope import TargetScope
from core.workflow import WorkflowEngine
from core.adapter_manager import AdapterManager
from core.executor import ToolExecutor
from core.preflight import ToolPreflight
from core.tool_registry import ToolRegistry
from core.settings import load_settings
from core.storage import SQLiteSessionStore
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from analysis.correlation import CorrelationEngine
from analysis.asset_intelligence import AssetIntelligenceBuilder
from reporting.reporter import Reporter
print('PhantomX imports OK')
"

    # Check adapters
    log_info "Checking scanner adapters..."
    run_cmd python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from core.adapter_manager import AdapterManager
mgr = AdapterManager()
for name in ['nmap','whatweb','nikto','nuclei','subfinder','dnsx','httpx','katana','testssl','gobuster']:
    adapter = mgr.get(name)
    print(f'  {name}: {\"OK\" if adapter else \"MISSING\"} (available: {adapter.is_available() if adapter else False})')
"

    # Check scanner executables
    log_info "Checking scanner executables..."
    local available=0 total=0
    for cmd in nmap whatweb nikto nuclei subfinder dnsx httpx-toolkit katana testssl testssl.sh gobuster; do
        ((total+=1))
        if command -v "$cmd" >/dev/null 2>&1; then
            ((available+=1))
            echo "  $cmd: FOUND"
        else
            echo "  $cmd: MISSING"
        fi
    done
    log_success "Executables available: $available/$total"

    # Quick functionality test (no scan)
    log_info "Running quick functionality test..."
    run_cmd python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from core.scope import TargetScope
scope = TargetScope(True, ['127.0.0.1', 'localhost', '::1'])
assert scope.validate('127.0.0.1') == '127.0.0.1'
print('Scope validation OK')
"

    # Verify Nikto handling
    log_info "Verifying Nikto handling..."
    run_cmd python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from modules.nikto.parser import NiktoParser
parser = NiktoParser()
# Test with sample Nikto output containing completion markers
sample = '''+ Target IP: 127.0.0.1
+ Target Hostname: localhost
+ Target Port: 80
+ Start Time: 2024-01-01 00:00:00
+ Server: Apache
+ Retrieved x-powered-by header: PHP/7.4
+ OSVDB-12345: Test finding
+ 1 host(s) tested
+ 1 item(s) reported on remote host
+ End Time: 2024-01-01 00:00:01'''
findings = parser.parse(sample, '127.0.0.1')
print(f'Parsed {len(findings)} findings')
for f in findings:
    print(f'  - {f.title} (verification: {f.metadata.get(\"verification_status\")})')
"

    # Quick functionality test (no scan)
    log_info "Running quick functionality test..."
    run_cmd python3 -c "
import sys
sys.path.insert(0, '$REPO_DIR')
from core.scope import TargetScope
scope = TargetScope(True, ['127.0.0.1', 'localhost', '::1'])
assert scope.validate('127.0.0.1') == '127.0.0.1'
print('Scope validation OK')
"

    log_success "All verification checks passed"
}

# ──────────────────────────────────────────────────────────────────────
# Summary & Launch Instructions
# ──────────────────────────────────────────────────────────────────────

print_summary() {
    log_step "Installation Summary"

    echo -e "\n${C_GREEN}═══ PhantomX Installation Complete ═══${C_RESET}"
    echo
    echo "Repository:     $REPO_DIR"
    echo "Virtual env:    $VENV_DIR"
    echo "Python:         $(python3 --version)"
    echo "Git branch:     $(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
    echo "Git commit:     $(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    echo
    echo -e "${C_CYAN}Available scanners:${C_RESET}"
    for s in "${SCANNERS_AVAILABLE[@]}"; do
        echo "  ✓ $s"
    done
    if [[ ${#SCANNERS_UNAVAILABLE[@]} -gt 0 ]]; then
        echo -e "${C_YELLOW}Unavailable scanners:${C_RESET}"
        for s in "${SCANNERS_UNAVAILABLE[@]}"; do
            echo "  ✗ $s"
        done
    fi
    echo
    echo -e "${C_BLUE}Launch commands:${C_RESET}"
    echo "  CLI:  cd $REPO_DIR && source .venv/bin/activate && python main.py"
    echo "  GUI:  cd $REPO_DIR && source .venv/bin/activate && python gui.py"
    echo
    echo -e "${C_YELLOW}Next steps:${C_RESET}"
    echo "  1. Run 'preflight' in CLI to check tool availability"
    echo "  2. Set authorized target: 'target <host/IP/CIDR>'"
    echo "  3. Run a profile: 'scan profile standard' (or passive/stealth/full/aggressive)"
    echo "  4. Generate reports: 'report all'"
    echo
    echo -e "${C_GREEN}Installation completed successfully!${C_RESET}"
}

# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    echo -e "${C_BLUE}╔════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BLUE}║     PhantomX Kali Linux Installer                  ║${C_RESET}"
    echo -e "${C_BLUE}╚═══════════════════════════════════════════════════╝${C_RESET}"
    echo

    if [[ "${DRY_RUN}" == true ]]; then
        log_warn "DRY-RUN MODE: No changes will be made"
        echo
    fi

    check_os
    check_user
    check_internet

    install_system_prerequisites
    install_optional_scanners
    clone_or_update_repo
    setup_python_environment
    verify_installation
    print_summary

    log_success "All done!"
}

main "$@"
