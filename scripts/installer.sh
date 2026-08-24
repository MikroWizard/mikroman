#!/usr/bin/env bash
# =============================================================================
# MikroWizard Enterprise System Installer
# =============================================================================
# Professional automated installation & orchestration script for MikroWizard.
# Performs pre-flight requirement checks, container orchestration, database
# migrations, and post-installation security hardening recommendations.
# =============================================================================

set -eo pipefail

# -----------------------------------------------------------------------------
# Log File Setup
# -----------------------------------------------------------------------------
# Log file is created in the directory where the installer is executed.
INSTALL_LOG_DIR="$(pwd)"
INSTALL_LOG="${INSTALL_LOG_DIR}/mikrowizard-install-$(date +%Y%m%d_%H%M%S).log"

# Write a timestamped raw (no color) line to the log file
_log_raw() {
    printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "${INSTALL_LOG}" 2>/dev/null || true
}

# Append arbitrary text block to the log file (used to save command output)
_log_append_file() {
    local label="$1"
    local file="$2"
    if [ -f "$file" ] && [ -s "$file" ]; then
        {
            echo "--- ${label} ---"
            cat "$file"
            echo "--- end ---"
        } >> "${INSTALL_LOG}" 2>/dev/null || true
    fi
}

# -----------------------------------------------------------------------------
# Color & UI Formatting Utilities
# -----------------------------------------------------------------------------
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

log_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "======================================================================"
    echo "           MikroWizard Management Platform Installer                 "
    echo "======================================================================"
    echo -e "${RESET}"
    _log_raw "======================================================================"
    _log_raw "  MikroWizard Management Platform Installer"
    _log_raw "  Log file: ${INSTALL_LOG}"
    _log_raw "  Executed by: $(id) from $(pwd)"
    _log_raw "  Host: $(hostname -f 2>/dev/null || hostname)"
    _log_raw "  OS: $(uname -a)"
    _log_raw "======================================================================"
    echo -e "  ${DIM}Installation log: ${INSTALL_LOG}${RESET}"
    echo ""
}

log_step() {
    local step="$1"
    local total="$2"
    local title="$3"
    echo ""
    echo -e "${BLUE}${BOLD}[$step/$total] $title${RESET}"
    echo -e "${DIM}----------------------------------------------------------------------${RESET}"
    _log_raw ""
    _log_raw "[$step/$total] $title"
    _log_raw "----------------------------------------------------------------------"
}

log_info() {
    echo -e "${CYAN}[INFO]${RESET} $1"
    _log_raw "[INFO] $1"
}

log_success() {
    echo -e "${GREEN}[OK]${RESET} $1"
    _log_raw "[OK]   $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${RESET} $1"
    _log_raw "[WARN] $1"
}

log_error() {
    echo -e "${RED}[FAIL]${RESET} $1" >&2
    _log_raw "[FAIL] $1"
}


# -----------------------------------------------------------------------------
# Spinner / Progress Animation
# -----------------------------------------------------------------------------
# Usage: run_with_spinner "Message" command [args...]
# Runs command in background while animating a spinner.
# On failure, dumps last 20 lines of captured output for diagnostics.
_SPINNER_PID=""
_SPINNER_LOG=""

_start_spinner() {
    local msg="$1"
    local frames=('\u280b' '\u2819' '\u2839' '\u2838' '\u283c' '\u2834' '\u2826' '\u2827' '\u2807' '\u280f')
    local i=0
    tput civis 2>/dev/null || true
    (
        while true; do
            printf "\r  ${CYAN}${frames[$i]}${RESET}  %s" "$msg"
            i=$(( (i + 1) % ${#frames[@]} ))
            sleep 0.1
        done
    ) &
    _SPINNER_PID=$!
}

_stop_spinner() {
    local success="$1"
    local msg="$2"
    if [ -n "$_SPINNER_PID" ] && kill -0 "$_SPINNER_PID" 2>/dev/null; then
        kill "$_SPINNER_PID" 2>/dev/null
        wait "$_SPINNER_PID" 2>/dev/null || true
        _SPINNER_PID=""
    fi
    tput cnorm 2>/dev/null || true
    if [ "$success" = "ok" ]; then
        printf "\r  ${GREEN}\u2714${RESET}  %-70s\n" "$msg"
    else
        printf "\r  ${RED}\u2718${RESET}  %-70s\n" "$msg"
    fi
}

run_with_spinner() {
    local msg="$1"
    shift
    _SPINNER_LOG=$(mktemp /tmp/mw_install_XXXXXX.log)

    _log_raw "[RUN]  $msg"
    _log_raw "[CMD]  $*"

    _start_spinner "$msg"
    local exit_code=0
    "$@" >"$_SPINNER_LOG" 2>&1 || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        _stop_spinner "ok" "$msg"
        _log_raw "[OK]   $msg (exit 0)"
        _log_append_file "output: $*" "$_SPINNER_LOG"
    else
        _stop_spinner "fail" "$msg"
        _log_raw "[FAIL] $msg (exit $exit_code)"
        _log_append_file "output: $*" "$_SPINNER_LOG"
        echo ""
        echo -e "${DIM}--- Last output (diagnostics) ---${RESET}"
        tail -n 20 "$_SPINNER_LOG" 2>/dev/null | sed 's/^/  /'
        echo -e "${DIM}---------------------------------${RESET}"
        echo -e "${DIM}Full output saved to: ${INSTALL_LOG}${RESET}"
        rm -f "$_SPINNER_LOG"
        return $exit_code
    fi
    rm -f "$_SPINNER_LOG"
    return 0
}

_cleanup_spinner() {
    if [ -n "$_SPINNER_PID" ] && kill -0 "$_SPINNER_PID" 2>/dev/null; then
        kill "$_SPINNER_PID" 2>/dev/null
        wait "$_SPINNER_PID" 2>/dev/null || true
        tput cnorm 2>/dev/null || true
        echo ""
    fi
    rm -f "$_SPINNER_LOG" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Execution & TTY Context Detection
# -----------------------------------------------------------------------------
DOCKER_EXEC_FLAGS="-i"
if [ -t 0 ] && [ -t 1 ]; then
    IS_INTERACTIVE=true
elif [ -r /dev/tty ] && [ -w /dev/tty ]; then
    IS_INTERACTIVE=true
else
    IS_INTERACTIVE=false
fi

# TTY-aware read helper: reads from /dev/tty if stdin is connected to a pipe (e.g. curl ... | sudo bash)
prompt_read() {
    if [ -t 0 ]; then
        read "$@"
    elif [ -r /dev/tty ]; then
        read "$@" < /dev/tty
    else
        read "$@"
    fi
}

# -----------------------------------------------------------------------------
# Cleanup Trap on Error
# -----------------------------------------------------------------------------
cleanup_on_exit() {
    local exit_code=$?
    _cleanup_spinner
    rm -f ./init.sql ./init.sql.rendered 2>/dev/null || true
    if [ $exit_code -ne 0 ]; then
        echo ""
        log_error "Installation failed or was interrupted (Exit Code: $exit_code)."
        log_info "Check logs above for details. You can safely re-run this script after resolving the issue."
        echo -e "${YELLOW}${BOLD}Full installation log saved at:${RESET} ${INSTALL_LOG}"
        _log_raw "======================================================================"
        _log_raw "INSTALLATION FAILED (Exit Code: $exit_code)"
        _log_raw "======================================================================"
    else
        _log_raw "======================================================================"
        _log_raw "INSTALLATION COMPLETED SUCCESSFULLY"
        _log_raw "======================================================================"
    fi
}
trap cleanup_on_exit EXIT

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -Htlpn "sport = :${port}" 2>/dev/null | grep -q "." && return 0 || return 1
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"${port}" -sTCP:LISTEN -t >/dev/null 2>&1 && return 0 || return 1
    else
        (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && exec 3<&- && return 0 || return 1
    fi
}

get_port_owner() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -Htlpn "sport = :${port}" 2>/dev/null | head -n 1 | awk '{print $NF}'
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | head -n 2 | tail -n 1 | awk '{print $1 "[" $2 "]"}'
    else
        echo "Unknown Process"
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        if [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && ${octets[2]} -le 255 && ${octets[3]} -le 255 ]]; then
            return 0
        fi
    fi
    return 1
}

validate_username() {
    local username="$1"
    if [[ ${#username} -ge 1 && ${#username} -le 63 && "$username" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
        return 0
    fi
    return 1
}

validate_secret() {
    local secret="$1"
    if [[ ${#secret} -ge 8 && "$secret" =~ [A-Z] && "$secret" =~ [a-z] && "$secret" =~ [0-9] ]]; then
        return 0
    fi
    return 1
}

is_valid_path() {
    local path="$1"
    if [[ -z "$path" ]]; then
        return 1
    elif [[ "$path" == "/" ]]; then
        return 0
    elif [[ -d "$path" ]]; then
        return 0
    else
        local parent_dir
        parent_dir=$(dirname "$path")
        is_valid_path "$parent_dir"
    fi
}

# Compare semver strings ($1 >= $2) using zero-dependency Python tuple comparison
semver_ge() {
    python3 -c "
import sys

def parse_ver(v):
    return [int(x) for x in v.replace('-', '.').split('.') if x.isdigit()]

sys.exit(0 if parse_ver(sys.argv[1]) >= parse_ver(sys.argv[2]) else 1)
" "$1" "$2" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# STEP 1: Pre-flight & System Requirements Checks
# -----------------------------------------------------------------------------
check_prerequisites() {
    log_step 1 6 "Pre-flight System & Requirement Checks"

    # Root Privilege Check
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be executed as root (e.g. sudo bash installer.sh)."
        exit 1
    fi
    log_success "Executed with root privileges."

    # Architecture Check
    local arch
    arch=$(uname -m)
    log_info "System Architecture: ${arch}"
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
        log_warn "Architecture $arch is non-standard. x86_64 or aarch64 is recommended."
    fi

    # Free Memory Check
    if command -v free >/dev/null 2>&1; then
        local free_ram
        free_ram=$(free -m | awk '/^Mem:/{print $7}')
        if [ -n "$free_ram" ] && [ "$free_ram" -lt 1000 ]; then
            log_warn "Available RAM is under 1GB (${free_ram}MB). MikroWizard operates best with 2GB+ RAM."
        else
            log_success "System Memory: ${free_ram:-OK}MB available."
        fi
    fi

    # Free Disk Space Check
    local free_space
    free_space=$(df -BG /opt 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ -n "$free_space" ] && [ "$free_space" -lt 3 ]; then
        log_warn "Disk space on /opt is under 3GB (${free_space}GB free)."
    else
        log_success "Disk Storage: ${free_space:-OK}GB available in /opt."
    fi

    # Missing Tool Dependencies Check & Auto-Install
    local missing_tools=()
    for tool in curl python3 iproute2; do
        if [[ "$tool" == "iproute2" ]]; then
            command -v ss >/dev/null 2>&1 || command -v lsof >/dev/null 2>&1 || missing_tools+=("iproute2")
        else
            command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_info "Installing missing utility dependencies: ${missing_tools[*]}..."
        if command -v apt-get >/dev/null 2>&1; then
            run_with_spinner "Updating package index..." \
                apt-get update -qq
            run_with_spinner "Installing prerequisite tools..." \
                env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl python3 iproute2 ca-certificates
        elif command -v yum >/dev/null 2>&1; then
            run_with_spinner "Installing prerequisite tools (yum)..." \
                yum install -y curl python3 iproute
        fi
    fi
    log_success "All prerequisite CLI tools are available."
}

# -----------------------------------------------------------------------------
# STEP 2: Docker Engine Verification & Installation
# -----------------------------------------------------------------------------

# Internal: install Docker via apt on Debian/Ubuntu (non-interactive, with progress)
_install_docker_apt() {
    export DEBIAN_FRONTEND=noninteractive
    run_with_spinner "Updating package index..." \
        apt-get update -qq
    run_with_spinner "Installing Docker prerequisites (ca-certificates, curl, gnupg)..." \
        apt-get install -y -qq apt-transport-https ca-certificates curl software-properties-common gnupg
    run_with_spinner "Adding Docker official GPG key..." \
        bash -c '
            mkdir -p /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
                | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
        '
    local distro arch_dpkg
    distro=$(lsb_release -cs 2>/dev/null || echo "focal")
    arch_dpkg=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    echo "deb [arch=${arch_dpkg} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${distro} stable" \
        > /etc/apt/sources.list.d/docker.list
    run_with_spinner "Refreshing package index with Docker repository..." \
        apt-get update -qq
    run_with_spinner "Installing Docker Engine (docker-ce, docker-ce-cli, containerd.io)..." \
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io
}

# Internal: install Docker via official convenience script (non-interactive)
# NOTE: We download the script first, then run with DEBIAN_FRONTEND=noninteractive.
# Do NOT use "curl | sh" directly — that creates a pipeline that can hang SSH
# if systemd post-install hooks request a TTY.
_install_docker_script() {
    local tmp_script
    tmp_script=$(mktemp /tmp/get-docker-XXXXXX.sh)
    run_with_spinner "Downloading Docker install script from get.docker.com..." \
        curl -fsSL https://get.docker.com -o "$tmp_script"
    run_with_spinner "Running Docker convenience installer (may take a few minutes)..." \
        env DEBIAN_FRONTEND=noninteractive bash "$tmp_script"
    rm -f "$tmp_script"
}

check_and_setup_docker() {
    log_step 2 6 "Docker Engine Verification & Setup"

    local min_docker_ver="20.10.0"
    local docker_installed=false
    local curr_docker_ver=""

    if command -v docker >/dev/null 2>&1; then
        curr_docker_ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "")
        if [ -n "$curr_docker_ver" ]; then
            docker_installed=true
        fi
    fi

    if [ "$docker_installed" = true ]; then
        log_info "Detected Docker Engine version: ${curr_docker_ver}"
        if semver_ge "$curr_docker_ver" "$min_docker_ver"; then
            log_success "Docker Engine meets minimum version requirements (>= ${min_docker_ver})."
        else
            log_warn "Docker version ${curr_docker_ver} is older than recommended ${min_docker_ver}."
        fi
    else
        log_info "Docker Engine not detected. Proceeding with Docker installation..."
        echo ""

        local install_ok=false
        if command -v apt-get >/dev/null 2>&1; then
            if _install_docker_apt; then
                install_ok=true
            else
                log_warn "Apt-based Docker install failed. Falling back to official install script..."
                _install_docker_script && install_ok=true || true
            fi
        else
            _install_docker_script && install_ok=true || true
        fi

        if [ "$install_ok" = false ]; then
            log_error "Docker installation failed. Please install Docker manually and re-run this script."
            exit 1
        fi

        run_with_spinner "Starting and enabling Docker daemon..." \
            bash -c 'systemctl start docker && systemctl enable docker'

        log_success "Docker Engine installed and started successfully."
    fi

    # Verify Docker daemon responsiveness
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not responding. Please check: systemctl status docker"
        exit 1
    fi
    log_success "Docker daemon is responsive."
    docker version >> "${INSTALL_LOG}" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# STEP 3: Active Installation Detection & Port Verification
# -----------------------------------------------------------------------------
check_ports_and_existing_install() {
    log_step 3 6 "Active Installation Guard & Network Port Check"

    # Detect Existing MikroWizard Containers
    local mw_containers=("redis-stack-server" "MikroWizard-postgre" "mikrofront" "mikroman")
    local existing_found=()

    for container in "${mw_containers[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            existing_found+=("$container")
        fi
    done

    if [ ${#existing_found[@]} -gt 0 ]; then
        log_warn "Active MikroWizard installation containers detected:"
        docker ps -a --format "  - {{.Names}} (Status: {{.Status}}, Ports: {{.Ports}})" | grep -E "redis-stack-server|MikroWizard-postgre|mikrofront|mikroman" || true
        echo ""

        if [ "${NONINTERACTIVE:-0}" -eq 1 ] || [ "${FORCE_OVERWRITE:-0}" -eq 1 ]; then
            log_info "NONINTERACTIVE/FORCE_OVERWRITE enabled. Existing containers will be safely updated."
        else
            if [ "$IS_INTERACTIVE" = true ]; then
                prompt_read -p "Do you want to proceed and update existing MikroWizard containers? [y/N]: " confirm_overwrite
                if [[ ! "$confirm_overwrite" =~ ^[Yy]$ ]]; then
                    log_info "Installation aborted by user to preserve existing containers."
                    exit 0
                fi
            else
                log_warn "Non-interactive shell detected. Proceeding with container update..."
            fi
        fi
    fi

    # Check Required Network Ports (6379, 5432, 80, 443)
    local required_ports=(6379 5432 80 443)
    local conflicting_ports=()

    for port in "${required_ports[@]}"; do
        if is_port_in_use "$port"; then
            # Ignore if port is currently used by our OWN existing containers
            local is_self_container=false
            for container in "${existing_found[@]}"; do
                if docker ps --format '{{.Names}} {{.Ports}}' | grep "^${container}[[:space:]]" | grep -q ":${port}"; then
                    is_self_container=true
                    break
                fi
            done

            if [ "$is_self_container" = false ]; then
                local owner
                owner=$(get_port_owner "$port")
                conflicting_ports+=("Port $port (Process: $owner)")
            fi
        fi
    done

    if [ ${#conflicting_ports[@]} -gt 0 ]; then
        log_error "The following required network ports are already bound by external services:"
        for conflict in "${conflicting_ports[@]}"; do
            echo -e "  ${RED}* ${conflict}${RESET}"
        done
        echo ""
        log_info "Port Requirements Breakdown:"
        log_info "  - Port 6379 : Redis Stack Server"
        log_info "  - Port 5432 : PostgreSQL Database"
        log_info "  - Port 80   : Nginx HTTP Frontend"
        log_info "  - Port 443  : Nginx HTTPS Frontend"
        log_info "Please stop the conflicting host processes or free these ports before retrying."
        exit 1
    fi

    log_success "Port validation passed. All required network ports are available."
}

# -----------------------------------------------------------------------------
# STEP 4: Configuration & Input Collection
# -----------------------------------------------------------------------------
prompt_inputs() {
    log_step 4 6 "Configuration Parameters & Credentials Setup"

    dbname="MikroWizardDB"

    # PostgreSQL Username
    if [ -n "$DB_USER" ]; then
        username="$DB_USER"
        log_info "Using PostgreSQL Username from environment: ${username}"
        _log_raw "[INPUT] PostgreSQL username (from env): $username"
    else
        while true; do
            prompt_read -p "Enter PostgreSQL Database Username [default: postgres]: " input_user
            username="${input_user:-postgres}"
            if validate_username "$username"; then
                _log_raw "[INPUT] PostgreSQL username set to: $username"
                break
            else
                log_warn "Invalid PostgreSQL username. Must be 1-63 alphanumeric/underscore characters."
            fi
        done
    fi

    # PostgreSQL Password
    if [ -n "$DB_PASS" ]; then
        password="$DB_PASS"
        log_info "Using PostgreSQL Password from environment."
    else
        while true; do
            prompt_read -s -p "Enter secure PostgreSQL Password (min 8 chars, uppercase, lowercase, digit): " password
            echo ""
            if validate_secret "$password"; then
                log_success "PostgreSQL password validated."
                _log_raw "[INPUT] PostgreSQL password: [REDACTED - validated OK]"
                break
            else
                log_warn "Insecure password. Criteria: 8+ characters, including [A-Z], [a-z], [0-9]."
            fi
        done
    fi

    # Primary Server IP Address
    local default_detected_ip
    default_detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

    if [ -n "$SERVER_IP" ]; then
        serverip="$SERVER_IP"
        log_info "Using Server IP from environment: ${serverip}"
        _log_raw "[INPUT] Server IP (from env): $serverip"
    else
        while true; do
            prompt_read -p "Enter Primary Server IP address [default: $default_detected_ip]: " input_ip
            serverip="${input_ip:-$default_detected_ip}"
            if validate_ip "$serverip"; then
                _log_raw "[INPUT] Server IP set to: $serverip"
                break
            else
                log_warn "Invalid IPv4 address format. Please enter a valid IP (e.g. 192.168.1.100)."
            fi
        done
    fi

    # RADIUS Secret
    if [ -n "$RAD_SECRET" ]; then
        secret="$RAD_SECRET"
        log_info "Using RADIUS Secret from environment."
    else
        while true; do
            prompt_read -s -p "Enter secure RADIUS Secret (min 8 chars, uppercase, lowercase, digit): " secret
            echo ""
            if validate_secret "$secret"; then
                log_success "RADIUS secret validated."
                _log_raw "[INPUT] RADIUS secret: [REDACTED - validated OK]"
                break
            else
                log_warn "Insecure RADIUS secret. Criteria: 8+ characters, including [A-Z], [a-z], [0-9]."
            fi
        done
    fi

    # Firmware Storage Path
    local default_firmpath="/opt/mikrowizard/firmwares"
    if [ -n "$FIRMWARE_PATH" ]; then
        firmpath="$FIRMWARE_PATH"
    else
        prompt_read -p "Enter path for firmware storage [default: $default_firmpath]: " input_firmpath
        firmpath="${input_firmpath:-$default_firmpath}"
    fi

    while ! [[ "$firmpath" == /* ]] || ! is_valid_path "$firmpath"; do
        log_warn "Invalid path format. Path must start with /."
        prompt_read -p "Enter valid absolute path for firmware storage: " firmpath
    done
    mkdir -p "$firmpath"
    log_success "Firmware directory configured: ${firmpath}"
    _log_raw "[INPUT] Firmware path: $firmpath"

    # Backup Storage Path
    local default_backuppath="/opt/mikrowizard/backup"
    if [ -n "$BACKUP_PATH" ]; then
        backuppath="$BACKUP_PATH"
    else
        prompt_read -p "Enter path for backup storage [default: $default_backuppath]: " input_backuppath
        backuppath="${input_backuppath:-$default_backuppath}"
    fi

    while ! [[ "$backuppath" == /* ]] || ! is_valid_path "$backuppath"; do
        log_warn "Invalid path format. Path must start with /."
        prompt_read -p "Enter valid absolute path for backup storage: " backuppath
    done
    mkdir -p "$backuppath"
    log_success "Backup directory configured: ${backuppath}"
    _log_raw "[INPUT] Backup path: $backuppath"
}

# -----------------------------------------------------------------------------
# STEP 5: Configuration Files & Directory Preparation
# -----------------------------------------------------------------------------
setup_directories_and_config() {
    log_step 5 6 "Directory Structures & Security Configurations"

    mkdir -p /opt/mikrowizard/

    # Generate secure random keys
    log_info "Generating cryptographic tokens and passwords..."
    encryptKey=$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8'))")
    redisPassword=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

    # Generate server-conf.json safely via Python JSON dump using Environment Variables to prevent string injection
    DB_NAME="$dbname"     DB_USER="$username"     DB_PASS="$password"     CRYPT_KEY="$encryptKey"     REDIS_PASS="$redisPassword"     python3 -c '
import json, os

conf = {
    "name": "MikroWizard Production Configuration",
    "PYSRV_IS_PRODUCTION": "1",
    "PYSRV_DATABASE_HOST": "127.0.0.1",
    "PYSRV_DATABASE_HOST_POSTGRESQL": "127.0.0.1",
    "PYSRV_DATABASE_HOST_SQLITE": "/app/data/mydb.sqlite",
    "PYSRV_DATABASE_PORT": "5432",
    "PYSRV_DATABASE_NAME": os.environ["DB_NAME"],
    "PYSRV_DATABASE_USER": os.environ["DB_USER"],
    "PYSRV_DATABASE_PASSWORD": os.environ["DB_PASS"],
    "PYSRV_CRYPT_KEY": os.environ["CRYPT_KEY"],
    "PYSRV_BACKUP_FOLDER": "/backups/",
    "PYSRV_FIRM_FOLDER": "/firms/",
    "PYSRV_COOKIE_HTTPS_ONLY": False,
    "PYSRV_REDIS_HOST": "127.0.0.1:6379",
    "PYSRV_REDIS_PASSWORD": os.environ["REDIS_PASS"],
    "PYSRV_DOMAIN_NAME": "",
    "PYSRV_CORS_ALLOW_ORIGIN": "*"
}

with open("/opt/mikrowizard/server-conf.json", "w") as f:
    json.dump(conf, f, indent=4)
'
    chmod 600 /opt/mikrowizard/server-conf.json
    log_success "Configuration file generated securely at /opt/mikrowizard/server-conf.json (Mode 0600)."
}

# -----------------------------------------------------------------------------
# STEP 6: Container Orchestration & Database Migration
# -----------------------------------------------------------------------------
deploy_containers_and_initialize() {
    log_step 6 6 "Container Orchestration & Database Initialization"

    # Stop and remove old containers safely if present
    log_info "Recreating container environment..."
    docker rm -f redis-stack-server MikroWizard-postgre mikrofront mikroman mikroman-migrator 2>/dev/null || true

    # 1. Redis Stack Server Container
    run_with_spinner "Pulling Redis Stack Server image..." \
        docker pull redis/redis-stack-server:latest

    log_info "Launching Redis Stack Server container..."
    _log_raw "[CMD]  docker run redis-stack-server (port 127.0.0.1:6379)"
    # redis/redis-stack-server uses REDIS_ARGS env var for flags like --requirepass.
    # Passing --requirepass as a container command arg causes OCI runtime error.
    docker run -d --restart unless-stopped \
        --name redis-stack-server \
        -p 127.0.0.1:6379:6379 \
        -e REDIS_ARGS="--requirepass $redisPassword" \
        redis/redis-stack-server >/dev/null
    log_success "Redis Stack Server container running (Bound: 127.0.0.1:6379)."

    # 2. PostgreSQL Container
    run_with_spinner "Pulling PostgreSQL image..." \
        docker pull postgres:latest

    log_info "Launching PostgreSQL container..."
    _log_raw "[CMD]  docker run MikroWizard-postgre db=$dbname user=$username (port 5432)"
    docker run -d --restart unless-stopped \
        --name MikroWizard-postgre \
        -p 5432:5432 \
        -e POSTGRES_DB="$dbname" \
        -e POSTGRES_USER="$username" \
        -e POSTGRES_PASSWORD="$password" \
        postgres >/dev/null
    log_success "PostgreSQL container running (Port: 5432)."

    # 3. MikroFront Frontend Container
    run_with_spinner "Pulling MikroFront Web UI image..." \
        docker pull mikrowizard/mikrofront:latest

    log_info "Launching MikroFront Web UI container..."
    _log_raw "[CMD]  docker run mikrofront (ports 80, 443)"
    docker run -d --restart unless-stopped \
        --add-host=host.docker.internal:host-gateway \
        --name mikrofront \
        -p 80:80 \
        -p 443:443 \
        -v /opt/mikrowizard/:/conf/ \
        mikrowizard/mikrofront:latest >/dev/null
    log_success "MikroFront Web UI container running (Ports: 80, 443)."

    # Wait for PostgreSQL Database Readiness (poll actual database connection, not just socket)
    log_info "Waiting for PostgreSQL database service readiness..."
    local attempts=0
    until docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U "$username" -d "$dbname" -c "SELECT 1;" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ $attempts -ge 30 ]; then
            # If server is accepting connections but $dbname does not exist yet, create it explicitly
            if docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U postgres -c "CREATE DATABASE \"$dbname\" OWNER \"$username\";" >/dev/null 2>&1 || \
               docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U "$username" -c "CREATE DATABASE \"$dbname\";" >/dev/null 2>&1; then
                if docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U "$username" -d "$dbname" -c "SELECT 1;" >/dev/null 2>&1; then
                    break
                fi
            fi
            log_error "PostgreSQL database (${dbname}) failed to initialize within 60 seconds."
            exit 1
        fi
        printf "\r  ${CYAN}\u280b${RESET}  Waiting for PostgreSQL database (${dbname})... (attempt %d/30)" "$attempts"
        sleep 2
    done
    printf "\r  ${GREEN}\u2714${RESET}  PostgreSQL database (${dbname}) is ready for connections.              \n"
    _log_raw "[OK]   PostgreSQL database ($dbname) is ready (after $attempts attempts)"

    # Enable Postgres Extensions
    log_info "Initializing PostgreSQL extensions..."
    docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U "$username" -d "$dbname" \
        -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' >/dev/null 2>&1 || \
    docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U postgres -d "$dbname" \
        -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' >/dev/null 2>&1 || true

    # 4. Database Migrations Execution
    run_with_spinner "Running MikroWizard schema migrations (this may take a minute)..." \
        docker run --rm --net host \
            --name mikroman-migrator \
            -v /opt/mikrowizard/:/conf/ \
            mikrowizard/mikroman:latest \
            /bin/bash -c "cd /app/; export PYTHONPATH=/app/py; export PYSRV_CONFIG_PATH=/conf/server-conf.json; python3 scripts/dbmigrate.py;"
    log_success "Database schema migrations applied successfully."

    # 5. Build and Apply init.sql Template Safely
    log_info "Constructing and executing initial system records..."
    cat << 'EOF' > ./init.sql
INSERT INTO public.tasks( signal, name, status) VALUES ( 100, 'check-update',  false);
INSERT INTO public.tasks( signal, name, status) VALUES ( 110, 'upgrade-firmware',  false);
INSERT INTO public.tasks( signal, name, status) VALUES ( 120, 'backup', false);
INSERT INTO public.tasks( signal, name, status) VALUES ( 130, 'scanner',  false);
INSERT INTO public.tasks( signal, name, status) VALUES ( 140, 'downloader',  false);
INSERT INTO public.tasks( signal, name, status) VALUES ( 150, 'firmware-service',  false);
INSERT INTO public.sysconfig( key,  value) VALUES ( 'scan_mode', 'mac');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'mac_scan_interval', '5');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'ip_scan_interval', '4');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'old_firmware_action', 'keep');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'default_user', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'default_password', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'old_version', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'latest_version', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'default_ip', '__SERVER_IP__');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'rad_secret', '__RAD_SECRET__');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'system_url', 'http://__SERVER_IP__');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'force_perms', 'True');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'force_radius', 'True');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'force_syslog', 'True');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'safe_install', 'True');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'timezone', 'UTC');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'username', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'install_date', '');
INSERT INTO public.sysconfig( key,  value) VALUES ( 'all_ip', '');

INSERT INTO public.device_groups( id, name ) VALUES (1, 'Default');
INSERT INTO public.users(username, first_name, last_name,email, role) VALUES ('system', 'system', '','system@localhost', 'disabled');
INSERT INTO public.users(id,username, password, first_name, last_name, email, role,adminperms) VALUES ('37cc36e0-afec-4545-9219-94655805868b','mikrowizard', '$pbkdf2-sha256$29000$yVnr/d9b6917j7G2tlYqRQ$.8fbnLorUGGt6z8SZK9t7Q5WHrRnmKIYL.RW5IkyZLo', 'admin','admin','admin@localhost', 'admin','{"device": "full", "device_group": "full", "task": "full", "backup": "full", "snippet": "full", "accounting": "full", "authentication": "full", "users": "full", "permissions": "full", "settings": "full", "system_backup": "full", "sequence": "full", "cloner": "full", "vault": "full", "device_log": "full", "system_log": "full", "customer": "full", "customer_ticket": "full", "customer_chat": "full", "pam_session": "full", "pam_config": "full", "policy": "full", "alerts": "full", "wireguard": "full"}');

INSERT INTO public.permissions(id, name, perms) VALUES (1, 'full', '{"api": true, "ftp": true, "password": true, "read": true, "romon": true, "sniff": true, "telnet": true, "tikapp": true, "winbox": true, "dude": true, "local": true, "policy": true, "reboot": true, "rest-api": true, "sensitive": true, "ssh": true, "test": true, "web": true, "write": true}');
INSERT INTO public.permissions(id, name, perms) VALUES (2, 'read', '{"api": true, "ftp": false, "password": true, "read": true, "romon": true, "sniff": true, "telnet": true, "tikapp": true, "winbox": true, "dude": false, "local": true, "policy": false, "reboot": true, "rest-api": true, "sensitive": true, "ssh": true, "test": true, "web": true, "write": false}');
INSERT INTO public.permissions(id, name, perms) VALUES (3, 'write', '{"api": true, "dude": false, "ftp": false, "local": true, "password": true, "policy": false, "read": true, "reboot": true, "rest-api": true, "sensitive": true, "sniff": true, "telnet": true, "test": true, "tikapp": true, "web": true, "winbox": true, "write": true}');

INSERT INTO public.user_group_perm_rel(group_id, user_id, perm_id) VALUES ( 1, '37cc36e0-afec-4545-9219-94655805868b', 1);
EOF

    # Safely replace place-holder parameters using python3 and Environment Variables
    SERVER_IP="$serverip" RAD_SECRET="$secret" python3 -c '
import os

with open("./init.sql", "r") as f:
    content = f.read()

content = content.replace("__SERVER_IP__", os.environ["SERVER_IP"])
content = content.replace("__RAD_SECRET__", os.environ["RAD_SECRET"])

with open("./init.sql.rendered", "w") as f:
    f.write(content)
'

    docker cp ./init.sql.rendered MikroWizard-postgre:/init.sql
    _log_raw "[CMD]  psql -U $username -d $dbname -f /init.sql"
    docker exec -e PGPASSWORD="$password" -i MikroWizard-postgre psql -U "$username" -d "$dbname" -f /init.sql >/dev/null
    rm -f ./init.sql ./init.sql.rendered
    log_success "Initial database seed records applied cleanly."

    # 6. Main MikroMan Backend Container
    run_with_spinner "Pulling MikroMan Backend image..." \
        docker pull mikrowizard/mikroman:latest

    log_info "Launching MikroMan Backend container..."
    _log_raw "[CMD]  docker run mikroman --net host firms=$firmpath backups=$backuppath"
    docker run -d --restart unless-stopped \
        -it --net host \
        --name mikroman \
        --add-host=host.docker.internal:host-gateway \
        -v /opt/mikrowizard/:/conf/ \
        -v "$firmpath":/firms \
        -v "$backuppath":/backups \
        mikrowizard/mikroman:latest >/dev/null
    log_success "MikroMan Backend container running in host mode."
}

# -----------------------------------------------------------------------------
# STEP 7: Completion Summary & Security Hardening Recommendations
# -----------------------------------------------------------------------------
print_summary_and_security_guide() {
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "======================================================================"
    echo "       [✓] MikroWizard Installation Completed Successfully!          "
    echo "======================================================================"
    echo -e "${RESET}"

    echo -e "${WHITE}${BOLD}Access Details:${RESET}"
    echo -e "  * Web Interface URL : ${CYAN}http://${serverip}${RESET}"
    echo -e "  * Default Admin User: ${CYAN}mikrowizard${RESET}"
    echo -e "  * Default Admin Pass: ${CYAN}admin${RESET}"
    echo -e "  * Database Name     : ${CYAN}${dbname}${RESET}"
    echo -e "  * Firmware Directory: ${CYAN}${firmpath}${RESET}"
    echo -e "  * Backup Directory  : ${CYAN}${backuppath}${RESET}"
    echo ""

    echo -e "${YELLOW}${BOLD}Security & Firewall Hardening Recommendations:${RESET}"
    echo -e "PostgreSQL (port 5432) is active for container and add-on module access."
    echo -e "To restrict external public access while allowing Docker containers & local network:"
    echo ""
    echo -e "  ${BOLD}Using UFW (Uncomplicated Firewall):${RESET}"
    echo -e "    ${BLUE}sudo ufw allow 80/tcp${RESET}               # Allow Web HTTP"
    echo -e "    ${BLUE}sudo ufw allow 443/tcp${RESET}              # Allow Web HTTPS"
    echo -e "    ${BLUE}sudo ufw allow from 192.168.1.0/24 to any port 5432${RESET} # Allow local subnet to Postgres"
    echo -e "    ${BLUE}sudo ufw deny 5432/tcp${RESET}              # Block public external access to Postgres"
    echo ""
    echo -e "  ${BOLD}Using Native iptables (Docker User Chain):${RESET}"
    echo -e "    ${BLUE}sudo iptables -I DOCKER-USER ! -i lo ! -i docker0 -p tcp --dport 5432 -j DROP${RESET}"
    echo -e "    ${BLUE}sudo netfilter-persistent save${RESET}"
    echo ""
    echo -e "${DIM}======================================================================${RESET}"
    echo ""
    echo -e "  ${DIM}Full installation log: ${INSTALL_LOG}${RESET}"
    _log_raw "Access URL: http://$serverip"
    _log_raw "Admin user: mikrowizard"
    _log_raw "DB name: $dbname"
    _log_raw "Firmware dir: $firmpath"
    _log_raw "Backup dir: $backuppath"
}

# -----------------------------------------------------------------------------
# Main Execution Entry Point
# -----------------------------------------------------------------------------
main() {
    log_banner
    check_prerequisites
    check_and_setup_docker
    check_ports_and_existing_install
    prompt_inputs
    setup_directories_and_config
    deploy_containers_and_initialize
    print_summary_and_security_guide
}

main "$@"
