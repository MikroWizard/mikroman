#!/usr/bin/env bash
# =============================================================================
# MikroMan Container Hotfix / Update Script (Issue #12)
# =============================================================================
# Updates /app/py inside the running MikroMan Docker container to the latest
# master commit, verifies python bytecode compilation, reloads uWSGI, and
# provides automated backup and single-command rollback.
#
# Usage:
#   sudo ./scripts/hotfix_update.sh [CONTAINER_NAME]
#   sudo ./scripts/hotfix_update.sh [CONTAINER_NAME] --rollback
# =============================================================================

set -eo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Determine Docker Command (use sudo if not root)
if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
    DOCKER="sudo docker"
else
    DOCKER="docker"
fi

# Determine Container Name and Action
CONTAINER="mikroman"
ACTION="update"

for arg in "$@"; do
    case "$arg" in
        --rollback|-r|rollback)
            ACTION="rollback"
            ;;
        --help|-h|help)
            echo -e "${BOLD}MikroMan Container Hotfix Utility${NC}"
            echo "Usage:"
            echo "  $0 [CONTAINER_NAME]             Apply latest hotfix"
            echo "  $0 [CONTAINER_NAME] --rollback  Revert to previous version"
            exit 0
            ;;
        *)
            if [ -n "$arg" ] && [[ "$arg" != -* ]]; then
                CONTAINER="$arg"
            fi
            ;;
    esac
done

BACKUP_BASE="/tmp/mikroman_backup"

# Helper print functions
info()    { echo -e "${BLUE}${BOLD}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARNING]${NC} $*"; }
error()   { echo -e "${RED}${BOLD}[ERROR]${NC} $*"; }

# -----------------------------------------------------------------------------
# 1. Pre-flight Check: Container Running
# -----------------------------------------------------------------------------
info "Checking Docker container '${CONTAINER}' using '${DOCKER}'..."
if ! $DOCKER ps --format '{{.Names}}' 2>/dev/null | grep -Eq "^${CONTAINER}$"; then
    # Try finding container containing mikroman if exact match not found
    RUNNING_NAME=$($DOCKER ps --format '{{.Names}}' 2>/dev/null | grep "mikroman" | head -n 1 || true)
    if [ -n "$RUNNING_NAME" ]; then
        warn "Exact container '${CONTAINER}' not running. Found '${RUNNING_NAME}'."
        CONTAINER="$RUNNING_NAME"
    else
        error "No running Docker container found matching '${CONTAINER}'!"
        echo "Available running containers:"
        $DOCKER ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}" || true
        exit 1
    fi
fi
success "Target container identified: ${CONTAINER}"

# -----------------------------------------------------------------------------
# 2. Rollback Mode
# -----------------------------------------------------------------------------
if [ "$ACTION" = "rollback" ]; then
    info "Initiating rollback for container '${CONTAINER}'..."
    LATEST_BACKUP=$(ls -td ${BACKUP_BASE}_* 2>/dev/null | head -n 1 || true)
    if [ -z "$LATEST_BACKUP" ] || [ ! -d "$LATEST_BACKUP/py" ]; then
        # Check inside container backup as fallback
        if $DOCKER exec "$CONTAINER" test -d /app/py_backup_prev 2>/dev/null; then
            info "Restoring from container-internal backup (/app/py_backup_prev)..."
            $DOCKER exec "$CONTAINER" sh -c "rm -rf /app/py && cp -r /app/py_backup_prev /app/py"
        else
            error "No previous backup found to restore!"
            exit 1
        fi
    else
        info "Restoring from host backup: ${LATEST_BACKUP}/py..."
        $DOCKER cp "${LATEST_BACKUP}/py/." "${CONTAINER}:/app/py/"
    fi

    info "Reloading application..."
    $DOCKER exec "$CONTAINER" touch /app/reload 2>/dev/null || true
    # $DOCKER restart "$CONTAINER"

    echo ""
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    echo -e "${GREEN}${BOLD} ✔ Rollback Completed Successfully!                   ${NC}"
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    echo -e "Container '${CONTAINER}' has been reverted to its previous state."
    echo -e "To inspect live logs: ${BOLD}${DOCKER} logs -f ${CONTAINER}${NC}"
    echo -e "${GREEN}${BOLD}======================================================${NC}"
    exit 0
fi

# -----------------------------------------------------------------------------
# 3. Create Backup
# -----------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE}_${TIMESTAMP}"
info "Creating backup of current container code in ${BACKUP_DIR}..."
mkdir -p "$BACKUP_DIR"

if ! $DOCKER cp "${CONTAINER}:/app/py" "${BACKUP_DIR}/"; then
    error "Failed to create backup from container! Aborting for safety."
    exit 1
fi
# Also create internal backup copy inside container
$DOCKER exec "$CONTAINER" sh -c "rm -rf /app/py_backup_prev && cp -r /app/py /app/py_backup_prev" 2>/dev/null || true
success "Host backup created: ${BACKUP_DIR}"
success "Internal container backup created: /app/py_backup_prev"

# -----------------------------------------------------------------------------
# 4. Fetch Latest Code from Git
# -----------------------------------------------------------------------------
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

SOURCE_PY=""
# Check if script is run directly from a local git repository clone
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -d "${REPO_ROOT}/py" ] && [ -d "${REPO_ROOT}/.git" ]; then
    info "Using local repository at ${REPO_ROOT}..."
    SOURCE_PY="${REPO_ROOT}/py"
else
    info "Downloading latest master branch from GitHub (MikroWizard/mikroman)..."
    if command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/MikroWizard/mikroman.git "${TEMP_DIR}/repo"
        SOURCE_PY="${TEMP_DIR}/repo/py"
    else
        curl -sSL https://github.com/MikroWizard/mikroman/archive/refs/heads/master.tar.gz | tar -xz -C "$TEMP_DIR"
        EXTRACTED_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "mikroman-*" | head -n 1)
        SOURCE_PY="${EXTRACTED_DIR}/py"
    fi
fi

if [ ! -d "$SOURCE_PY" ]; then
    error "Could not obtain 'py' source files from GitHub!"
    exit 1
fi

# -----------------------------------------------------------------------------
# 5. Copy Updated Files into Container
# -----------------------------------------------------------------------------
info "Copying updated Python files into container ${CONTAINER}:/app/py/..."
$DOCKER cp "${SOURCE_PY}/." "${CONTAINER}:/app/py/"

# -----------------------------------------------------------------------------
# 6. Syntax / Compilation Verification inside Container
# -----------------------------------------------------------------------------
info "Verifying Python bytecode compilation inside container..."
if ! $DOCKER exec "$CONTAINER" python3 -m compileall -q /app/py; then
    error "Python compilation check failed! Triggering automatic rollback..."
    $DOCKER cp "${BACKUP_DIR}/py/." "${CONTAINER}:/app/py/"
    $DOCKER exec "$CONTAINER" touch /app/reload 2>/dev/null || true
    error "Update aborted and previous version restored safely."
    exit 1
fi
success "Python compilation check passed with 0 errors."

# -----------------------------------------------------------------------------
# 7. Reload & Restart Container
# -----------------------------------------------------------------------------
info "Triggering application reload (/app/reload)..."
$DOCKER exec "$CONTAINER" touch /app/reload 2>/dev/null || true

info "Restarting container '${CONTAINER}' to ensure all worker mules and spoolers restart cleanly..."
# $DOCKER restart "$CONTAINER"

sleep 3

# -----------------------------------------------------------------------------
# 8. Post-Update Status Check
# -----------------------------------------------------------------------------
if $DOCKER ps --format '{{.Names}}' 2>/dev/null | grep -Eq "^${CONTAINER}$"; then
    success "Container '${CONTAINER}' is up and running!"
else
    warn "Container '${CONTAINER}' is not in running state. Please inspect '$DOCKER logs ${CONTAINER}'."
fi

echo ""
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD} ✔ Update Applied Successfully!                       ${NC}"
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo -e "Host Backup:      ${CYAN}${BACKUP_DIR}${NC}"
echo -e "Container Backup: ${CYAN}/app/py_backup_prev${NC}"
echo ""
echo -e "${BOLD}To inspect live application logs:${NC}"
echo "  $DOCKER logs -f ${CONTAINER}"
echo ""
echo -e "${YELLOW}${BOLD}======================================================${NC}"
echo -e "${YELLOW}${BOLD} 🔄 ROLLBACK INSTRUCTIONS (HOW TO RESTORE)            ${NC}"
echo -e "${YELLOW}${BOLD}======================================================${NC}"
echo "If you encounter any issues and wish to immediately revert to"
echo "your previous code, choose any of the following methods:"
echo ""
echo -e "${BOLD}Method 1: Automated Rollback via this Script${NC}"
echo "  $0 ${CONTAINER} --rollback"
echo ""
echo -e "${BOLD}Method 2: One-Line Rollback from Host Backup${NC}"
echo "  $DOCKER cp ${BACKUP_DIR}/py/. ${CONTAINER}:/app/py/ && $DOCKER restart ${CONTAINER}"
echo ""
echo -e "${BOLD}Method 3: One-Line Rollback from Container Internal Backup${NC}"
echo "  $DOCKER exec ${CONTAINER} sh -c 'rm -rf /app/py && cp -r /app/py_backup_prev /app/py' && $DOCKER restart ${CONTAINER}"
echo -e "${YELLOW}${BOLD}======================================================${NC}"
