#!/usr/bin/env bash
# =============================================================================
# MikroMan Container Hotfix / Update Script (Issue #12)
# =============================================================================
# Updates /app/py inside the running MikroMan Docker container to the latest
# master commit, verifies python bytecode compilation, reloads uWSGI, and
# provides automated backup and single-command rollback.
#
# Usage:
#   ./hotfix_update.sh [CONTAINER_NAME]
#   ./hotfix_update.sh [CONTAINER_NAME] --rollback
# =============================================================================

set -eo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine Container Name
CONTAINER="${1:-mikroman}"
if [ "$CONTAINER" = "--rollback" ]; then
    CONTAINER="mikroman"
    ACTION="rollback"
else
    ACTION="${2:-update}"
fi

BACKUP_BASE="/tmp/mikroman_backup"

# Helper print functions
info()    { echo -e "${BLUE}${BOLD}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARNING]${NC} $*"; }
error()   { echo -e "${RED}${BOLD}[ERROR]${NC} $*"; }

# -----------------------------------------------------------------------------
# 1. Pre-flight Check: Container Running
# -----------------------------------------------------------------------------
info "Checking Docker container '${CONTAINER}'..."
if ! docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER}$"; then
    # Try finding container containing mikroman if exact match not found
    RUNNING_NAME=$(docker ps --format '{{.Names}}' | grep "mikroman" | head -n 1 || true)
    if [ -n "$RUNNING_NAME" ]; then
        warn "Exact container '${CONTAINER}' not running. Found '${RUNNING_NAME}'."
        CONTAINER="$RUNNING_NAME"
    else
        error "No running Docker container found matching '${CONTAINER}'!"
        echo "Available running containers:"
        docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
        exit 1
    fi
fi
success "Target container identified: ${CONTAINER}"

# -----------------------------------------------------------------------------
# 2. Rollback Mode
# -----------------------------------------------------------------------------
if [ "$ACTION" = "--rollback" ] || [ "$ACTION" = "rollback" ]; then
    info "Initiating rollback..."
    LATEST_BACKUP=$(ls -td ${BACKUP_BASE}_* 2>/dev/null | head -n 1 || true)
    if [ -z "$LATEST_BACKUP" ] || [ ! -d "$LATEST_BACKUP/py" ]; then
        # Check inside container backup as fallback
        if docker exec "$CONTAINER" test -d /app/py_backup_prev 2>/dev/null; then
            info "Restoring from container-internal backup /app/py_backup_prev..."
            docker exec "$CONTAINER" sh -c "rm -rf /app/py && cp -r /app/py_backup_prev /app/py"
        else
            error "No previous backup found to restore!"
            exit 1
        fi
    else
        info "Restoring from host backup: ${LATEST_BACKUP}/py..."
        docker cp "${LATEST_BACKUP}/py/." "${CONTAINER}:/app/py/"
    fi

    info "Reloading application..."
    docker exec "$CONTAINER" touch /app/reload 2>/dev/null || true
    docker restart "$CONTAINER"
    success "Rollback complete! Container '${CONTAINER}' restored to previous state."
    exit 0
fi

# -----------------------------------------------------------------------------
# 3. Create Backup
# -----------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE}_${TIMESTAMP}"
info "Creating backup of current container code in ${BACKUP_DIR}..."
mkdir -p "$BACKUP_DIR"

if ! docker cp "${CONTAINER}:/app/py" "${BACKUP_DIR}/"; then
    error "Failed to create backup from container! Aborting for safety."
    exit 1
fi
# Also create internal backup copy inside container
docker exec "$CONTAINER" sh -c "rm -rf /app/py_backup_prev && cp -r /app/py /app/py_backup_prev" 2>/dev/null || true
success "Backup created successfully at ${BACKUP_DIR}"

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
docker cp "${SOURCE_PY}/." "${CONTAINER}:/app/py/"

# -----------------------------------------------------------------------------
# 6. Syntax / Compilation Verification inside Container
# -----------------------------------------------------------------------------
info "Verifying Python bytecode compilation inside container..."
if ! docker exec "$CONTAINER" python3 -m compileall -q /app/py; then
    error "Python compilation check failed! Triggering automatic rollback..."
    docker cp "${BACKUP_DIR}/py/." "${CONTAINER}:/app/py/"
    docker exec "$CONTAINER" touch /app/reload 2>/dev/null || true
    error "Update aborted and previous version restored safely."
    exit 1
fi
success "Python compilation check passed with 0 errors."

# -----------------------------------------------------------------------------
# 7. Reload & Restart Container
# -----------------------------------------------------------------------------
info "Triggering application reload (/app/reload)..."
docker exec "$CONTAINER" touch /app/reload 2>/dev/null || true

info "Restarting container '${CONTAINER}' to ensure data grabber mule restarts cleanly..."
docker restart "$CONTAINER"

sleep 3

# -----------------------------------------------------------------------------
# 8. Post-Update Status Check
# -----------------------------------------------------------------------------
if docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER}$"; then
    success "Container '${CONTAINER}' is up and running!"
else
    warn "Container '${CONTAINER}' is not in running state. Please inspect 'docker logs ${CONTAINER}'."
fi

echo ""
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD} Update Applied Successfully!                        ${NC}"
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo -e "Backup location: ${BOLD}${BACKUP_DIR}${NC}"
echo ""
echo "To view live data grabber logs:"
echo "  docker logs -f ${CONTAINER}"
echo ""
echo "If you need to rollback to the previous version at any time, run:"
echo "  docker cp ${BACKUP_DIR}/py/. ${CONTAINER}:/app/py/ && docker restart ${CONTAINER}"
echo -e "${GREEN}${BOLD}======================================================${NC}"
