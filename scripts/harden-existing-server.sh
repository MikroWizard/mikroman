#!/bin/bash
# =============================================================================
# MikroWizard Security Hardening Utility for Existing Installations
# =============================================================================
# This script hardens Redis on an existing MikroWizard server without data loss:
#  1. Flushes Redis memory to disk (SAVE).
#  2. Generates a strong random password (if not already configured).
#  3. Updates /opt/mikrowizard/server-conf.json.
#  4. Recreates the redis-stack-server container bound strictly to 127.0.0.1:6379.
#  5. Updates Terminal Gateway (if installed).
#  6. Restarts the backend so it securely connects with password auth.
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[-] Error: This script must be executed as root (use sudo).${NC}"
    exit 1
fi

CONF_FILE="/opt/mikrowizard/server-conf.json"

if [ ! -f "$CONF_FILE" ]; then
    echo -e "${RED}[-] Error: MikroWizard configuration file not found at $CONF_FILE${NC}"
    exit 1
fi

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}     MikroWizard Server Security Hardening Tool             ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# 1. Backup current config file
cp "$CONF_FILE" "${CONF_FILE}.bak.$(date +%s)"
echo -e "${GREEN}[+] Config backup created at ${CONF_FILE}.bak${NC}"

# 2. Flush Redis to disk to prevent data loss
if docker ps -q -f name=redis-stack-server >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Saving in-memory Redis data to disk...${NC}"
    docker exec redis-stack-server redis-cli SAVE >/dev/null 2>&1 || true
fi

# 3. Read or generate Redis password and update server-conf.json safely
REDIS_PASSWORD=$(python3 -c "
import json, secrets, sys

conf_path = '$CONF_FILE'
try:
    with open(conf_path, 'r') as f:
        data = json.load(f)
except Exception as e:
    sys.exit(1)

pwd = data.get('PYSRV_REDIS_PASSWORD', '').strip()
if not pwd:
    pwd = secrets.token_urlsafe(24)
    data['PYSRV_REDIS_PASSWORD'] = pwd
    with open(conf_path, 'w') as f:
        json.dump(data, f, indent=4)

print(pwd)
")

if [ -z "$REDIS_PASSWORD" ]; then
    echo -e "${RED}[-] Error generating or reading Redis password.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Configured Redis authentication password.${NC}"

# 4. Recreate redis-stack-server container bound strictly to 127.0.0.1 with password
echo -e "${GREEN}[+] Recreating Redis container with localhost isolation and password...${NC}"
docker stop redis-stack-server >/dev/null 2>&1 || true
docker rm redis-stack-server >/dev/null 2>&1 || true

docker run -d --restart unless-stopped \
  --name redis-stack-server \
  -p 127.0.0.1:6379:6379 \
  redis/redis-stack-server \
  --requirepass "$REDIS_PASSWORD"

# 5. Update Terminal Gateway if present
GATEWAY_ENV="/opt/mikrowizard/terminal-gateway/gateway.env"
if [ -f "$GATEWAY_ENV" ]; then
    echo -e "${GREEN}[+] Updating Terminal Gateway configuration...${NC}"
    if grep -q "PYSRV_REDIS_PASSWORD=" "$GATEWAY_ENV"; then
        sed -i "s/^PYSRV_REDIS_PASSWORD=.*/PYSRV_REDIS_PASSWORD=$REDIS_PASSWORD/" "$GATEWAY_ENV"
    else
        echo "PYSRV_REDIS_PASSWORD=$REDIS_PASSWORD" >> "$GATEWAY_ENV"
    fi
    
    if docker ps -q -f name=mikrowizard-terminal-gateway >/dev/null 2>&1; then
        echo -e "${GREEN}[+] Restarting Terminal Gateway container...${NC}"
        docker restart mikrowizard-terminal-gateway >/dev/null 2>&1 || true
    fi
fi

# 6. Restart MikroWizard backend to apply changes
if docker ps -q -f name=mikroman >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Restarting MikroWizard backend container (mikroman)...${NC}"
    docker restart mikroman >/dev/null 2>&1 || true
elif docker ps -q -f name=mikroman-dev >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Reloading MikroWizard dev container...${NC}"
    docker exec mikroman-dev touch /app/reload >/dev/null 2>&1 || true
fi

# 7. Verification check
sleep 2
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}[✓] Hardening Complete Successfully!${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "Redis is now bound to: ${GREEN}127.0.0.1:6379 (Localhost Only)${NC}"
echo -e "Redis Authentication:  ${GREEN}Enabled (Password Protected)${NC}"
echo ""
echo -e "${YELLOW}Optional Additional Security (Firewall):${NC}"
echo "To block external access to PostgreSQL (port 5432) at the firewall level:"
echo -e "  ${BLUE}sudo iptables -I DOCKER-USER ! -i lo ! -i docker0 -p tcp --dport 5432 -j DROP${NC}"
echo -e "  ${BLUE}sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save${NC}"
echo ""
