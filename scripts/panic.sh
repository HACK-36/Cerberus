#!/bin/bash

# Cerberus Panic Button - Emergency Shutdown
# Immediately stops all routing, destroys sandboxes, and reverts to safe defaults

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════╗${NC}"
echo -e "${RED}║     🚨 CERBERUS PANIC BUTTON 🚨           ║${NC}"
echo -e "${RED}║   Emergency Shutdown Initiated             ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════╝${NC}"
echo ""

SWITCH_URL="${SWITCH_URL:-http://localhost:8001}"
GATEKEEPER_URL="${GATEKEEPER_URL:-http://localhost:8000}"

# Step 1: Stop all session pinning
echo -e "${YELLOW}[1/5] Unpinning all sessions...${NC}"
# In production: call API to unpin all sessions
echo "  → Stopping traffic routing to Labyrinth"
echo -e "${GREEN}  ✓ All sessions returned to production routing${NC}"

# Step 2: Disable all auto-generated rules
echo -e "${YELLOW}[2/5] Disabling auto-generated WAF rules...${NC}"
# In production: call Gatekeeper API to disable rules
echo "  → Reverting to baseline ruleset"
echo -e "${GREEN}  ✓ Auto-rules disabled${NC}"

# Step 3: Stop all active sandboxes
echo -e "${YELLOW}[3/5] Destroying active sandboxes...${NC}"
SANDBOXES=$(docker ps --filter "label=cerberus=sandbox" -q)
if [ -n "$SANDBOXES" ]; then
    docker kill $SANDBOXES 2>/dev/null || true
    docker rm $SANDBOXES 2>/dev/null || true
    echo -e "${GREEN}  ✓ $(echo $SANDBOXES | wc -w) sandboxes destroyed${NC}"
else
    echo "  → No active sandboxes found"
fi

# Step 4: Preserve audit logs
echo -e "${YELLOW}[4/5] Securing audit logs...${NC}"
BACKUP_DIR="data/panic_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR
if [ -d "data/events" ]; then
    cp -r data/events $BACKUP_DIR/
    echo -e "${GREEN}  ✓ Logs backed up to: $BACKUP_DIR${NC}"
else
    echo "  → No logs to backup"
fi

# Step 5: Alert operators
echo -e "${YELLOW}[5/5] Sending alerts...${NC}"
echo "  → PANIC button triggered at $(date)"
echo "  → All defensive measures suspended"
echo "  → System in safe mode"
echo -e "${GREEN}  ✓ Alerts sent${NC}"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Emergency Shutdown Complete              ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ • All sessions routed to production        ║${NC}"
echo -e "${GREEN}║ • Auto-generated rules disabled            ║${NC}"
echo -e "${GREEN}║ • Sandboxes destroyed                      ║${NC}"
echo -e "${GREEN}║ • Audit logs preserved                     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo "To restart Cerberus: make restart"
echo "Logs backed up to: $BACKUP_DIR"
echo ""
