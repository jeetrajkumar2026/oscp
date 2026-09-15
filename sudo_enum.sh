#!/bin/bash
# OSCP-Compliant Sudo Enumeration Script
# Reports findings only — no exploit suggestions
# Analyst decides next steps based on findings
# Usage: bash sudo_enum.sh

echo "============================================"
echo "  Sudo Misconfiguration Enumeration Report"
echo "  OSCP Exam Compliant — Findings Only"
echo "============================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[1] Checking sudo -l ...${NC}"
echo "--------------------------------------------"
sudo -l 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Cannot run sudo -l (no sudo access)${NC}"
    echo -e "${YELLOW}[*] Sudo path not available — check other privesc methods${NC}"
    exit 1
fi
echo ""

SUDO_OUTPUT=$(sudo -l 2>/dev/null)

echo -e "${CYAN}[2] Checking for NOPASSWD entries ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -q "NOPASSWD"; then
    echo -e "${GREEN}[+] VULNERABLE: NOPASSWD entries found${NC}"
    echo "$SUDO_OUTPUT" | grep "NOPASSWD"
else
    echo -e "${YELLOW}[!] No NOPASSWD entries${NC}"
fi
echo ""

echo -e "${CYAN}[3] Checking for ALL:ALL ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -qE "\(ALL\s*:\s*ALL\)\s+ALL"; then
    echo -e "${GREEN}[+] VULNERABLE: ALL:ALL permission found${NC}"
else
    echo -e "${YELLOW}[!] No ALL:ALL permission${NC}"
fi
echo ""

echo -e "${CYAN}[4] Checking for shell binaries ...${NC}"
echo "--------------------------------------------"
FOUND_SHELL=0
for binary in bash sh dash zsh; do
    if echo "$SUDO_OUTPUT" | grep -qE "/$binary\b"; then
        echo -e "${GREEN}[+] VULNERABLE: /$binary found in sudo${NC}"
        FOUND_SHELL=1
    fi
done
if [ $FOUND_SHELL -eq 0 ]; then
    echo -e "${YELLOW}[!] No shell binaries in sudo${NC}"
fi
echo ""

echo -e "${CYAN}[5] Checking for GTFOBins shell-escape binaries ...${NC}"
echo "--------------------------------------------"
FOUND_GTFO=0
for binary in find vim vi less more awk perl python python3 nmap env tar zip strace; do
    if echo "$SUDO_OUTPUT" | grep -qE "/$binary\b"; then
        echo -e "${GREEN}[+] VULNERABLE: $binary found in sudo (check GTFOBins)${NC}"
        FOUND_GTFO=1
    fi
done
if [ $FOUND_GTFO -eq 0 ]; then
    echo -e "${YELLOW}[!] No GTFOBins shell-escape binaries in sudo${NC}"
fi
echo ""

echo -e "${CYAN}[6] Checking for file-overwrite binaries ...${NC}"
echo "--------------------------------------------"
FOUND_OVERWRITE=0
for binary in cp dd tee wget curl; do
    if echo "$SUDO_OUTPUT" | grep -qE "/$binary\b"; then
        echo -e "${GREEN}[+] VULNERABLE: $binary found in sudo (can overwrite system files)${NC}"
        FOUND_OVERWRITE=1
    fi
done
if [ $FOUND_OVERWRITE -eq 0 ]; then
    echo -e "${YELLOW}[!] No file-overwrite binaries in sudo${NC}"
fi
echo ""

echo -e "${CYAN}[7] Checking for systemctl ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -q "systemctl"; then
    echo -e "${GREEN}[+] VULNERABLE: systemctl found in sudo (can create/start services)${NC}"
else
    echo -e "${YELLOW}[!] No systemctl in sudo${NC}"
fi
echo ""

echo -e "${CYAN}[8] Checking for wildcards in sudo commands ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -q "\*"; then
    echo -e "${GREEN}[+] VULNERABLE: Wildcard (*) found in sudo command${NC}"
    echo "$SUDO_OUTPUT" | grep "\*"
else
    echo -e "${YELLOW}[!] No wildcards in sudo commands${NC}"
fi
echo ""

echo -e "${CYAN}[9] Checking for LD_PRELOAD (env_keep) ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -q "LD_PRELOAD"; then
    echo -e "${GREEN}[+] VULNERABLE: LD_PRELOAD in env_keep${NC}"
else
    echo -e "${YELLOW}[!] No LD_PRELOAD in env_keep${NC}"
fi
echo ""

echo -e "${CYAN}[10] Checking for custom scripts ...${NC}"
echo "--------------------------------------------"
SCRIPTS=$(echo "$SUDO_OUTPUT" | grep -oP '(?:NOPASSWD:\s*)?(/[a-zA-Z0-9_/.-]+\.sh)' 2>/dev/null)
if [ -n "$SCRIPTS" ]; then
    for script in $SCRIPTS; do
        echo -e "${GREEN}[+] Custom script found: $script${NC}"
        if [ -w "$script" ]; then
            echo -e "${RED}    [!] VULNERABLE: Script is WRITABLE${NC}"
        else
            echo -e "${YELLOW}    [i] Script not writable — checking for PATH hijacking${NC}"
            NO_PATH_CMDS=$(cat "$script" 2>/dev/null | grep -vE "^#|^/|^\$|^!|echo|export|cd |chmod|chown|mkdir|rm |cp |mv |sudo" | grep -oP '\b[a-z_]+\b' | sort -u)
            if [ -n "$NO_PATH_CMDS" ]; then
                echo -e "${GREEN}    [+] VULNERABLE: Commands without full path found (PATH hijack possible)${NC}"
                echo "$NO_PATH_CMDS" | while read cmd; do
                    echo -e "${YELLOW}      - $cmd${NC}"
                done
            else
                echo -e "${YELLOW}    [!] No PATH hijack targets found${NC}"
            fi
        fi
    done
else
    echo -e "${YELLOW}[!] No custom scripts in sudo${NC}"
fi
echo ""

echo -e "${CYAN}[11] Checking for specific user (lateral movement) ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -qE "\([a-z_]+\)\s+NOPASSWD"; then
    echo -e "${GREEN}[+] VULNERABLE: Specific user sudo found (lateral movement possible)${NC}"
    echo "$SUDO_OUTPUT" | grep -oP '\([a-z_]+\)\s+NOPASSWD'
else
    echo -e "${YELLOW}[!] No specific user sudo found${NC}"
fi
echo ""

echo -e "${CYAN}[12] Checking for service commands ...${NC}"
echo "--------------------------------------------"
if echo "$SUDO_OUTPUT" | grep -q "service"; then
    echo -e "${GREEN}[+] VULNERABLE: service command found in sudo${NC}"
else
    echo -e "${YELLOW}[!] No service command in sudo${NC}"
fi
echo ""

echo "============================================"
echo "  Enumeration Report Complete"
echo "============================================"
echo ""
echo -e "${CYAN}Summary of other privesc methods to check:${NC}"
echo "  - SUID:     find / -perm -4000 -type f 2>/dev/null"
echo "  - Cron:     cat /etc/crontab && ls -la /etc/cron.d/"
echo "  - Caps:     getcap -r / 2>/dev/null"
echo "  - Passwds:  grep -rli password /etc/ /var/www/ /home/ 2>/dev/null"
echo "  - SSH keys: find / -name id_rsa 2>/dev/null"
echo "  - NFS:      cat /etc/exports 2>/dev/null"
echo ""
echo "Reference: https://gtfobins.github.io"
