#!/bin/bash
# OSCP-Compliant Cron Job Enumeration Script
# Reports findings only — no exploitation
# Usage: bash cron_enum.sh

echo "============================================"
echo "  Cron Job & Scheduler Enumeration"
echo "  OSCP Exam Compliant — Findings Only"
echo "============================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[1] Current user and privileges${NC}"
echo "--------------------------------------------"
whoami
id
echo ""

echo -e "${CYAN}[2] /etc/crontab${NC}"
echo "--------------------------------------------"
if [ -r /etc/crontab ]; then
    cat /etc/crontab
else
    echo -e "${YELLOW}[!] Cannot read /etc/crontab${NC}"
fi
echo ""

echo -e "${CYAN}[3] System cron.d directory${NC}"
echo "--------------------------------------------"
for f in /etc/cron.d/*; do
    if [ -r "$f" ]; then
        echo -e "${CYAN}--- $f ---${NC}"
        cat "$f"
    else
        echo -e "${YELLOW}[!] Cannot read $f${NC}"
    fi
done
echo ""

echo -e "${CYAN}[4] Cron directories (files and permissions)${NC}"
echo "--------------------------------------------"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$d" ]; then
        echo -e "${CYAN}--- $d ---${NC}"
        ls -la "$d"
    else
        echo -e "${YELLOW}[!] $d does not exist${NC}"
    fi
done
echo ""

echo -e "${CYAN}[5] User crontabs${NC}"
echo "--------------------------------------------"
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$u" -l 2>/dev/null | grep -v '^no crontab' && echo -e "${GREEN}[+] Crontab for $u${NC}"
done
echo ""

echo -e "${CYAN}[6] Cron-related files / scripts (permissions)${NC}"
echo "--------------------------------------------"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [ -d "$d" ] && find "$d" -type f -exec ls -la {} \; 2>/dev/null
done
echo ""

echo -e "${CYAN}[7] Check if cron scripts call binaries without full path${NC}"
echo "--------------------------------------------"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        if [ -r "$f" ]; then
            NO_PATH=$(grep -oP '^\s*[a-zA-Z0-9_][a-zA-Z0-9_-]*\s+.*$' "$f" 2>/dev/null | grep -vE '^\s*(if|then|else|fi|for|while|do|done|case|esac|echo|export|source|\.\s|#|/|function|\[)' | grep -vE '/' | head -20)
            if [ -n "$NO_PATH" ]; then
                echo -e "${YELLOW}[!] $f may call binaries without full path${NC}"
            fi
        fi
    done
done
echo ""

echo -e "${CYAN}[8] Check writable cron directories / scripts${NC}"
echo "--------------------------------------------"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d /etc/crontab; do
    [ -e "$d" ] || continue
    if [ -w "$d" ]; then
        echo -e "${GREEN}[+] Writable: $d${NC}"
    fi
done
find /etc/cron* -type f -perm -002 2>/dev/null
echo ""

echo -e "${CYAN}[9] Modifiable root scripts referenced by cron (exploitable)${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Command reference (run manually):${NC}"
echo "  cat /etc/crontab"
echo "  cat /etc/cron.d/*"
echo "  ls -la /etc/cron.*"
echo "  ls -la <script_path>"
echo ""

# Parse script paths from /etc/crontab and /etc/cron.d/*
CRON_SCRIPTS=$(
    (grep -oE '^[^#].*[[:space:]]+[0-9a-zA-Z_/-]+\.[^[:space:]]+' /etc/crontab 2>/dev/null; \
     cat /etc/cron.d/* 2>/dev/null | grep -oE '^[^#].*[[:space:]]+[0-9a-zA-Z_/-]+\.[^[:space:]]+') | \
    awk '{for(i=1;i<=NF;i++) if($i ~ /\// && $i ~ /\./) print $i}' | sort -u
)

# Also check scripts directly inside cron directories
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -f "$f" ] && echo "$f"
    done
done >> /tmp/cron_script_list_$$

for script in $CRON_SCRIPTS $(cat /tmp/cron_script_list_$$ 2>/dev/null | sort -u); do
    [ -e "$script" ] || continue
    owner=$(stat -c '%u' "$script" 2>/dev/null || echo "?")
    perms=$(stat -c '%a' "$script" 2>/dev/null || echo "?")
    if [ "$owner" = "0" ] && [ -w "$script" ]; then
        echo -e "${RED}[!] EXPLOITABLE: $script is root-owned and writable by you${NC}"
        echo "    Owner: root | Permissions: $perms | Command: ls -la $script"
    elif [ "$owner" = "0" ] && [ "$perms" -ge 666 ] 2>/dev/null; then
        echo -e "${RED}[!] EXPLOITABLE: $script is root-owned and world-writable${NC}"
        echo "    Owner: root | Permissions: $perms | Command: ls -la $script"
    fi
done
rm -f /tmp/cron_script_list_$$
echo ""

echo -e "${CYAN}[10] Active systemd timers${NC}"
echo "--------------------------------------------"
systemctl list-timers --all 2>/dev/null | head -30
echo ""

echo -e "${CYAN}[11] Recent cron / at activity (last 50 lines)${NC}"
echo "--------------------------------------------"
grep -i cron /var/log/syslog 2>/dev/null | tail -50
grep -i cron /var/log/messages 2>/dev/null | tail -50
atq 2>/dev/null | head -20
echo ""

echo "============================================"
echo "  Enumeration Report Complete"
echo "============================================"
echo ""
echo -e "${CYAN}Manual checks to perform:${NC}"
echo "  - Identify cron scripts that run as root / other users"
echo "  - Check if writable cron scripts exist and are scheduled"
echo "  - Look for cron jobs that execute files in writable directories"
echo "  - Combine with writable_path_enum.sh for overlapping findings"
echo ""
echo "Reference: https://gtfobins.github.io"
