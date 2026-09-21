#!/bin/bash
# OSCP-Compliant Writable Files & PATH Abuse Enumeration Script
# Reports findings only — no exploitation
# Usage: bash writable_path_enum.sh

echo "============================================"
echo "  Writable Files & PATH Abuse Enumeration"
echo "  OSCP Exam Compliant — Findings Only"
echo "============================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[1] Current user and groups${NC}"
echo "--------------------------------------------"
whoami
id
echo ""

echo -e "${CYAN}[2] PATH variable${NC}"
echo "--------------------------------------------"
echo "$PATH" | tr ':' '\n'
echo ""

echo -e "${CYAN}[3] Writable directories in PATH${NC}"
echo "--------------------------------------------"
for d in $(echo "$PATH" | tr ':' ' '); do
    if [ -d "$d" ] && [ -w "$d" ]; then
        echo -e "${GREEN}[+] Writable PATH dir: $d${NC}"
    fi
done
echo ""

echo -e "${CYAN}[4] Writable files / directories owned by root${NC}"
echo "--------------------------------------------"
find / -type f -uid 0 -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50
find / -type d -uid 0 -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50
echo ""

echo -e "${CYAN}[5] World-writable files and directories (top 100)${NC}"
echo "--------------------------------------------"
find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -100
find / -type d -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -100
echo ""

echo -e "${CYAN}[6] Files writable by current user (top 100)${NC}"
echo "--------------------------------------------"
find / -type f -writable ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -100
echo ""

echo -e "${CYAN}[7] Interesting writable config/script locations${NC}"
echo "--------------------------------------------"
for p in /etc /etc/cron* /var/spool/cron /home /opt /tmp /var/tmp /var/www /var/backups /usr/local/bin /usr/local/sbin; do
    [ -e "$p" ] && find "$p" -maxdepth 3 -type f -writable ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20
done
echo ""

echo -e "${CYAN}[8] Check for scripts that call binaries without full path${NC}"
echo "--------------------------------------------"
for f in $(find /etc /opt /var /home /tmp /usr/local -type f \( -name '*.sh' -o -name '*.pl' -o -name '*.py' -o -name '*.rb' \) 2>/dev/null | head -50); do
    if [ -r "$f" ]; then
        NO_PATH=$(grep -oP '^\s*[a-zA-Z0-9_][a-zA-Z0-9_-]*\s+.*$' "$f" 2>/dev/null | grep -vE '^\s*(if|then|else|fi|for|while|do|done|case|esac|echo|export|source|\.\s|#|/|function|\[)' | grep -vE '/' | head -20)
        if [ -n "$NO_PATH" ]; then
            echo -e "${YELLOW}[!] $f may call binaries without full path${NC}"
        fi
    fi
done
echo ""

echo -e "${CYAN}[9] Modifiable root-owned scripts (exploitable)${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Command reference (run manually):${NC}"
echo "  find / -type f -uid 0 -perm -002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null"
echo "  ls -la <file_path>"
echo "  file <file_path>"
echo ""

find / -type f -uid 0 -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | while read -r f; do
    echo -e "${RED}[!] EXPLOITABLE: $f is root-owned and world-writable${NC}"
    echo "    Command: ls -la $f"
    echo "    Command: file $f"
done

echo ""

echo -e "${CYAN}[10] Writable files owned by root for current user${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Command reference (run manually):${NC}"
echo "  find / -type f -uid 0 -writable ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null"
echo "  ls -la <file_path>"
echo ""

find / -type f -uid 0 -writable ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 | while read -r f; do
    echo -e "${RED}[!] EXPLOITABLE: $f is root-owned and writable by you${NC}"
    echo "    Command: ls -la $f"
    echo "    Command: file $f"
done
echo ""

echo "============================================"
echo "  Enumeration Report Complete"
echo "============================================"
echo ""
echo -e "${CYAN}Manual checks to perform:${NC}"
echo "  - [9] Modifiable root-owned scripts (world-writable): directly exploitable"
echo "  - [10] Root-owned files writable by current user: directly exploitable"
echo "  - Verify writable PATH dirs are exploitable: create test binary"
echo "  - Inspect writable scripts: could an admin or cron run them?"
echo "  - Check crontab / systemd timers calling writable scripts"
echo "  - Look for SUID binaries calling missing binaries without full path"
echo ""
echo "Reference: https://gtfobins.github.io"
