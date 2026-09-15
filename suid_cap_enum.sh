#!/bin/bash
# OSCP-Compliant SUID & Capabilities Enumeration Script
# Reports findings only — no exploit suggestions
# Analyst decides next steps based on findings
# Usage: bash suid_cap_enum.sh

echo "============================================"
echo "  SUID & Capabilities Enumeration Report"
echo "  OSCP Exam Compliant — Findings Only"
echo "============================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Standard SUID binaries — not interesting
STANDARD_SUID="sudo passwd su chsh newgrp chfn gpasswd mount umount pkexec fusermount sg crontab at unix_chkpwd pam_extrausers pkcheck vmware-user-suid-wrapper ntfs-3g eject-dmcrypt polkit-agent-helper-1 dbus-daemon-launch-helper ssh-keysign pppd chrome-sandbox"

echo -e "${CYAN}[1] Finding all SUID binaries ...${NC}"
echo "--------------------------------------------"
ALL_SUID=$(find / -perm -4000 -type f 2>/dev/null)
echo "$ALL_SUID"
echo ""
echo "Total SUID binaries found: $(echo "$ALL_SUID" | wc -l)"
echo ""

echo -e "${CYAN}[2] Filtering standard SUID binaries ...${NC}"
echo "--------------------------------------------"
UNUSUAL_SUID=""
for suid in $ALL_SUID; do
    base=$(basename "$suid")
    is_standard=0
    for std in $STANDARD_SUID; do
        if [ "$base" = "$std" ]; then
            is_standard=1
            break
        fi
    done
    if [ $is_standard -eq 0 ]; then
        UNUSUAL_SUID="$UNUSUAL_SUID $suid"
    fi
done

if [ -n "$UNUSUAL_SUID" ]; then
    for suid in $UNUSUAL_SUID; do
        echo -e "${GREEN}[+] UNUSUAL SUID: $suid${NC}"
    done
else
    echo -e "${YELLOW}[!] No unusual SUID binaries found${NC}"
fi
echo ""

echo -e "${CYAN}[3] Checking unusual SUID binaries against known GTFOBins ...${NC}"
echo "--------------------------------------------"
GTFO_SUID="find vim vi nano less more awk perl python python3 nmap env cp dd tee wget curl nc netcat bash sh dash zsh tar zip strace ltrace openssl systemctl service ruby lua node php gcc make git scp rsync taskset nsenter unshare xargs timeout nohup script ionice flock dialog ed mail tee hexdump od base64 cut sort uniq tr head tail wc cat tac rev nl paste column expand fmt fold pr fold fmt shuf shred truncate env printenv"

FOUND_GTFO=0
for suid in $UNUSUAL_SUID; do
    base=$(basename "$suid")
    for gtfo in $GTFO_SUID; do
        if [ "$base" = "$gtfo" ]; then
            echo -e "${GREEN}[+] VULNERABLE: $suid is a known GTFOBins binary with SUID${NC}"
            FOUND_GTFO=1
            break
        fi
    done
done
if [ $FOUND_GTFO -eq 0 ]; then
    echo -e "${YELLOW}[!] No known GTFOBins SUID binaries found${NC}"
fi
echo ""

echo -e "${CYAN}[4] Checking SUID binaries outside standard directories ...${NC}"
echo "--------------------------------------------"
NON_STANDARD_PATH=$(echo "$ALL_SUID" | grep -v "/usr/bin/" | grep -v "/usr/lib/" | grep -v "/usr/sbin/" | grep -v "/snap/" | grep -v "/bin/")
if [ -n "$NON_STANDARD_PATH" ]; then
    for suid in $NON_STANDARD_PATH; do
        echo -e "${GREEN}[+] VULNERABLE: SUID binary in non-standard location: $suid${NC}"
    done
else
    echo -e "${YELLOW}[!] All SUID binaries are in standard directories${NC}"
fi
echo ""

echo -e "${CYAN}[5] Finding all SGID binaries ...${NC}"
echo "--------------------------------------------"
ALL_SGID=$(find / -perm -2000 -type f 2>/dev/null)
echo "$ALL_SGID"
echo ""
echo "Total SGID binaries found: $(echo "$ALL_SGID" | wc -l)"
echo ""

echo -e "${CYAN}[6] Checking SGID binaries outside standard directories ...${NC}"
echo "--------------------------------------------"
NON_STANDARD_SGID=$(echo "$ALL_SGID" | grep -v "/usr/bin/" | grep -v "/usr/lib/" | grep -v "/usr/sbin/" | grep -v "/snap/" | grep -v "/bin/")
if [ -n "$NON_STANDARD_SGID" ]; then
    for sgid in $NON_STANDARD_SGID; do
        echo -e "${GREEN}[+] VULNERABLE: SGID binary in non-standard location: $sgid${NC}"
    done
else
    echo -e "${YELLOW}[!] All SGID binaries are in standard directories${NC}"
fi
echo ""

echo -e "${CYAN}[7] Finding all capabilities ...${NC}"
echo "--------------------------------------------"
ALL_CAPS=$(getcap -r / 2>/dev/null)
if [ -n "$ALL_CAPS" ]; then
    echo "$ALL_CAPS"
else
    echo -e "${YELLOW}[!] No capabilities found${NC}"
fi
echo ""

echo -e "${CYAN}[8] Checking for dangerous capabilities ...${NC}"
echo "--------------------------------------------"
DANGEROUS_CAPS="cap_setuid cap_setgid cap_dac_read_search cap_dac_override cap_net_raw cap_net_admin cap_sys_admin cap_sys_ptrace cap_sys_module cap_chown cap_fowner cap_setfcap"

FOUND_DANGEROUS_CAP=0
if [ -n "$ALL_CAPS" ]; then
    for cap in $DANGEROUS_CAPS; do
        MATCH=$(echo "$ALL_CAPS" | grep -i "$cap")
        if [ -n "$MATCH" ]; then
            echo -e "${GREEN}[+] VULNERABLE: $cap found${NC}"
            echo "    $MATCH"
            FOUND_DANGEROUS_CAP=1
        fi
    done
fi
if [ $FOUND_DANGEROUS_CAP -eq 0 ]; then
    echo -e "${YELLOW}[!] No dangerous capabilities found${NC}"
fi
echo ""

echo -e "${CYAN}[9] Checking capabilities on GTFOBins binaries ...${NC}"
echo "--------------------------------------------"
GTFO_CAPS="python python3 perl ruby lua node bash sh vim vi nano nmap find awk cp mv cat less more env tar zip strace gdb"
FOUND_CAP_GTFO=0
if [ -n "$ALL_CAPS" ]; then
    for binary in $GTFO_CAPS; do
        MATCH=$(echo "$ALL_CAPS" | grep -E "/$binary\b")
        if [ -n "$MATCH" ]; then
            echo -e "${GREEN}[+] VULNERABLE: $binary has capabilities (check GTFOBins)${NC}"
            echo "    $MATCH"
            FOUND_CAP_GTFO=1
        fi
    done
fi
if [ $FOUND_CAP_GTFO -eq 0 ]; then
    echo -e "${YELLOW}[!] No GTFOBins binaries with capabilities found${NC}"
fi
echo ""

echo -e "${CYAN}[10] Checking for custom SUID binaries (strings analysis) ...${NC}"
echo "--------------------------------------------"
for suid in $UNUSUAL_SUID; do
    base=$(basename "$suid")
    # Skip known GTFOBins — already reported
    IS_GTFO=0
    for gtfo in $GTFO_SUID; do
        if [ "$base" = "$gtfo" ]; then
            IS_GTFO=1
            break
        fi
    done
    if [ $IS_GTFO -eq 0 ]; then
        echo -e "${CYAN}    Analyzing: $suid${NC}"
        file "$suid" 2>/dev/null
        STRINGS_CMD=$(strings "$suid" 2>/dev/null | grep -iE "(sh|bash|python|perl|cat|ls|id|whoami|/bin/|/tmp/|system|exec|popen|command|password|key|token|secret)" | head -10)
        if [ -n "$STRINGS_CMD" ]; then
            echo -e "${GREEN}    [+] Interesting strings found:${NC}"
            echo "$STRINGS_CMD" | while read line; do
                echo -e "${YELLOW}      - $line${NC}"
            done
        else
            echo -e "${YELLOW}    [!] No interesting strings found${NC}"
        fi
        echo ""
    fi
done

echo -e "${CYAN}[11] Checking for SUID binaries that call other binaries without full path ...${NC}"
echo "--------------------------------------------"
for suid in $UNUSUAL_SUID; do
    base=$(basename "$suid")
    NO_PATH=$(strings "$suid" 2>/dev/null | grep -vE "^/|^#|^\.|^@|^\*" | grep -oP '^[a-z_][a-z0-9_-]*$' | sort -u | head -10)
    if [ -n "$NO_PATH" ]; then
        echo -e "${GREEN}[+] VULNERABLE: $suid may call binaries without full path (PATH hijack possible)${NC}"
        echo "$NO_PATH" | while read cmd; do
            echo -e "${YELLOW}      - $cmd${NC}"
        done
    fi
done
echo ""

echo "============================================"
echo "  Enumeration Report Complete"
echo "============================================"
echo ""
echo -e "${CYAN}Summary of other privesc methods to check:${NC}"
echo "  - Sudo:     sudo -l"
echo "  - Cron:     cat /etc/crontab && ls -la /etc/cron.d/"
echo "  - Passwds:  grep -rli password /etc/ /var/www/ /home/ 2>/dev/null"
echo "  - SSH keys: find / -name id_rsa 2>/dev/null"
echo "  - NFS:      cat /etc/exports 2>/dev/null"
echo "  - Writable: find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys"
echo ""
echo "Reference: https://gtfobins.github.io"
