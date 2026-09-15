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
SUDO_OUTPUT=$(sudo -l 2>/dev/null)
if [ -z "$SUDO_OUTPUT" ]; then
    echo -e "${RED}[-] Cannot run sudo -l (no sudo access)${NC}"
    echo -e "${YELLOW}[*] Continuing with alternative enumeration methods ...${NC}"
else
    echo "$SUDO_OUTPUT"
fi
echo ""

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

echo -e "${CYAN}[13] Checking /etc/sudoers readability ...${NC}"
echo "--------------------------------------------"
SUDOERS_PERMS=$(ls -la /etc/sudoers 2>/dev/null)
echo "$SUDOERS_PERMS"
if cat /etc/sudoers 2>/dev/null | grep -qE "NOPASSWD|ALL"; then
    echo -e "${GREEN}[+] VULNERABLE: /etc/sudoers is readable and contains rules${NC}"
    cat /etc/sudoers 2>/dev/null | grep -E "NOPASSWD|ALL|env_keep|LD_PRELOAD|\*"
else
    echo -e "${YELLOW}[!] /etc/sudoers not readable${NC}"
fi
echo ""

echo -e "${CYAN}[14] Checking /etc/sudoers.d/ ...${NC}"
echo "--------------------------------------------"
ls -la /etc/sudoers.d/ 2>/dev/null
SUDOERS_D=$(cat /etc/sudoers.d/* 2>/dev/null)
if [ -n "$SUDOERS_D" ]; then
    if echo "$SUDOERS_D" | grep -qE "NOPASSWD|ALL"; then
        echo -e "${GREEN}[+] VULNERABLE: /etc/sudoers.d/ contains rules${NC}"
        echo "$SUDOERS_D" | grep -E "NOPASSWD|ALL|env_keep|LD_PRELOAD|\*"
    else
        echo -e "${YELLOW}[!] /etc/sudoers.d/ readable but no interesting rules${NC}"
    fi
else
    echo -e "${YELLOW}[!] /etc/sudoers.d/ not readable or empty${NC}"
fi
echo ""

echo -e "${CYAN}[15] Checking group membership ...${NC}"
echo "--------------------------------------------"
id
groups
for grp in sudo wheel admin; do
    if id 2>/dev/null | grep -q "$grp"; then
        echo -e "${GREEN}[+] VULNERABLE: Current user is in $grp group${NC}"
    fi
done
SUDO_USERS=$(grep "sudo\|wheel\|admin" /etc/group 2>/dev/null)
if [ -n "$SUDO_USERS" ]; then
    echo -e "${YELLOW}[i] Users in sudo/wheel/admin groups:${NC}"
    echo "$SUDO_USERS"
else
    echo -e "${YELLOW}[!] No users found in sudo/wheel/admin groups${NC}"
fi
echo ""

echo -e "${CYAN}[16] Checking sudo version ...${NC}"
echo "--------------------------------------------"
SUDO_VERSION=$(sudo --version 2>/dev/null | head -1)
echo "$SUDO_VERSION"
if echo "$SUDO_VERSION" | grep -oP 'Sudo version \K[0-9]+\.[0-9]+' | head -1 | grep -qE "1\.[0-7]"; then
    echo -e "${GREEN}[+] VULNERABLE: Old sudo version — check CVE-2021-3156, CVE-2019-14287${NC}"
else
    echo -e "${YELLOW}[!] Sudo version appears current${NC}"
fi
echo ""

echo -e "${CYAN}[17] Checking for doas ...${NC}"
echo "--------------------------------------------"
DOAS_PATH=$(which doas 2>/dev/null)
if [ -n "$DOAS_PATH" ]; then
    echo -e "${GREEN}[+] doas found: $DOAS_PATH${NC}"
    DOAS_CONF=$(cat /etc/doas.conf 2>/dev/null)
    if [ -n "$DOAS_CONF" ]; then
        echo "$DOAS_CONF"
        if echo "$DOAS_CONF" | grep -q "permit nopass"; then
            echo -e "${GREEN}[+] VULNERABLE: doas permit nopass found${NC}"
        fi
    else
        echo -e "${YELLOW}[!] /etc/doas.conf not readable${NC}"
    fi
else
    echo -e "${YELLOW}[!] doas not installed${NC}"
fi
echo ""

echo -e "${CYAN}[18] Checking polkit policies ...${NC}"
echo "--------------------------------------------"
PKACTION=$(pkaction --verbose 2>/dev/null | grep -i "auth_admin_keep\|yes\|allow")
if [ -n "$PKACTION" ]; then
    echo -e "${GREEN}[+] VULNERABLE: Polkit actions found without auth requirement${NC}"
    echo "$PKACTION" | head -10
else
    echo -e "${YELLOW}[!] No permissive polkit policies found${NC}"
fi
echo ""

echo -e "${CYAN}[19] Checking pkexec (PwnKit) ...${NC}"
echo "--------------------------------------------"
PKEXEC_PERMS=$(ls -la /usr/bin/pkexec 2>/dev/null)
echo "$PKEXEC_PERMS"
if echo "$PKEXEC_PERMS" | grep -q "rws"; then
    echo -e "${YELLOW}[i] pkexec has SUID — check if system is patched against CVE-2021-4034${NC}"
else
    echo -e "${YELLOW}[!] pkexec not found or no SUID${NC}"
fi
echo ""

echo -e "${CYAN}[20] Checking if /usr/bin/sudo is writable ...${NC}"
echo "--------------------------------------------"
SUDO_PERMS=$(ls -la /usr/bin/sudo 2>/dev/null)
echo "$SUDO_PERMS"
if echo "$SUDO_PERMS" | grep -qE "rwxrwx|rw-rw-|rwxrw"; then
    echo -e "${RED}[!] VULNERABLE: /usr/bin/sudo is writable${NC}"
else
    echo -e "${YELLOW}[!] /usr/bin/sudo not writable${NC}"
fi
echo ""

echo -e "${CYAN}[21] Checking PAM configuration ...${NC}"
echo "--------------------------------------------"
PAM_SU=$(cat /etc/pam.d/su 2>/dev/null)
PAM_SUDO=$(cat /etc/pam.d/sudo 2>/dev/null)
PAM_COMMON=$(cat /etc/pam.d/common-auth 2>/dev/null)
if echo "$PAM_SU $PAM_SUDO $PAM_COMMON" | grep -q "pam_permit"; then
    echo -e "${RED}[!] VULNERABLE: pam_permit.so found in PAM config${NC}"
    echo "$PAM_SU $PAM_SUDO $PAM_COMMON" | grep "pam_permit"
elif echo "$PAM_SU $PAM_SUDO $PAM_COMMON" | grep -q "nullok"; then
    echo -e "${RED}[!] VULNERABLE: nullok found in PAM config (empty passwords accepted)${NC}"
    echo "$PAM_SU $PAM_SUDO $PAM_COMMON" | grep "nullok"
else
    echo -e "${YELLOW}[!] No PAM misconfiguration found${NC}"
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
echo "Full guide: [[03a - Sudo Misconfiguration Guide]]"
