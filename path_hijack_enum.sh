#!/bin/bash
# OSCP-Compliant PATH Hijack Enumeration Script
# Reports findings only — no exploitation
# Checks: scripts calling bare binaries + writable PATH directories = exploitable
# Usage: bash path_hijack_enum.sh

echo "============================================"
echo "  PATH Hijack Enumeration"
echo "  OSCP Exam Compliant — Findings Only"
echo "============================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[1] Current user and PATH${NC}"
echo "--------------------------------------------"
whoami
id
echo ""
echo "PATH directories:"
echo "$PATH" | tr ':' '\n'
echo ""

echo -e "${CYAN}[2] Writable directories in current PATH${NC}"
echo "--------------------------------------------"
WRITABLE_PATH_DIRS=""
for d in $(echo "$PATH" | tr ':' ' '); do
    if [ -d "$d" ] && [ -w "$d" ]; then
        echo -e "${GREEN}[+] WRITABLE: $d${NC}"
        WRITABLE_PATH_DIRS="$WRITABLE_PATH_DIRS $d"
    fi
done
if [ -z "$WRITABLE_PATH_DIRS" ]; then
    echo -e "${YELLOW}[-] No writable directories found in current PATH${NC}"
fi
echo ""

echo -e "${CYAN}[3] All writable directories on system (potential PATH targets)${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Command reference (run manually):${NC}"
echo "  find / -type d -writable ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null"
echo ""
find / -type d -writable ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50
echo ""

echo -e "${CYAN}[4] Standard cron PATH directories writability${NC}"
echo "--------------------------------------------"
CRON_PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
for d in $(echo "$CRON_PATH" | tr ':' ' '); do
    if [ -d "$d" ] && [ -w "$d" ]; then
        echo -e "${RED}[!] WRITABLE cron PATH dir: $d${NC}"
    else
        echo -e "${CYAN}[-] Not writable: $d${NC}"
    fi
done
echo ""

echo -e "${CYAN}[5] Scripts that call binaries without full path${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Command reference (run manually):${NC}"
echo "  grep -nE '^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]' <script>"
echo ""
SCRIPT_LIST="/tmp/path_hijack_scripts_$$"
> "$SCRIPT_LIST"

for f in $(find /etc /opt /var/www /var/spool /home /usr/local /tmp -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' \) 2>/dev/null | head -200); do
    if [ -r "$f" ]; then
        NO_PATH=$(grep -nE '^[[:space:]]*[a-zA-Z0-9_][a-zA-Z0-9_-]*[[:space:]]' "$f" 2>/dev/null | \
            grep -vE '^\s*[0-9]+:\s*(if|then|else|fi|for|while|do|done|case|esac|echo|export|source|\.|#|/|function|\[|return|local|set|unset|trap|wait|read|umask|ulimit|cd|pwd|exit|kill|jobs|bg|fg|disown|suspend|times|type|hash|alias|unalias|bind|builtin|caller|command|declare|enable|exec|getopts|help|let|mapfile|popd|printf|pushd|select|shift|shopt|test|true|false|continue|break)' | \
            grep -vE '/')

        # Filter out shell builtins, keywords, aliases, and functions
        EXTERNAL_ONLY=""
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            # Extract the bare command name from the line
            cmd=$(echo "$line" | sed -E 's/^\s*[0-9]+:\s*([a-zA-Z0-9_][a-zA-Z0-9_-]*).*/\1/')
            [ -n "$cmd" ] || continue
            ctype=$(type -t "$cmd" 2>/dev/null || echo "")
            if [ "$ctype" = "file" ]; then
                EXTERNAL_ONLY="${EXTERNAL_ONLY}${line}\n"
            fi
        done <<< "$NO_PATH"

        if [ -n "$EXTERNAL_ONLY" ]; then
            echo -e "${YELLOW}[!] $f may call binaries without full path${NC}"
            echo "$f" >> "$SCRIPT_LIST"
        fi
    fi
done
echo ""

echo -e "${CYAN}[6] Cross-reference: exploitable PATH hijack combinations${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}Checking: script calls bare binary + writable PATH dir exists${NC}"
echo ""

EXPLOITABLE_FOUND=0

# Check if any writable PATH directories exist
# Exclude /run/user/* (per-user tmpfs runtime dirs not in root/cron PATH)
ALL_WRITABLE_DIRS=$(find / -type d -writable ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/user/*" 2>/dev/null | head -100)

if [ -z "$ALL_WRITABLE_DIRS" ]; then
    echo -e "${YELLOW}[-] No writable directories found on system — PATH hijack not possible${NC}"
    echo ""
else
    while read -r script; do
        [ -f "$script" ] || continue
        [ -r "$script" ] || continue

        owner=$(stat -c '%U' "$script" 2>/dev/null || echo "?")
        perms=$(stat -c '%a' "$script" 2>/dev/null || echo "?")

        # Extract bare command names from the script
        BARE_CMDS=$(grep -oE '^[[:space:]]*[a-zA-Z0-9_][a-zA-Z0-9_-]*' "$script" 2>/dev/null | \
            grep -vE '^(if|then|else|fi|for|while|do|done|case|esac|echo|export|source|\.|#|function|\[|return|local|set|unset|trap|wait|read|umask|ulimit|cd|pwd|exit|kill|jobs|bg|fg|disown|suspend|times|type|hash|alias|unalias|bind|builtin|caller|command|declare|enable|exec|getopts|help|let|mapfile|popd|printf|pushd|select|shift|shopt|test|true|false|continue|break)$' | \
            sort -u)

        for cmd in $BARE_CMDS; do
            # Skip shell builtins, keywords, aliases, and functions
            ctype=$(type -t "$cmd" 2>/dev/null || echo "")
            [ "$ctype" = "file" ] || continue

            # Check if this command is an external binary (type -P ignores shell builtins/keywords)
            CMD_PATH=$(type -P "$cmd" 2>/dev/null)
            [ -z "$CMD_PATH" ] && continue
            [ -x "$CMD_PATH" ] || continue

            # Check if any writable directory could be used to hijack this command
            for wdir in $ALL_WRITABLE_DIRS; do
                echo -e "${RED}[!] EXPLOITABLE: $script calls '$cmd' (no full path)${NC}"
                echo "    Script owner: $owner | Permissions: $perms"
                echo "    Bare command: $cmd (currently at: $CMD_PATH)"
                echo "    Writable dir: $wdir"
                echo "    Manual verify: cat $script | grep -n '$cmd'"
                echo "    Manual verify: ls -la $wdir"
                echo "    Manual verify: type -P $cmd"
                echo ""
                EXPLOITABLE_FOUND=1
                break  # One writable dir is enough per command
            done
        done
    done < "$SCRIPT_LIST"
fi

if [ "$EXPLOITABLE_FOUND" -eq 0 ]; then
    echo -e "${YELLOW}[-] No exploitable PATH hijack combinations found${NC}"
    echo "    Either no scripts call bare binaries, or no writable PATH directories exist"
fi
echo ""

echo -e "${CYAN}[7] Root-owned scripts calling bare binaries (highest priority)${NC}"
echo "--------------------------------------------"
echo -e "${CYAN}These run as root — if you can hijack the binary, you get root${NC}"
echo ""

while read -r script; do
    [ -f "$script" ] || continue
    [ -r "$script" ] || continue

    owner_uid=$(stat -c '%u' "$script" 2>/dev/null || echo "?")
    if [ "$owner_uid" = "0" ]; then
        perms=$(stat -c '%a' "$script" 2>/dev/null || echo "?")
        BARE_CMDS=$(grep -oE '^[[:space:]]*[a-zA-Z0-9_][a-zA-Z0-9_-]*' "$script" 2>/dev/null | \
            grep -vE '^(if|then|else|fi|for|while|do|done|case|esac|echo|export|source|\.|#|function|\[|return|local|set|unset|trap|wait|read|umask|ulimit|cd|pwd|exit|kill|jobs|bg|fg|disown|suspend|times|type|hash|alias|unalias|bind|builtin|caller|command|declare|enable|exec|getopts|help|let|mapfile|popd|printf|pushd|select|shift|shopt|test|true|false|continue|break)$' | \
            sort -u)

        for cmd in $BARE_CMDS; do
            ctype=$(type -t "$cmd" 2>/dev/null || echo "")
            [ "$ctype" = "file" ] || continue
            CMD_PATH=$(type -P "$cmd" 2>/dev/null)
            [ -z "$CMD_PATH" ] && continue
            [ -x "$CMD_PATH" ] || continue
            echo -e "${RED}[!] ROOT SCRIPT: $script calls '$cmd' (no full path)${NC}"
            echo "    Owner: root | Permissions: $perms"
            echo "    Command: cat $script | grep -n '$cmd'"
            echo "    Command: type -P $cmd"
            echo ""
        done
    fi
done < "$SCRIPT_LIST"

rm -f "$SCRIPT_LIST"

echo "============================================"
echo "  Enumeration Report Complete"
echo "============================================"
echo ""
echo -e "${CYAN}Manual checks to perform:${NC}"
echo "  1. Read each flagged script: cat <script>"
echo "  2. Identify bare commands: grep -nE '^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]' <script>"
echo "  3. Check writable dirs: find / -type d -writable 2>/dev/null"
echo "  4. If both exist: create fake binary in writable dir"
echo "  5. Wait for script to run or trigger it"
echo ""
echo "Reference: https://gtfobins.github.io"
