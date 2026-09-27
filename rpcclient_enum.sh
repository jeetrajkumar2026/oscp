#!/usr/bin/env bash

set -u

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

TARGET="${1:-}"
USERNAME="${2:-}"
OUTPUT_DIR="rpcclient_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/rpcclient_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                RPCCLIENT ENUMERATION'
    printf '%s\n' '          Basic non-exploitative probes only'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf 'Usage: %s <target> [username]\n' "$0"
    printf 'Null session: %s 192.168.80.40\n' "$0"
    printf 'Authenticated: %s 192.168.80.40 user\n' "$0"
}

section() {
    printf "\n${MAGENTA}============================================================${RESET}\n"
    printf "${WHITE}%s${RESET}\n" "$1"
    printf "${MAGENTA}============================================================${RESET}\n"
}

show_command() {
    printf "${BLUE}[COMMAND]${RESET} ${CYAN}"
    printf '%q ' "$@"
    printf "${RESET}\n\n"
}

run_probe() {
    local purpose="$1"
    local rpc_commands="$2"
    local command=(rpcclient "${AUTH_ARGS[@]}" "$TARGET" -c "$rpc_commands")

    printf "\n${BLUE}[PORT]${RESET}    ${YELLOW}445/TCP (fallback 139/TCP)${RESET}\n"
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}MSRPC over SMB${RESET}\n"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    show_command "${command[@]}"

    {
        printf '\n============================================================\n'
        printf 'PORT: 445/TCP (fallback 139/TCP)\n'
        printf 'SERVICE: MSRPC over SMB\n'
        printf 'PROBE: %s\n' "$purpose"
        printf 'COMMAND: '
        printf '%q ' "${command[@]}"
        printf '\n============================================================\n'
    } >> "$LOG_FILE"

    "${command[@]}" 2>&1 | tee -a "$LOG_FILE"
    local status=${PIPESTATUS[0]}

    if [[ $status -eq 0 ]]; then
        printf "${GREEN}[+] Probe completed${RESET}\n"
    else
        printf "${YELLOW}[!] Probe exited with status %s${RESET}\n" "$status"
    fi
}

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! command -v rpcclient >/dev/null 2>&1; then
    printf "${RED}[-] The required 'rpcclient' command is not installed.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install samba-common-bin${RESET}\n"
    exit 1
fi

if [[ -n "$USERNAME" ]]; then
    if [[ -z "${PASSWD:-}" ]]; then
        read -r -s -p "Password for ${USERNAME}: " PASSWD
        printf '\n'
    fi
    export PASSWD
    AUTH_ARGS=(-U "$USERNAME")
    AUTH_MODE="authenticated as ${USERNAME}"
else
    AUTH_ARGS=(-N -U '')
    AUTH_MODE="null session"
fi

mkdir -p "$OUTPUT_DIR"
banner
printf "${BLUE}[TARGET]${RESET} ${YELLOW}%s${RESET}\n" "$TARGET"
printf "${BLUE}[AUTH]${RESET}   ${YELLOW}%s${RESET}\n" "$AUTH_MODE"
printf "${BLUE}[OUTPUT]${RESET} ${YELLOW}%s${RESET}\n" "$LOG_FILE"

section "1. SERVER AND DOMAIN INFORMATION"
run_probe "Server platform and version information" "srvinfo"
run_probe "Domain role and server information" "querydominfo"
run_probe "List visible domains" "enumdomains"
run_probe "Query domain SID" "lsaquery"
run_probe "Query domain password policy" "getdompwinfo"

section "2. USER ENUMERATION"
run_probe "Enumerate domain users and RIDs" "enumdomusers"
run_probe "Query display information for users" "querydispinfo"

section "3. GROUP ENUMERATION"
run_probe "Enumerate domain groups" "enumdomgroups"
run_probe "Enumerate builtin local groups" "enumalsgroups builtin"
run_probe "Enumerate domain local groups" "enumalsgroups domain"

section "4. SHARE AND PRINTER ENUMERATION"
run_probe "Enumerate all SMB shares" "netshareenumall"
run_probe "Enumerate printers" "enumprinters"

section "5. CONSOLIDATED READ-ONLY ENUMERATION"
run_probe "Run the primary read-only RPC checks together" "srvinfo;querydominfo;getdompwinfo;netshareenumall;enumdomusers;enumdomgroups;enumalsgroups builtin;enumprinters"

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] rpcclient probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] STATUS_ACCESS_DENIED can mean the session connected but that operation is restricted.${RESET}\n"
