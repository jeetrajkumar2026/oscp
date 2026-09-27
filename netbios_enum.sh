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
OUTPUT_DIR="netbios_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/netbios_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '          NETBIOS UDP 137/138 TCP 139 ENUMERATION'
    printf '%s\n' '          Basic non-exploitative probes only'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf 'Usage: %s <target>\n' "$0"
    printf 'Example: %s 192.168.80.40\n' "$0"
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
    local ports="$1"
    local service="$2"
    local purpose="$3"
    shift 3
    local command=("$@")

    printf "\n${BLUE}[PORT]${RESET}    ${YELLOW}%s${RESET}\n" "$ports"
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}%s${RESET}\n" "$service"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    show_command "${command[@]}"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s\n' "$ports"
        printf 'SERVICE: %s\n' "$service"
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

skip_probe() {
    local tool="$1"
    local purpose="$2"
    printf "\n${YELLOW}[!] Skipping %s: '%s' is not installed.${RESET}\n" "$purpose" "$tool"
    printf "SKIPPED: %s (%s not installed)\n" "$purpose" "$tool" >> "$LOG_FILE"
}

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    printf "${RED}[-] The required 'nmap' command is not installed.${RESET}\n"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
banner
printf "${BLUE}[TARGET]${RESET} ${YELLOW}%s${RESET}\n" "$TARGET"
printf "${BLUE}[OUTPUT]${RESET} ${YELLOW}%s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] Use only against systems you are authorized to assess.${RESET}\n"

section "1. TCP 139 SERVICE DETECTION"
run_probe "139/TCP" "NetBIOS-SSN" "Detect NetBIOS Session Service on TCP 139" \
    nmap -Pn -sV -p139 --open "$TARGET"

section "2. UDP 137/138 SERVICE DETECTION"
run_probe "137,138/UDP" "NetBIOS-NS/DGM" "Detect NetBIOS Name and Datagram services on UDP 137 and 138" \
    nmap -Pn -sU -sV -p137,138 --version-all --reason "$TARGET"

section "3. NETBIOS NAME ENUMERATION (Nmap nbstat)"
run_probe "139,445/TCP" "NetBIOS" "Request NetBIOS name table via Nmap nbstat" \
    nmap -Pn -p139,445 --script nbstat "$TARGET"

section "4. NETBIOS NAME ENUMERATION (nmblookup)"
if command -v nmblookup >/dev/null 2>&1; then
    run_probe "137/UDP" "NetBIOS-NS" "Query NetBIOS name table via nmblookup" \
        nmblookup -A "$TARGET"
else
    skip_probe "nmblookup" "NetBIOS name enumeration"
fi

section "5. NETBIOS NAME ENUMERATION (nbtscan)"
if command -v nbtscan >/dev/null 2>&1; then
    run_probe "137/UDP" "NetBIOS-NS" "Scan for NetBIOS names via nbtscan" \
        nbtscan "$TARGET"
else
    skip_probe "nbtscan" "NetBIOS name scan"
fi

section "6. SMB OVER NETBIOS (TCP 139)"
if command -v smbclient >/dev/null 2>&1; then
    run_probe "139/TCP" "NetBIOS-SSN/SMB" "Test anonymous SMB share listing over NetBIOS" \
        smbclient -N -L "//$TARGET"
else
    skip_probe "smbclient" "SMB over NetBIOS"
fi

section "7. RPC OVER NETBIOS (TCP 139)"
if command -v rpcclient >/dev/null 2>&1; then
    run_probe "139/TCP" "NetBIOS-SSN/RPC" "Test null session RPC over NetBIOS" \
        rpcclient -N -U '' "$TARGET" -c 'srvinfo'
else
    skip_probe "rpcclient" "RPC over NetBIOS"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] NetBIOS probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No exploitation was performed.${RESET}\n"
