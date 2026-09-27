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
OUTPUT_DIR="msrpc_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/msrpc_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                MSRPC PORT 135 ENUMERATION'
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

section "1. PORT 135 SERVICE DETECTION"
run_probe "135/TCP" "MSRPC" "Confirm port 135 and service version" \
    nmap -Pn -sV -p135 --open "$TARGET"

section "2. DYNAMIC RPC PORT DETECTION"
run_probe "49152-49158/TCP" "MSRPC" "Probe dynamic RPC ports for service versions" \
    nmap -Pn -sV -p49152-49158 --version-all --reason "$TARGET"

section "3. RPC ENDPOINT ENUMERATION (Nmap)"
run_probe "135/TCP" "MSRPC" "Enumerate RPC interface UUIDs via Nmap msrpc-enum" \
    nmap -Pn -p135 --script msrpc-enum "$TARGET"

section "4. RPC ENDPOINT ENUMERATION (Impacket)"
if command -v impacket-rpcdump >/dev/null 2>&1; then
    run_probe "135/TCP" "MSRPC" "Dump RPC endpoints via Impacket rpcdump" \
        impacket-rpcdump "$TARGET"
else
    skip_probe "impacket-rpcdump" "RPC endpoint dump"
fi

section "5. NULL SESSION RPC VIA SMB (PORT 445)"
if command -v rpcclient >/dev/null 2>&1; then
    run_probe "445/TCP" "MSRPC over SMB" "Test null session RPC server info via SMB" \
        rpcclient -N -U '' "$TARGET" -c 'srvinfo'
else
    skip_probe "rpcclient" "null session RPC via SMB"
fi

section "6. SAMR DUMP VIA SMB (Impacket)"
if command -v impacket-samrdump >/dev/null 2>&1; then
    run_probe "445/TCP" "MSRPC over SMB" "Dump SAMR user and group info via Impacket" \
        impacket-samrdump "$TARGET"
else
    skip_probe "impacket-samrdump" "SAMR dump"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] MSRPC probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No exploitation or remote execution was performed.${RESET}\n"
