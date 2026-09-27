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
OUTPUT_DIR="ike_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/ike_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '             IKE/IPSEC UDP 500/4500 ENUMERATION'
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

section "1. UDP SERVICE DETECTION"
run_probe "500,4500/UDP" "IKE/IPsec" "Detect IKE and NAT-T on UDP 500 and 4500" \
    nmap -Pn -sU -sV -p500,4500 --version-all --reason "$TARGET"

section "2. IKE SCAN (MAIN MODE)"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "500/UDP" "IKE" "Basic IKE scan to confirm service responds" \
        ike-scan "$TARGET"
else
    skip_probe "ike-scan" "IKE main mode scan"
fi

section "3. IKE SCAN WITH NAT-T"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "4500/UDP" "IKE/NAT-T" "IKE scan using NAT-T on UDP 4500" \
        ike-scan --nat-t "$TARGET"
else
    skip_probe "ike-scan" "IKE NAT-T scan"
fi

section "4. AGGRESSIVE MODE SCAN"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "500/UDP" "IKE" "Aggressive mode scan to discover vendor IDs" \
        ike-scan --aggressive "$TARGET"
else
    skip_probe "ike-scan" "IKE aggressive mode scan"
fi

section "5. AGGRESSIVE MODE WITH NAT-T"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "4500/UDP" "IKE/NAT-T" "Aggressive mode scan using NAT-T" \
        ike-scan --aggressive --nat-t "$TARGET"
else
    skip_probe "ike-scan" "IKE aggressive mode NAT-T scan"
fi

section "6. TRANSFORM ENUMERATION"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "500/UDP" "IKE" "Enumerate supported transforms (3DES, AES-256, DES)" \
        ike-scan --trans=5,2,1,2 --trans=7,2,1,2 --trans=1,2,1,2 "$TARGET"
else
    skip_probe "ike-scan" "IKE transform enumeration"
fi

section "7. BACKOFF ANALYSIS"
if command -v ike-scan >/dev/null 2>&1; then
    run_probe "500/UDP" "IKE" "Show backoff timing for vendor fingerprinting" \
        ike-scan --showbackoff "$TARGET"
else
    skip_probe "ike-scan" "IKE backoff analysis"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] IKE/IPsec probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No exploitation or PSK cracking was performed.${RESET}\n"
