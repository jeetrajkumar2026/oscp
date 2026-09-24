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
OUTPUT_DIR="smb_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/smb_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                  SMB ENUMERATION'
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

    printf "\n${BLUE}[PORT]${RESET}    ${YELLOW}%s/TCP${RESET}\n" "$ports"
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}%s${RESET}\n" "$service"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    show_command "${command[@]}"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s/TCP\n' "$ports"
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

section "1. SMB PORT AND SERVICE DETECTION"
run_probe "139,445" "NetBIOS/SMB" "Confirm ports, service versions, and basic SMB identity" \
    nmap -Pn -sV -p139,445 --open "$TARGET"

section "2. SMB PROTOCOL AND SECURITY SETTINGS"
run_probe "139,445" "SMB" "Identify supported SMB dialects, signing policy, OS, and server time" \
    nmap -Pn -p139,445 --script smb-protocols,smb-security-mode,smb2-security-mode,smb-os-discovery,smb2-time "$TARGET"

section "3. NETBIOS NAME INFORMATION"
run_probe "139,445" "NetBIOS/SMB" "Request NetBIOS host and workgroup information" \
    nmap -Pn -p139,445 --script nbstat "$TARGET"

section "4. ANONYMOUS SHARE LISTING"
if command -v smbclient >/dev/null 2>&1; then
    run_probe "445" "SMB" "Test whether anonymous share listing is permitted" \
        smbclient -N -g -L "//$TARGET"
else
    skip_probe "smbclient" "anonymous share listing"
fi

section "5. ANONYMOUS RPC SERVER INFORMATION"
if command -v rpcclient >/dev/null 2>&1; then
    run_probe "445" "SMB/RPC" "Request server information using an anonymous session" \
        rpcclient -N -U '' "$TARGET" -c srvinfo
else
    skip_probe "rpcclient" "anonymous RPC server information"
fi

section "6. OPTIONAL CONSOLIDATED ENUMERATION"
if command -v enum4linux-ng >/dev/null 2>&1; then
    run_probe "139,445" "NetBIOS/SMB/RPC" "Run consolidated anonymous enumeration without credentials" \
        enum4linux-ng -A "$TARGET"
else
    skip_probe "enum4linux-ng" "consolidated anonymous enumeration"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] SMB probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No password guessing, vulnerability scripts, share downloads, or exploitation were performed.${RESET}\n"
