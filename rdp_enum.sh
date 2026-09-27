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
OUTPUT_DIR="rdp_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/rdp_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                RDP PORT 3389 ENUMERATION'
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

section "1. SERVICE DETECTION AND IDENTITY"
run_probe "3389/TCP" "RDP" "Detect RDP service and version" \
    nmap -Pn -sV -p3389 --open "$TARGET"

section "2. RDP NTLM INFORMATION"
run_probe "3389/TCP" "RDP" "Extract Windows version, hostname, and domain via NTLM info" \
    nmap -Pn -p3389 --script rdp-ntlm-info "$TARGET"

section "3. ENCRYPTION AND SECURITY MODES"
run_probe "3389/TCP" "RDP" "Enumerate supported RDP encryption and security protocols" \
    nmap -Pn -p3389 --script rdp-enum-encryption "$TARGET"

section "4. CERTIFICATE INSPECTION"
run_probe "3389/TCP" "RDP/TLS" "Extract and inspect the RDP TLS certificate" \
    nmap -Pn -p3389 --script ssl-cert "$TARGET"

section "5. SSL CIPHER AND DATE CHECK"
run_probe "3389/TCP" "RDP/TLS" "Check SSL ciphers and certificate date validity" \
    nmap -Pn -p3389 --script ssl-cert,ssl-date,ssl-enum-ciphers "$TARGET"

section "6. BLUEKEEP (CVE-2019-0708) DETECTION"
run_probe "3389/TCP" "RDP" "Check for BlueKeep vulnerability (safe detection only)" \
    nmap -Pn -p3389 --script rdp-vuln-cve2019-0708 "$TARGET"

section "7. MS12-020 DETECTION"
run_probe "3389/TCP" "RDP" "Check for MS12-020 vulnerability (safe detection only)" \
    nmap -Pn -p3389 --script rdp-vuln-ms12-020 "$TARGET"

section "8. NLA REQUIREMENT CHECK"
if command -v xfreerdp3 >/dev/null 2>&1; then
    run_probe "3389/TCP" "RDP" "Test whether NLA is required (sec:rdp attempt)" \
        timeout 10 xfreerdp3 /v:"$TARGET" /sec:rdp /cert:ignore
elif command -v xfreerdp >/dev/null 2>&1; then
    run_probe "3389/TCP" "RDP" "Test whether NLA is required (sec:rdp attempt)" \
        timeout 10 xfreerdp /v:"$TARGET" /sec:rdp /cert:ignore
else
    skip_probe "xfreerdp3/xfreerdp" "NLA requirement check"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] RDP probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No exploitation or credential guessing was performed.${RESET}\n"
