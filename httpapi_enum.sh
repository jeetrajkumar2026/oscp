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
OUTPUT_DIR="httpapi_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/httpapi_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '             HTTPAPI PORT 5357 ENUMERATION'
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

section "1. SERVICE DETECTION"
run_probe "5357/TCP" "HTTPAPI" "Detect service and version on port 5357" \
    nmap -Pn -sV -p5357 --open "$TARGET"

section "2. HTTP HEADERS AND TITLE"
run_probe "5357/TCP" "HTTPAPI" "Enumerate HTTP title, headers, methods, and server header" \
    nmap -Pn -sV -p5357 --script http-title,http-headers,http-methods,http-server-header "$TARGET"

section "3. MANUAL HTTP GET"
if command -v curl >/dev/null 2>&1; then
    run_probe "5357/TCP" "HTTPAPI" "Manual GET request to root path" \
        curl -i --max-time 10 "http://${TARGET}:5357/"
else
    skip_probe "curl" "manual HTTP GET"
fi

section "4. MANUAL HTTP OPTIONS"
if command -v curl >/dev/null 2>&1; then
    run_probe "5357/TCP" "HTTPAPI" "OPTIONS request to discover allowed methods" \
        curl -i --max-time 10 -X OPTIONS "http://${TARGET}:5357/"
else
    skip_probe "curl" "manual HTTP OPTIONS"
fi

section "5. COMMON METADATA PATHS"
if command -v curl >/dev/null 2>&1; then
    for path in / /wsd/ /WSD/ /metadata /wsdl /simple /device; do
        run_probe "5357/TCP" "HTTPAPI" "Probe path: ${path}" \
            curl -i --max-time 5 "http://${TARGET}:5357${path}"
    done
else
    skip_probe "curl" "common metadata path probing"
fi

section "6. HTTPS CHECK"
if command -v curl >/dev/null 2>&1; then
    run_probe "5357/TCP" "HTTPAPI/TLS" "Test whether TLS is accepted on port 5357" \
        curl -vk --max-time 10 "https://${TARGET}:5357/"
else
    skip_probe "curl" "HTTPS check"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] HTTPAPI probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
printf "${YELLOW}[!] No exploitation or upload testing was performed.${RESET}\n"
