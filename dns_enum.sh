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
DOMAIN="${2:-}"
OUTPUT_DIR="dns_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/dns_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                  DNS ENUMERATION'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf "Usage: %s <DNS-server> [domain]\n" "$0"
    printf "Example: %s 192.168.80.40 internal\n" "$0"
}

section() {
    printf "\n${MAGENTA}============================================================${RESET}\n"
    printf "${WHITE}%s${RESET}\n" "$1"
    printf "${MAGENTA}============================================================${RESET}\n"
}

run_probe() {
    local protocol="$1"
    local port="$2"
    local purpose="$3"
    shift 3
    local command=("$@")

    printf "\n${BLUE}[PORT]${RESET}    ${YELLOW}%s/%s${RESET}\n" "$port" "$protocol"
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}DNS${RESET}\n"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    printf "${BLUE}[COMMAND]${RESET} ${CYAN}"
    printf '%q ' "${command[@]}"
    printf "${RESET}\n\n"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s/%s\n' "$port" "$protocol"
        printf 'SERVICE: DNS\n'
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
        printf "${RED}[-] Probe failed with status %s${RESET}\n" "$status"
    fi
}

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! command -v dig >/dev/null 2>&1; then
    printf "${RED}[-] The 'dig' command is not installed.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install dnsutils${RESET}\n"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
banner

printf "${BLUE}[TARGET]${RESET}  ${YELLOW}%s${RESET}\n" "$TARGET"
printf "${BLUE}[DOMAIN]${RESET}  ${YELLOW}%s${RESET}\n" "${DOMAIN:-not supplied}"
printf "${BLUE}[OUTPUT]${RESET}  ${YELLOW}%s${RESET}\n" "$LOG_FILE"

section "1. DNS SERVER CONNECTIVITY"
run_probe "UDP" "53" "Basic UDP DNS response" dig +time=5 +tries=1 @"$TARGET" . NS
run_probe "TCP" "53" "Basic TCP DNS response" dig +tcp +time=5 +tries=1 @"$TARGET" . NS

section "2. SERVER INFORMATION"
run_probe "UDP" "53" "DNS server version disclosure" dig +time=5 +tries=1 @"$TARGET" version.bind CHAOS TXT
run_probe "UDP" "53" "DNS server identity disclosure" dig +time=5 +tries=1 @"$TARGET" hostname.bind CHAOS TXT
run_probe "UDP" "53" "DNS server ID disclosure" dig +time=5 +tries=1 @"$TARGET" id.server CHAOS TXT

section "3. RECURSION CHECK"
run_probe "UDP" "53" "Check whether recursive queries are permitted" dig +time=5 +tries=1 @"$TARGET" example.com A

section "4. REVERSE LOOKUP"
run_probe "UDP" "53" "Reverse DNS lookup for target address" dig +time=5 +tries=1 @"$TARGET" -x "$TARGET"

if [[ -n "$DOMAIN" ]]; then
    section "5. DOMAIN RECORDS"
    run_probe "UDP" "53" "Start of Authority record" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" SOA
    run_probe "TCP" "53" "Start of Authority record over TCP" dig +tcp +time=5 +tries=1 @"$TARGET" "$DOMAIN" SOA
    run_probe "UDP" "53" "Authoritative name servers" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" NS
    run_probe "UDP" "53" "IPv4 address records" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" A
    run_probe "UDP" "53" "IPv6 address records" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" AAAA
    run_probe "UDP" "53" "Mail server records" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" MX
    run_probe "UDP" "53" "Domain text records" dig +time=5 +tries=1 @"$TARGET" "$DOMAIN" TXT

    section "6. WINDOWS AND ACTIVE DIRECTORY RECORDS"
    run_probe "UDP" "53" "LDAP domain controller records" dig +time=5 +tries=1 @"$TARGET" "_ldap._tcp.dc._msdcs.${DOMAIN}" SRV
    run_probe "UDP" "53" "Domain LDAP records" dig +time=5 +tries=1 @"$TARGET" "_ldap._tcp.${DOMAIN}" SRV
    run_probe "UDP" "53" "Kerberos TCP records" dig +time=5 +tries=1 @"$TARGET" "_kerberos._tcp.${DOMAIN}" SRV
    run_probe "UDP" "53" "Kerberos UDP records" dig +time=5 +tries=1 @"$TARGET" "_kerberos._udp.${DOMAIN}" SRV
    run_probe "UDP" "53" "Global Catalog records" dig +time=5 +tries=1 @"$TARGET" "_gc._tcp.${DOMAIN}" SRV
    run_probe "UDP" "53" "Kerberos password-change records" dig +time=5 +tries=1 @"$TARGET" "_kpasswd._tcp.${DOMAIN}" SRV
else
    printf "\n${YELLOW}[!] No domain was provided.${RESET}\n"
    printf "Domain and Active Directory record checks were skipped.\n"
    printf "Example: ${CYAN}%s %s internal${RESET}\n" "$0" "$TARGET"
fi

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] DNS probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
