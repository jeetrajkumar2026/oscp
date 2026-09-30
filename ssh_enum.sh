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
PORT="${2:-22}"
USERNAME="${3:-root}"
OUTPUT_DIR="ssh_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/ssh_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '                  SSH ENUMERATION'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf "Usage: %s <target> [port] [username]\n" "$0"
    printf "Example: %s 192.168.80.40\n" "$0"
    printf "Example: %s 192.168.80.40 2222 admin\n" "$0"
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
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}SSH${RESET}\n"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    printf "${BLUE}[COMMAND]${RESET} ${CYAN}"
    printf '%q ' "${command[@]}"
    printf "${RESET}\n\n"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s/%s\n' "$port" "$protocol"
        printf 'SERVICE: SSH\n'
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

if ! command -v nmap >/dev/null 2>&1; then
    printf "${RED}[-] The 'nmap' command is not installed.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install nmap${RESET}\n"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
{
    printf 'SSH ENUMERATION\n'
    printf 'TARGET: %s\n' "$TARGET"
    printf 'DATE: %s\n' "$(date)"
} > "$LOG_FILE"
banner

printf "${BLUE}[TARGET]${RESET}  ${YELLOW}%s${RESET}\n" "$TARGET"
printf "${BLUE}[PORT]${RESET}    ${YELLOW}%s${RESET}\n" "$PORT"
printf "${BLUE}[USER]${RESET}    ${YELLOW}%s${RESET}\n" "$USERNAME"
printf "${BLUE}[OUTPUT]${RESET}  ${YELLOW}%s${RESET}\n" "$LOG_FILE"

section "1. SSH SERVICE DETECTION"
run_probe "TCP" "$PORT" "SSH banner and version detection" nmap -Pn -sV --version-intensity 5 -p "$PORT" "$TARGET"

section "2. HOST KEY COLLECTION"
run_probe "TCP" "$PORT" "Collect all SSH host keys (RSA/DSA/ECDSA/Ed25519)" ssh-keyscan -T 5 -p "$PORT" "$TARGET"
run_probe "TCP" "$PORT" "Collect host key fingerprints" nmap -Pn -p "$PORT" --script ssh-hostkey --script-args ssh_hostkey=full "$TARGET"

section "3. AUTHENTICATION METHODS"
run_probe "TCP" "$PORT" "Allowed authentication methods for user '$USERNAME'" nmap -Pn -p "$PORT" --script ssh-auth-methods --script-args "ssh.auth-user=$USERNAME" "$TARGET"
run_probe "TCP" "$PORT" "Verbose SSH handshake for user '$USERNAME'" ssh -v -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$PORT" "$USERNAME@$TARGET" true

section "4. LEGACY PROTOCOL CHECK"
run_probe "TCP" "$PORT" "Check whether SSH protocol version 1 is supported" nmap -Pn -p "$PORT" --script sshv1 "$TARGET"

section "5. ALGORITHM AND CIPHER AUDIT"
if command -v ssh-audit >/dev/null 2>&1; then
    run_probe "TCP" "$PORT" "Audit supported algorithms and ciphers" ssh-audit -p "$PORT" "$TARGET"
else
    printf "\n${YELLOW}[!] 'ssh-audit' is not installed. Skipping the algorithm audit.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install ssh-audit${RESET}\n"
fi

section "6. PUBLIC EXPLOIT SEARCH"
SSH_VERSION=$(grep -ioE 'openssh[ _-]?[0-9]+(\.[0-9]+)*' "$LOG_FILE" | head -1)
if [[ -z "$SSH_VERSION" ]]; then
    SSH_VERSION=$(grep -ioE 'dropbear[ _-]?[0-9]+(\.[0-9]+)*' "$LOG_FILE" | head -1)
fi
if [[ -n "$SSH_VERSION" ]] && command -v searchsploit >/dev/null 2>&1; then
    run_probe "TCP" "$PORT" "Search public exploits for '${SSH_VERSION}'" searchsploit "$SSH_VERSION"
else
    printf "\n${YELLOW}[!] No SSH version identified or 'searchsploit' not installed.${RESET}\n"
fi

section "SUGGESTED NEXT STEPS"
printf "${YELLOW}[!] If password authentication is allowed, brute-force it:${RESET}\n"
printf "    ${CYAN}hydra -l %s -P /usr/share/wordlists/rockyou.txt ssh://%s:%s -t 4${RESET}\n" "$USERNAME" "$TARGET" "$PORT"
printf "${YELLOW}[!] If valid credentials are found, connect with:${RESET}\n"
printf "    ${CYAN}ssh %s@%s -p %s${RESET}\n" "$USERNAME" "$TARGET" "$PORT"

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] SSH probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
