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
PORT="${2:-3306}"
DB_USER="${3:-root}"
DB_PASS="${4:-}"
OUTPUT_DIR="mysql_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/mysql_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '               MYSQL ENUMERATION'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf "Usage: %s <target> [port] [user] [password]\n" "$0"
    printf "Example: %s 192.168.80.40\n" "$0"
    printf "Example: %s 192.168.80.40 3306 root toor\n" "$0"
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
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}MySQL${RESET}\n"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    printf "${BLUE}[COMMAND]${RESET} ${CYAN}"
    printf '%q ' "${command[@]}"
    printf "${RESET}\n\n"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s/%s\n' "$port" "$protocol"
        printf 'SERVICE: MySQL\n'
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
    printf 'MYSQL ENUMERATION\n'
    printf 'TARGET: %s\n' "$TARGET"
    printf 'DATE: %s\n' "$(date)"
} > "$LOG_FILE"
banner

printf "${BLUE}[TARGET]${RESET}   ${YELLOW}%s${RESET}\n" "$TARGET"
printf "${BLUE}[PORT]${RESET}     ${YELLOW}%s${RESET}\n" "$PORT"
printf "${BLUE}[USER]${RESET}     ${YELLOW}%s${RESET}\n" "$DB_USER"
printf "${BLUE}[PASSWORD]${RESET} ${YELLOW}%s${RESET}\n" "${DB_PASS:-(empty)}"
printf "${BLUE}[OUTPUT]${RESET}   ${YELLOW}%s${RESET}\n" "$LOG_FILE"

section "1. MYSQL SERVICE DETECTION"
run_probe "TCP" "$PORT" "MySQL banner and version detection" nmap -Pn -sV --version-intensity 5 -p "$PORT" "$TARGET"

section "2. SERVER INFORMATION"
run_probe "TCP" "$PORT" "MySQL server information (protocol version, thread ID, capabilities)" nmap -Pn -p "$PORT" --script mysql-info "$TARGET"

section "3. CREDENTIAL CHECKS"
run_probe "TCP" "$PORT" "Check whether root or anonymous accounts use an empty password" nmap -Pn -p "$PORT" --script mysql-empty-password "$TARGET"
run_probe "TCP" "$PORT" "Enumerate valid MySQL usernames" nmap -Pn -p "$PORT" --script mysql-enum "$TARGET"

section "4. KNOWN VULNERABILITY CHECKS"
run_probe "TCP" "$PORT" "Check for the CVE-2012-2122 authentication bypass" nmap -Pn -p "$PORT" --script mysql-vuln-cve2012-2122 "$TARGET"

section "5. AUTHENTICATED ENUMERATION"
if ! command -v mysql >/dev/null 2>&1; then
    printf "\n${YELLOW}[!] The 'mysql' client is not installed.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install default-mysql-client${RESET}\n"
elif mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 -e "SELECT 1;" >/dev/null 2>&1; then
    printf "\n${GREEN}[+] Credentials accepted for user '%s'.${RESET}\n" "$DB_USER"
    run_probe "TCP" "$PORT" "Server version, current user and data directory" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SELECT VERSION(), CURRENT_USER(), @@hostname, @@datadir;"
    run_probe "TCP" "$PORT" "List all databases" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SHOW DATABASES;"
    run_probe "TCP" "$PORT" "List MySQL user accounts" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SELECT user, host FROM mysql.user;"
    run_probe "TCP" "$PORT" "List MySQL password hashes (MySQL 5.7+/MariaDB)" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SELECT user, host, authentication_string FROM mysql.user;"
    run_probe "TCP" "$PORT" "List MySQL password hashes (MySQL 5.6 and earlier)" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SELECT user, host, password FROM mysql.user;"
    run_probe "TCP" "$PORT" "List user privileges" mysql -h "$TARGET" -P "$PORT" -u "$DB_USER" --password="$DB_PASS" --connect-timeout=10 --batch -e "SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges;"
    run_probe "TCP" "$PORT" "Enumerate databases, users and variables via nmap" nmap -Pn -p "$PORT" --script mysql-databases,mysql-users,mysql-variables --script-args "mysqluser='$DB_USER',mysqlpass='$DB_PASS'" "$TARGET"
else
    printf "\n${YELLOW}[!] Credentials rejected for user '%s'.${RESET}\n" "$DB_USER"
    printf "Re-run with valid credentials: ${CYAN}%s %s %s <user> <password>${RESET}\n" "$0" "$TARGET" "$PORT"
fi

section "6. PUBLIC EXPLOIT SEARCH"
MARIADB_MATCH=$(grep -oiE '[0-9]+(\.[0-9]+)+-mariadb' "$LOG_FILE" | head -1)
SEARCH_TERM=""
if [[ -n "$MARIADB_MATCH" ]]; then
    SEARCH_TERM="MariaDB ${MARIADB_MATCH%-*}"
else
    MYSQL_MATCH=$(grep -oiE 'mysql[ -][0-9]+(\.[0-9]+)+' "$LOG_FILE" | head -1)
    [[ -n "$MYSQL_MATCH" ]] && SEARCH_TERM="$MYSQL_MATCH"
fi
if [[ -n "$SEARCH_TERM" ]] && command -v searchsploit >/dev/null 2>&1; then
    run_probe "TCP" "$PORT" "Search public exploits for '${SEARCH_TERM}'" searchsploit "$SEARCH_TERM"
else
    printf "\n${YELLOW}[!] No MySQL version identified or 'searchsploit' not installed.${RESET}\n"
fi

section "SUGGESTED NEXT STEPS"
printf "${YELLOW}[!] If credentials were rejected, brute-force them:${RESET}\n"
printf "    ${CYAN}hydra -l %s -P /usr/share/wordlists/rockyou.txt mysql://%s:%s -t 4${RESET}\n" "$DB_USER" "$TARGET" "$PORT"
printf "${YELLOW}[!] If valid credentials are found, connect manually:${RESET}\n"
printf "    ${CYAN}mysql -h %s -P %s -u <user> -p${RESET}\n" "$TARGET" "$PORT"

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] MySQL probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
