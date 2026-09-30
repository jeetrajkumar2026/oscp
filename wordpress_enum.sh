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

BASE_URL="${1:-}"
OUTPUT_DIR="wordpress_enum_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${OUTPUT_DIR}/wordpress_results.txt"

banner() {
    printf "${CYAN}"
    printf '%s\n' '============================================================'
    printf '%s\n' '               WORDPRESS ENUMERATION'
    printf '%s\n' '============================================================'
    printf "${RESET}"
}

usage() {
    printf "Usage: %s <base-url>\n" "$0"
    printf "Example: %s http://192.168.80.40\n" "$0"
    printf "Example: %s http://192.168.80.40/wordpress\n" "$0"
    printf "Example: %s http://192.168.80.40:8080/blog\n" "$0"
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
    printf "${BLUE}[SERVICE]${RESET} ${GREEN}WordPress${RESET}\n"
    printf "${BLUE}[PROBE]${RESET}   ${WHITE}%s${RESET}\n" "$purpose"
    printf "${BLUE}[COMMAND]${RESET} ${CYAN}"
    printf '%q ' "${command[@]}"
    printf "${RESET}\n\n"

    {
        printf '\n============================================================\n'
        printf 'PORT: %s/%s\n' "$port" "$protocol"
        printf 'SERVICE: WordPress\n'
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

if [[ -z "$BASE_URL" ]]; then
    usage
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}[-] The 'curl' command is not installed.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install curl${RESET}\n"
    exit 1
fi

if [[ "$BASE_URL" != http://* && "$BASE_URL" != https://* ]]; then
    BASE_URL="http://${BASE_URL}"
fi
BASE_URL="${BASE_URL%/}"

WP_PORT=$(printf '%s' "$BASE_URL" | grep -oE ':[0-9]+' | tail -1 | tr -d ':')
if [[ -z "$WP_PORT" ]]; then
    if [[ "$BASE_URL" == https://* ]]; then
        WP_PORT=443
    else
        WP_PORT=80
    fi
fi

mkdir -p "$OUTPUT_DIR"
{
    printf 'WORDPRESS ENUMERATION\n'
    printf 'TARGET: %s\n' "$BASE_URL"
    printf 'DATE: %s\n' "$(date)"
} > "$LOG_FILE"
banner

printf "${BLUE}[TARGET]${RESET}  ${YELLOW}%s${RESET}\n" "$BASE_URL"
printf "${BLUE}[PORT]${RESET}    ${YELLOW}%s${RESET}\n" "$WP_PORT"
printf "${BLUE}[OUTPUT]${RESET}  ${YELLOW}%s${RESET}\n" "$LOG_FILE"

section "1. WORDPRESS INSTALLATION DETECTION"
run_probe "TCP" "$WP_PORT" "Check for the WordPress login page" curl -s -m 15 -o /dev/null -w "%{http_code}\n" "$BASE_URL/wp-login.php"
run_probe "TCP" "$WP_PORT" "Check for the wp-content directory" curl -s -m 15 -o /dev/null -w "%{http_code}\n" "$BASE_URL/wp-content/"
run_probe "TCP" "$WP_PORT" "Look for WordPress content references on the homepage" bash -c "curl -s -m 15 -L '$BASE_URL/' | grep -ioE 'wp-content/(plugins|themes|uploads)/[a-z0-9._-]+' | sort -u | head -20"

section "2. VERSION DISCLOSURE"
run_probe "TCP" "$WP_PORT" "Read the version from readme.html" bash -c "curl -s -m 15 '$BASE_URL/readme.html' | grep -i -m 1 'Version'"
run_probe "TCP" "$WP_PORT" "Read the version from the meta generator tag" bash -c "curl -s -m 15 -L '$BASE_URL/' | grep -io '<meta name=\"generator\"[^>]*>'"
run_probe "TCP" "$WP_PORT" "Read the version from the RSS feed generator" bash -c "curl -s -m 15 '$BASE_URL/feed/' | grep -io '<generator>[^<]*</generator>'"

section "3. USER ENUMERATION"
run_probe "TCP" "$WP_PORT" "Enumerate users via the REST API" curl -s -m 15 "$BASE_URL/wp-json/wp/v2/users"
for i in 1 2 3 4 5; do
    run_probe "TCP" "$WP_PORT" "Enumerate user via ?author=$i redirect" curl -s -m 15 -o /dev/null -w "%{http_code} %{redirect_url}\n" "$BASE_URL/?author=$i"
done

section "4. PLUGIN AND THEME DISCOVERY"
HOMEPAGE_HTML=$(curl -s -m 15 -L "$BASE_URL/")
PLUGINS=$(printf '%s\n' "$HOMEPAGE_HTML" | grep -ioE 'wp-content/plugins/[a-z0-9._-]+' | cut -d/ -f3 | sort -u)
THEMES=$(printf '%s\n' "$HOMEPAGE_HTML" | grep -ioE 'wp-content/themes/[a-z0-9._-]+' | cut -d/ -f3 | sort -u)

printf "\n${BLUE}[PLUGINS]${RESET} ${YELLOW}%s${RESET}\n" "${PLUGINS:-(none found)}"
printf "${BLUE}[THEMES]${RESET}  ${YELLOW}%s${RESET}\n" "${THEMES:-(none found)}"

{
    printf '\n============================================================\n'
    printf 'DISCOVERED PLUGINS:\n%s\n' "${PLUGINS:-(none found)}"
    printf '\n============================================================\n'
    printf 'DISCOVERED THEMES:\n%s\n' "${THEMES:-(none found)}"
} >> "$LOG_FILE"

if [[ -n "$PLUGINS" ]]; then
    for plugin in $PLUGINS; do
        run_probe "TCP" "$WP_PORT" "Plugin '$plugin' readme.txt (name and version)" bash -c "curl -s -m 15 '$BASE_URL/wp-content/plugins/$plugin/readme.txt' | head -12"
    done
fi

if [[ -n "$THEMES" ]]; then
    for theme in $THEMES; do
        run_probe "TCP" "$WP_PORT" "Theme '$theme' style.css header (name and version)" bash -c "curl -s -m 15 '$BASE_URL/wp-content/themes/$theme/style.css' | head -15"
    done
fi

section "5. SENSITIVE FILE CHECKS"
run_probe "TCP" "$WP_PORT" "Confirm that xmlrpc.php is reachable" curl -s -m 15 "$BASE_URL/xmlrpc.php"
for path in wp-config.php.bak wp-config.php.save wp-config.php.txt wp-config.php~ .env debug.log wp-content/debug.log wp-content/uploads/ wp-content/backup/ backup.sql db.sql; do
    run_probe "TCP" "$WP_PORT" "Check for '$path'" curl -s -m 15 -o /dev/null -w "%{http_code}\n" "$BASE_URL/$path"
done

section "6. WPSCAN"
if command -v wpscan >/dev/null 2>&1; then
    run_probe "TCP" "$WP_PORT" "WPScan enumeration (users, plugins, themes, config backups)" wpscan --url "$BASE_URL" --enumerate u,ap,at,cb
else
    printf "\n${YELLOW}[!] 'wpscan' is not installed. Skipping the WPScan enumeration.${RESET}\n"
    printf "Install it with: ${CYAN}sudo apt install wpscan${RESET}\n"
fi

section "7. PUBLIC EXPLOIT SEARCH"
WP_VERSION=$(grep -ioE 'WordPress [0-9]+(\.[0-9]+)+' "$LOG_FILE" | head -1)
if [[ -z "$WP_VERSION" ]]; then
    README_NUM=$(grep -ioE 'Version [0-9]+(\.[0-9]+)+' "$LOG_FILE" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
    [[ -n "$README_NUM" ]] && WP_VERSION="WordPress $README_NUM"
fi
if [[ -n "$WP_VERSION" ]] && command -v searchsploit >/dev/null 2>&1; then
    run_probe "TCP" "$WP_PORT" "Search public exploits for '${WP_VERSION}'" searchsploit "$WP_VERSION"
else
    printf "\n${YELLOW}[!] No WordPress version identified or 'searchsploit' not installed.${RESET}\n"
fi

if command -v searchsploit >/dev/null 2>&1 && [[ -n "$PLUGINS" ]]; then
    for plugin in $PLUGINS; do
        run_probe "TCP" "$WP_PORT" "Search public exploits for plugin '$plugin'" searchsploit "wordpress $plugin"
    done
fi

section "SUGGESTED NEXT STEPS"
printf "${YELLOW}[!] If users were identified, brute-force their passwords:${RESET}\n"
printf "    ${CYAN}wpscan --url %s --usernames <user-file> --passwords /usr/share/wordlists/rockyou.txt${RESET}\n" "$BASE_URL"
printf "${YELLOW}[!] Investigate any outdated plugin or theme listed above.${RESET}\n"

section "ENUMERATION COMPLETE"
printf "${GREEN}[+] WordPress probes completed.${RESET}\n"
printf "${GREEN}[+] Results saved to: %s${RESET}\n" "$LOG_FILE"
