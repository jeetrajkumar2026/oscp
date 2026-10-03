#!/usr/bin/env bash
# Read-only Linux privilege-escalation inventory and CVE candidate checker.
# Version matches are leads only; distro vendors backport fixes.

set +e

log_file="${LOG_FILE:-$PWD/log.txt}"
exec > >(tee "$log_file") 2>&1

kernel=$(uname -r 2>/dev/null)
kernel_base=${kernel%%-*}
arch=$(uname -m 2>/dev/null)
if [ -r /etc/os-release ]; then . /etc/os-release; fi
ID=${ID:-unknown}
VERSION_ID=${VERSION_ID:-unknown}
NAME=${NAME:-unknown}

version_lt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]
}
version_ge() { ! version_lt "$1" "$2"; }
candidate() { printf '[CANDIDATE] %s\n' "$*"; }
not_candidate() { printf '[NO UPSTREAM MATCH] %s\n' "$*"; }

echo '=== Linux system inventory ==='
printf 'OS: %s %s (ID=%s, version=%s)\n' "$NAME" "${VERSION_CODENAME:-}" "$ID" "$VERSION_ID"
printf 'Kernel: %s (base=%s)\nArchitecture: %s\n' "$kernel" "$kernel_base" "$arch"
printf 'Kernel command line: '; cat /proc/cmdline 2>/dev/null

pkg_version=''
if command -v dpkg-query >/dev/null 2>&1; then
    pkg_version=$(dpkg-query -W -f='${Version}' "linux-image-$kernel" 2>/dev/null)
    [ -n "$pkg_version" ] || pkg_version=$(dpkg-query -W -f='${Version}' "linux-image-$kernel_base" 2>/dev/null)
elif command -v rpm >/dev/null 2>&1; then
    pkg_version=$(rpm -q --whatprovides "kernel-uname-r = $kernel" --qf '%{VERSION}-%{RELEASE}\n' 2>/dev/null | head -n 1)
fi
printf 'Kernel package version: %s\n' "${pkg_version:-not identified}"

echo
echo '=== Common Linux kernel LPE CVE heuristics ==='
echo 'These use upstream version ranges; vendor backports and configuration can change the result.'

if version_ge "$kernel_base" '3.18' && version_lt "$kernel_base" '4.5'; then
    candidate 'CVE-2017-16995 eBPF verifier: NVD lists Linux through 4.4; check CONFIG_BPF_SYSCALL, unprivileged BPF policy, and vendor package advisories.'
else
    not_candidate 'CVE-2017-16995 eBPF verifier: outside the upstream affected range (through 4.4).'
fi

if version_lt "$kernel_base" '4.8.3'; then
    case "$kernel_base" in
        4.4.*) if version_ge "$kernel_base" '4.4.26'; then not_candidate 'CVE-2016-5195 Dirty COW: upstream 4.4 fix threshold reached.'; else candidate 'CVE-2016-5195 Dirty COW: upstream range match; check vendor package advisories.'; fi ;;
        4.7.*) if version_ge "$kernel_base" '4.7.9'; then not_candidate 'CVE-2016-5195 Dirty COW: upstream 4.7 fix threshold reached.'; else candidate 'CVE-2016-5195 Dirty COW: upstream range match; check vendor package advisories.'; fi ;;
        *) candidate 'CVE-2016-5195 Dirty COW: upstream range match; check vendor package advisories.' ;;
    esac
else
    not_candidate 'CVE-2016-5195 Dirty COW: kernel is at or beyond upstream 4.8.3 threshold.'
fi

if version_lt "$kernel_base" '5.1.17'; then
    candidate 'CVE-2019-13272 PTRACE_TRACEME: upstream range match; stable distro kernels may contain backports.'
else
    not_candidate 'CVE-2019-13272 PTRACE_TRACEME: kernel is at or beyond upstream 5.1.17 threshold.'
fi

if version_ge "$kernel_base" '5.8.0' && version_lt "$kernel_base" '5.17.0'; then
    case "$kernel_base" in
        5.10.*) if version_ge "$kernel_base" '5.10.102'; then not_candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.10 fix threshold reached.'; else candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.10 range match; check vendor package advisories.'; fi ;;
        5.15.*) if version_ge "$kernel_base" '5.15.25'; then not_candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.15 fix threshold reached.'; else candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.15 range match; check vendor package advisories.'; fi ;;
        5.16.*) if version_ge "$kernel_base" '5.16.11'; then not_candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.16 fix threshold reached.'; else candidate 'CVE-2022-0847 Dirty Pipe: upstream 5.16 range match; check vendor package advisories.'; fi ;;
        *) candidate 'CVE-2022-0847 Dirty Pipe: upstream range match; check vendor package advisories.' ;;
    esac
else
    not_candidate 'CVE-2022-0847 Dirty Pipe: kernel is outside the upstream 5.8–5.16 range.'
fi

if [ "$ID" = ubuntu ] && [ "$VERSION_ID" = '20.04' ]; then
    echo '[REVIEW] Ubuntu Focal OverlayFS candidates: CVE-2021-3493, CVE-2023-2640, CVE-2023-32629.'
    if [ -n "$pkg_version" ] && command -v dpkg >/dev/null 2>&1; then
        if dpkg --compare-versions "$pkg_version" lt '5.4.0-72.80'; then
            candidate 'CVE-2021-3493: installed Focal package is older than 5.4.0-72.80; verify overlayfs/user-namespace prerequisites.'
        else
            echo '[CHECK VENDOR STATUS] CVE-2021-3493: compare this exact package with Canonical advisories; package branches differ.'
        fi
    else
        echo '[CHECK VENDOR STATUS] CVE-2021-3493: package version not identified.'
    fi
    echo '[CHECK VENDOR STATUS] CVE-2023-2640 / CVE-2023-32629: Ubuntu-specific OverlayFS issues; verify exact kernel flavor/package and vendor status.'
fi

echo
echo '=== Kernel configuration and namespace indicators ==='
config_file="/boot/config-$kernel"
if [ -r "$config_file" ]; then
    grep -E '^(CONFIG_USER_NS|CONFIG_OVERLAY_FS|CONFIG_BPF|CONFIG_BPF_SYSCALL)=' "$config_file"
elif [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
    zcat /proc/config.gz | grep -E '^(CONFIG_USER_NS|CONFIG_OVERLAY_FS|CONFIG_BPF|CONFIG_BPF_SYSCALL)='
else
    echo 'Kernel config unavailable in standard locations.'
fi
for knob in kernel.unprivileged_userns_clone user.max_user_namespaces; do
    if command -v sysctl >/dev/null 2>&1; then sysctl "$knob" 2>/dev/null; fi
done

echo
echo '=== OSCP-note package checks (not kernel CVEs) ==='
for bin in sudo pkexec; do
    path=$(command -v "$bin" 2>/dev/null)
    if [ -n "$path" ]; then
        ls -l "$path" 2>/dev/null
    else
        printf '%s: not found in PATH\n' "$bin"
    fi
done
if command -v sudo >/dev/null 2>&1; then sudo --version 2>/dev/null | head -n 1; fi
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${binary:Package} ${Version}\n' sudo policykit-1 polkitd 2>/dev/null
elif command -v rpm >/dev/null 2>&1; then
    rpm -q sudo polkit 2>/dev/null
fi
echo 'Notes-vault CVEs to assess against exact vendor package revisions:'
echo '  sudo: CVE-2021-3156 (Baron Samedit), CVE-2019-14287, CVE-2019-18634 (pwfeedback configuration matters).'
echo '  pkexec/polkit: CVE-2021-4034 (PwnKit), CVE-2021-3560.'
echo 'These are package/configuration CVEs, not kernel CVEs; version strings alone are not a verdict.'
echo 'Do not infer vulnerable status from upstream version alone; vendor package revisions may backport fixes.'

echo
echo '=== SearchSploit commands to run separately on Kali ==='
printf 'searchsploit -t "Linux Kernel %s"\n' "$kernel_base"
printf 'searchsploit CVE-2016-5195\nsearchsploit CVE-2017-16995\nsearchsploit CVE-2019-13272\nsearchsploit CVE-2022-0847\n'
printf 'searchsploit CVE-2021-3156\nsearchsploit CVE-2019-14287\nsearchsploit CVE-2019-18634\nsearchsploit CVE-2021-4034\nsearchsploit CVE-2021-3560\n'
if [ "$ID" = ubuntu ]; then printf 'searchsploit CVE-2021-3493\nsearchsploit CVE-2023-2640\nsearchsploit CVE-2023-32629\n'; fi

echo
printf 'Log saved to: %s\n' "$log_file"
