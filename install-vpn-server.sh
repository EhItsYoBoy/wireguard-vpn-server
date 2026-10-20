#!/usr/bin/env bash
# install-vpn-server.sh — runs the whole VPN server install in order, with checks:
#   1. setup-wireguard-server.sh  WireGuard, SSH hardening, commented iptables policy
#   2. setup-wgdashboard.sh       WGDashboard web UI (skip with SKIP_DASHBOARD=1)
#   3. setup-fail2ban.sh          Fail2ban for SSH (and the dashboard when reachable over the VPN)
#   4. health check               services, firewall, forwarding, persistence
#
# Steps that already completed are skipped, so it is safe to re-run after fixing a failure.
#
# Usage (on the server, in an interactive SSH session; do NOT pipe into bash, step 1 needs the keyboard):
#   curl -fsSLO https://raw.githubusercontent.com/EhItsYoBoy/wireguard-vpn-server/v0.4.1/install-vpn-server.sh
#   sudo bash install-vpn-server.sh [--config FILE] [--check] [--skip-dashboard]
#
#   --config FILE     shared KEY=VALUE settings for all steps (see vpn-server.conf.example)
#   --check           run only the health check
#   --skip-dashboard  install WireGuard and Fail2ban only
#
# The step scripts are used from this script's directory when present; otherwise they are
# downloaded from VPN_SCRIPTS_URL and verified against its SHA256SUMS before anything runs.
set -euo pipefail
umask 077

# Raw GitHub URL of the tagged release holding these scripts. Pin a tag or commit, never a branch.
VPN_SCRIPTS_URL="${VPN_SCRIPTS_URL:-https://raw.githubusercontent.com/EhItsYoBoy/wireguard-vpn-server/v0.4.1}"
# Optional: sha256 of the SHA256SUMS file itself, so a changed release is refused.
VPN_SCRIPTS_SHA256="${VPN_SCRIPTS_SHA256:-}"

STEP_SCRIPTS=(setup-wireguard-server.sh setup-wgdashboard.sh setup-fail2ban.sh)
WG_STATE=/root/wireguard-setup
SUITE_KEYS="PUBLIC_ENDPOINT WAN_IF VPN_IF ADMIN_CIDRS ADMIN_USER SSH_PORT SSH_FROM_VPN ALLOW_ROOT_LOGIN ALLOW_PASSWORD_LOGIN DNS_IPV4 VPN_NET VPN_PORT
 ALLOW_DHCP CLIENT_NAME CLIENT_PUBLIC_KEY DASHBOARD_VERSION DASHBOARD_ACCESS DASHBOARD_PORT DASHBOARD_USER
 DASHBOARD_ALLOWED_CIDRS IGNORE_IPS BANACTION SKIP_DASHBOARD WGDASHBOARD_DB WGDASHBOARD_PORT"
SKIP_DASHBOARD="${SKIP_DASHBOARD:-}"
CONFIG=""
CHECK_ONLY=0
SCRIPT_DIR=""

die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
banner() { printf '\n==================== %s ====================\n' "$*"; }

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; }

# Parse KEY=VALUE lines without executing them. Values already set in the environment win.
load_config() {
    local file=$1 line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || die "Bad line in $file: $line"
        key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
        value="${line#*=}"; value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"
        if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then value="${BASH_REMATCH[1]}"; fi
        [[ " ${SUITE_KEYS//$'\n'/ } " == *" $key "* ]] || die "Unknown setting in $file: $key"
        [[ -n "${!key:-}" ]] || printf -v "$key" '%s' "$value"
    done < "$file"
}

# ---------------------------------------------------------------------------
# Locate or download the step scripts
# ---------------------------------------------------------------------------
locate_scripts() {
    local here script missing=0
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
    for script in "${STEP_SCRIPTS[@]}"; do [[ -f "$here/$script" ]] || missing=1; done
    if (( ! missing )) && [[ -n "$here" ]]; then
        SCRIPT_DIR=$here
        echo "Using step scripts from $SCRIPT_DIR"
    else
        download_scripts
    fi
}

download_scripts() {
    local file listed
    [[ "$VPN_SCRIPTS_URL" != *CHANGE-ME* ]] || die 'Set VPN_SCRIPTS_URL (or edit it at the top of this script) to your raw GitHub release URL.'
    [[ "$VPN_SCRIPTS_URL" == https://* ]] || die 'VPN_SCRIPTS_URL must use https.'
    command -v curl >/dev/null || die 'curl is required to download the step scripts.'
    SCRIPT_DIR="/root/vpn-installer/$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -m 700 "$SCRIPT_DIR"
    echo "Downloading step scripts from $VPN_SCRIPTS_URL"
    for file in SHA256SUMS "${STEP_SCRIPTS[@]}"; do
        curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$SCRIPT_DIR/$file" "$VPN_SCRIPTS_URL/$file" \
            || die "Download failed: $VPN_SCRIPTS_URL/$file"
    done
    if [[ -n "$VPN_SCRIPTS_SHA256" ]]; then
        sha256sum --quiet --check <<< "$VPN_SCRIPTS_SHA256  $SCRIPT_DIR/SHA256SUMS" \
            || die 'SHA256SUMS does not match VPN_SCRIPTS_SHA256; refusing to run.'
    fi
    for file in "${STEP_SCRIPTS[@]}"; do
        listed=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$SCRIPT_DIR/SHA256SUMS")
        [[ -n "$listed" ]] || die "$file is not listed in SHA256SUMS."
    done
    (cd "$SCRIPT_DIR" && sha256sum --quiet --strict --ignore-missing --check SHA256SUMS) \
        || die 'Checksum verification failed; the downloaded scripts are incomplete or modified.'
    echo "Checksums verified. Scripts saved in $SCRIPT_DIR"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
    banner 'Preflight checks'
    local script free_kb
    [[ $EUID -eq 0 ]] || die 'Run with sudo.'
    [[ -t 0 ]] || die 'Run in an interactive terminal (download first; do not pipe this script into bash).'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == ubuntu ]] && dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04 \
        || die "Ubuntu 24.04 or newer is required (found ${PRETTY_NAME:-unknown})."
    echo "OS: $PRETTY_NAME"
    for script in "${STEP_SCRIPTS[@]}"; do
        # Files edited on Windows often gain CRLF line endings, which break bash.
        if grep -q $'\r' "$SCRIPT_DIR/$script"; then
            die "$script has Windows line endings. Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/$script"
        fi
        bash -n "$SCRIPT_DIR/$script" || die "$script has a syntax error."
    done
    if [[ -n "$CONFIG" ]]; then
        [[ -r "$CONFIG" ]] || die "Cannot read config file: $CONFIG"
        load_config "$CONFIG"
    fi
    free_kb=$(df --output=avail -k / | tail -n 1 | tr -d ' ')
    (( free_kb > 2 * 1024 * 1024 )) || die 'Less than 2 GB free on /.'
    getent ahostsv4 archive.ubuntu.com >/dev/null || die 'DNS lookup failed; check the network.'
    if [[ "$SKIP_DASHBOARD" != 1 ]]; then
        curl -fsS --max-time 15 -o /dev/null https://github.com || die 'Cannot reach github.com (needed for WGDashboard).'
        curl -fsS --max-time 15 -o /dev/null https://pypi.org/simple/ || die 'Cannot reach pypi.org (needed for WGDashboard).'
    fi
    if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" != yes ]]; then
        warn 'System clock is not NTP-synchronised.'
    fi
    echo 'Preflight passed.'
}

run_step() {
    local name=$1; shift
    banner "$name"
    "$@" || die "$name failed. Fix the problem above, then re-run this installer; completed steps are skipped."
}

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
FAILURES=0
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
note() { printf '  [WARN] %s\n' "$*"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi; }

health_check() {
    banner 'Health check'
    local rules sshd_config jails listen port
    FAILURES=0
    echo 'WireGuard'
    local vpn_if
    vpn_if=$(awk -F'"' '/^VPN_IF=/ { print $2 }' "$WG_STATE/install.env" 2>/dev/null)
    vpn_if=${vpn_if:-wg0}
    check "wg-quick@$vpn_if running" systemctl is-active "wg-quick@$vpn_if"
    check "wg-quick@$vpn_if starts at boot" systemctl is-enabled "wg-quick@$vpn_if"
    check "$vpn_if interface up" ip link show "$vpn_if" up
    check '/etc/wireguard is private (700)' test "$(stat -c %a /etc/wireguard 2>/dev/null)" = 700
    check "$vpn_if.conf is private (600)" test "$(stat -c %a "/etc/wireguard/$vpn_if.conf" 2>/dev/null)" = 600
    check 'IPv4 forwarding on' test "$(sysctl -n net.ipv4.ip_forward)" = 1
    check 'IPv6 disabled' test "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" = 1

    echo 'Firewall'
    rules=$(iptables -w -S 2>/dev/null || true)
    check 'INPUT policy DROP' grep -qx -- '-P INPUT DROP' <<< "$rules"
    check 'FORWARD policy DROP' grep -qx -- '-P FORWARD DROP' <<< "$rules"
    check 'SSH access rule present' grep -q 'vpn: SSH access' <<< "$rules"
    check 'NAT rule present' bash -c "iptables -w -t nat -S | grep -q 'vpn: NAT only VPN to WAN'"
    check 'netfilter-persistent enabled' systemctl is-enabled netfilter-persistent
    check 'saved rules include the VPN policy' grep -q 'vpn: Internet exit' /etc/iptables/rules.v4
    if grep -q 'f2b-' /etc/iptables/rules.v4 2>/dev/null; then
        fail 'saved rules contain Fail2ban chains (re-save with vpn-firewall-save)'
    else
        pass 'saved rules exclude Fail2ban chains'
    fi

    echo 'SSH'
    sshd_config=$(sshd -T 2>/dev/null || true)
    # Compare the live SSH policy with what was chosen at install time (default: both allowed).
    local want_root=yes want_password=yes
    want_root=$(awk -F'"' '/^ALLOW_ROOT_LOGIN=/ { print $2 }' "$WG_STATE/install.env" 2>/dev/null)
    want_password=$(awk -F'"' '/^ALLOW_PASSWORD_LOGIN=/ { print $2 }' "$WG_STATE/install.env" 2>/dev/null)
    check "root login = ${want_root:-yes} (as configured)" grep -qx "permitrootlogin ${want_root:-yes}" <<< "$sshd_config"
    check "password login = ${want_password:-yes} (as configured)" grep -qx "passwordauthentication ${want_password:-yes}" <<< "$sshd_config"
    [[ "${want_password:-yes}" == no ]] || note 'password login is enabled; Fail2ban is the brute-force protection'

    if systemctl cat wg-dashboard.service >/dev/null 2>&1; then
        echo 'WGDashboard'
        check 'wg-dashboard running' systemctl is-active wg-dashboard
        check 'wg-dashboard starts at boot' systemctl is-enabled wg-dashboard
        port=$(awk -F' *= *' '$1 == "app_port" { print $2 }' /opt/WGDashboard/src/wg-dashboard.ini 2>/dev/null | tr -d '\r')
        listen=$(ss -Hltn "sport = :${port:-10086}" | awk 'NR == 1 { print $4 }')
        if [[ -z "$listen" ]]; then
            fail 'dashboard is listening'
        elif [[ "$listen" == 0.0.0.0:* || "$listen" == \*:* || "$listen" == '[::]:'* ]]; then
            fail "dashboard listens on all interfaces ($listen)"
        else
            pass "dashboard listens on $listen only"
        fi
    fi

    echo 'Fail2ban'
    check 'fail2ban running' systemctl is-active fail2ban
    jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p')
    check 'sshd jail active' grep -qw sshd <<< "$jails"
    if grep -qw wgdashboard <<< "$jails"; then
        pass 'wgdashboard jail active'
        check 'dashboard login exporter running' systemctl is-active wgdashboard-fail2ban-export
    fi

    echo 'Maintenance'
    check 'unattended security upgrades enabled' grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades
    if [[ -e /var/run/reboot-required ]]; then note 'reboot required to finish updates; schedule one and re-run --check'; else pass 'no reboot pending'; fi

    if (( FAILURES )); then
        printf '\n%d check(s) failed.\n' "$FAILURES"
        return 1
    fi
    printf '\nAll checks passed.\n'
}

# ---------------------------------------------------------------------------
main() {
    local config_args=() log
    while (( $# )); do
        case $1 in
            --config) [[ $# -ge 2 ]] || die '--config needs a file'; CONFIG=$(realpath -- "$2"); shift ;;
            --check) CHECK_ONLY=1 ;;
            --skip-dashboard) SKIP_DASHBOARD=1 ;;
            -h|--help) usage; return 0 ;;
            *) usage >&2; return 2 ;;
        esac
        shift
    done
    [[ $EUID -eq 0 ]] || die 'Run with sudo.'
    if (( CHECK_ONLY )); then health_check; return; fi

    log="/root/vpn-install-$(date -u +%Y%m%dT%H%M%SZ).log"
    exec > >(tee -a "$log") 2>&1
    echo "Logging to $log"

    locate_scripts
    preflight
    [[ -z "$CONFIG" ]] || config_args=(--config "$CONFIG")

    # Step 1 is a first-install script; it refuses to run twice.
    if [[ -e "$WG_STATE/rollback/COMMITTED" ]]; then
        banner 'Step 1/3 WireGuard'; echo 'Already installed; skipping.'
    elif [[ -e "$WG_STATE" ]]; then
        die "$WG_STATE exists from an incomplete attempt. Inspect it (and $WG_STATE/rollback), move it aside, then re-run."
    else
        run_step 'Step 1/3 WireGuard' bash "$SCRIPT_DIR/setup-wireguard-server.sh" "${config_args[@]}"
    fi

    if [[ "$SKIP_DASHBOARD" == 1 ]]; then
        banner 'Step 2/3 WGDashboard'; echo 'Skipped (SKIP_DASHBOARD=1).'
    else
        run_step 'Step 2/3 WGDashboard' bash "$SCRIPT_DIR/setup-wgdashboard.sh" "${config_args[@]}"
    fi

    run_step 'Step 3/3 Fail2ban' env ${SKIP_DASHBOARD:+SKIP_DASHBOARD=$SKIP_DASHBOARD} \
        bash "$SCRIPT_DIR/setup-fail2ban.sh" --apply "${config_args[@]}"

    health_check || true
    banner 'Done'
    cat <<EOF
Log: $log
Next steps:
  * Open UDP $(awk -F'"' '/^VPN_PORT=/ { print $2 }' "$WG_STATE/install.env" 2>/dev/null || echo 51820) in the cloud provider's firewall.
  * Copy client profiles from $WG_STATE/clients securely, then delete the server copies.
  * Reboot in a maintenance window, then run: sudo bash $0 --check
EOF
}

main "$@"
