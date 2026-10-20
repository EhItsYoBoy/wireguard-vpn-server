#!/usr/bin/env bash
# setup-wgdashboard.sh — step 2 of 3 (see install-vpn-server.sh)
#
# Installs a pinned WGDashboard release for the wg0 server created by setup-wireguard-server.sh,
# preseeds the admin credentials (upstream defaults to admin/admin and a first-run wizard), and
# runs it as a systemd service. Safe to re-run: it reconfigures an existing install in place.
#
# Access modes (DASHBOARD_ACCESS):
#   ssh-tunnel  (default) listen on 127.0.0.1 only. Reach it from your workstation with
#               ssh -N -L 10086:127.0.0.1:10086 <admin>@<server>  then browse http://127.0.0.1:10086
#   vpn         listen on the VPN server address (e.g. 10.77.0.1). iptables admits only
#               DASHBOARD_ALLOWED_CIDRS arriving on wg0, and Fail2ban can ban password guessers.
#
# Usage: sudo bash setup-wgdashboard.sh [--config FILE] [--reset-password]
# The password comes from DASHBOARD_PASSWORD in the environment or a hidden prompt; leave the
# prompt blank to generate one, saved to /root/wgdashboard-setup/credentials. It is never printed.
set -euo pipefail
umask 077

DASHBOARD_VERSION="${DASHBOARD_VERSION:-}"             # Release tag to install; default below
DASHBOARD_ACCESS="${DASHBOARD_ACCESS:-}"               # ssh-tunnel | vpn
DASHBOARD_PORT="${DASHBOARD_PORT:-}"                   # TCP port; default 10086
DASHBOARD_USER="${DASHBOARD_USER:-}"                   # Admin username; default admin
DASHBOARD_ALLOWED_CIDRS="${DASHBOARD_ALLOWED_CIDRS:-}" # vpn mode: VPN addresses allowed in; default the whole VPN_NET
DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-}"           # Environment only; never put it in the config file
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
DNS_IPV4="${DNS_IPV4:-}"
VPN_NET="${VPN_NET:-}"
SERVER_IP="${SERVER_IP:-}"
VPN_IF="${VPN_IF:-}"

DEFAULT_VERSION="v4.3.3"   # Latest stable on 2026-10-20. Check upstream release notes before raising it.
REPO_URL="https://github.com/WGDashboard/WGDashboard.git"
INSTALL_DIR="/opt/WGDashboard"
SRC="$INSTALL_DIR/src"
INI="$SRC/wg-dashboard.ini"
SERVICE="wg-dashboard.service"
STATE="/root/wgdashboard-setup"
WG_INSTALL_ENV="/root/wireguard-setup/install.env"
FIREWALL_COMMENT="vpn: WGDashboard from VPN"
SUITE_KEYS="PUBLIC_ENDPOINT WAN_IF ADMIN_CIDRS ADMIN_USER SSH_PORT SSH_FROM_VPN ALLOW_ROOT_LOGIN ALLOW_PASSWORD_LOGIN DNS_IPV4 VPN_NET VPN_PORT
 ALLOW_DHCP CLIENT_NAME CLIENT_PUBLIC_KEY DASHBOARD_VERSION DASHBOARD_ACCESS DASHBOARD_PORT DASHBOARD_USER
 DASHBOARD_ALLOWED_CIDRS IGNORE_IPS BANACTION SKIP_DASHBOARD WGDASHBOARD_DB WGDASHBOARD_PORT"
RESET_PASSWORD=0
GENERATED_PASSWORD=0

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
step() { printf '\n==> %s\n' "$*"; }

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"
}

# Parse KEY=VALUE lines without executing them. Values already set in the environment win.
# strict=1 rejects keys outside the allowed list; strict=0 silently skips them.
load_config() {
    local file=$1 allowed=$2 strict=$3 line key value
    [[ -r "$file" ]] || die "Cannot read config file: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || die "Bad line in $file: $line"
        key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
        value="${line#*=}"; value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"
        if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then value="${BASH_REMATCH[1]}"; fi
        if [[ " ${allowed//$'\n'/ } " != *" $key "* ]]; then
            (( strict )) && die "Unknown setting in $file: $key"
            continue
        fi
        [[ -n "${!key:-}" ]] || printf -v "$key" '%s' "$value"
    done < "$file"
}

host_check() {
    [[ $EUID -eq 0 ]] || die 'Run using sudo bash.'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == ubuntu ]] && dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04 \
        || die 'Supported target: Ubuntu 24.04 LTS or newer.'
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null \
        || die 'WGDashboard needs Python 3.12 or newer.'
    [[ -s /etc/wireguard/wg0.conf ]] || die 'Run setup-wireguard-server.sh first (/etc/wireguard/wg0.conf missing).'
    systemctl is-active --quiet wg-quick@wg0 || die 'wg-quick@wg0 is not running.'
}

collect_settings() {
    [[ ! -r "$WG_INSTALL_ENV" ]] \
        || load_config "$WG_INSTALL_ENV" "PUBLIC_ENDPOINT DNS_IPV4 VPN_NET SERVER_IP VPN_IF" 0
    DASHBOARD_VERSION=${DASHBOARD_VERSION:-$DEFAULT_VERSION}
    DASHBOARD_ACCESS=${DASHBOARD_ACCESS:-ssh-tunnel}
    DASHBOARD_PORT=${DASHBOARD_PORT:-10086}
    DASHBOARD_USER=${DASHBOARD_USER:-admin}
    VPN_IF=${VPN_IF:-wg0}
    DNS_IPV4=${DNS_IPV4:-1.1.1.1}
    if [[ -z "$VPN_NET" || -z "$SERVER_IP" ]]; then
        # Fall back to the live interface address, e.g. 10.77.0.1/24.
        local address
        address=$(ip -4 -o address show dev "$VPN_IF" | awk 'NR == 1 { print $4 }')
        [[ -n "$address" ]] || die "Cannot read the $VPN_IF address; set VPN_NET and SERVER_IP."
        SERVER_IP=${SERVER_IP:-${address%/*}}
        VPN_NET=${VPN_NET:-$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$address")}
    fi
    DASHBOARD_ALLOWED_CIDRS=${DASHBOARD_ALLOWED_CIDRS:-$VPN_NET}
    [[ -n "$PUBLIC_ENDPOINT" ]] || die 'PUBLIC_ENDPOINT is unknown; set it in the config file.'

    [[ "$DASHBOARD_VERSION" =~ ^v[0-9]+(\.[0-9]+)+$ ]] || die "Invalid DASHBOARD_VERSION: $DASHBOARD_VERSION"
    [[ "$DASHBOARD_ACCESS" == ssh-tunnel || "$DASHBOARD_ACCESS" == vpn ]] || die 'DASHBOARD_ACCESS must be ssh-tunnel or vpn.'
    [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] && (( DASHBOARD_PORT >= 1 && DASHBOARD_PORT <= 65535 )) \
        || die "Invalid DASHBOARD_PORT: $DASHBOARD_PORT"
    [[ "$DASHBOARD_USER" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || die 'DASHBOARD_USER may use letters, digits and _ . @ - only.'
    [[ "$PUBLIC_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid PUBLIC_ENDPOINT: $PUBLIC_ENDPOINT"
    DASHBOARD_ALLOWED_CIDRS=$(python3 - "$DASHBOARD_ALLOWED_CIDRS" "$VPN_NET" "$SERVER_IP" "$DNS_IPV4" <<'PY'
import ipaddress as ip, sys
allowed, net, server, dns = sys.argv[1:]
n = ip.IPv4Network(net)
ip.IPv4Address(dns)
if ip.IPv4Address(server) not in n:
    sys.exit(f'SERVER_IP {server} is outside VPN_NET {net}')
out = []
for item in allowed.replace(',', ' ').split():
    a = ip.IPv4Network(item, strict=False)
    if not a.subnet_of(n):
        sys.exit(f'DASHBOARD_ALLOWED_CIDRS entry {a} is outside VPN_NET {net}')
    out.append(str(a))
if not out:
    sys.exit('DASHBOARD_ALLOWED_CIDRS is empty')
print(' '.join(out))
PY
    ) || die 'Invalid address settings (see message above).'
    if [[ "$DASHBOARD_ACCESS" == vpn ]]; then LISTEN_IP=$SERVER_IP; else LISTEN_IP=127.0.0.1; fi
}

# Returns success when the existing ini already holds a real (bcrypt) password and the wizard is off.
password_already_set() {
    [[ -r "$INI" ]] || return 1
    python3 - "$INI" <<'PY'
import configparser, sys
c = configparser.RawConfigParser()
c.read(sys.argv[1])
ok = c.get('Account', 'password', fallback='').startswith('$2') and \
     c.get('Other', 'welcome_session', fallback='true').lower() in ('false', '0', 'no', 'off')
sys.exit(0 if ok else 1)
PY
}

choose_password() {
    if (( ! RESET_PASSWORD )) && password_already_set; then
        echo 'Keeping the existing dashboard password (use --reset-password to change it).'
        DASHBOARD_PASSWORD=""
        return
    fi
    if [[ -z "$DASHBOARD_PASSWORD" ]]; then
        [[ -t 0 ]] || die 'Set DASHBOARD_PASSWORD or run interactively to choose the dashboard password.'
        local again
        read -r -s -p "Dashboard password for '$DASHBOARD_USER' (blank = generate): " DASHBOARD_PASSWORD; echo
        if [[ -n "$DASHBOARD_PASSWORD" ]]; then
            read -r -s -p 'Repeat password: ' again; echo
            [[ "$DASHBOARD_PASSWORD" == "$again" ]] || die 'Passwords do not match.'
        fi
    fi
    if [[ -z "$DASHBOARD_PASSWORD" ]]; then
        DASHBOARD_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
        GENERATED_PASSWORD=1
    fi
    (( ${#DASHBOARD_PASSWORD} >= 12 )) || die 'Use a dashboard password of at least 12 characters.'
}

install_packages() {
    step 'Installing packages'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # Everything upstream's wgd.sh would otherwise apt-install itself, plus git and curl.
    apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y \
        git curl python3-venv python3-pip net-tools iputils-ping wireguard-tools
}

fetch_release() {
    step "Fetching WGDashboard $DASHBOARD_VERSION"
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        local current
        current=$(git -C "$INSTALL_DIR" describe --tags --exact-match 2>/dev/null || echo unknown)
        [[ "$current" == "$DASHBOARD_VERSION" ]] \
            || die "$INSTALL_DIR holds $current, not $DASHBOARD_VERSION. Upgrade deliberately (cd $SRC && ./wgd.sh update) or set DASHBOARD_VERSION=$current."
        echo "Already at $current."
    else
        [[ ! -e "$INSTALL_DIR" ]] || die "$INSTALL_DIR exists but is not a git checkout; move it aside first."
        git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$DASHBOARD_VERSION" "$REPO_URL" "$INSTALL_DIR"
    fi
    # The install holds the dashboard database, credentials hash and generated peer keys.
    chmod 700 "$INSTALL_DIR"
    chmod 700 "$SRC/wgd.sh"
}

venv_ready() {
    [[ -x "$SRC/venv/bin/python3" ]] && "$SRC/venv/bin/python3" -c 'import flask, gunicorn, bcrypt, sqlalchemy' 2>/dev/null
}

install_dashboard() {
    if venv_ready; then
        echo 'Python environment already installed.'
    else
        step 'Running upstream installer (wgd.sh install; needs Internet access to PyPI)'
        # wgd.sh asks which PyPI mirror to use and auto-picks after 15 s; answer 1 = pypi.org.
        (cd "$SRC" && echo 1 | ./wgd.sh install) || true
        # wgd.sh does not fail when pip fails, so verify the result directly.
        venv_ready || { tail -n 30 "$SRC/log/install.txt" >&2 2>/dev/null || true; die 'WGDashboard Python dependencies failed to install.'; }
    fi
    # wgd.sh runs 'chmod -R 755 /etc/wireguard', exposing the server private key. Restore it.
    chmod 700 /etc/wireguard
    find /etc/wireguard -mindepth 1 -type d -exec chmod 700 {} +
    find /etc/wireguard -type f -exec chmod 600 {} +
}

write_dashboard_config() {
    step "Writing $INI"
    systemctl stop "$SERVICE" 2>/dev/null || true
    # Missing keys are filled with upstream defaults on first start; existing values are kept.
    # The code is passed with -c so stdin can carry the password (never on a command line).
    local writer
    writer=$(cat <<'PY'
import configparser, os, sys
import bcrypt
ini, user, listen_ip, port, endpoint, dns = sys.argv[1:]
password = sys.stdin.read()
c = configparser.RawConfigParser()
c.read(ini)
def put(section, key, value):
    if not c.has_section(section):
        c.add_section(section)
    c.set(section, key, value)
put('Account', 'username', user)
if password:
    put('Account', 'password', bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode())
put('Server', 'app_ip', listen_ip)
put('Server', 'app_port', port)
put('Server', 'auth_req', 'true')
put('Server', 'wg_conf_path', '/etc/wireguard')
# Defaults for peers created in the dashboard. remote_endpoint must be the PUBLIC address;
# upstream otherwise guesses the server's local (possibly private) IP.
put('Peers', 'remote_endpoint', endpoint)
put('Peers', 'peer_global_dns', dns)
put('Peers', 'peer_endpoint_allowed_ip', '0.0.0.0/0')
put('Peers', 'peer_keep_alive', '25')
# Skip the first-run wizard (it would otherwise accept admin/admin) and turn off the client
# self-service portal, which upstream enables with open sign-up by default.
put('Other', 'welcome_session', 'false')
put('Clients', 'enable', 'false')
put('Clients', 'sign_up', 'false')
temporary = ini + '.tmp'
with open(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as handle:
    c.write(handle)
os.replace(temporary, ini)
PY
    )
    printf '%s' "$DASHBOARD_PASSWORD" | "$SRC/venv/bin/python3" -c "$writer" "$INI" "$DASHBOARD_USER" "$LISTEN_IP" \
        "$DASHBOARD_PORT" "$PUBLIC_ENDPOINT" "$DNS_IPV4"
    if (( GENERATED_PASSWORD )); then
        install -d -m 700 "$STATE"
        printf 'url=http://%s:%s\nusername=%s\npassword=%s\n' "$LISTEN_IP" "$DASHBOARD_PORT" "$DASHBOARD_USER" \
            "$DASHBOARD_PASSWORD" > "$STATE/credentials"
        chmod 600 "$STATE/credentials"
    fi
}

write_service() {
    step "Installing $SERVICE"
    # Based on upstream src/wg-dashboard.service, ordered after wg0 so a VPN-address bind succeeds.
    cat > "/etc/systemd/system/$SERVICE" <<EOF
# Managed by setup-wgdashboard.sh (based on upstream src/wg-dashboard.service)
[Unit]
Description=WGDashboard web interface for WireGuard
After=network-online.target wg-quick@wg0.service
Wants=network-online.target wg-quick@wg0.service
ConditionPathIsDirectory=/etc/wireguard

[Service]
Type=forking
PIDFile=$SRC/gunicorn.pid
WorkingDirectory=$SRC
ExecStart=$SRC/wgd.sh start
ExecStop=$SRC/wgd.sh stop
ExecReload=$SRC/wgd.sh restart
TimeoutSec=120
PrivateTmp=yes
UMask=0077
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "/etc/systemd/system/$SERVICE"
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    systemctl restart "$SERVICE"
}

configure_firewall() {
    step 'Updating iptables'
    local number cidr
    # Remove earlier dashboard rules (highest line number first) so re-runs and mode changes stay clean.
    for number in $(iptables -w -L INPUT -n --line-numbers | awk -v c="/* $FIREWALL_COMMENT */" 'index($0, c) { print $1 }' | sort -rn); do
        iptables -w -D INPUT "$number"
    done
    if [[ "$DASHBOARD_ACCESS" == vpn ]]; then
        for cidr in $DASHBOARD_ALLOWED_CIDRS; do
            # Allow NEW dashboard connections only from these VPN addresses, only through the tunnel,
            # and only to the server's VPN address. Everything else still hits the INPUT DROP policy.
            iptables -w -A INPUT -i "$VPN_IF" -s "$cidr" -d "$SERVER_IP" -p tcp --dport "$DASHBOARD_PORT" \
                -m conntrack --ctstate NEW -m comment --comment "$FIREWALL_COMMENT" -j ACCEPT
        done
    fi
    if command -v vpn-firewall-save >/dev/null; then
        vpn-firewall-save
    else
        warn 'vpn-firewall-save not found; the dashboard firewall rule is not persisted across reboots.'
    fi
}

verify() {
    step 'Verifying'
    local listening="" response
    for _ in $(seq 1 30); do
        listening=$(ss -Hltn "sport = :$DASHBOARD_PORT" | awk '{ print $4 }')
        [[ -z "$listening" ]] || break
        sleep 2
    done
    [[ -n "$listening" ]] || { journalctl -u "$SERVICE" -n 30 --no-pager >&2; die "WGDashboard is not listening on port $DASHBOARD_PORT."; }
    [[ "$listening" == "$LISTEN_IP:$DASHBOARD_PORT" ]] \
        || die "WGDashboard listens on $listening, expected $LISTEN_IP:$DASHBOARD_PORT. Do not expose it publicly."
    echo "Listening on $listening"
    if [[ -n "$DASHBOARD_PASSWORD" ]]; then
        # Confirms the stored hash works. The password travels on stdin, never on a command line.
        response=$(printf '%s' "$DASHBOARD_PASSWORD" \
            | "$SRC/venv/bin/python3" -c 'import json, sys; sys.stdout.write(json.dumps({"username": sys.argv[1], "password": sys.stdin.read()}))' "$DASHBOARD_USER" \
            | curl -s --max-time 10 -H 'Content-Type: application/json' --data-binary @- \
                "http://$LISTEN_IP:$DASHBOARD_PORT/api/authenticate" || true)
        if [[ "$response" == *'"status":true'* || "$response" == *'"status": true'* ]]; then
            echo 'Login check passed.'
        else
            warn 'Could not confirm the login automatically; sign in manually to check.'
        fi
    fi
}

summary() {
    printf '\nWGDashboard %s installed in %s\n' "$DASHBOARD_VERSION" "$INSTALL_DIR"
    if [[ "$DASHBOARD_ACCESS" == vpn ]]; then
        printf 'Access: connect to the VPN from %s, then browse http://%s:%s\n' "$DASHBOARD_ALLOWED_CIDRS" "$SERVER_IP" "$DASHBOARD_PORT"
    else
        printf 'Access: from your workstation run\n  ssh -N -L 127.0.0.1:%s:127.0.0.1:%s <admin>@%s\nthen browse http://127.0.0.1:%s\n' \
            "$DASHBOARD_PORT" "$DASHBOARD_PORT" "$PUBLIC_ENDPOINT" "$DASHBOARD_PORT"
    fi
    printf 'Username: %s\n' "$DASHBOARD_USER"
    (( ! GENERATED_PASSWORD )) || printf 'Generated password saved to %s/credentials (mode 600). Move it to your password manager, then delete it.\n' "$STATE"
    echo 'Next: enable TOTP in the dashboard settings, and run setup-fail2ban.sh.'
}

main() {
    local config=""
    while (( $# )); do
        case $1 in
            -h|--help) usage; return 0 ;;
            --config) [[ $# -ge 2 ]] || die '--config needs a file'; config=$2; shift ;;
            --reset-password) RESET_PASSWORD=1 ;;
            *) usage >&2; return 2 ;;
        esac
        shift
    done
    host_check
    [[ -z "$config" ]] || load_config "$config" "$SUITE_KEYS" 1
    collect_settings
    choose_password
    install_packages
    fetch_release
    install_dashboard
    write_dashboard_config
    write_service
    configure_firewall
    verify
    summary
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
