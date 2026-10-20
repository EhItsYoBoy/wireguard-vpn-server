#!/usr/bin/env bash
# setup-wireguard-server.sh — step 1 of 3 (see install-vpn-server.sh)
#
# Fresh, dedicated Ubuntu 24.04+ IPv4 WireGuard server:
#   * hardens SSH (keys only, no root login)
#   * applies a commented iptables policy (default deny, VPN Internet exit, client isolation)
#   * enables IPv4 forwarding and disables IPv6
#   * creates wg0 and, optionally, the first client profile
#
# Safety: before touching the network it arms a 10-minute automatic rollback of the firewall,
# SSH and sysctl changes. The rollback is cancelled only after you confirm a NEW SSH session works.
#
# Usage: sudo bash setup-wireguard-server.sh [--config FILE]
# Settings come from the environment, then FILE (KEY=VALUE lines), then auto-detection; anything
# still missing is prompted for. Confirmations are always interactive. No secrets are printed.
set -euo pipefail
umask 077

PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"     # Public IPv4 or DNS name clients connect to
WAN_IF="${WAN_IF:-}"                       # Auto-detected from the default route
ADMIN_CIDRS="${ADMIN_CIDRS:-${ADMIN_IP:-}}" # IPv4 hosts/networks allowed to SSH; default: your current SSH source
ADMIN_USER="${ADMIN_USER:-}"               # Existing non-root sudo user with a tested SSH key; default: $SUDO_USER
SSH_PORT="${SSH_PORT:-}"                   # Existing sshd port (not changed); default: from 'sshd -T'
SSH_FROM_VPN="${SSH_FROM_VPN:-}"           # yes = also allow SSH from VPN clients (backup path if your IP changes)
DNS_IPV4="${DNS_IPV4:-}"                   # Public DNS resolver pushed to clients
VPN_NET="${VPN_NET:-}"                     # Private, non-overlapping /24
VPN_PORT="${VPN_PORT:-}"                   # UDP listen port
ALLOW_DHCP="${ALLOW_DHCP:-}"               # yes/no; default: yes if the WAN address is DHCP-assigned
CLIENT_NAME="${CLIENT_NAME:-}"             # First client profile name, or 'none' to add clients later (e.g. WGDashboard)
CLIENT_PUBLIC_KEY="${CLIENT_PUBLIC_KEY:-}" # Optional client-generated public key; blank = generate the key here

VPN_IF="wg0"
VPN_SERVICE="wg-quick@wg0"
STATE="/root/wireguard-setup"
# Every setting used by the install suite, so one shared config file works for all scripts.
SUITE_KEYS="PUBLIC_ENDPOINT WAN_IF ADMIN_CIDRS ADMIN_USER SSH_PORT SSH_FROM_VPN DNS_IPV4 VPN_NET VPN_PORT
 ALLOW_DHCP CLIENT_NAME CLIENT_PUBLIC_KEY DASHBOARD_VERSION DASHBOARD_ACCESS DASHBOARD_PORT DASHBOARD_USER
 DASHBOARD_ALLOWED_CIDRS IGNORE_IPS BANACTION SKIP_DASHBOARD WGDASHBOARD_DB WGDASHBOARD_PORT"
BACKUP=""
ROLLBACK_UNIT=""
ARMED=0

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
Usage: sudo bash setup-wireguard-server.sh [--config FILE]

Fresh, dedicated Ubuntu 24.04+ hosts only. Requires an existing non-root sudo administrator
with a tested SSH key. Existing VPN or firewall configurations are refused; this is not an
upgrade or migration script. Settings: see the variables at the top of this file or
vpn-server.conf.example. Confirmations cannot be bypassed.
EOF
}

# Parse KEY=VALUE lines without executing them. Values already set in the environment win.
load_config() {
    local file=$1 line key value
    [[ -r "$file" ]] || die "Cannot read config file: $file"
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

ask_if_missing() {
    local variable=$1 label=$2 value
    [[ -z "${!variable}" ]] || return 0
    read -r -p "$label: " value
    printf -v "$variable" '%s' "$value"
    [[ -n "${!variable}" ]] || die "$variable is required."
}

confirm() {
    local answer
    read -r -p "$1 Type YES: " answer
    [[ "$answer" == YES ]] || die 'Cancelled.'
}

host_check() {
    [[ $EUID -eq 0 ]] || die 'Run using sudo bash.'
    [[ -t 0 ]] || die 'An interactive terminal is required.'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == ubuntu ]] && dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04 \
        || die 'Supported target: Ubuntu 24.04 LTS or newer.'
    command -v python3 >/dev/null || die 'Install python3 first.'
    command -v systemctl >/dev/null || die 'systemd is required.'
}

collect_settings() {
    local sshd_config wan_addresses
    WAN_IF=${WAN_IF:-$(ip -4 route show default | awk 'NR==1 {print $5}')}
    ADMIN_USER=${ADMIN_USER:-${SUDO_USER:-}}
    if [[ -z "$ADMIN_CIDRS" && -n ${SSH_CONNECTION:-} ]]; then
        ADMIN_CIDRS="${SSH_CONNECTION%% *}/32"
    fi
    if [[ -z "$SSH_PORT" ]]; then
        sshd_config=$(/usr/sbin/sshd -T 2>/dev/null || true)
        SSH_PORT=$(awk '$1 == "port" && !found { print $2; found = 1 }' <<< "$sshd_config")
    fi
    if [[ -z "$ALLOW_DHCP" && -n "$WAN_IF" ]]; then
        wan_addresses=$(ip -4 address show dev "$WAN_IF" 2>/dev/null || true)
        if [[ "$wan_addresses" == *" dynamic "* ]]; then ALLOW_DHCP=yes; else ALLOW_DHCP=no; fi
    fi
    SSH_PORT=${SSH_PORT:-22}
    SSH_FROM_VPN=${SSH_FROM_VPN:-no}
    DNS_IPV4=${DNS_IPV4:-1.1.1.1}
    VPN_NET=${VPN_NET:-10.77.0.0/24}
    VPN_PORT=${VPN_PORT:-51820}
    CLIENT_NAME=${CLIENT_NAME:-client1}

    ask_if_missing PUBLIC_ENDPOINT 'Public VPN IPv4 or DNS hostname'
    ask_if_missing WAN_IF 'WAN interface'
    ask_if_missing ADMIN_CIDRS 'Administrator IPv4 address(es) allowed to SSH, space-separated'
    ask_if_missing ADMIN_USER 'Existing non-root sudo administrator'
    validate_values
    NET_BASE=${VPN_NET%.*}
    SERVER_IP="$NET_BASE.1"
    CLIENT_IP="$NET_BASE.2"
}

validate_values() {
    # Reject shell/config injection and ambiguous or non-private address plans.
    # Prints the normalized administrator networks on success.
    local source=""
    [[ -z ${SSH_CONNECTION:-} ]] || source=${SSH_CONNECTION%% *}
    ADMIN_CIDRS=$(python3 - "$PUBLIC_ENDPOINT" "$ADMIN_CIDRS" "$DNS_IPV4" "$VPN_NET" "$VPN_PORT" "$SSH_PORT" \
        "$ADMIN_USER" "$CLIENT_NAME" "$WAN_IF" "$source" "$CLIENT_PUBLIC_KEY" <<'PY'
import base64, ipaddress as ip, re, sys
endpoint, admins, dns, net, port, ssh, user, client, wan, source, client_key = sys.argv[1:]
fail = sys.exit
try:
    n = ip.IPv4Network(net, strict=True)
except ValueError:
    fail('VPN_NET must be an IPv4 network such as 10.77.0.0/24')
private = [ip.IPv4Network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
if n.prefixlen != 24 or not any(n.subnet_of(p) for p in private):
    fail('VPN_NET must be an RFC1918 /24')
networks = []
for item in admins.replace(',', ' ').split():
    try:
        a = ip.IPv4Network(item, strict=False)
    except ValueError:
        fail(f'Invalid ADMIN_CIDRS entry: {item}')
    if a.prefixlen and (a.is_loopback or a.is_link_local or a.is_multicast):
        fail(f'Unusable ADMIN_CIDRS entry: {a}')
    if a.prefixlen and a.overlaps(n):
        fail(f'ADMIN_CIDRS entry {a} overlaps VPN_NET; use SSH_FROM_VPN=yes instead')
    networks.append(a)
if not networks:
    fail('ADMIN_CIDRS is required')
if source:
    try:
        s = ip.ip_address(source)
    except ValueError:
        fail(f'Unrecognised SSH source address: {source}')
    if s.version != 4:
        fail('Connect over IPv4: this setup disables IPv6 and would drop your session')
    if not any(s in a for a in networks):
        fail(f'Your current SSH source {s} is outside ADMIN_CIDRS; you would be locked out')
try:
    if not ip.IPv4Address(dns).is_global:
        fail('DNS_IPV4 must be a public resolver; clients cannot reach private destinations')
except ValueError:
    fail('DNS_IPV4 must be an IPv4 address')
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', endpoint):
    fail('Invalid PUBLIC_ENDPOINT')
if endpoint.lower() in ('localhost', 'vpn.example.net', 'vpn.example.com'):
    fail('Replace the PUBLIC_ENDPOINT placeholder')
if re.fullmatch(r'[0-9.]+', endpoint):
    try:
        if not ip.IPv4Address(endpoint).is_global:
            fail('PUBLIC_ENDPOINT must be a public IPv4 address')
    except ValueError:
        fail('Invalid PUBLIC_ENDPOINT IPv4 address')
for value in (port, ssh):
    if not (value.isdecimal() and 1 <= int(value) <= 65535):
        fail(f'Invalid port: {value}')
if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user) or user == 'root':
    fail('ADMIN_USER must be an existing non-root account')
if client != 'none' and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', client):
    fail('Invalid CLIENT_NAME')
if client_key:
    try:
        assert len(base64.b64decode(client_key, validate=True)) == 32
    except Exception:
        fail('Invalid CLIENT_PUBLIC_KEY (expected a WireGuard base64 public key)')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', wan):
    fail('Invalid WAN interface name')
print(' '.join(str(a) for a in networks))
PY
    ) || die 'Settings validation failed (see message above).'
    [[ "$ALLOW_DHCP" == yes || "$ALLOW_DHCP" == no ]] || die 'ALLOW_DHCP must be yes or no.'
    [[ "$SSH_FROM_VPN" == yes || "$SSH_FROM_VPN" == no ]] || die 'SSH_FROM_VPN must be yes or no.'
}

preflight() {
    local directory unit existing groups admin_home sshd_config routes
    [[ ! -e "$STATE" ]] || die "$STATE exists. This is a first-install script; inspect it instead of rerunning."
    [[ ! -e /etc/sysctl.d/99-vpn-setup.conf && ! -e /etc/ssh/sshd_config.d/00-vpn-setup.conf ]] \
        || die 'A file owned by this installer already exists.'
    for directory in /etc/wireguard /etc/openvpn/server; do
        if [[ -d "$directory" ]] && [[ -n $(find "$directory" -mindepth 1 -print -quit) ]]; then
            die "Existing files in $directory; refusing replacement."
        fi
    done
    if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
        die 'UFW is active; use a dedicated clean host (this installer replaces UFW with iptables-persistent).'
    fi
    for unit in firewalld docker containerd nftables; do
        if systemctl is-active --quiet "$unit"; then die "Active $unit service: use a dedicated clean host."; fi
    done
    for command in iptables-save ip6tables-save; do
        command -v "$command" >/dev/null || continue
        existing=$("$command")
        if grep -Eq '^-A |^:[^ ]+ (DROP|-) ' <<< "$existing"; then
            die "Existing firewall rules, chains or DROP policy found by $command."
        fi
    done
    # Read-only check for native nftables rules that iptables cannot safely manage.
    if command -v nft >/dev/null && [[ -n $(nft list ruleset) ]]; then
        die 'An existing nftables ruleset exists; review it manually.'
    fi
    ip link show dev "$WAN_IF" >/dev/null 2>&1 || die "WAN interface $WAN_IF does not exist."
    id "$ADMIN_USER" >/dev/null 2>&1 || die "User $ADMIN_USER does not exist."
    groups=$(id -nG "$ADMIN_USER")
    [[ " $groups " == *" sudo "* ]] || die "$ADMIN_USER must be a member of the sudo group."
    admin_home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    [[ -s "$admin_home/.ssh/authorized_keys" ]] || die "Install and test an SSH key for $ADMIN_USER first."
    ssh-keygen -l -f "$admin_home/.ssh/authorized_keys" >/dev/null 2>&1 || die 'No valid administrator SSH key found.'
    /usr/sbin/sshd -t || die 'Current SSH configuration is invalid.'
    sshd_config=$(/usr/sbin/sshd -T)
    grep -qx "port $SSH_PORT" <<< "$sshd_config" || die "SSH_PORT $SSH_PORT does not match the running sshd configuration."
    getent ahostsv4 "$PUBLIC_ENDPOINT" >/dev/null || die 'PUBLIC_ENDPOINT has no resolvable IPv4 address.'
    routes=$(ip -j -4 route show table all)
    python3 -c '
import json, sys, ipaddress as ip
n = ip.IPv4Network(sys.argv[1])
for r in json.loads(sys.argv[2]):
    d = r.get("dst", "default")
    if d == "default":
        continue
    try:
        other = ip.IPv4Network(d, strict=False)
    except ValueError:
        continue
    if n.overlaps(other):
        sys.exit("VPN network overlaps existing route: " + d)
' "$VPN_NET" "$routes" || die 'Choose a different VPN_NET.'
    if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" != yes ]]; then
        warn 'System clock is not NTP-synchronised; fix this before relying on logs and bans.'
    fi

    printf '\n%-22s %s\n' \
        'Endpoint:' "$PUBLIC_ENDPOINT UDP $VPN_PORT" \
        'WAN interface:' "$WAN_IF (DHCP renewal allowed: $ALLOW_DHCP)" \
        'SSH:' "port $SSH_PORT as $ADMIN_USER from $ADMIN_CIDRS" \
        'SSH from VPN clients:' "$SSH_FROM_VPN" \
        'VPN network:' "$VPN_NET (server $SERVER_IP)" \
        'Client DNS:' "$DNS_IPV4" \
        'First client:' "$( [[ $CLIENT_NAME == none ]] && echo none || echo "$CLIENT_NAME $CLIENT_IP" )"
    echo
    if [[ " $ADMIN_CIDRS " == *" 0.0.0.0/0 "* ]]; then
        warn 'ADMIN_CIDRS includes 0.0.0.0/0: SSH will be reachable from the whole Internet (keys only).'
    fi
    confirm 'Have you tested SSH KEY login and sudo in a NEW session as this administrator, and confirmed the host does not need IPv6?'
    confirm 'Install packages, harden SSH, disable IPv6, enable forwarding and apply this dedicated-host firewall?'
}

install_packages() {
    local apt_options=(-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # Keep existing config files if an upgrade ships new ones, instead of stopping at a prompt.
    apt-get "${apt_options[@]}" upgrade -y
    printf '%s\n' 'iptables-persistent iptables-persistent/autosave_v4 boolean false' \
        'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections
    # iptables-persistent replaces the (inactive) ufw package on Ubuntu.
    apt-get "${apt_options[@]}" install -y iptables iptables-persistent unattended-upgrades wireguard wireguard-tools
}

arm_rollback() {
    install -d -m 700 "$STATE"
    BACKUP="$STATE/rollback"
    install -d -m 700 "$BACKUP"
    iptables-save > "$BACKUP/rules.v4.before"
    ip6tables-save > "$BACKUP/rules.v6.before"
    [[ ! -e /etc/iptables/rules.v4 ]] || cp -p /etc/iptables/rules.v4 "$BACKUP/saved.v4.before"
    [[ ! -e /etc/iptables/rules.v6 ]] || cp -p /etc/iptables/rules.v6 "$BACKUP/saved.v6.before"
    {
        printf 'BACKUP=%q\nVPN_SERVICE=%q\n' "$BACKUP" "$VPN_SERVICE"
        printf 'OLD_FORWARD=%q\n' "$(sysctl -n net.ipv4.ip_forward)"
        printf 'OLD_V6_ALL=%q\n' "$(sysctl -n net.ipv6.conf.all.disable_ipv6)"
        printf 'OLD_V6_DEFAULT=%q\n' "$(sysctl -n net.ipv6.conf.default.disable_ipv6)"
    } > "$BACKUP/state"
    cat > "$BACKUP/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
# Restores the pre-install firewall, SSH and sysctl state. Run by a 10-minute timer, on installer
# failure, or manually from the provider console: bash /root/wireguard-setup/rollback/rollback.sh
set -u
cd -- "$(dirname -- "$0")" || exit 1
source ./state
exec 9>"$BACKUP/lock"
flock -x 9
[[ ! -e "$BACKUP/COMMITTED" && ! -e "$BACKUP/ROLLED_BACK" ]] || exit 0
failed=0
systemctl disable --now "$VPN_SERVICE" || true
# Preflight proved the host had no rules and ACCEPT policies, so reset to that state explicitly:
# restoring an empty snapshot alone would leave the installer's DROP policies in place.
for command in iptables ip6tables; do
    for table in filter nat; do
        "$command" -w -t "$table" -F 2>/dev/null
        "$command" -w -t "$table" -X 2>/dev/null
    done
    for chain in INPUT FORWARD OUTPUT; do "$command" -w -P "$chain" ACCEPT || failed=1; done
done
if [[ -s rules.v4.before ]]; then iptables-restore < rules.v4.before || failed=1; fi
if [[ -s rules.v6.before ]]; then ip6tables-restore < rules.v6.before || failed=1; fi
for version in 4 6; do
    if [[ -e "saved.v$version.before" ]]; then
        cp -p "saved.v$version.before" "/etc/iptables/rules.v$version" || failed=1
    else
        rm -f -- "/etc/iptables/rules.v$version" || failed=1
    fi
done
# These files did not exist at preflight and belong only to this installer.
rm -f -- /etc/ssh/sshd_config.d/00-vpn-setup.conf /etc/sysctl.d/99-vpn-setup.conf || failed=1
sysctl -w "net.ipv4.ip_forward=$OLD_FORWARD" || failed=1
sysctl -w "net.ipv6.conf.all.disable_ipv6=$OLD_V6_ALL" || failed=1
sysctl -w "net.ipv6.conf.default.disable_ipv6=$OLD_V6_DEFAULT" || failed=1
if /usr/sbin/sshd -t; then systemctl try-reload-or-restart ssh.service || failed=1; else failed=1; fi
if [[ "$failed" != 0 ]]; then
    touch "$BACKUP/ROLLBACK_FAILED"
    echo 'Rollback incomplete. Use the provider console and inspect the saved snapshot/state.' >&2
    exit 1
fi
touch "$BACKUP/ROLLED_BACK"
ROLLBACK
    chmod 700 "$BACKUP/rollback.sh"
    ROLLBACK_UNIT="vpn-setup-rollback-$(date +%s)-$$"
    systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active=10m "$BACKUP/rollback.sh"
    ARMED=1
    printf 'Rollback armed for 10 minutes: %s\n' "$BACKUP/rollback.sh"
}

on_exit() {
    local result=$?
    if [[ "$ARMED" == 1 && ! -e "$BACKUP/COMMITTED" ]]; then
        printf '\nSetup did not commit. Rolling back firewall, SSH and sysctl changes; generated files are kept for inspection.\n' >&2
        bash "$BACKUP/rollback.sh" || printf 'Automatic rollback failed; use the provider console and saved state.\n' >&2
        systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
        printf 'Inspect %s before attempting another install. Packages are not removed.\n' "$STATE" >&2
        [[ $result != 0 ]] || result=1
    fi
    exit "$result"
}

harden_host() {
    local effective setting check_addr
    cat > /etc/sysctl.d/99-vpn-setup.conf <<'SYSCTL'
# Owned by setup-wireguard-server.sh
# Route VPN client traffic out of the WAN interface.
net.ipv4.ip_forward = 1
# IPv4-only design: no IPv6 addresses means no unfiltered IPv6 path.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL
    sysctl -p /etc/sysctl.d/99-vpn-setup.conf
    # sshd uses the FIRST value it reads, so this 00- drop-in wins over later files such as
    # 50-cloud-init.conf. Match blocks can still override; the effective check below catches that.
    cat > /etc/ssh/sshd_config.d/00-vpn-setup.conf <<'SSH'
# Owned by setup-wireguard-server.sh
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 4
SSH
    chmod 600 /etc/ssh/sshd_config.d/00-vpn-setup.conf
    /usr/sbin/sshd -t
    check_addr=${SSH_CONNECTION%% *}
    [[ -n "$check_addr" ]] || check_addr=${ADMIN_CIDRS%%/*}
    effective=$(/usr/sbin/sshd -T -C "user=$ADMIN_USER,host=$check_addr,addr=$check_addr")
    for setting in 'pubkeyauthentication yes' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitrootlogin no'; do
        grep -qx "$setting" <<< "$effective" || die "Earlier SSH policy overrides '$setting'; review the SSH configuration."
    done
    # Ubuntu 24.04+ socket-activates sshd; try-reload works whether or not ssh.service is running.
    systemctl try-reload-or-restart ssh.service
    # Enable unattended security updates from the distribution's default origins.
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
    # Saves the firewall for netfilter-persistent while excluding Fail2ban's dynamic chains.
    cat > /usr/local/sbin/vpn-firewall-save <<'SAVE'
#!/usr/bin/env bash
# Save the live iptables policy to /etc/iptables/rules.v4 and rules.v6 for netfilter-persistent.
# Use this instead of 'netfilter-persistent save': Fail2ban creates its f2b-* chains at start-up,
# and saving them makes Fail2ban fail with "chain already exists" after a reboot.
set -euo pipefail
umask 077
install -d -m 755 /etc/iptables
iptables-save | grep -v -- 'f2b-' > /etc/iptables/rules.v4.new
ip6tables-save | grep -v -- 'f2b-' > /etc/iptables/rules.v6.new
mv /etc/iptables/rules.v4.new /etc/iptables/rules.v4
mv /etc/iptables/rules.v6.new /etc/iptables/rules.v6
echo 'Saved /etc/iptables/rules.v4 and /etc/iptables/rules.v6 (Fail2ban chains excluded).'
SAVE
    chmod 755 /usr/local/sbin/vpn-firewall-save
}

apply_firewall() {
    local admin forbidden
    # Preflight proved the chains are empty, so appended rules are evaluated in exactly this order.

    # ---------------- IPv4 INPUT: traffic addressed to the server itself ----------------
    # Discard malformed or untrackable packets before any other rule sees them.
    iptables -w -A INPUT -m conntrack --ctstate INVALID -m comment --comment 'vpn: drop invalid input' -j DROP
    # Allow local processes to talk to each other over loopback (WGDashboard, DNS stub, etc.).
    iptables -w -A INPUT -i lo -m comment --comment 'vpn: local loopback' -j ACCEPT
    # Allow replies to connections the server started and keep existing sessions (including this SSH).
    iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment 'vpn: established input' -j ACCEPT
    # Allow ping and the ICMP errors that path-MTU discovery depends on.
    iptables -w -A INPUT -p icmp -m comment --comment 'vpn: ICMP and path MTU' -j ACCEPT
    # Allow NEW SSH connections only from the trusted administrator networks.
    for admin in $ADMIN_CIDRS; do
        iptables -w -A INPUT -i "$WAN_IF" -s "$admin" -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
            -m comment --comment 'vpn: trusted SSH admin' -j ACCEPT
    done
    # Optional backup path: SSH from connected VPN clients, useful when an admin's public IP changes.
    if [[ "$SSH_FROM_VPN" == yes ]]; then
        iptables -w -A INPUT -i "$VPN_IF" -s "$VPN_NET" -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
            -m comment --comment 'vpn: SSH from VPN clients' -j ACCEPT
    fi
    # Allow encrypted WireGuard packets to reach the UDP listener from anywhere.
    iptables -w -A INPUT -i "$WAN_IF" -p udp --dport "$VPN_PORT" -m comment --comment 'vpn: WireGuard UDP listener' -j ACCEPT
    # Allow DHCPv4 lease renewals so a DHCP-assigned WAN address does not expire.
    if [[ "$ALLOW_DHCP" == yes ]]; then
        iptables -w -A INPUT -i "$WAN_IF" -p udp --sport 67 --dport 68 -m comment --comment 'vpn: DHCP lease renewal' -j ACCEPT
    fi

    # ---------------- IPv4 FORWARD: traffic passing through the server ----------------
    # Discard invalid forwarded packets.
    iptables -w -A FORWARD -m conntrack --ctstate INVALID -m comment --comment 'vpn: drop invalid forwarding' -j DROP
    # Stop VPN clients reaching private, carrier-grade NAT and cloud metadata networks via the WAN.
    # These come BEFORE the established and Internet-exit rules so nothing can bypass them.
    for forbidden in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do
        iptables -w -A FORWARD -i "$VPN_IF" -o "$WAN_IF" -s "$VPN_NET" -d "$forbidden" \
            -m comment --comment "vpn: deny private WAN $forbidden" -j DROP
    done
    # Allow replies for connections that were permitted to start.
    iptables -w -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment 'vpn: established forwarding' -j ACCEPT
    # Allow VPN clients to start Internet connections out of the WAN. Client-to-client (wg0 -> wg0)
    # traffic matches no ACCEPT rule, so clients are isolated from each other by the DROP policy.
    iptables -w -A FORWARD -i "$VPN_IF" -o "$WAN_IF" -s "$VPN_NET" -m comment --comment 'vpn: Internet exit' -j ACCEPT

    # ---------------- IPv4 NAT ----------------
    # Rewrite VPN client source addresses to the server's WAN address; nothing else is translated.
    iptables -w -t nat -A POSTROUTING -s "$VPN_NET" -o "$WAN_IF" -m comment --comment 'vpn: NAT only VPN to WAN' -j MASQUERADE

    # ---------------- IPv6: defence in depth ----------------
    # IPv6 is disabled by sysctl. If it is ever re-enabled, nothing new may reach or cross the server.
    ip6tables -w -A INPUT -i lo -m comment --comment 'vpn: local loopback' -j ACCEPT
    ip6tables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment 'vpn: established input' -j ACCEPT

    # ---------------- Default policies: set LAST, after admin and established rules exist ----------------
    # Anything not explicitly accepted above is dropped; the server itself may still connect out
    # (updates, DNS, NTP).
    iptables -w -P INPUT DROP
    iptables -w -P FORWARD DROP
    iptables -w -P OUTPUT ACCEPT
    ip6tables -w -P INPUT DROP
    ip6tables -w -P FORWARD DROP
    ip6tables -w -P OUTPUT ACCEPT
}

configure_wireguard() {
    local server_key server_public client_key="" client_public=""
    install -d -m 700 /etc/wireguard "$STATE/clients"
    server_key=$(wg genkey)
    server_public=$(wg pubkey <<< "$server_key")
    printf '%s\n' "$server_public" > "$STATE/server.pub"
    {
        printf '# Managed by setup-wireguard-server.sh. Peers may also be added by WGDashboard.\n'
        printf '# Firewall rules live in /etc/iptables (netfilter-persistent), not in PostUp/PostDown.\n'
        printf '[Interface]\nAddress = %s/24\nListenPort = %s\nPrivateKey = %s\n' "$SERVER_IP" "$VPN_PORT" "$server_key"
    } > /etc/wireguard/wg0.conf
    if [[ "$CLIENT_NAME" != none ]]; then
        if [[ -n "$CLIENT_PUBLIC_KEY" ]]; then
            client_public="$CLIENT_PUBLIC_KEY"
        else
            client_key=$(wg genkey)
            client_public=$(wg pubkey <<< "$client_key")
        fi
        printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n' "$CLIENT_NAME" "$client_public" "$CLIENT_IP" \
            >> /etc/wireguard/wg0.conf
        {
            printf '[Interface]\nAddress = %s/32\nPrivateKey = %s\nDNS = %s\n\n' \
                "$CLIENT_IP" "${client_key:-<KEEP_THE_PRIVATE_KEY_ALREADY_ON_YOUR_CLIENT>}" "$DNS_IPV4"
            printf '[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n' \
                "$server_public" "$PUBLIC_ENDPOINT" "$VPN_PORT"
        } > "$STATE/clients/$CLIENT_NAME.conf"
    fi
    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable --now "$VPN_SERVICE"
}

write_install_env() {
    # Read by setup-wgdashboard.sh, setup-fail2ban.sh and install-vpn-server.sh.
    {
        printf '# Written by setup-wireguard-server.sh on %s. Read by the other install scripts.\n' "$(date -u +%FT%TZ)"
        printf 'PUBLIC_ENDPOINT="%s"\nWAN_IF="%s"\nVPN_IF="%s"\nVPN_NET="%s"\nVPN_PORT="%s"\n' \
            "$PUBLIC_ENDPOINT" "$WAN_IF" "$VPN_IF" "$VPN_NET" "$VPN_PORT"
        printf 'SERVER_IP="%s"\nDNS_IPV4="%s"\nADMIN_CIDRS="%s"\nADMIN_USER="%s"\nSSH_PORT="%s"\nSSH_FROM_VPN="%s"\n' \
            "$SERVER_IP" "$DNS_IPV4" "$ADMIN_CIDRS" "$ADMIN_USER" "$SSH_PORT" "$SSH_FROM_VPN"
    } > "$STATE/install.env"
    chmod 600 "$STATE/install.env"
}

commit_setup() {
    local answer admin
    systemctl is-active --quiet "$VPN_SERVICE" || die "$VPN_SERVICE failed to start."
    for admin in $ADMIN_CIDRS; do
        iptables -w -C INPUT -i "$WAN_IF" -s "$admin" -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
            -m comment --comment 'vpn: trusted SSH admin' -j ACCEPT || die 'SSH admin rule is missing.'
    done
    printf '\nOpen a NEW SSH key session as %s on port %s and test sudo now. Keep this session open.\n' "$ADMIN_USER" "$SSH_PORT"
    read -r -t 300 -p 'After that succeeds, type CONFIRM to save the firewall and cancel rollback: ' answer \
        || die 'Confirmation timed out.'
    [[ "$answer" == CONFIRM ]] || die 'New-session verification was not confirmed.'
    # A separate process takes the lock, so the rollback timer and this commit cannot race.
    cat > "$BACKUP/commit.sh" <<'COMMIT'
#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
source ./state
exec 9>"$BACKUP/lock"
flock -x 9
[[ ! -e "$BACKUP/ROLLED_BACK" && ! -e "$BACKUP/ROLLBACK_FAILED" ]] || { echo 'Rollback already ran or failed; inspect state.' >&2; exit 1; }
systemctl is-active --quiet "$VPN_SERVICE"
/usr/local/sbin/vpn-firewall-save
systemctl enable netfilter-persistent
touch "$BACKUP/COMMITTED"
COMMIT
    bash "$BACKUP/commit.sh"
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    ARMED=0
    write_install_env
    printf '\nSetup committed. Backup/recovery state: %s\n' "$STATE"
    printf 'Open UDP %s in the provider firewall. Test client traffic, denied access and a maintenance reboot.\n' "$VPN_PORT"
    printf 'Disable/block native IPv6 on clients separately; disabling it on the server does not protect clients.\n'
    printf 'After changing firewall rules later, save them with: sudo vpn-firewall-save\n'
}

main() {
    local config=""
    while (( $# )); do
        case $1 in
            -h|--help) usage; return 0 ;;
            --config) [[ $# -ge 2 ]] || die '--config needs a file'; config=$2; shift ;;
            install) ;;
            *) usage >&2; return 2 ;;
        esac
        shift
    done
    host_check
    [[ -z "$config" ]] || load_config "$config"
    collect_settings
    preflight
    install_packages
    arm_rollback
    trap on_exit EXIT
    trap 'exit 130' INT TERM
    harden_host
    apply_firewall
    configure_wireguard
    commit_setup
    if [[ "$CLIENT_NAME" != none ]]; then
        printf 'Client profile: %s/clients/%s.conf (mode 600). Transfer it securely; never paste it into notes.\n' "$STATE" "$CLIENT_NAME"
        [[ -z "$CLIENT_PUBLIC_KEY" ]] || echo 'The profile is a template: add the private key already stored on your client.'
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
