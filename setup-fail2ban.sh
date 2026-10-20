#!/usr/bin/env bash
# setup-fail2ban.sh — step 3 of 3 (see install-vpn-server.sh)
#
# Installs Fail2ban jails for SSH and WGDashboard login failures. Idempotent and host-agnostic:
# ports, database path and firewall backend are detected per server, and the admin networks from
# setup-wireguard-server.sh are never banned.
#
# The dashboard jail only makes sense when WGDashboard is reached over the VPN
# (DASHBOARD_ACCESS=vpn). In ssh-tunnel mode every login comes from 127.0.0.1, so the jail is
# skipped automatically; the SSH login (protected by the sshd jail) already gates dashboard access.
#
# Usage: sudo bash setup-fail2ban.sh [--apply] [--config FILE]
# Default is a dry run that prints every change; pass --apply to make them.
set -euo pipefail

STATE_FILE=/var/lib/wgdashboard-fail2ban/cursor.json
WG_INSTALL_ENV=/root/wireguard-setup/install.env
SUITE_KEYS="PUBLIC_ENDPOINT WAN_IF VPN_IF ADMIN_CIDRS ADMIN_USER SSH_PORT SSH_FROM_VPN ALLOW_ROOT_LOGIN ALLOW_PASSWORD_LOGIN CLIENT_TO_CLIENT DNS_IPV4 VPN_NET VPN_PORT
 ALLOW_DHCP CLIENT_NAME CLIENT_PUBLIC_KEY DASHBOARD_VERSION DASHBOARD_ACCESS DASHBOARD_PORT DASHBOARD_USER
 DASHBOARD_ALLOWED_CIDRS IGNORE_IPS BANACTION SKIP_DASHBOARD WGDASHBOARD_DB WGDASHBOARD_PORT"

usage() {
 cat <<EOF
Usage: $0 [--apply] [--config FILE]

Default is a dry run. Settings come from the environment, then FILE (KEY=VALUE lines),
then $WG_INSTALL_ENV, then auto-detection:
  SSH_PORT          port(s) to ban on            (default: from 'sshd -T', else 22)
  WGDASHBOARD_DB    path to wgdashboard_log.db   (default: searched in common install paths)
  WGDASHBOARD_PORT  dashboard port(s)            (default: app_port in wg-dashboard.ini, else 10086)
  IGNORE_IPS        IPs/CIDRs never banned       (default: loopback + ADMIN_CIDRS, except 0.0.0.0/0)
  BANACTION         fail2ban ban action          (default: iptables-multiport, or
                                                  nftables-multiport when iptables is absent)
  SKIP_DASHBOARD    1 = SSH jail only, 0 = force the dashboard jail
                                                 (default: auto; skipped when the dashboard is loopback-only)
EOF
}

# Colour only on a terminal (or when install-vpn-server.sh passes VPN_COLOR=1); NO_COLOR disables it.
if [[ -z ${NO_COLOR:-} && ( -t 1 || ${VPN_COLOR:-} == 1 ) ]]; then
 RED=$'\e[1;31m' GREEN=$'\e[1;32m' YELLOW=$'\e[1;33m' CYAN=$'\e[1;36m' DIM=$'\e[2m' RESET=$'\e[0m'
else
 RED="" GREEN="" YELLOW="" CYAN="" DIM="" RESET=""
fi
die() { printf '%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
warn() { printf '%sWarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }

APPLY=0
CONFIG_FILE=""
while (( $# )); do
 case "$1" in
 --apply) APPLY=1 ;;
 --config) [[ $# -ge 2 ]] || die "--config needs a file"; CONFIG_FILE="$2"; shift ;;
 -h|--help) usage; exit 0 ;;
 *) usage >&2; die "unknown argument: $1" ;;
 esac
 shift
done

[[ "$(id -u)" == 0 ]] || die "run as root"

# Parse KEY=VALUE lines without executing them. Values already set in the environment win.
# strict=1 rejects keys outside the allowed list; strict=0 silently skips them.
load_config() {
 local file=$1 allowed=$2 strict=$3 line key value
 [[ -r "$file" ]] || die "cannot read config file: $file"
 while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  line="${line#"${line%%[![:space:]]*}"}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || die "bad line in $file: $line"
  key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
  value="${line#*=}"; value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"
  if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then value="${BASH_REMATCH[1]}"; fi
  if [[ " ${allowed//$'\n'/ } " != *" $key "* ]]; then
   (( strict )) && die "unknown key in $file: $key"
   continue
  fi
  [[ -n "${!key:-}" ]] || printf -v "$key" '%s' "$value"
 done < "$file"
}

[[ -z "$CONFIG_FILE" ]] || load_config "$CONFIG_FILE" "$SUITE_KEYS" 1
ADMIN_CIDRS="${ADMIN_CIDRS:-}"
[[ ! -r "$WG_INSTALL_ENV" ]] || load_config "$WG_INSTALL_ENV" "ADMIN_CIDRS SSH_PORT" 0

# --- Detection ---------------------------------------------------------------
detect_ssh_ports() {
 local config
 command -v sshd >/dev/null || return 0
 config=$(sshd -T 2>/dev/null || true)
 awk '$1 == "port" { print $2 }' <<< "$config" | sort -un | paste -sd, -
}

detect_dashboard_db() {
 local dir candidate
 local candidates=()
 dir="$(systemctl show -p WorkingDirectory --value wg-dashboard.service 2>/dev/null || true)"
 [[ -n "$dir" ]] && candidates+=("$dir/db/wgdashboard_log.db")
 candidates+=(/opt/WGDashboard/src/db/wgdashboard_log.db /root/WGDashboard/src/db/wgdashboard_log.db
  /home/*/WGDashboard/src/db/wgdashboard_log.db)
 for candidate in "${candidates[@]}"; do
  [[ -r "$candidate" ]] && { echo "$candidate"; return 0; }
 done
}

# Print a [Server] key from wg-dashboard.ini next to the database's db/ directory.
dashboard_setting() {
 local ini
 ini="$(dirname "$(dirname "$1")")/wg-dashboard.ini"
 [[ -r "$ini" ]] || return 0
 awk -F' *= *' -v key="$2" '/^\[/ { section = $0 } section == "[Server]" && $1 == key { print $2; exit }' "$ini" | tr -d '\r'
}

SSH_PORT="${SSH_PORT:-$(detect_ssh_ports)}"
SSH_PORT="${SSH_PORT:-22}"
# Never ban loopback or specific admin networks. A /0 entry ("SSH from anywhere") is left out:
# ignoring it would exempt every address and Fail2ban would never ban anyone.
trusted=""
for cidr in $ADMIN_CIDRS; do
 [[ "$cidr" == */0 ]] || trusted+=" $cidr"
done
IGNORE_IPS="${IGNORE_IPS:-127.0.0.1/8 ::1$trusted}"
SKIP_DASHBOARD="${SKIP_DASHBOARD:-auto}"

if [[ "$SKIP_DASHBOARD" != 1 ]]; then
 WGDASHBOARD_DB="${WGDASHBOARD_DB:-$(detect_dashboard_db)}"
 if [[ -z "$WGDASHBOARD_DB" && "$SKIP_DASHBOARD" == auto ]]; then
  echo "WGDashboard not found; configuring the SSH jail only."
  SKIP_DASHBOARD=1
 fi
fi
if [[ "$SKIP_DASHBOARD" != 1 ]]; then
 [[ -n "$WGDASHBOARD_DB" ]] || die "WGDashboard log database not found; set WGDASHBOARD_DB, or SKIP_DASHBOARD=1 for an SSH-only host"
 WGDASHBOARD_PORT="${WGDASHBOARD_PORT:-$(dashboard_setting "$WGDASHBOARD_DB" app_port)}"
 WGDASHBOARD_PORT="${WGDASHBOARD_PORT:-10086}"
 dashboard_ip="$(dashboard_setting "$WGDASHBOARD_DB" app_ip)"
 if [[ "$SKIP_DASHBOARD" == auto ]]; then
  if [[ "$dashboard_ip" == 127.* || "$dashboard_ip" == ::1 || "$dashboard_ip" == localhost ]]; then
   echo "WGDashboard listens on $dashboard_ip only (SSH-tunnel access): every login comes from loopback,"
   echo "so a dashboard jail could never ban anyone. Configuring the SSH jail only."
   SKIP_DASHBOARD=1
  else
   SKIP_DASHBOARD=0
  fi
 fi
fi

packages=()
if [[ -z "${BANACTION:-}" ]]; then
 if command -v iptables >/dev/null; then
  BANACTION=iptables-multiport
 else
  BANACTION=nftables-multiport
  command -v nft >/dev/null || packages+=(nftables)
 fi
fi
BANACTION_ALLPORTS="${BANACTION/-multiport/-allports}"

# --- Validation --------------------------------------------------------------
[[ "$SSH_PORT" =~ ^[A-Za-z0-9:,]+$ ]] || die "invalid SSH_PORT: $SSH_PORT"
[[ "$IGNORE_IPS" =~ ^[0-9A-Fa-f.:/\ ]+$ ]] || die "IGNORE_IPS must contain only IPs/CIDRs"
[[ "$BANACTION" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid BANACTION: $BANACTION"
[[ "$SKIP_DASHBOARD" =~ ^[01]$ ]] || die "SKIP_DASHBOARD must be 0 or 1"
if [[ "$SKIP_DASHBOARD" != 1 ]]; then
 [[ "$WGDASHBOARD_PORT" =~ ^[A-Za-z0-9:,]+$ ]] || die "invalid WGDASHBOARD_PORT: $WGDASHBOARD_PORT"
 [[ "$WGDASHBOARD_DB" =~ ^/[a-zA-Z0-9_./-]+$ ]] || die "unsupported DB path: $WGDASHBOARD_DB"
 [[ -r "$WGDASHBOARD_DB" ]] || die "missing dashboard database: $WGDASHBOARD_DB"
fi

label() { printf '%s%-12s%s %s\n' "$CYAN" "$1" "$RESET" "$2"; }
label 'Host:' "$(hostname)"
label 'SSH ports:' "$SSH_PORT"
if [[ "$SKIP_DASHBOARD" == 1 ]]; then
 label 'Dashboard:' 'no jail'
else
 label 'Dashboard:' "$WGDASHBOARD_DB (ports $WGDASHBOARD_PORT)"
fi
label 'Ban action:' "$BANACTION"
label 'Ignore IPs:' "$IGNORE_IPS"
if [[ -n "${SSH_CLIENT:-}" && " $IGNORE_IPS " != *" ${SSH_CLIENT%% *} "* ]]; then
 warn "this session comes from ${SSH_CLIENT%% *}, which can be banned like any other address after 5 failed logins."
fi
echo

# --- Helpers -----------------------------------------------------------------
run() { if (( APPLY )); then "$@"; else printf '%s[dry-run]%s ' "$YELLOW" "$RESET"; printf '%q ' "$@"; printf '\n'; fi; }

TMP_FILES=()
CREATED_FILES=()
backup=""
cleanup() { (( ${#TMP_FILES[@]} )) && rm -f "${TMP_FILES[@]}"; return 0; }
on_error() {
 local status=$?
 if [[ -n "$backup" ]]; then
  printf '%sFailed (exit %s).%s Restore replaced files with: cp -a %s/. /\n' "$RED" "$status" "$RESET" "$backup" >&2
  (( ${#CREATED_FILES[@]} )) && echo "Remove newly created files with: rm -f ${CREATED_FILES[*]}" >&2
 fi
 exit "$status"
}
trap cleanup EXIT
trap on_error ERR

# Install a file from stdin, backing up any existing version; unchanged files are skipped.
write_file() {
 local path="$1" mode="$2" tmp
 tmp="$(mktemp)"
 TMP_FILES+=("$tmp")
 cat > "$tmp"
 if [[ -e "$path" ]] && cmp -s "$tmp" "$path"; then
  printf '%sunchanged: %s%s\n' "$DIM" "$path" "$RESET"
  return 0
 fi
 if (( APPLY )); then
  if [[ -e "$path" ]]; then
   cp -a --parents "$path" "$backup"
  else
   CREATED_FILES+=("$path")
  fi
  install -D -m "$mode" "$tmp" "$path"
  printf '%swrote:%s %s\n' "$GREEN" "$RESET" "$path"
 elif [[ -e "$path" ]]; then
  printf '%s[dry-run] update%s %s\n' "$YELLOW" "$RESET" "$path"; diff -u "$path" "$tmp" || true
 else
  printf '%s[dry-run] create%s %s\n' "$YELLOW" "$RESET" "$path"; cat "$tmp"
 fi
}

if (( APPLY )); then
 backup="/root/fail2ban-backup-$(date -u +%Y%m%dT%H%M%SZ)"
 mkdir -m 700 "$backup"
 echo "Backup: $backup"
fi

# --- Dependencies -----------------------------------------------------------
command -v fail2ban-client >/dev/null || packages+=(fail2ban)
command -v python3 >/dev/null || packages+=(python3)
# backend = systemd needs the journal bindings, which are not always pulled in.
if ! command -v python3 >/dev/null || ! python3 -c 'import systemd.journal' 2>/dev/null; then
 packages+=(python3-systemd)
fi
if (( ${#packages[@]} )); then
 run apt-get update
 run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
fi

# --- Shared Fail2ban defaults ------------------------------------------------
write_file /etc/fail2ban/jail.d/00-defaults.local 0644 <<EOF
# Managed by setup-fail2ban.sh
[DEFAULT]
banaction = $BANACTION
banaction_allports = $BANACTION_ALLPORTS
ignoreip = $IGNORE_IPS
findtime = 10m
bantime = 1h
# Repeat offenders get progressively longer bans, up to one week.
bantime.increment = true
bantime.maxtime = 1w
EOF

write_file /etc/fail2ban/jail.d/sshd.local 0644 <<EOF
# Managed by setup-fail2ban.sh
[sshd]
enabled = true
port = $SSH_PORT
# aggressive also counts pre-auth failures (no matching key, bad key exchange, scanners), which is
# what brute-force attempts look like when password login is disabled.
filter = sshd[mode=aggressive]
backend = systemd
maxretry = 5
EOF

# --- WGDashboard -------------------------------------------------------------
if [[ "$SKIP_DASHBOARD" == 1 ]]; then
 # Turn off a dashboard jail left from an earlier run (for example after switching to ssh-tunnel mode).
 if [[ -e /etc/fail2ban/jail.d/wgdashboard.local ]]; then
  write_file /etc/fail2ban/jail.d/wgdashboard.local 0644 <<'EOF'
# Managed by setup-fail2ban.sh — disabled because WGDashboard is not reachable over the network.
[wgdashboard]
enabled = false
EOF
 fi
 if systemctl cat wgdashboard-fail2ban-export.service >/dev/null 2>&1; then
  run systemctl disable --now wgdashboard-fail2ban-export.service
 fi
else
 if command -v python3 >/dev/null; then
  python3 - "$WGDASHBOARD_DB" <<'PY' || die "dashboard database check failed"
import ipaddress, pathlib, sqlite3, sys
conn = sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri() + "?mode=ro", uri=True, timeout=10)
columns = {row[1] for row in conn.execute("PRAGMA table_info(DashboardLog)")}
missing = {"LogID", "LogDate", "IP", "Message"} - columns
if missing:
    sys.exit(f"DashboardLog table missing or lacks columns: {', '.join(sorted(missing))}")
ips = [r[0] for r in conn.execute(
    "SELECT IP FROM DashboardLog WHERE Message LIKE 'Login failed:%' ORDER BY rowid DESC LIMIT 20")]
loopback = 0
for ip in ips:
    try:
        loopback += ipaddress.ip_address(ip).is_loopback
    except ValueError:
        pass
if ips and loopback == len(ips):
    print("Warning: every recent failed login came from loopback. WGDashboard is probably behind a "
          "reverse proxy or SSH tunnel, so this jail will never see real client IPs.", file=sys.stderr)
PY
 else
  warn "python3 not installed yet; skipping database check in dry run"
 fi

 write_file /usr/local/sbin/wgdashboard-fail2ban-export 0755 <<'PY'
#!/usr/bin/python3
"""Export new WGDashboard login failures to journald. Never logs usernames or passwords."""
import contextlib
import datetime
import ipaddress
import json
import os
import pathlib
import sqlite3
import sys
import time

MAX_AGE = 600  # seconds; older rows (e.g. backlog after downtime) are not reported
MAX_SKEW = 60  # seconds; tolerate timestamps slightly in the future
POLL_INTERVAL = 2
ERROR_BACKOFF = 30


def log(message):
    # "<4>" sets journald priority to warning; fail2ban's filter never matches these lines.
    print(f"<4>{message}", file=sys.stderr, flush=True)


def load_state(path):
    try:
        state = json.loads(path.read_text())
        if isinstance(state, dict) and isinstance(state.get("rowid"), int) and "id" in state:
            return state
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        pass
    log("Cursor file unreadable; restarting from the latest entry")
    return None


def save_state(path, state):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def is_recent(log_date):
    stamp = datetime.datetime.fromisoformat(str(log_date)).replace(tzinfo=None)
    now_local = datetime.datetime.now()
    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    # WGDashboard versions differ: some store LogDate in local time, others in UTC.
    return any(-MAX_SKEW <= (now - stamp).total_seconds() <= MAX_AGE for now in (now_local, now_utc))


def normalize_ip(address):
    ip = ipaddress.ip_address(str(address).strip())
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d
    return str(ip)


def poll(conn, state):
    if state is not None and state["rowid"]:
        anchor = conn.execute("SELECT LogID FROM DashboardLog WHERE rowid=?", (state["rowid"],)).fetchone()
        if anchor is None or anchor[0] != state["id"]:
            log("Dashboard database changed; resetting export cursor")
            state = None
    if state is None:
        latest = conn.execute("SELECT rowid, LogID FROM DashboardLog ORDER BY rowid DESC LIMIT 1").fetchone()
        return ({"rowid": latest[0], "id": latest[1]} if latest else {"rowid": 0, "id": None}), [], True
    rows = conn.execute(
        "SELECT rowid, LogID, LogDate, IP, Message FROM DashboardLog WHERE rowid>? ORDER BY rowid LIMIT 1000",
        (state["rowid"],),
    ).fetchall()
    return state, rows, False


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} DATABASE STATE_FILE [--once]", file=sys.stderr)
        return 2
    uri = pathlib.Path(sys.argv[1]).as_uri() + "?mode=ro"
    state_file = pathlib.Path(sys.argv[2])
    once = "--once" in sys.argv[3:]
    state = load_state(state_file)

    while True:
        try:
            with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=10)) as conn:
                state, rows, reset = poll(conn, state)
        except sqlite3.Error as error:
            log(f"Database read failed: {error}")
            if once:
                return 1
            time.sleep(ERROR_BACKOFF)
            continue

        for rowid, log_id, log_date, address, message in rows:
            if message and str(message).startswith("Login failed:"):
                try:
                    if is_recent(log_date):
                        print(f"WGDashboard authentication failure from {normalize_ip(address)}", flush=True)
                except (ValueError, TypeError):
                    log("Skipped malformed dashboard failure record")
            state = {"rowid": rowid, "id": log_id}
        if rows or reset:
            save_state(state_file, state)

        if once:
            return 0
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
PY

 # ProtectSystem=strict + ProtectHome=read-only make the whole filesystem read-only
 # except the StateDirectory, wherever WGDASHBOARD_DB lives.
 write_file /etc/systemd/system/wgdashboard-fail2ban-export.service 0644 <<EOF
# Managed by setup-fail2ban.sh
[Unit]
Description=Export WGDashboard failed logins to Fail2ban
After=wg-dashboard.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/wgdashboard-fail2ban-export $WGDASHBOARD_DB $STATE_FILE
Restart=on-failure
RestartSec=5
StateDirectory=wgdashboard-fail2ban
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wgdashboard-fail2ban-export

[Install]
WantedBy=multi-user.target
EOF

 write_file /etc/fail2ban/filter.d/wgdashboard.conf 0644 <<'EOF'
# Managed by setup-fail2ban.sh
[INCLUDES]
before = common.conf

[Definition]
_daemon = wgdashboard-fail2ban-export
failregex = ^%(__prefix_line)sWGDashboard authentication failure from <HOST>$
ignoreregex =
journalmatch = _SYSTEMD_UNIT=wgdashboard-fail2ban-export.service
EOF

 write_file /etc/fail2ban/jail.d/wgdashboard.local 0644 <<EOF
# Managed by setup-fail2ban.sh
[wgdashboard]
enabled = true
port = $WGDASHBOARD_PORT
filter = wgdashboard
backend = systemd
maxretry = 8
EOF
fi

# --- Activate ----------------------------------------------------------------
run fail2ban-client -t
run systemctl daemon-reload
if [[ "$SKIP_DASHBOARD" != 1 ]]; then
 # Start the exporter first so its cursor is initialised before the jail reads the journal.
 run systemctl enable wgdashboard-fail2ban-export.service
 run systemctl restart wgdashboard-fail2ban-export.service
fi
run systemctl enable --now fail2ban
run fail2ban-client reload

if (( APPLY )); then
 sleep 3
 if [[ "$SKIP_DASHBOARD" != 1 ]] && ! systemctl is-active --quiet wgdashboard-fail2ban-export.service; then
  journalctl -u wgdashboard-fail2ban-export.service -n 20 --no-pager >&2
  die "exporter service is not running"
 fi
 fail2ban-client status sshd
 [[ "$SKIP_DASHBOARD" == 1 ]] || fail2ban-client status wgdashboard
 printf '%sCompleted.%s Backup of replaced files: %s\n' "$GREEN" "$RESET" "$backup"
 echo "Fail2ban chains are rebuilt at start-up; save other firewall changes with vpn-firewall-save, not netfilter-persistent save."
else
 printf '%sDry run complete.%s Re-run with --apply to make these changes.\n' "$YELLOW" "$RESET"
fi
