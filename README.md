# WireGuard VPN server installer

Builds a dedicated Ubuntu 24.04+ WireGuard server with a configurable SSH login policy, a commented iptables firewall, an optional WGDashboard web UI, and Fail2ban.

| Script | What it does |
| --- | --- |
| `install-vpn-server.sh` | Runs the three steps in order, checks the host first, and finishes with a health check |
| `setup-wireguard-server.sh` | WireGuard (`wg0`), SSH login policy, iptables policy, IP forwarding, IPv6 disabled, unattended upgrades |
| `setup-wgdashboard.sh` | Pinned WGDashboard release, preset admin login, systemd service |
| `setup-fail2ban.sh` | Fail2ban for SSH, plus dashboard logins when the dashboard is reachable over the VPN |

## Before you start

1. You need a fresh Ubuntu 24.04 (or newer) server with no Docker, UFW rules, or other firewall in use. Have the cloud provider's web console open in case you lock yourself out.

   An existing **WireGuard client** on the server is fine if it only routes specific networks (split tunnel). The installer leaves its config untouched, puts the server on the next free interface (e.g. `wg1`; choose the name with `VPN_IF` in the config), and refuses to run if:
   - the client routes all traffic (`AllowedIPs = 0.0.0.0/0`)
   - the client's addresses overlap `VPN_NET`
   - the client already uses UDP port `VPN_PORT`
2. Make sure the account you log in with has a strong password: `passwd root` (or that user's name).
3. In the provider firewall, allow SSH (TCP 22) and the WireGuard UDP port (51820 by default).
4. Connect over **IPv4**, as root or a sudo user. The installer disables IPv6.

**SSH defaults:**
- **Who can connect:** SSH stays reachable from anywhere.
- **Root login** stays allowed.
- **Logins:** passwords and SSH keys both work.
- **Fail2ban** bans any address that racks up failed attempts. Five failures within 10 minutes earns a 1-hour ban, growing to 1 week for repeat offenders.

To tighten this later, set these in the config file: `ALLOW_ROOT_LOGIN=no`, `ALLOW_PASSWORD_LOGIN=no` (key-only), or `ADMIN_CIDRS` (only known networks).

## Install

```bash
BASE=https://raw.githubusercontent.com/EhItsYoBoy/wireguard-vpn-server/v0.4.1
curl -fsSLO "$BASE/install-vpn-server.sh"
curl -fsSLO "$BASE/vpn-server.conf.example"
cp vpn-server.conf.example vpn-server.conf && nano vpn-server.conf     # at least PUBLIC_ENDPOINT
sudo bash install-vpn-server.sh --config vpn-server.conf
```

> **Status:** v0.4.1 has not yet been run end to end on a real server. Test it on a disposable Ubuntu 24.04 VM before relying on it.

Do **not** use `curl ... | sudo bash`. The WireGuard step reads confirmations from the keyboard, and piping takes the keyboard away.

The installer downloads the step scripts from the same tag and checks them against `SHA256SUMS` before running anything. Setting `VPN_SCRIPTS_SHA256=<sha256 of SHA256SUMS>` as well makes it refuse a release that has been changed since you recorded the hash.

What to expect during step 1:
- It asks you to type `YES` twice.
- It then arms a **10-minute automatic rollback** and applies the firewall.
- Open a **new** SSH session, check that `sudo` works, then type `CONFIRM` in the original session. If you don't confirm, the firewall, SSH and sysctl changes are undone automatically.

If a step fails, fix the cause and run the installer again. Steps that already finished are skipped.

## After install

```bash
sudo bash install-vpn-server.sh --check     # health check, any time (e.g. after a reboot)
sudo vpn-firewall-save                      # save firewall changes; never use 'netfilter-persistent save'
```

- **Dashboard (default `ssh-tunnel` mode):** run `ssh -N -L 127.0.0.1:10086:127.0.0.1:10086 vpnadmin@<server>` on your workstation, then browse to `http://127.0.0.1:10086`. Turn on TOTP in the dashboard settings.
- **Client profiles:** they are in `/root/wireguard-setup/clients/`. Move them off the server securely, then delete them.
- **Reboot:** reboot in a maintenance window, then run `--check` again.

## Publishing a release

1. Change the tag in `VPN_SCRIPTS_URL` (top of `install-vpn-server.sh`) and in the install commands above.
2. Regenerate the checksums **after** that edit, then commit, tag and push:
   ```bash
   sha256sum setup-wireguard-server.sh setup-wgdashboard.sh setup-fail2ban.sh install-vpn-server.sh > SHA256SUMS
   git add -A && git commit -m "Release v0.5.0" && git tag v0.5.0 && git push origin main --tags
   ```

Always install from a tag, never from `main`. Never move or re-push an existing tag: servers that pinned it would get different code.
