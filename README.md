# ccdc-firewall

Default-deny inbound host firewalls for CCDC-style competitions. Run one script per box:

- it finds what is listening,
- keeps the ports that look like real services,
- blocks everything else inbound (backdoors, bind shells, RPC/WinRM, mDNS…),
- **rolls itself back automatically** unless you confirm, so a mistake can't lock you out,
- optionally re-checks every minute and puts the rules back if the red team flushes or edits them.

| Script | Runs on | Backend |
|---|---|---|
| `linux/ccdc-fw.sh` | Debian, Ubuntu, Rocky/RHEL, Arch, Alpine, Tiny Core (POSIX sh / busybox) | nftables, falls back to iptables |
| `windows/ccdc-fw.ps1` | Server 2016–2025 (incl. Server Core), Windows 10/11, PowerShell 5.1+ | Windows Defender Firewall |

Both only filter **inbound** traffic. Outbound and replies to your own connections are untouched, so
DNS, AD, package updates and DB connections from web servers keep working.

## Quick start

### Linux

```sh
curl -fsSLo ccdc-fw.sh https://raw.githubusercontent.com/jogeshwaranish/ccdc-firewall/main/linux/ccdc-fw.sh
sudo sh ccdc-fw.sh scan        # dry run: what would be allowed / blocked + the exact ruleset
sudo sh ccdc-fw.sh apply       # applies; reverts in 120 s unless you answer "y"
sudo /etc/ccdc-fw/ccdc-fw.sh persist   # re-apply at boot + tamper check every minute
```

Run it from a file, not `curl | sh`, because the rollback timer calls the file.

### Windows (elevated PowerShell)

```powershell
Unblock-File .\ccdc-fw.ps1
powershell -ExecutionPolicy Bypass -File .\ccdc-fw.ps1 -Action Scan
powershell -ExecutionPolicy Bypass -File .\ccdc-fw.ps1 -Action Apply      # reverts in 120 s unless you answer "y"
powershell -ExecutionPolicy Bypass -File C:\ProgramData\ccdc-fw\ccdc-fw.ps1 -Action Persist
```

## How a port gets decided

In order, first match wins:

1. **Your SSH session port** → always allowed (Linux).
2. **`--deny` / `-Deny`** → blocked.
3. **Suspicious listener** → blocked: `nc`/`ncat`/`socat`/shells/`perl`/`powershell`/`cmd`/`rundll32`…, or a
   binary running from `/tmp`, `/dev/shm`, `AppData`, `Temp`, `Users\Public`, etc.
4. **Domain controller** (Windows, NTDS running) → DNS, Kerberos, LDAP(S), GC, SMB, kpasswd, NTP, NetBIOS
   allowed from anywhere; RPC dynamic range and ADWS only from the local subnet.
5. **Noise** → blocked: CUPS, mDNS, LLMNR, SSDP, WSD, RPC endpoint mapper (non-DC), WinRM's 47001, dynamic
   RPC on non-DCs, SMB on Windows boxes with no real file shares.
6. **Well-known service port** (FTP, SSH, SMTP, DNS, HTTP/S, POP3/IMAP(S), LDAP, SMB, MySQL, Postgres,
   MSSQL, Mongo, RDP, VNC, OpenVPN, NFS, SNMP, 8080/8443 …) → allowed.
7. **Known server process** on any port (nginx, apache, java, node, gunicorn, puma, jellyfin, mattermost,
   docker-proxy, k3s, IIS `w3wp`, `sqlservr` …) → allowed.
8. **Anything else** → you're asked `allow? [y/N]`, or it's blocked with `--yes` / `-Yes`.

Always allowed: loopback, established/related traffic, ICMP (ping), DHCP replies, and container/k8s
interfaces (`docker*`, `cni*`, `flannel*`, `cali*`, `veth*` …). On Windows the *Core Networking* rule
group stays on.

## Options

| Linux | Windows | Meaning |
|---|---|---|
| `-a 8065` `-a 3306/tcp@192.168.220.0/24` `-a 6881-6889/udp` | `-Allow 8065,'1433/TCP@192.168.220.0/24'` | Always allow (optionally only from a source) |
| `-d 23` `-d 3306` | `-Deny 23,3389` | Never auto-allow. Combine with an `@CIDR` allow to *restrict* instead of block |
| `-t 100.64.0.0/10` | `-Trust 100.64.0.0/10` | Allow everything from a source (e.g. your team jump box) |
| `-y` | `-Yes` | No prompts; unknown listeners are blocked |
| `-r 300` | `-RollbackSeconds 300` | Rollback window (default 120 s) |
| `-b iptables` | | Force a backend |

Commands: `scan`, `apply`, `confirm`, `revert` (back to the previous confirmed rules), `off` (remove
everything this script added), `status`, `persist`, `unpersist`. Windows uses the same names via `-Action`.

Example: lock the database box so only the web tier can reach MySQL, keeping SSH:

```sh
sudo sh ccdc-fw.sh apply -d 3306 -a 3306/tcp@192.168.220.0/24
```

## Safety nets

- **Auto-rollback.** A detached timer (`setsid` on Linux, a SYSTEM scheduled task on Windows) restores the
  previous state if you don't confirm, even if your SSH/RDP session dies.
- **Established connections survive**, so applying never kicks you off the box you're on.
- **Linux never flushes anything.** It only manages its own `inet ccdc_fw` nft table or `CCDC_IN` iptables
  chain, so Docker, Kubernetes, firewalld and ufw rules are left alone. The nft ruleset is validated
  (`nft -c`) and loaded atomically.
- **Windows** exports the full policy (`netsh advfirewall export`) before every apply; `off` restores the
  policy from before the first run.
- **Tamper check** (`persist`): every minute, and at boot, the rules are compared against what was applied
  and re-applied if they were flushed, edited, a rogue inbound rule was enabled, or the firewall was turned
  off. Findings go to the log.
- State/log directories are root/SYSTEM-only (`/etc/ccdc-fw` mode 700; `C:\ProgramData\ccdc-fw` ACL
  limited to SYSTEM and Administrators), so a low-priv user can't swap the script that SYSTEM/root runs.

Logs for incident reports: `/etc/ccdc-fw/ccdc-fw.log` and `C:\ProgramData\ccdc-fw\ccdc-fw.log`. Dropped
packets are logged with the prefix `ccdc-fw drop:` (`journalctl -k | grep ccdc-fw`) and to
`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`.

## Competition playbook

1. **Inventory first.** `scan` on every box. Compare against the scored services in the scoring engine.
2. Make sure every scored service is **running** before you apply. A service that's down at scan time
   isn't detected. The Linux script warns about enabled-but-stopped units, but for anything else use `--allow`.
3. `apply` one box at a time. While the timer runs, check the scoreboard / curl the service from another box.
   Answer `y` only when everything scored is still green.
4. `persist` once you're happy.
5. Re-run `apply` whenever you add or move a service. The previous confirmed rules stay as the rollback point.

Things the scripts deliberately don't do:

- **Egress filtering.** Valuable against reverse shells, but easy to break scoring with. Do it on the
  router once you know the scoring engine's IPs.
- **FTP passive mode.** Uses the configured `pasv_min_port`/`pasv_max_port` (vsftpd), `PassivePorts`
  (proftpd) or pure-ftpd's range when one is set, and otherwise the conntrack FTP helper. If passive
  transfers fail, pin a range in the FTP config and re-run.
- **Group Policy firewall rules** on domain members override local policy. The Windows script warns when it
  sees GPO inbound allow rules. Check the DC's GPOs if the red team owns it.

## The router (OPNsense)

A router reset costs 100 points and a mistake can cut off the scoring engine, so there is no router
automation here. Recommended order:

1. Back up first: *System → Configuration → Backups → Download*. *System → Configuration → History* can
   roll back any change.
2. Keep the anti-lockout rule and your own management access. Restrict the WebGUI/SSH to your team's
   VPN source instead of disabling it.
3. On WAN, allow inbound only to the hosts/ports that are scored. The 1:1 NAT maps `10.100.1XX.Y` to
   `192.168.220.Y`, so rules match the *internal* `192.168.220.Y` address. Use the same port list `scan` gives you.
4. Watch *Firewall → Log Files → Live View* for blocks from the scoring engine before you tighten anything else.
5. Only then consider LAN egress rules.

## Tests

```sh
sh tests/netns-test.sh nft          # rootless: runs in a throwaway network namespace
sh tests/netns-test.sh iptables
sh tests/distro-test.sh debian:trixie podman
```

The netns test starts real listeners (a "web server", a "node app", an unknown port and a fake `nc`),
applies the firewall, and checks from a second namespace that only the right ports answer. It also
covers confirm, `--allow`, revert, the rollback timer, tamper recovery and `off`. It has passed on Debian 12/13,
Ubuntu 22.04, Rocky 9, Arch and Alpine.
