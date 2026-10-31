#!/bin/sh
# ccdc-fw.sh - default-deny inbound firewall for Linux competition hosts.
#
# Scans what is listening, keeps the ports that look like real services,
# drops everything else inbound, and rolls back on its own unless you confirm.
# Uses nftables when it can and falls back to iptables. Plain POSIX sh, so it
# runs under bash, dash and busybox ash (Tiny Core).
#
# It only ever touches its own nft table / iptables chain, so Docker, k8s,
# firewalld and ufw rules are left alone.
#
#   sudo ./ccdc-fw.sh scan              dry run: show decisions and the ruleset
#   sudo ./ccdc-fw.sh apply             apply; auto-revert in 120s unless confirmed
#   sudo ./ccdc-fw.sh confirm           keep the rules
#   sudo ./ccdc-fw.sh revert            go back to the previous confirmed rules
#   sudo ./ccdc-fw.sh off               remove everything this script added
#   sudo ./ccdc-fw.sh status
#   sudo ./ccdc-fw.sh persist           re-apply at boot and every minute if tampered with
#
# Run "./ccdc-fw.sh help" for options.

set -u
umask 077

STATE_DIR=${CCDC_FW_DIR:-/etc/ccdc-fw}
TABLE=ccdc_fw
CHAIN=CCDC_IN
ROLLBACK_SECS=120
ASSUME_YES=0
BACKEND=auto
USER_ALLOW=""
USER_DENY=""
USER_TRUST=""
# Container/overlay interfaces: pod and container traffic to the host stays open.
TRUST_IFACES="docker* cni* flannel* cali* vxlan.calico cilium* weave* kube-bridge veth* br-* podman*"

# Well-known service ports. Listening on one of these = allowed.
KNOWN_PORTS="
21/tcp ftp
22/tcp ssh
23/tcp telnet(insecure!)
25/tcp smtp
53/tcp dns
53/udp dns
69/udp tftp
80/tcp http
88/tcp kerberos
88/udp kerberos
110/tcp pop3
111/tcp rpcbind
111/udp rpcbind
123/udp ntp
137/udp netbios-ns
138/udp netbios-dgm
139/tcp netbios-ssn
143/tcp imap
161/udp snmp
389/tcp ldap
389/udp ldap
443/tcp https
443/udp https-quic
445/tcp smb
464/tcp kpasswd
464/udp kpasswd
465/tcp smtps
514/udp syslog
587/tcp submission
636/tcp ldaps
990/tcp ftps
993/tcp imaps
995/tcp pop3s
1194/tcp openvpn
1194/udp openvpn
1433/tcp mssql
2049/tcp nfs
2049/udp nfs
3306/tcp mysql
3389/tcp rdp
3389/udp rdp
5432/tcp postgresql
5900/tcp vnc
5901/tcp vnc
5902/tcp vnc
8080/tcp http-alt
8443/tcp https-alt
27017/tcp mongodb
"

# Things that listen by default but nobody needs from the network.
NOISE_PORTS="
68/udp dhcp-client
323/udp chrony
546/udp dhcpv6-client
631/tcp cups
631/udp cups
1900/udp ssdp
3702/udp wsd
5353/udp mdns
5355/tcp llmnr
5355/udp llmnr
"

# systemd unit -> ports, used to warn about services that are enabled but down.
UNIT_PORTS="
sshd 22/tcp
ssh 22/tcp
nginx 80/tcp,443/tcp
apache2 80/tcp,443/tcp
httpd 80/tcp,443/tcp
lighttpd 80/tcp,443/tcp
mariadb 3306/tcp
mysql 3306/tcp
mysqld 3306/tcp
postgresql 5432/tcp
vsftpd 21/tcp
proftpd 21/tcp
postfix 25/tcp,587/tcp
dovecot 110/tcp,143/tcp,993/tcp,995/tcp
named 53/tcp,53/udp
bind9 53/tcp,53/udp
smbd 445/tcp,139/tcp
smb 445/tcp,139/tcp
xrdp 3389/tcp
"

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log()  { [ -d "$STATE_DIR" ] && printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$STATE_DIR/ccdc-fw.log"; }

need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }
have() { command -v "$1" >/dev/null 2>&1; }
have_tty() { ( : < /dev/tty ) 2>/dev/null; }

usage() {
	cat <<'EOF'
Usage: ccdc-fw.sh COMMAND [options]

Commands:
  scan        Dry run. Show what would be allowed/denied and the ruleset.
  apply       Scan, apply, then auto-revert after the rollback window unless confirmed.
  confirm     Keep the pending rules (cancels the rollback timer).
  revert      Restore the previous confirmed rules (or none).
  off         Remove all rules and the enforcer installed by this script.
  status      Show current state and rules.
  persist     Re-apply at boot and every minute if the rules were changed or flushed.
  unpersist   Remove the boot/minute enforcer.

Options:
  -a, --allow SPEC   Always allow. SPEC = PORT[-PORT][/tcp|udp][@CIDR], comma separated.
                     e.g. -a 8065 -a 3306/tcp@192.168.220.0/24 -a 6881-6889/udp
  -d, --deny  SPEC   Never auto-allow this port, even if a service listens on it.
                     e.g. -d 23 -d 3306  (combine with -a ...@CIDR to restrict instead)
  -t, --trust CIDR   Allow everything from CIDR (e.g. your team's jump host).
  -y, --yes          Don't ask about unknown listeners (they get blocked).
  -r, --rollback N   Rollback window in seconds (default 120).
  -b, --backend B    nft | iptables | auto (default auto).

State, rules and log live in /etc/ccdc-fw (override with CCDC_FW_DIR).
EOF
}

# ---------------------------------------------------------------- state

state_get() { # KEY -> value from state file
	[ -f "$STATE_DIR/state" ] || return 0
	sed -n "s/^$1=//p" "$STATE_DIR/state" | tail -n 1
}

state_set() { # KEY VALUE
	mkdir -p "$STATE_DIR"
	touch "$STATE_DIR/state"
	grep -v "^$1=" "$STATE_DIR/state" > "$STATE_DIR/state.tmp"
	printf '%s=%s\n' "$1" "$2" >> "$STATE_DIR/state.tmp"
	mv "$STATE_DIR/state.tmp" "$STATE_DIR/state"
}

lookup() { # LIST KEY
	printf '%s\n' "$1" | awk -v k="$2" '$1 == k { print $2; exit }'
}

# ---------------------------------------------------------------- scanning

# Prints one line per non-loopback listener: proto port addr proc pid
collect_listeners() {
	if have ss; then
		ss -lntup 2>/dev/null | awk 'NR > 1 {
			proto = $1; local = $5
			n = split(local, a, ":"); port = a[n]
			addr = substr(local, 1, length(local) - length(port) - 1)
			gsub(/[][]/, "", addr); sub(/%.*/, "", addr)
			proc = "-"; pid = "-"
			if (match($0, /users:\(\("[^"]+",pid=[0-9]+/)) {
				s = substr($0, RSTART + 9, RLENGTH - 9)
				i = index(s, "\",pid=")
				proc = substr(s, 1, i - 1); pid = substr(s, i + 6)
				gsub(/ /, "_", proc)
			}
			print proto, port, addr, proc, pid
		}'
	elif have netstat; then
		netstat -lntup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
			proto = $1; sub(/6$/, "", proto)
			n = split($4, a, ":"); port = a[n]
			addr = substr($4, 1, length($4) - length(port) - 1)
			proc = "-"; pid = "-"
			for (i = 5; i <= NF; i++) if ($i ~ /^[0-9]+\//) {
				pid = $i; sub(/\/.*/, "", pid)
				proc = $i; sub(/^[0-9]+\//, "", proc); sub(/:.*/, "", proc)
			}
			print proto, port, addr, proc, pid
		}'
	else
		die "need ss or netstat to find listening ports"
	fi | awk '$3 !~ /^(127\.|::1$|::ffff:127\.|fe80|localhost)/' | sort -k1,1 -k2,2n -u
}

is_server_proc() {
	case $1 in
	sshd|nginx*|apache2|httpd*|lighttpd|caddy|haproxy|traefik|envoy|squid|lshttpd|litespeed|\
	java|node|nodejs|bun|deno|dotnet|gunicorn*|uwsgi|uvicorn|hypercorn|puma*|unicorn*|php-fpm*|\
	mysqld|mariadbd|postgres|postmaster|mongod|dovecot|master|exim*|sendmail*|\
	named|unbound|dnsmasq|pdns*|coredns|smbd|nmbd|vsftpd|proftpd|pure-ftpd*|slapd|krb5kdc|kadmind|\
	xrdp|Xvnc*|Xtigervnc|x11vnc|vncserver|openvpn|ocserv|stunnel*|snmpd|rsyslogd|syslog-ng|\
	rpcbind|rpc.mountd|rpc.statd|docker-proxy|containerd*|k3s*|kubelet|kube-proxy|\
	jellyfin*|emby*|Plex*|gitea|gogs|grafana*|mattermost|prosody|beam.smp|minio|influxd|\
	mosquitto|xinetd|inetd|in.telnetd|telnetd|opentracker|chihaya|transmission*)
		return 0 ;;
	esac
	return 1
}

# Sets SUS_WHY when the listener looks like a shell / implant rather than a service.
is_suspicious() { # proc pid
	SUS_WHY=""
	case $1 in
	nc|nc.*|ncat|netcat|socat|sh|bash|dash|zsh|ash|ksh|csh|tcsh|fish|perl|lua|awk|gawk|mawk|telnet|openssl)
		SUS_WHY="shell/netcat-style process"; return 0 ;;
	esac
	if [ "$2" != - ] && exe=$(readlink "/proc/$2/exe" 2>/dev/null); then
		case $exe in
		/tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/home/*/.*)
			SUS_WHY="runs from $exe"; return 0 ;;
		esac
	fi
	return 1
}

# Normalise "PORT[/proto]" to "PORT/proto".
norm_port() {
	case $1 in */*) printf '%s\n' "$1" ;; *) printf '%s/tcp\n' "$1" ;; esac
}

# Parses an --allow SPEC into SP_PORT SP_PROTO SP_SRC.
parse_spec() {
	s=$1; SP_SRC=any; SP_PROTO=tcp
	case $s in *@*) SP_SRC=${s#*@}; s=${s%%@*} ;; esac
	case $s in */*) SP_PROTO=${s#*/}; s=${s%%/*} ;; esac
	SP_PORT=$s
	case $SP_PROTO in tcp|udp) ;; *) return 1 ;; esac
	case $SP_PORT in ''|*[!0-9-]*|-*|*-|*-*-*) return 1 ;; esac
	case $SP_SRC in any) ;; ''|*[!0-9a-fA-F.:/]*) return 1 ;; esac
	return 0
}

session_port() {
	# SSH_CONNECTION = "client_ip client_port server_ip server_port" (often dropped by sudo)
	# shellcheck disable=SC2086
	set -- ${SSH_CONNECTION:-}
	[ $# -eq 4 ] && printf '%s\n' "$4"
}

# Decide what to do with one listener. Sets DEC (ALLOW|DENY|ASK) and WHY.
decide() { # proto port proc pid
	key="$2/$1"
	case " $USER_DENY " in *" $key "*)
		if [ "$1" = tcp ] && [ "$2" = "$SESSION_PORT" ]; then
			DEC=ALLOW; WHY="your SSH session (ignoring --deny)"; return
		fi
		DEC=DENY; WHY="--deny"; return ;;
	esac
	if [ "$1" = tcp ] && [ "$2" = "$SESSION_PORT" ]; then DEC=ALLOW; WHY="your SSH session"; return; fi
	if is_suspicious "$3" "$4"; then DEC=DENY; WHY="SUSPICIOUS: $SUS_WHY"; return; fi
	n=$(lookup "$NOISE_PORTS" "$key")
	if [ -n "$n" ]; then DEC=DENY; WHY="not needed ($n)"; return; fi
	n=$(lookup "$KNOWN_PORTS" "$key")
	if [ -n "$n" ]; then DEC=ALLOW; WHY=$n; return; fi
	if is_server_proc "$3"; then DEC=ALLOW; WHY="server process"; return; fi
	if [ "$1" = udp ] && [ "$2" -ge 32768 ]; then DEC=DENY; WHY="ephemeral udp"; return; fi
	DEC=ASK; WHY="unknown"
}

# Builds $WORK/allow ("proto port src comment" lines) and $WORK/ftp.
# MODE=scan never prompts; MODE=apply asks about unknowns unless --yes.
plan() {
	MODE=$1
	SESSION_PORT=$(session_port)
	collect_listeners > "$WORK/listen"
	: > "$WORK/allow"
	: > "$WORK/ftp"

	[ "$(id -u)" = 0 ] || warn "not root: process names are hidden, so more ports will be 'unknown'"
	printf '\n%-12s %-5s %-18s %-6s %s\n' PORT PROTO PROCESS ACTION WHY
	printf '%-12s %-5s %-18s %-6s %s\n' ---- ----- ------- ------ ---
	while read -r proto port addr proc pid; do
		decide "$proto" "$port" "$proc" "$pid"
		if [ "$DEC" = ASK ]; then
			if [ "$MODE" = apply ] && [ "$ASSUME_YES" = 0 ] && have_tty; then
				exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "?")
				printf '  ? %s/%s on %s by %s (pid %s, %s) - allow? [y/N] ' \
					"$port" "$proto" "$addr" "$proc" "$pid" "$exe" > /dev/tty
				read -r ans < /dev/tty || ans=n
				case $ans in [yY]*) DEC=ALLOW; WHY="you said yes" ;; *) DEC=DENY; WHY="you said no" ;; esac
			elif [ "$MODE" = apply ]; then
				DEC=DENY; WHY="unknown (open it with --allow $port/$proto)"
			fi
		fi
		printf '%-12s %-5s %-18s %-6s %s\n' "$port" "$proto" "$proc" "$DEC" "$WHY"
		if [ "$DEC" = ALLOW ]; then
			printf '%s %s any %s\n' "$proto" "$port" "$(printf '%s' "$WHY" | tr -c 'A-Za-z0-9.()_ -' '_')" >> "$WORK/allow"
			[ "$proto/$port" = tcp/21 ] && echo 1 > "$WORK/ftp"
		fi
	done < "$WORK/listen"

	for spec in $USER_ALLOW; do
		parse_spec "$spec" || die "bad --allow spec: $spec"
		printf '%-12s %-5s %-18s %-6s %s\n' "$SP_PORT" "$SP_PROTO" "" ALLOW "--allow (from $SP_SRC)"
		printf '%s %s %s user-allow\n' "$SP_PROTO" "$SP_PORT" "$SP_SRC" >> "$WORK/allow"
		[ "$SP_PROTO/$SP_PORT" = tcp/21 ] && echo 1 > "$WORK/ftp"
	done
	for c in $USER_TRUST; do
		printf '%-12s %-5s %-18s %-6s %s\n' all any "" ALLOW "--trust $c"
	done

	# FTP passive data ports are not listening at scan time; open the configured range.
	if [ -s "$WORK/ftp" ]; then
		range=$(ftp_passive_range)
		if [ -n "$range" ]; then
			printf '%-12s %-5s %-18s %-6s %s\n' "$range" tcp "" ALLOW "ftp passive range"
			printf 'tcp %s any ftp-passive\n' "$range" >> "$WORK/allow"
		else
			warn "FTP has no fixed passive port range; relying on the conntrack ftp helper." \
				"If passive transfers fail, set pasv_min_port/pasv_max_port and re-run."
		fi
	fi
	sort -u "$WORK/allow" -o "$WORK/allow"

	warn_down_services
}

ftp_passive_range() {
	for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
		[ -f "$f" ] || continue
		lo=$(sed -n 's/^[[:space:]]*pasv_min_port=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
		hi=$(sed -n 's/^[[:space:]]*pasv_max_port=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
		[ -n "$lo" ] && [ -n "$hi" ] && { echo "$lo-$hi"; return; }
	done
	for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
		[ -f "$f" ] || continue
		r=$(awk 'tolower($1) == "passiveports" { print $2 "-" $3 }' "$f" | tail -n 1)
		[ -n "$r" ] && { echo "$r"; return; }
	done
	f=/etc/pure-ftpd/conf/PassivePortRange
	[ -f "$f" ] && awk '{ print $1 "-" $2; exit }' "$f"
}

warn_down_services() {
	have systemctl || return 0
	printf '%s\n' "$UNIT_PORTS" | while read -r unit ports; do
		[ -n "$unit" ] || continue
		systemctl is-enabled "$unit" >/dev/null 2>&1 || continue
		systemctl is-active "$unit" >/dev/null 2>&1 && continue
		warn "$unit is enabled but not running, so its ports ($ports) were not detected." \
			"If it is scored: start it and re-run, or add --allow $ports"
	done
}

# ---------------------------------------------------------------- rendering

render_nft() { # allowfile ftpflag
	echo "table inet $TABLE"
	echo "delete table inet $TABLE"
	echo "table inet $TABLE {"
	if [ -s "$2" ]; then
		printf '\tct helper ftp-standard {\n\t\ttype "ftp" protocol tcp;\n\t\tl3proto inet;\n\t}\n'
		printf '\tchain helpers {\n\t\ttype filter hook prerouting priority 0;\n'
		printf '\t\ttcp dport 21 ct helper set "ftp-standard"\n\t}\n'
	fi
	printf '\tchain input {\n'
	printf '\t\ttype filter hook input priority -10; policy drop;\n'
	printf '\t\tct state established,related accept\n'
	printf '\t\tiifname "lo" accept\n'
	for i in $TRUST_IFACES; do printf '\t\tiifname "%s" accept\n' "$i"; done
	printf '\t\tmeta l4proto icmp accept\n'
	printf '\t\tmeta l4proto ipv6-icmp accept\n'
	printf '\t\tudp sport 67 udp dport 68 accept\n'
	printf '\t\tudp sport 547 udp dport 546 accept\n'
	for c in $USER_TRUST; do
		case $c in *:*) fam=ip6 ;; *) fam=ip ;; esac
		printf '\t\t%s saddr %s accept comment "trusted"\n' "$fam" "$c"
	done
	while read -r proto port src comment; do
		if [ "$src" = any ]; then
			printf '\t\t%s dport %s accept comment "%s"\n' "$proto" "$port" "$comment"
		else
			case $src in *:*) fam=ip6 ;; *) fam=ip ;; esac
			printf '\t\t%s saddr %s %s dport %s accept comment "%s"\n' "$fam" "$src" "$proto" "$port" "$comment"
		fi
	done < "$1"
	printf '\t\tlimit rate 10/minute burst 20 packets log prefix "ccdc-fw drop: "\n'
	printf '\t}\n}\n'
}

# One rule per line: FAMILY ARGS...  ("4?" / "6?" = optional, failure ignored).
render_ipt() { # allowfile ftpflag
	for f in 4 6; do
		echo "$f -i lo -j ACCEPT"
		for i in $TRUST_IFACES; do
			case $i in *\*) i="${i%\*}+" ;; esac
			echo "$f -i $i -j ACCEPT"
		done
	done
	echo "4 -p icmp -j ACCEPT"
	echo "6 -p ipv6-icmp -j ACCEPT"
	echo "4 -p udp --sport 67 --dport 68 -j ACCEPT"
	echo "6 -p udp --sport 547 --dport 546 -j ACCEPT"
	for c in $USER_TRUST; do
		case $c in *:*) echo "6 -s $c -j ACCEPT" ;; *) echo "4 -s $c -j ACCEPT" ;; esac
	done
	while read -r proto port src comment; do
		p=$(printf '%s' "$port" | tr - :)
		if [ "$src" = any ]; then
			echo "4 -p $proto --dport $p -j ACCEPT"
			echo "6 -p $proto --dport $p -j ACCEPT"
		else
			case $src in *:*) f=6 ;; *) f=4 ;; esac
			echo "$f -s $src -p $proto --dport $p -j ACCEPT"
		fi
	done < "$1"
	for f in 4 6; do
		echo "$f? -m limit --limit 10/min --limit-burst 20 -j LOG --log-prefix ccdc-fw-drop:"
		echo "$f -j DROP"
	done
	[ -s "$2" ] && echo "@ftp"
	return 0
}

# ---------------------------------------------------------------- backends

pick_backend() {
	case $BACKEND in
	nft|iptables) echo "$BACKEND"; return ;;
	esac
	if have nft && nft add table inet ccdc_probe 2>/dev/null; then
		nft delete table inet ccdc_probe 2>/dev/null
		echo nft
	elif have iptables; then
		echo iptables
	else
		die "neither a working nft nor iptables was found"
	fi
}

ipt_for() { if [ "$1" = 4 ]; then echo iptables; else echo ip6tables; fi; }

ipt_family_ok() { have "$1" && "$1" -S INPUT >/dev/null 2>&1; }

nft_apply() { # rulesfile
	have modprobe && modprobe nf_conntrack_ftp 2>/dev/null
	nft -f "$1"
}

nft_remove() { nft delete table inet "$TABLE" 2>/dev/null; return 0; }

nft_hash() { nft list table inet "$TABLE" 2>/dev/null | cksum; }

ipt_apply() { # rulesfile
	set -f
	ftp=0; grep -q '^@ftp' "$1" && ftp=1
	[ "$ftp" = 1 ] && have modprobe && modprobe nf_conntrack_ftp 2>/dev/null
	for fam in 4 6; do
		ipt=$(ipt_for $fam)
		ipt_family_ok "$ipt" || { [ $fam = 4 ] && { set +f; return 1; }; continue; }
		$ipt -N CCDC_NEW 2>/dev/null || $ipt -F CCDC_NEW
		$ipt -A CCDC_NEW -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
			$ipt -A CCDC_NEW -m state --state ESTABLISHED,RELATED -j ACCEPT
		grep -E "^$fam\\??( |\$)" "$1" > "$WORK/ipt.$fam"
		while read -r tag args; do
			# shellcheck disable=SC2086
			if ! $ipt -A CCDC_NEW $args 2>/dev/null; then
				case $tag in *\?) continue ;; esac
				warn "$ipt rejected: $args"
				$ipt -F CCDC_NEW; $ipt -X CCDC_NEW
				set +f; return 1
			fi
		done < "$WORK/ipt.$fam"
		# Swap the new chain in, then drop the old one.
		$ipt -I INPUT 1 -j CCDC_NEW
		while $ipt -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
		$ipt -F "$CHAIN" 2>/dev/null; $ipt -X "$CHAIN" 2>/dev/null
		$ipt -E CCDC_NEW "$CHAIN"
		if [ "$ftp" = 1 ]; then
			$ipt -t raw -C PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null ||
				$ipt -t raw -I PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null ||
				warn "could not enable the ftp conntrack helper ($ipt)"
		fi
	done
	set +f
}

ipt_remove() {
	for fam in 4 6; do
		ipt=$(ipt_for $fam)
		ipt_family_ok "$ipt" || continue
		for c in "$CHAIN" CCDC_NEW; do
			while $ipt -D INPUT -j "$c" 2>/dev/null; do :; done
			$ipt -F "$c" 2>/dev/null; $ipt -X "$c" 2>/dev/null
		done
		while $ipt -t raw -D PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null; do :; done
	done
	return 0
}

ipt_hash() {
	for fam in 4 6; do
		ipt=$(ipt_for $fam)
		ipt_family_ok "$ipt" && $ipt -S "$CHAIN" 2>/dev/null
	done | cksum
}

# True when our jump is in INPUT and no ACCEPT sits in front of it.
ipt_jump_ok() {
	for fam in 4 6; do
		ipt=$(ipt_for $fam)
		ipt_family_ok "$ipt" || continue
		$ipt -S INPUT | awk -v c="-j $CHAIN" '
			index($0, c) { found = 1; exit }
			/ -j ACCEPT/ { bad = 1 }
			END { exit (found && !bad) ? 0 : 1 }' || return 1
	done
}

rules_file() { if [ "$1" = nft ]; then echo "$STATE_DIR/rules.nft"; else echo "$STATE_DIR/rules.ipt"; fi; }

load_rules() { # backend file
	if [ "$1" = nft ]; then nft_apply "$2"; else ipt_apply "$2"; fi || return 1
	if [ "$1" = nft ]; then state_set HASH "$(nft_hash)"; else state_set HASH "$(ipt_hash)"; fi
}

remove_rules() { # backend
	if [ "$1" = nft ]; then nft_remove; else ipt_remove; fi
}

# ---------------------------------------------------------------- rollback timer

kill_timer() {
	pid=$(cat "$STATE_DIR/timer.pid" 2>/dev/null) || return 0
	[ -n "$pid" ] && kill "$pid" 2>/dev/null
	rm -f "$STATE_DIR/timer.pid"
}

start_timer() {
	kill_timer
	# Detached from this shell so it still fires if your SSH session dies.
	if have setsid; then ss_cmd=setsid; else ss_cmd=""; fi
	$ss_cmd nohup sh -c "echo \$\$ > '$STATE_DIR/timer.pid'; sleep $ROLLBACK_SECS; exec '$STATE_DIR/ccdc-fw.sh' __timer" \
		</dev/null >/dev/null 2>&1 &
	i=0
	while [ ! -s "$STATE_DIR/timer.pid" ] && [ $i -lt 20 ]; do sleep 0.1 2>/dev/null || sleep 1; i=$((i + 1)); done
	[ -s "$STATE_DIR/timer.pid" ] || die "could not start the rollback timer; nothing applied"
}

# ---------------------------------------------------------------- commands

cmd_scan() {
	plan scan
	be=$(pick_backend 2>/dev/null || echo nft)
	say ""
	say "Ruleset that 'apply' would load ($be backend):"
	say ""
	if [ "$be" = nft ]; then render_nft "$WORK/allow" "$WORK/ftp"; else render_ipt "$WORK/allow" "$WORK/ftp"; fi
	say ""
	say "Unknown (ASK) ports are asked about during apply, or blocked with --yes."
}

cmd_apply() {
	need_root
	mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
	[ -f "$0" ] || die "run this from a file (not curl | sh) so the rollback timer can call it"
	if [ "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" != "$STATE_DIR/ccdc-fw.sh" ]; then
		cp "$0" "$STATE_DIR/ccdc-fw.sh"
	fi
	chmod 700 "$STATE_DIR/ccdc-fw.sh"

	plan apply
	be=$(pick_backend) || exit 1
	new=$(rules_file "$be")

	old_be=$(state_get BACKEND)
	status=$(state_get STATUS)
	if [ "$status" = confirmed ] && [ -n "$old_be" ]; then
		cp "$(rules_file "$old_be")" "$STATE_DIR/rules.prev" 2>/dev/null && state_set PREV_BACKEND "$old_be"
	elif [ "$status" != pending ]; then
		rm -f "$STATE_DIR/rules.prev"; state_set PREV_BACKEND ""
	fi
	# Switching backend: clear the old one so they don't stack.
	[ -n "$old_be" ] && [ "$old_be" != "$be" ] && remove_rules "$old_be"

	if [ "$be" = nft ]; then render_nft "$WORK/allow" "$WORK/ftp"; else render_ipt "$WORK/allow" "$WORK/ftp"; fi > "$new.tmp"
	if [ "$be" = nft ] && ! nft -c -f "$new.tmp" 2>"$WORK/err"; then
		cat "$WORK/err" >&2; die "nft rejected the generated ruleset; nothing applied ($new.tmp)"
	fi
	mv "$new.tmp" "$new"

	state_set BACKEND "$be"
	state_set STATUS pending
	start_timer
	if ! load_rules "$be" "$new"; then
		kill_timer; do_revert; die "applying rules failed; reverted"
	fi
	log "applied ($be): $(awk '{ printf "%s/%s ", $2, $1 }' "$WORK/allow")"

	say ""
	say "Rules are live ($be). They roll back in ${ROLLBACK_SECS}s unless confirmed."
	say "Check your services now (open a NEW ssh session too)."
	if [ -t 0 ]; then
		printf 'Keep these rules? [y/N] '
		read -r ans || ans=n
		case $ans in [yY]*) cmd_confirm ;; *) kill_timer; do_revert ;; esac
	else
		say "Then run: $STATE_DIR/ccdc-fw.sh confirm"
	fi
}

cmd_confirm() {
	need_root
	if [ "$(state_get STATUS)" != pending ]; then
		die "nothing pending (status: $(state_get STATUS)). If the timer already fired, run apply again."
	fi
	kill_timer
	state_set STATUS confirmed
	rm -f "$STATE_DIR/rules.prev"
	log "confirmed"
	say "Confirmed. Rules stay in place. Run '$STATE_DIR/ccdc-fw.sh persist' to survive reboots/flushes."
}

do_revert() {
	be=$(state_get BACKEND)
	prev_be=$(state_get PREV_BACKEND)
	[ -n "$be" ] && remove_rules "$be"
	if [ -n "$prev_be" ] && [ -f "$STATE_DIR/rules.prev" ]; then
		mv "$STATE_DIR/rules.prev" "$(rules_file "$prev_be")"
		state_set BACKEND "$prev_be"
		if load_rules "$prev_be" "$(rules_file "$prev_be")"; then
			state_set STATUS confirmed
			log "reverted to previous confirmed rules"
			say "Reverted to the previous confirmed rules."
			return
		fi
		remove_rules "$prev_be"
	fi
	state_set STATUS reverted
	log "reverted: no rules from this script are active"
	say "Reverted: no rules from this script are active."
}

cmd_revert() { need_root; kill_timer; do_revert; }

cmd_timer() {
	rm -f "$STATE_DIR/timer.pid"
	[ "$(state_get STATUS)" = pending ] || exit 0
	log "rollback timer fired"
	do_revert
}

cmd_off() {
	need_root
	kill_timer
	cmd_unpersist >/dev/null 2>&1
	nft_remove 2>/dev/null
	have iptables && ipt_remove
	state_set STATUS off
	rm -f "$STATE_DIR/rules.prev"
	log "off"
	say "All rules from this script removed."
}

cmd_status() {
	say "status:   $(state_get STATUS)"
	say "backend:  $(state_get BACKEND)"
	if [ -s "$STATE_DIR/timer.pid" ]; then say "rollback: timer running (pid $(cat "$STATE_DIR/timer.pid"))"; fi
	if [ -f /etc/systemd/system/ccdc-fw.timer ] || crontab -l 2>/dev/null | grep -q ccdc-fw; then
		say "persist:  enabled"
	else
		say "persist:  no"
	fi
	say ""
	case $(state_get BACKEND) in
	nft) nft list table inet "$TABLE" 2>/dev/null || say "(table $TABLE not loaded)" ;;
	iptables) iptables -S "$CHAIN" 2>/dev/null || say "(chain $CHAIN not loaded)" ;;
	esac
	if [ -f "$STATE_DIR/ccdc-fw.log" ]; then say ""; say "recent log:"; tail -n 10 "$STATE_DIR/ccdc-fw.log"; fi
}

# Called every minute by the enforcer: put the rules back if they were flushed/edited.
cmd_enforce() {
	[ "$(state_get STATUS)" = confirmed ] || exit 0
	be=$(state_get BACKEND)
	f=$(rules_file "$be")
	[ -f "$f" ] || exit 0
	if [ "$be" = nft ]; then
		[ "$(nft_hash)" = "$(state_get HASH)" ] && exit 0
	else
		[ "$(ipt_hash)" = "$(state_get HASH)" ] && ipt_jump_ok && exit 0
	fi
	log "TAMPER: rules missing or changed, re-applying"
	load_rules "$be" "$f" || log "re-apply FAILED"
}

cmd_persist() {
	need_root
	[ "$(state_get STATUS)" = confirmed ] || die "confirm the rules first"
	if have systemctl && [ -d /run/systemd/system ]; then
		cat > /etc/systemd/system/ccdc-fw.service <<EOF
[Unit]
Description=ccdc-fw inbound firewall (apply + tamper check)
After=local-fs.target

[Service]
Type=oneshot
Environment=CCDC_FW_DIR=$STATE_DIR
ExecStart=$STATE_DIR/ccdc-fw.sh enforce

[Install]
WantedBy=multi-user.target
EOF
		cat > /etc/systemd/system/ccdc-fw.timer <<EOF
[Unit]
Description=ccdc-fw tamper check every minute

[Timer]
OnBootSec=15s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
		chmod 644 /etc/systemd/system/ccdc-fw.service /etc/systemd/system/ccdc-fw.timer
		systemctl daemon-reload
		systemctl enable ccdc-fw.service >/dev/null 2>&1
		systemctl enable --now ccdc-fw.timer
		say "Enforcer installed (systemd: ccdc-fw.service + ccdc-fw.timer)."
	elif have crontab; then
		{ crontab -l 2>/dev/null | grep -v ccdc-fw
		  echo "* * * * * CCDC_FW_DIR=$STATE_DIR $STATE_DIR/ccdc-fw.sh enforce >/dev/null 2>&1"
		  echo "@reboot CCDC_FW_DIR=$STATE_DIR $STATE_DIR/ccdc-fw.sh enforce >/dev/null 2>&1"
		} | crontab -
		say "Enforcer installed (root crontab)."
	else
		die "no systemd or crontab found; re-run apply after reboots"
	fi
	log "persist enabled"
}

cmd_unpersist() {
	need_root
	if [ -f /etc/systemd/system/ccdc-fw.timer ]; then
		systemctl disable --now ccdc-fw.timer >/dev/null 2>&1
		systemctl disable ccdc-fw.service >/dev/null 2>&1
		rm -f /etc/systemd/system/ccdc-fw.service /etc/systemd/system/ccdc-fw.timer
		systemctl daemon-reload
	fi
	if have crontab && crontab -l 2>/dev/null | grep -q ccdc-fw; then
		crontab -l 2>/dev/null | grep -v ccdc-fw | crontab -
	fi
	log "persist disabled"
	say "Enforcer removed."
}

# ---------------------------------------------------------------- main

CMD=${1:-help}
[ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
	case $1 in
	-a|--allow) USER_ALLOW="$USER_ALLOW $(printf '%s' "${2:?--allow needs a value}" | tr , ' ')"; shift ;;
	-d|--deny)
		for d in $(printf '%s' "${2:?--deny needs a value}" | tr , ' '); do USER_DENY="$USER_DENY $(norm_port "$d")"; done
		shift ;;
	-t|--trust)
		for c in $(printf '%s' "${2:?--trust needs a value}" | tr , ' '); do
			case $c in ''|*[!0-9a-fA-F.:/]*) die "bad --trust CIDR: $c" ;; esac
			USER_TRUST="$USER_TRUST $c"
		done
		shift ;;
	-y|--yes) ASSUME_YES=1 ;;
	-r|--rollback)
		ROLLBACK_SECS=${2:?--rollback needs seconds}; shift
		case $ROLLBACK_SECS in ''|*[!0-9]*) die "--rollback must be a number" ;; esac ;;
	-b|--backend)
		BACKEND=${2:?--backend needs a value}; shift
		case $BACKEND in nft|iptables|auto) ;; *) die "--backend must be nft, iptables or auto" ;; esac ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
	shift
done

WORK=$(mktemp -d 2>/dev/null || { d=/tmp/ccdc-fw.$$; mkdir -m 700 "$d" && echo "$d"; }) || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM

case $CMD in
scan) cmd_scan ;;
apply) cmd_apply ;;
confirm) cmd_confirm ;;
revert) cmd_revert ;;
off) cmd_off ;;
status) cmd_status ;;
enforce) cmd_enforce ;;
persist) cmd_persist ;;
unpersist) cmd_unpersist ;;
__timer) cmd_timer ;;
help|-h|--help) usage ;;
*) usage; exit 1 ;;
esac
