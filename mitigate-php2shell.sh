#!/usr/bin/env bash
#
# mitigate-php2shell.sh — apply the interim PHP2Shell mitigations
# (CVE-2026-109618 / CVE-2026-109619) on a server: PHP-FPM pools and Apache mod_php.
#
# What it sets (php.net 2026-10-21 announcement), at a level applications cannot override:
#   session.upload_progress.enabled = off      CVE-2026-109619
#   memory_limit = -1                          CVE-2026-109618
#   post_max_size = 8M (32M with uploads)      CVE-2026-109618
#   upload_max_filesize < post_max_size
#   fatal_error_backtraces = off               PHP 8.5 only
#   pm.max_requests = 500                      FPM: recycle workers
# plus, optionally, a systemd MemoryMax for the service, because memory_limit = -1
# needs a memory limit outside PHP.
#
# How: it adds ONE file next to the existing config, zz-php2shell-mitigation.conf.
# PHP-FPM keeps the FIRST php_admin_value/php_value it reads for a setting, so
# lines in existing pool files that set the same settings are commented out with
# the marker ";php2shell-disabled; " (rollback removes the marker). The config
# directory is backed up first, the service's config test must pass, and on a
# failed test everything is put back. If the script is stopped mid-change (error,
# Ctrl-C, kill) it undoes that change; after kill -9 or a power loss, run rollback.
# Rollback = remove the file and the markers, then restart.
#
# This is a mitigation, not a fix: upgrade PHP afterwards.
#
# Usage (run as root on the server):
#   mitigate-php2shell.sh plan     [options]   # default: show what would change, change nothing
#   mitigate-php2shell.sh apply    [options]   # write the files, config-test, (restart)
#   mitigate-php2shell.sh verify               # show effective values and whether a restart is pending
#   mitigate-php2shell.sh rollback [--restart] # remove every file this script added
#
# Options:
#   --post-max SIZE      post_max_size, default 8M (use 32M if the app accepts uploads)
#   --upload-max SIZE    upload_max_filesize, default 3/4 of --post-max
#   --max-requests N     pm.max_requests for FPM pools, default 500; 0 = leave as is
#   --memory-max VALUE   also add systemd MemoryMax=VALUE (e.g. 70% or 2G) and OOMPolicy=continue
#   --restart            restart services after a successful config test
#                        (default: print the restart command and stop there)
#   --pool-dir DIR --fpm-bin BIN --service NAME
#                        an FPM install in a non-standard place (all three together)
#   --allow-container    run inside a container anyway (testing only; containers
#                        should get the ini baked into the image instead)
#
set -euo pipefail

NAME=zz-php2shell-mitigation.conf
MARK=';php2shell-disabled; '
# Pool lines that would keep their old value over ours (FPM keeps the first one it reads).
CONFLICT='^[[:space:]]*php_(admin_)?(value|flag)\[(memory_limit|post_max_size|upload_max_filesize|session\.upload_progress\.enabled|fatal_error_backtraces)\]'
POST=8M; UPLOAD=""; MAXREQ=500; MEMMAX=""; RESTART=0; ALLOW_CT=0
X_POOL=""; X_BIN=""; X_SVC=""

die() { echo "error: $*" >&2; exit 2; }

to_mb() {
	case "$1" in
		*[0-9][Mm]) echo "${1%?}" ;;
		*[0-9][Gg]) echo $(( ${1%?} * 1024 )) ;;
		*) echo "" ;;
	esac
}

# ---- discover what is on this server ---------------------------------------

# Prints "pooldir|fpm binary|service" for each FPM install found.
fpm_installs() {
	local d v n
	if [ -n "$X_POOL" ]; then echo "$X_POOL|$X_BIN|$X_SVC"; return; fi
	for d in /etc/php/*/fpm/pool.d; do                       # Debian / Ubuntu (incl. sury)
		[ -d "$d" ] || continue
		v=${d#/etc/php/}; v=${v%%/*}
		[ -x "/usr/sbin/php-fpm$v" ] && echo "$d|/usr/sbin/php-fpm$v|php$v-fpm"
	done
	if [ -d /etc/php-fpm.d ] && [ -x /usr/sbin/php-fpm ]; then # RHEL / Alma / Rocky / Amazon Linux
		echo "/etc/php-fpm.d|/usr/sbin/php-fpm|php-fpm"
	fi
	for d in /etc/opt/remi/php*/php-fpm.d; do                # Remi SCL packages
		[ -d "$d" ] || continue
		n=${d#/etc/opt/remi/}; n=${n%%/*}
		[ -x "/opt/remi/$n/root/usr/sbin/php-fpm" ] && echo "$d|/opt/remi/$n/root/usr/sbin/php-fpm|$n-php-fpm"
	done
	return 0
}

# Prints "confdir|enable command|service|ctl" when Apache has mod_php loaded.
apache_install() {
	local ctl mods
	for ctl in apache2ctl apachectl; do
		command -v "$ctl" >/dev/null 2>&1 || continue
		mods=$("$ctl" -M 2>/dev/null) || {
			echo "warning: '$ctl -M' failed (is the Apache config already broken?): Apache skipped, fix it first" >&2
			return 0
		}
		printf '%s\n' "$mods" | grep -qiE 'php[0-9]*_module' || return 0
		if [ -d /etc/apache2/conf-available ]; then
			echo "/etc/apache2/conf-available|a2enconf ${NAME%.conf}|apache2|$ctl"
		elif [ -d /etc/httpd/conf.d ]; then
			echo "/etc/httpd/conf.d||httpd|$ctl"
		fi
		return 0
	done
}

# Pool names defined in a pool directory (our own file excluded).
pool_names() {
	grep -hE '^[[:space:]]*\[[^]]+\]' "$1"/*.conf 2>/dev/null | grep -v "$NAME" \
		| sed -E 's/^[[:space:]]*\[([^]]+)\].*/\1/' | grep -vx global | sort -u
}

# Existing pool lines that set the same settings: "file:line:text".
fpm_conflicts() {
	local f
	for f in "$1"/*.conf; do
		[ -f "$f" ] && [ "${f##*/}" != "$NAME" ] || continue
		grep -nHE "$CONFLICT" "$f" 2>/dev/null || true
	done
}

disable_conflicts() { # comment the conflicting lines out with $MARK
	local f
	for f in $(fpm_conflicts "$1" | cut -d: -f1 | sort -u); do
		sed -i -E "s/($CONFLICT.*)\$/$MARK\1/" "$f"
	done
}

restore_conflicts() { # remove $MARK again
	local f
	for f in "$1"/*.conf; do
		[ -f "$f" ] && grep -q "^$MARK" "$f" && sed -i "s/^$MARK//" "$f"
	done
	return 0
}

# pm.max_requests a pool already sets in the existing files (last one wins), empty if none.
existing_maxreq() { # existing_maxreq <pooldir> <pool>
	local f files=()
	for f in "$1"/*.conf; do [ -f "$f" ] && [ "${f##*/}" != "$NAME" ] && files+=("$f"); done
	[ ${#files[@]} -gt 0 ] || return 0
	awk -v want="$2" '
		/^[[:space:]]*\[[^]]+\]/ { s = $0; gsub(/^[[:space:]]*\[|\].*$/, "", s); cur = s; next }
		cur == want && /^[[:space:]]*pm\.max_requests[[:space:]]*=/ { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:];].*$/, "", v); val = v }
		END { print val }' "${files[@]}"
}

in_container() {
	[ -f /.dockerenv ] || grep -qE 'kubepods|docker|containerd' /proc/1/cgroup 2>/dev/null
}

# ---- file contents -----------------------------------------------------------

header() {
	echo "; Added by mitigate-php2shell.sh on $(date -u +%Y-%m-%dT%H:%MZ): temporary PHP2Shell mitigation"
	echo "; (CVE-2026-109618 / CVE-2026-109619). Roll back: delete this file and restart the service."
}

fpm_content() { # fpm_content <pooldir> <fpm binary>
	local pool ver cur
	ver=$("$2" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
	header
	for pool in $(pool_names "$1"); do
		echo "[$pool]"
		echo "php_admin_flag[session.upload_progress.enabled] = off"
		echo "php_admin_value[memory_limit] = -1"
		echo "php_admin_value[post_max_size] = $POST"
		echo "php_admin_value[upload_max_filesize] = $UPLOAD"
		[ "$ver" != 8.5 ] || echo "php_admin_flag[fatal_error_backtraces] = off"
		# never raise a stricter value the pool already has (lower = workers recycled more often)
		cur=$(existing_maxreq "$1" "$pool")
		if [ "$MAXREQ" != 0 ] && { [ -z "$cur" ] || [ "$cur" = 0 ] || [ "$cur" -gt "$MAXREQ" ]; }; then
			echo "pm.max_requests = $MAXREQ"
		fi
	done
}

apache_content() {
	local m
	header | sed 's/^;/#/'
	for m in php_module php7_module php5_module; do
		echo "<IfModule $m>"
		echo "    php_admin_flag session.upload_progress.enabled off"
		echo "    php_admin_value memory_limit -1"
		echo "    php_admin_value post_max_size $POST"
		echo "    php_admin_value upload_max_filesize $UPLOAD"
		echo "</IfModule>"
	done
}

systemd_content() {
	echo "# Added by mitigate-php2shell.sh: memory limit outside PHP, needed with memory_limit = -1"
	echo "[Service]"
	echo "MemoryMax=$MEMMAX"
	echo "OOMPolicy=continue"
}

container_snippet() {
	cat <<EOF
This looks like a container. Do not edit a running container (changes are lost on restart).
Bake this into the image instead, e.g. /usr/local/etc/php/conf.d/zz-mitigation.ini
for the official php image, then rebuild and redeploy:

session.upload_progress.enabled = 0
memory_limit = -1
post_max_size = $POST
upload_max_filesize = $UPLOAD

and set a container memory limit (--memory, or resources.limits.memory in Kubernetes).
EOF
}

# ---- service helpers -----------------------------------------------------------

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

restart_cmd() {
	if has_systemd; then echo "systemctl restart $1"; else echo "service $1 restart"; fi
}

# Epoch seconds the service's main process started, empty if unknown.
# Without systemd: the longest-running non-zombie process whose command line contains $2.
service_start() { # service_start <service> [process pattern]
	local pid="" et=""
	if has_systemd; then pid=$(systemctl show -p MainPID "$1" 2>/dev/null | cut -d= -f2); fi
	if [ -n "$pid" ] && [ "$pid" != 0 ]; then
		et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
	else
		et=$(ps -eo stat=,etimes=,args= 2>/dev/null | awk -v pat="${2:-$1}" \
			'$1 !~ /^Z/ && index($0, pat) && $2 > m { m = $2 } END { if (m != "") print m }')
	fi
	[ -z "$et" ] || echo $(( $(date +%s) - et ))
	return 0
}

# ---- safety net ------------------------------------------------------------------

# While a config directory is being changed, INFLIGHT names it ("fpm|<pooldir>" or
# "apache|<confdir>|<enable command>"). If the script stops before the change is
# confirmed (error, Ctrl-C, kill), the EXIT trap undoes it.
INFLIGHT=""
undo_inflight() {
	local kind dir enable
	[ -n "$INFLIGHT" ] || return 0
	IFS='|' read -r kind dir enable <<<"$INFLIGHT"
	rm -f "$dir/$NAME"
	if [ "$kind" = fpm ]; then restore_conflicts "$dir"; fi
	if [ "$kind" = apache ] && [ -n "$enable" ]; then a2disconf "${NAME%.conf}" >/dev/null 2>&1 || true; fi
	echo "stopped during the change: removed $dir/$NAME and restored the original lines" >&2
	INFLIGHT=""
}
trap undo_inflight EXIT
trap 'exit 130' INT TERM

# ---- modes ---------------------------------------------------------------------

do_plan() {
	local line pooldir bin svc found=0
	echo "Settings: post_max_size=$POST upload_max_filesize=$UPLOAD pm.max_requests=$MAXREQ${MEMMAX:+ MemoryMax=$MEMMAX}"
	echo
	while IFS='|' read -r pooldir bin svc; do
		[ -n "$pooldir" ] || continue
		found=1
		echo "== PHP-FPM: $bin ($svc)"
		echo "-- would write $pooldir/$NAME:"
		fpm_content "$pooldir" "$bin"
		[ -z "$MEMMAX" ] || { echo "-- would write /etc/systemd/system/$svc.service.d/$NAME:"; systemd_content; }
		echo "-- would comment out these existing lines (FPM keeps the first value it reads):"
		fpm_conflicts "$pooldir" | sed 's/^/   /' | grep . || echo "   none"
		echo "-- then: $bin -t && $(restart_cmd "$svc")"
		echo
	done < <(fpm_installs)
	line=$(apache_install)
	if [ -n "$line" ]; then
		IFS='|' read -r pooldir _ svc _ <<<"$line"
		found=1
		echo "== Apache mod_php ($svc)"
		echo "-- would write $pooldir/$NAME:"
		apache_content
		[ -z "$MEMMAX" ] || { echo "-- would write /etc/systemd/system/$svc.service.d/$NAME:"; systemd_content; }
		echo "-- then: configtest && $(restart_cmd "$svc")"
		echo "-- existing PHP settings in Apache config that may override this (vhost level wins):"
		grep -rnE 'php_(admin_)?(value|flag)[[:space:]]+(memory_limit|post_max_size|upload_max_filesize|session\.upload_progress)' \
			/etc/apache2 /etc/httpd 2>/dev/null | grep -v "$NAME" || echo "   none"
		echo
	fi
	[ "$found" = 1 ] || echo "No PHP-FPM pool directory or Apache mod_php found. Use --pool-dir/--fpm-bin/--service for other layouts."
}

backup_dir() { # backup_dir <dir> -> prints the archive path; fails if no backup was made
	local dest="/var/backups/php2shell-$(date +%Y%m%d%H%M%S)-$(echo "$1" | tr / _).tgz"
	command -v tar >/dev/null 2>&1 || return 1
	mkdir -p /var/backups && tar -czf "$dest" -C / "${1#/}" 2>/dev/null && [ -s "$dest" ] || return 1
	echo "$dest"
}

write_systemd() { # write_systemd <service>
	[ -n "$MEMMAX" ] || return 0
	has_systemd || { echo "   no systemd: set a memory limit for $1 another way"; return 0; }
	mkdir -p "/etc/systemd/system/$1.service.d"
	systemd_content > "/etc/systemd/system/$1.service.d/$NAME"
	systemctl daemon-reload
	echo "   wrote /etc/systemd/system/$1.service.d/$NAME"
}

do_apply() {
	local line pooldir bin svc enable ctl content bk rc=0
	[ "$(id -u)" = 0 ] || die "apply must run as root"
	while IFS='|' read -r pooldir bin svc; do
		[ -n "$pooldir" ] || continue
		echo "== PHP-FPM: $bin ($svc)"
		[ -n "$(pool_names "$pooldir")" ] || { echo "   no pool section found in $pooldir/*.conf, skipped"; rc=1; continue; }
		# build everything first: nothing on disk changes if this fails
		content=$(fpm_content "$pooldir" "$bin") || { echo "   could not build the config, skipped (nothing changed)"; rc=1; continue; }
		bk=$(backup_dir "$pooldir") || { echo "   backup of $pooldir failed (is tar installed?), skipped (nothing changed)"; rc=1; continue; }
		echo "   backup: $bk"
		fpm_conflicts "$pooldir" | sed 's/^/   commenting out: /'
		INFLIGHT="fpm|$pooldir"
		disable_conflicts "$pooldir"
		printf '%s\n' "$content" > "$pooldir/$NAME"
		if ! "$bin" -t >/dev/null 2>&1; then
			{ "$bin" -t 2>&1 | tail -5 | sed 's/^/   /'; } || true
			rm -f "$pooldir/$NAME"; restore_conflicts "$pooldir"; INFLIGHT=""
			echo "   config test FAILED: removed $pooldir/$NAME and restored the commented lines, nothing changed"; rc=1; continue
		fi
		INFLIGHT=""
		echo "   wrote $pooldir/$NAME, config test OK"
		write_systemd "$svc"
		if [ "$RESTART" = 1 ]; then $(restart_cmd "$svc") && echo "   restarted $svc"; else echo "   NOT active yet, run: $(restart_cmd "$svc")"; fi
	done < <(fpm_installs)

	line=$(apache_install)
	if [ -n "$line" ]; then
		IFS='|' read -r pooldir enable svc ctl <<<"$line"
		echo "== Apache mod_php ($svc)"
		content=$(apache_content) || { echo "   could not build the config, skipped (nothing changed)"; rc=1; content=""; }
		if [ -n "$content" ] && ! bk=$(backup_dir "$pooldir"); then
			echo "   backup of $pooldir failed (is tar installed?), skipped (nothing changed)"; rc=1; content=""
		fi
	fi
	if [ -n "$line" ] && [ -n "$content" ]; then
		echo "   backup: $bk"
		INFLIGHT="apache|$pooldir|$enable"
		printf '%s\n' "$content" > "$pooldir/$NAME"
		[ -z "$enable" ] || $enable >/dev/null
		if ! "$ctl" configtest >/dev/null 2>&1; then
			{ "$ctl" configtest 2>&1 | tail -5 | sed 's/^/   /'; } || true
			[ -z "$enable" ] || a2disconf "${NAME%.conf}" >/dev/null 2>&1 || true
			rm -f "$pooldir/$NAME"; INFLIGHT=""
			echo "   config test FAILED: removed $pooldir/$NAME, nothing changed"; rc=1
		else
			INFLIGHT=""
			echo "   wrote $pooldir/$NAME, config test OK"
			write_systemd "$svc"
			if [ "$RESTART" = 1 ]; then $(restart_cmd "$svc") && echo "   restarted $svc"; else echo "   NOT active yet, run: $(restart_cmd "$svc")"; fi
		fi
	fi
	echo
	echo "Next: run '$0 verify', then check phpinfo() of the web SAPI (Local value column) once and delete that page."
	return $rc
}

do_verify() {
	local line pooldir bin svc enable ctl started mtime f
	while IFS='|' read -r pooldir bin svc; do
		[ -n "$pooldir" ] || continue
		echo "== PHP-FPM: $bin ($svc)"
		f="$pooldir/$NAME"
		if [ ! -f "$f" ]; then echo "   mitigation file missing: $f"; continue; fi
		echo "   mitigation file: $f"
		if [ -n "$(fpm_conflicts "$pooldir")" ]; then
			echo "   CONFLICT: these lines still set the same settings and win over the mitigation:"
			fpm_conflicts "$pooldir" | sed 's/^/     /'
		else
			echo "   no conflicting pool lines"
		fi
		started=$(service_start "$svc" "php-fpm: master"); mtime=$(stat -c %Y "$f")
		if [ -n "$started" ] && [ "$started" -ge "$mtime" ]; then echo "   service restarted after the change: yes"
		else echo "   service restarted after the change: NO or unknown, run: $(restart_cmd "$svc")"; fi
		has_systemd && echo "   $(systemctl show -p MemoryMax "$svc" 2>/dev/null)"
	done < <(fpm_installs)
	line=$(apache_install)
	if [ -n "$line" ]; then
		IFS='|' read -r pooldir enable svc ctl <<<"$line"
		f="$pooldir/$NAME"
		echo "== Apache mod_php ($svc)"
		if [ -f "$f" ]; then
			started=$(service_start "$svc"); mtime=$(stat -c %Y "$f")
			if [ -n "$started" ] && [ "$started" -ge "$mtime" ]; then echo "   service restarted after the change: yes"
			else echo "   service restarted after the change: NO or unknown, run: $(restart_cmd "$svc")"; fi
			has_systemd && echo "   $(systemctl show -p MemoryMax "$svc" 2>/dev/null)"
			echo "   mod_php values can only be confirmed with phpinfo() served by Apache"
		else
			echo "   mitigation file missing: $f"
		fi
	fi
}

do_rollback() {
	local f svc removed=0
	[ "$(id -u)" = 0 ] || die "rollback must run as root"
	command -v a2disconf >/dev/null 2>&1 && a2disconf "${NAME%.conf}" >/dev/null 2>&1 || true
	for f in /etc/php/*/fpm/pool.d/$NAME /etc/php-fpm.d/$NAME /etc/opt/remi/php*/php-fpm.d/$NAME \
		/etc/apache2/conf-available/$NAME /etc/httpd/conf.d/$NAME /etc/systemd/system/*.service.d/$NAME \
		${X_POOL:+$X_POOL/$NAME}; do
		[ -f "$f" ] || continue
		rm -f "$f"; echo "removed $f"; removed=1
	done
	for f in /etc/php/*/fpm/pool.d /etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d ${X_POOL:+$X_POOL}; do
		[ -d "$f" ] || continue
		if grep -lq "^$MARK" "$f"/*.conf 2>/dev/null; then restore_conflicts "$f"; echo "restored commented lines in $f"; removed=1; fi
	done
	[ "$removed" = 1 ] || { echo "nothing to roll back"; return 0; }
	has_systemd && systemctl daemon-reload
	for svc in $( { fpm_installs | cut -d'|' -f3; apache_install | cut -d'|' -f3; } | sort -u); do
		if [ "$RESTART" = 1 ]; then $(restart_cmd "$svc") && echo "restarted $svc"; else echo "run: $(restart_cmd "$svc")"; fi
	done
}

# ---- arguments -------------------------------------------------------------------

MODE="${1:-plan}"; [ $# -eq 0 ] || shift
case "$MODE" in plan|apply|verify|rollback) ;; -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;; *) die "unknown mode: $MODE (plan | apply | verify | rollback)" ;; esac
while [ $# -gt 0 ]; do
	case "$1" in
		--post-max)     POST="${2:?}"; shift 2 ;;
		--upload-max)   UPLOAD="${2:?}"; shift 2 ;;
		--max-requests) MAXREQ="${2:?}"; shift 2 ;;
		--memory-max)   MEMMAX="${2:?}"; shift 2 ;;
		--restart)      RESTART=1; shift ;;
		--pool-dir)     X_POOL="${2:?}"; shift 2 ;;
		--fpm-bin)      X_BIN="${2:?}"; shift 2 ;;
		--service)      X_SVC="${2:?}"; shift 2 ;;
		--allow-container) ALLOW_CT=1; shift ;;
		*) die "unknown option: $1" ;;
	esac
done
[ -n "$(to_mb "$POST")" ] || die "--post-max must look like 8M, 32M or 1G"
[ -n "$UPLOAD" ] || UPLOAD="$(( $(to_mb "$POST") * 3 / 4 ))M"
[ -n "$(to_mb "$UPLOAD")" ] || die "--upload-max must look like 6M or 24M"
[ "$(to_mb "$UPLOAD")" -lt "$(to_mb "$POST")" ] || die "upload_max_filesize ($UPLOAD) must be smaller than post_max_size ($POST)"
case "$MAXREQ" in ''|*[!0-9]*) die "--max-requests must be a number" ;; esac
if [ -n "$X_POOL$X_BIN$X_SVC" ] && { [ -z "$X_POOL" ] || [ -z "$X_BIN" ] || [ -z "$X_SVC" ]; }; then
	die "--pool-dir, --fpm-bin and --service go together"
fi
if in_container && [ "$ALLOW_CT" = 0 ] && [ "$MODE" != verify ]; then container_snippet; exit 0; fi

case "$MODE" in
	plan)     do_plan ;;
	apply)    do_apply ;;
	verify)   do_verify ;;
	rollback) do_rollback ;;
esac
