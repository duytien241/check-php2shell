#!/usr/bin/env bash
#
# check-php2shell.sh — classify PHP versions against the PHP2Shell fixes
# (CVE-2026-109618 / CVE-2026-109619) and sweep for indicators, read-only.
#
# Official fixed releases (php.net, 2026-10-21):
#     8.5.12   8.4.27   8.3.36   8.2.35
# - 7.4 / 8.0 / 8.1: no release; only the PHP security team's source backports
#   (php-src branches PHP-<x.y>-CVE-2026-109618-109619) or a vendor package.
# - 5.4 – 7.3: end-of-life, no fix.
# - -dev / alpha / beta / RC builds of a fixed number are still vulnerable.
#
# CAVEAT (read before trusting PATCHED): the version number is only decisive
# for php.net / docker-official builds. Debian, Ubuntu, Alpine and some vendors
# BACKPORT the fix WITHOUT changing MAJOR.MINOR.PATCH, so a build that looks
# unpatched (even on an EOL branch) may in fact be fixed.
# crictl mode also prints the package version (dpkg/apk) so you can check the
# vendor advisory, and recognises Ubuntu backports from USN-8948-1
# (22.04 php8.1 >= 8.1.2-1ubuntu2.28, 24.04 php8.3 >= 8.3.6-0ubuntu0.24.04.13,
# 26.04/26.10 php8.5 >= 8.5.4-0ubuntu1.5 / 8.5.9-0ubuntu2.1).
# Debian 12/13 bumped the number: 8.2.35-1~deb12u1 (DLA-4848-1), 8.4.27-1~deb13u1 (DSA-6574-1).
# No backport information found yet for deb.sury.org packages -> read the package changelog.
#
# Mitigations from php.net (reduce exposure, do not replace the fix):
#   memory_limit=-1 via php_admin_value (applications cannot override it),
#   session.upload_progress.enabled=0 in php.ini or the pool (not ini_set, not .user.ini),
#   post_max_size 8M (no uploads) or 32M, upload_max_filesize < post_max_size,
#   fatal_error_backtraces=0 (8.5 only). Restart every worker afterwards.
#
# Usage:
#   check-php2shell.sh classify 8.3.35          # one version string
#   check-php2shell.sh classify "$(php-fpm -v)" # accepts the full -v banner
#   check-php2shell.sh crictl [FILTER]          # run ON A NODE: scan every container
#                                               # with PHP; FILTER matches image,
#                                               # pod, container or namespace
#   check-php2shell.sh audit [HOURS] [--log-dir DIR]... # HOURS default 168 (7 days)
#                                               # read-only indicator sweep; extra log
#                                               # paths also via PHP2SHELL_LOG_PATHS=a:b
#   check-php2shell.sh url https://host/        # read X-Powered-By (one HEAD request)
#   check-php2shell.sh -h
#
# crictl mode is READ-ONLY (execs sh to read version, ini, pool config and
# packages), but it still touches production containers: get the owner's
# approval first. Try it locally with: CRI=docker check-php2shell.sh crictl
#
# Sources: php.net 2026-10-21; GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp;
# nuclei-templates CVE-2026-109618; WoYinDao Sigma rules; adityaaravind/php2shell-check;
# m16a4666/php2shell-fix; crowdsecurity vpatch-CVE-2026-109618.
#
set -euo pipefail

CRI="${CRI:-crictl}"

# branch key = major*100+minor  ->  fixed patch level
fixed_patch() {
	case "$1" in
		805) echo 12 ;;
		804) echo 27 ;;
		803) echo 36 ;;
		802) echo 35 ;;
		*)   echo "" ;;   # branch without a fixed release
	esac
}

# First full version in arbitrary text, suffix kept: "8.3.35", "8.3.36RC1",
# "7.3.33-1+0~20221106.100+debian10~1.gbpa7cc1d" (first line of `php-fpm -v`).
parse_version() {
	# `|| true`: grep returns 1 on no match, which with pipefail would silently exit the script
	printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.~+_-]*' | head -1 || true
}

# Left-align a string by CHARACTER count (printf %-Ns counts bytes).
pad() {
	local s="$1" w="$2" n
	n=$((w - ${#s})); [ "$n" -gt 0 ] || n=0
	printf '%s%*s' "$s" "$n" ''
}

# print "STATUS|reason" for a version: VULNERABLE / PATCHED / UNKNOWN
classify_raw() {
	local raw="$*" full ver suffix major minor patch key fp
	full=$(parse_version "$raw")
	if [ -z "$full" ]; then
		echo "UNKNOWN|no X.Y.Z version found in: $raw"; return
	fi
	ver=$(printf '%s' "$full" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
	suffix=${full#"$ver"}
	IFS=. read -r major minor patch <<<"$ver"
	key=$((major * 100 + minor))

	if [ "$key" -lt 504 ]; then
		echo "UNKNOWN|$full (older than 5.4, outside the advisory scope, but long end-of-life)"
		return
	fi
	if [ "$key" -lt 704 ]; then
		echo "VULNERABLE|$full (branch $major.$minor is end-of-life, no fix exists)"
		return
	fi
	if [ "$key" -lt 802 ]; then
		echo "VULNERABLE|$full (no fixed release; only source backport PHP-$major.$minor-CVE-2026-109618-109619 or a patched vendor package)"
		return
	fi
	if [ "$key" -gt 805 ]; then
		echo "UNKNOWN|$full (branch newer than the known fixes, check the advisory)"
		return
	fi
	fp=$(fixed_patch "$key")
	if [ "$patch" -lt "$fp" ]; then
		echo "VULNERABLE|$full (fixed in $major.$minor.$fp)"
	elif [ "$patch" -eq "$fp" ] && printf '%s' "$suffix" | grep -qiE '^[-+_~.]?(dev|alpha|beta|rc|a[0-9]|b[0-9])'; then
		echo "VULNERABLE|$full (pre-release of $ver, not the fixed release)"
	else
		echo "PATCHED|$full (>= $major.$minor.$fp; for distro packages see the CAVEAT on backports)"
	fi
}

classify() {
	local r; r=$(classify_raw "$@")
	echo "$(pad "${r%%|*}" 11)${r#*|}"
}

# Convert "128M" / "1G" / "8388608" / "-1" to MB (-1 kept as is).
to_mb() {
	local v="${1:-}" n
	case "$v" in
		-1) echo -1 ;;
		*[0-9][Kk]) n=${v%?}; echo $((n / 1024)) ;;
		*[0-9][Mm]) echo "${v%?}" ;;
		*[0-9][Gg]) n=${v%?}; echo $((n * 1024)) ;;
		*[!0-9]*|'') echo "" ;;
		*) echo $((v / 1048576)) ;;
	esac
}

# Runs inside the container (sh). Prints key=value lines: bin, ver, ini.*, pool.*, pkg, backport.
# Exits 3 when the container has no PHP.
PROBE='
fpm=""
for b in php-fpm $(ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* 2>/dev/null); do
	p=$(command -v "$b" 2>/dev/null) && [ -n "$p" ] && { fpm=$p; break; }
done
[ -n "$fpm" ] || fpm=$(command -v php 2>/dev/null) || true
[ -n "$fpm" ] || exit 3
echo "bin=$fpm"
echo "ver=$("$fpm" -v 2>/dev/null | head -1)"
"$fpm" -i 2>/dev/null \
	| grep -E "^(memory_limit|session\.upload_progress\.enabled|post_max_size|upload_max_filesize|fatal_error_backtraces|max_input_vars) =>" \
	| sed -E "s/^([^ ]+) => ([^ ]+).*/ini.\1=\2/"
cat /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf /etc/php-fpm.d/*.conf /etc/php*/php-fpm.d/*.conf 2>/dev/null \
	| grep -E "^[[:space:]]*(php_admin_value|php_value|php_admin_flag|php_flag)\[(memory_limit|session\.upload_progress\.enabled|post_max_size)\]|^[[:space:]]*pm\.max_requests" \
	| sed -E "s/[[:space:]]+//g; s/^/pool./"
if command -v dpkg-query >/dev/null 2>&1; then
	dpkg-query -W -f="\${Package} \${Version}\n" "php*-fpm" "php*-common" 2>/dev/null | while read -r pk pv; do
		[ -n "$pv" ] || continue
		echo "pkg=$pk $pv"
		# Ubuntu packages that backported the fix without changing the number (USN-8948-1)
		floor=""
		case "$pk $pv" in
			"php8.1-fpm 8.1.2-1ubuntu2."*)       floor=8.1.2-1ubuntu2.28 ;;
			"php8.3-fpm 8.3.6-0ubuntu0.24.04."*) floor=8.3.6-0ubuntu0.24.04.13 ;;
			"php8.5-fpm 8.5.4-0ubuntu1."*)       floor=8.5.4-0ubuntu1.5 ;;
			"php8.5-fpm 8.5.9-0ubuntu2."*)       floor=8.5.9-0ubuntu2.1 ;;
		esac
		if [ -n "$floor" ] && dpkg --compare-versions "$pv" ge "$floor"; then
			echo "backport=$pk $pv >= $floor (USN-8948-1)"
		fi
	done
elif command -v apk >/dev/null 2>&1; then
	apk info -v 2>/dev/null | grep -E "^php[0-9]*-(fpm|common)-" | sed "s/^/pkg=/" || true
fi
exit 0
'

# "image|pod|container|namespace" of a container
cinfo() {
	if [ "$CRI" = docker ]; then
		docker inspect -f '{{.Config.Image}}|{{slice .Name 1}}|{{slice .Name 1}}|' "$1" 2>/dev/null || echo "|||"
	else
		crictl inspect -o go-template \
			--template '{{.status.image.image}}|{{index .status.labels "io.kubernetes.pod.name"}}|{{.status.metadata.name}}|{{index .status.labels "io.kubernetes.pod.namespace"}}' "$1" 2>/dev/null \
		|| echo "$(crictl inspect "$1" 2>/dev/null | grep -oE '"image": ?"[^"]+"' | head -1 | cut -d'"' -f4)|||"
	fi
}

# Assess mitigations from PROBE output, on one line.
mitigation_line() {
	local p="$1" up mem mem_src post upl maxreq feb v mb parts=()
	up=$(printf '%s\n' "$p" | sed -n 's/^ini\.session\.upload_progress\.enabled=//p' | head -1)
	v=$(printf '%s\n' "$p" | sed -nE 's/^pool\.php_admin_(value|flag)\[session\.upload_progress\.enabled\]=//p' | tail -1)
	[ -z "$v" ] || up="$v (pool)"
	# Unreadable is not the same as disabled (the PHP default is On).
	case "$up" in
		'')         parts+=("upload_progress=? [UNKNOWN]") ;;
		0*|[Oo]ff*) parts+=("upload_progress=$up [OK]") ;;
		*)          parts+=("upload_progress=$up [MISSING]") ;;
	esac

	mem=$(printf '%s\n' "$p" | sed -n 's/^ini\.memory_limit=//p' | head -1); mem_src="php.ini"
	v=$(printf '%s\n' "$p" | sed -nE 's/^pool\.php_admin_value\[memory_limit\]=//p' | tail -1)
	[ -z "$v" ] || { mem="$v"; mem_src="php_admin_value"; }
	if [ -z "$mem" ]; then
		parts+=("memory_limit=? [UNKNOWN]")
	elif [ "$mem" = "-1" ] && [ "$mem_src" = "php_admin_value" ]; then
		parts+=("memory_limit=-1 ($mem_src) [OK]")
	elif [ "$mem" = "-1" ]; then
		parts+=("memory_limit=-1 ($mem_src, applications can still override it) [WEAK]")
	else
		parts+=("memory_limit=$mem ($mem_src) [MISSING]")
	fi

	post=$(printf '%s\n' "$p" | sed -n 's/^ini\.post_max_size=//p' | head -1)
	upl=$(printf '%s\n' "$p" | sed -n 's/^ini\.upload_max_filesize=//p' | head -1)
	mb=$(to_mb "$post")
	if [ -n "$mb" ] && { [ "$mb" = -1 ] || [ "$mb" -eq 0 ] || [ "$mb" -gt 32 ]; }; then
		parts+=("post_max_size=$post [LOWER IT]")
	else
		parts+=("post_max_size=${post:-?}")
	fi
	parts+=("upload_max_filesize=${upl:-?}")

	maxreq=$(printf '%s\n' "$p" | sed -n 's/^pool\.pm\.max_requests=//p' | tail -1)
	parts+=("pm.max_requests=${maxreq:-0}")

	feb=$(printf '%s\n' "$p" | sed -n 's/^ini\.fatal_error_backtraces=//p' | head -1)
	[ -z "$feb" ] || case "$feb" in 0*|[Oo]ff*) parts+=("fatal_error_backtraces=$feb [OK]") ;; *) parts+=("fatal_error_backtraces=$feb [MISSING]") ;; esac

	local IFS='|'; printf '%s' "${parts[*]}" | sed 's/|/ | /g'
}

# Scan containers that have PHP via crictl (run on a Kubernetes node).
crictl_scan() {
	local pat="${1:-}" ids id img pod ctr ns probe st why ver status bp pkgs n=0 rc=0
	command -v "$CRI" >/dev/null 2>&1 || { echo "$CRI not found (run this on a node)" >&2; exit 1; }
	ids=$("$CRI" ps -q 2>/dev/null) || { echo "$CRI ps failed (run as root on the node)" >&2; exit 1; }
	[ -n "$ids" ] || { echo "no running containers"; return; }

	for id in $ids; do
		IFS='|' read -r img pod ctr ns <<<"$(cinfo "$id")"
		if [ -n "$pat" ]; then
			case "$img|$pod|$ctr|$ns" in *"$pat"*) ;; *) continue ;; esac
		elif [ "$ns" = kube-system ]; then
			continue   # do not exec into system pods unless asked to
		fi

		probe=$("$CRI" exec "$id" sh -c "$PROBE" 2>/dev/null) && st=0 || st=$?
		if [ "$st" -ne 0 ] || [ -z "$probe" ]; then
			# no sh or no PHP: only report when the image looks like PHP or a FILTER was given
			case "$img" in *php*|*fpm*) ;; *) [ -n "$pat" ] || continue ;; esac
			if [ "$st" -eq 3 ]; then why="no PHP in this container"; else why="could not exec sh in the container (exit code $st)"; fi
			printf '%s%s\n           image: %s\n           %s\n\n' \
				"$(pad 'UNKNOWN' 11)" "${pod:-$id} / ${ctr:-?}" "$img" "$why"
			rc=1; continue
		fi

		n=$((n + 1))
		ver=$(printf '%s\n' "$probe" | sed -n 's/^ver=//p' | head -1)
		status=$(classify_raw "$ver")
		bp=$(printf '%s\n' "$probe" | sed -n 's/^backport=//p' | head -1)
		if [ -n "$bp" ] && [ "${status%%|*}" = "VULNERABLE" ]; then
			status="PATCHED|$(parse_version "$ver") (vendor backport: $bp)"
		fi
		pkgs=$(printf '%s\n' "$probe" | sed -n 's/^pkg=//p' | paste -sd ';' - | sed 's/;/; /g')
		printf '%s%s\n' "$(pad "${status%%|*}" 11)" "${pod:-$id} / ${ctr:-?}"
		printf '           image: %s\n' "$img"
		printf '           PHP: %s  [%s]\n' "${status#*|}" "$(printf '%s\n' "$probe" | sed -n 's/^bin=//p' | head -1)"
		printf '           packages: %s\n' "${pkgs:-(unavailable: no dpkg/apk in the image, or PHP built from source)}"
		printf '           mitigations: %s\n\n' "$(mitigation_line "$probe")"
		case "$status" in "PATCHED|"*) ;; *) rc=1 ;; esac
	done
	echo "Scanned $n container(s) with PHP."
	return $rc
}

# Filter `ps -eo pid=,ppid=,comm=,args=` (stdin): print shells, downloaders and compilers
# whose parent or grandparent is php-fpm/php-cgi/apache/httpd/nginx (php-fpm -> sh -> curl).
proc_tree_scan() {
	awk '
		{ pid = $1; ppid[pid] = $2; comm[pid] = $3; line[pid] = $0 }
		END {
			for (p in comm) {
				if (comm[p] !~ /^(sh|bash|dash|ash|zsh|busybox|curl|wget|nc|ncat|netcat|socat|perl|python[0-9.]*|gcc|cc|tclsh)$/) continue
				q = ppid[p]
				for (i = 0; i < 2 && (q in comm); i++) {
					if (comm[q] ~ /^(php-fpm|php-cgi|apache2|httpd|lshttpd|nginx)/) {
						print "parent " q " (" comm[q] ") -> " line[p]; break
					}
					q = ppid[q]
				}
			}
		}'
}

# Best-effort, read-only indicator-of-compromise sweep on the current host.
# This is evidence collection, not an exploit test, and it proves neither compromise
# nor a clean state. Run it on the node. It does not exec into containers:
# container files are read through the overlay upperdir, container logs via /var/log/pods,
# and host web server / PHP-FPM logs from their usual paths under /var/log.
audit_scan() {
	local hours=168 minutes since roots uppers out review=0 p e lp n cov="" log_re
	local log_targets=() user_logs=() log_files=()
	while [ $# -gt 0 ]; do
		case "$1" in
			--log-dir) [ -n "${2:-}" ] || { echo "--log-dir needs a path" >&2; return 2; }
			           user_logs+=("$2"); shift 2 ;;
			*)         hours="$1"; shift ;;
		esac
	done
	case "$hours" in
		''|*[!0-9]*) echo "audit HOURS must be a positive integer" >&2; return 2 ;;
	esac
	[ "$hours" -gt 0 ] || { echo "audit HOURS must be greater than zero" >&2; return 2; }
	minutes=$((hours * 60))
	since="${hours} hours ago"
	printf '\n%s\n' '=============================================='
	echo " PHP2SHELL AUDIT — READ-ONLY"
	echo " Time window: last ${hours} hour(s)"
	echo " Results are heuristic; REVIEW items need a human to check"
	printf '%s\n\n' '=============================================='

	# Print one check. Any output is marked REVIEW, never automatically called an intrusion.
	report() {
		local number="$1" title="$2" value="$3"
		printf '[%s/7] %s\n' "$number" "$title"
		if [ -n "$value" ]; then
			review=1
			printf '      REVIEW — found data to review:\n%s\n\n' "$value"
		else
			printf '      PASS   — no indicator found within the scope of this check.\n\n'
		fi
	}

	# Writable layers of running containers (overlay upperdir), plus web roots on the host.
	uppers=$(awk '$3 == "overlay" { print $4 }' /proc/mounts 2>/dev/null | tr ',' '\n' | sed -n 's/^upperdir=//p' | sort -u | tr '\n' ' ' || true)
	roots="/var/www /srv/www /usr/share/nginx/html /opt $uppers"
	echo "Scope: web roots on the host and $(printf '%s\n' $uppers | grep -c . || true) container writable layer(s) (upperdir)."
	echo

	if command -v ps >/dev/null 2>&1; then
		out=$(ps -eo pid=,ppid=,comm=,args= | proc_tree_scan)
	else
		out="ps is not available"
	fi
	report 1 'PHP/web server spawned a shell, downloader or compiler' "$out"

	# -cmin (ctime) instead of -mmin: mtime can be faked with `touch`, ctime cannot.
	# Skip storage/framework and bootstrap/cache: Laravel generates PHP files there.
	out=$(find $roots -type f \( -name '*.php' -o -name '*.phtml' -o -name '.user.ini' -o -name '.htaccess' \
			-o -path '*/etc/php*' -name '*.ini' -o -path '*/etc/php*' -name '*.conf' \) \
		-not -path '*/storage/framework/*' -not -path '*/bootstrap/cache/*' \
		-cmin "-${minutes}" -printf '%CY-%Cm-%Cd %CH:%CM %u %p\n' 2>/dev/null | head -200 || true)
	report 2 'Recently changed PHP, .user.ini, .htaccess and ini files (host and containers)' "$out"

	out=$( {
		find $roots -type f \( -name '*.php' -o -name '*.phtml' \) -not -path '*/storage/framework/*' \
			-cmin "-${minutes}" -print0 2>/dev/null \
			| xargs -0 -r grep -nHE 'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|assert[[:space:]]*\(|system[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|proc_open[[:space:]]*\(|popen[[:space:]]*\(|\$_(GET|POST|REQUEST|COOKIE)\[' 2>/dev/null
		find $roots -type f \( -name '*.ini' -o -name '.user.ini' -o -name '*.conf' -o -name '.htaccess' \) -size -1024k \
			-print0 2>/dev/null \
			| xargs -0 -r grep -nHE '^[[:space:]]*(php_(admin_)?value[[:space:][]+)?auto_(prepend|append)_file(\]?[[:space:]]*=[[:space:]]*|[[:space:]]+)"?[^[:space:];"=]' 2>/dev/null
		} | head -200 || true)
	report 3 'Webshell-like code in recently changed PHP files; auto_prepend_file/auto_append_file in ini files' "$out"

	# Log files: container logs (php-fpm writes to stdout), host nginx/apache/PHP-FPM logs,
	# log paths set in their config (read with grep, not `nginx -T`, which can create log files),
	# then PHP2SHELL_LOG_PATHS (colon-separated) and --log-dir, which must be readable.
	# Rotated and .gz files are included; -mmin still bounds the window (gzip keeps the mtime).
	# Patterns from the WoYinDao Sigma rules, php2shell-detect, and how FPM reports a dead worker.
	log_re='Allowed memory size of [0-9]+ bytes exhausted.*Unknown on line 0|exited on signal (6|7|11)|SIGSEGV|SIGBUS|Input variables exceeded|session id is too long or contains illegal characters|PHP_SESSION_UPLOAD_PROGRESS|upstream prematurely closed connection'
	log_targets=(/var/log/pods /var/log/nginx /var/log/apache2 /var/log/httpd)
	for lp in /var/log/php*; do [ -e "$lp" ] && log_targets+=("$lp"); done
	while IFS= read -r lp; do
		for p in "$lp"*; do [ -e "$p" ] && log_targets+=("$p"); done   # the file and its rotations
	done < <(grep -rhsiE '^[[:space:]]*(access_log|error_log|CustomLog|ErrorLog|TransferLog|slowlog|access\.log)[[:space:]=]+"?/' \
			/etc/nginx /etc/apache2 /etc/httpd /etc/php* /etc/php-fpm* /usr/local/etc/php* 2>/dev/null \
		| sed -E 's#^[^/]*##; s#["; ].*$##' | sort -u || true)
	IFS=: read -ra p <<<"${PHP2SHELL_LOG_PATHS:-}"
	user_logs=(${p[@]+"${p[@]}"} ${user_logs[@]+"${user_logs[@]}"})

	# Default and configured paths: files named *log*. Paths the user gave: every file.
	for lp in "${log_targets[@]}" ${user_logs[@]+"${user_logs[@]}"}; do
		[ -n "$lp" ] && [ -e "$lp" ] || continue
		e='*log*'
		for p in ${user_logs[@]+"${user_logs[@]}"}; do [ "$p" != "$lp" ] || e='*'; done
		n=0
		while IFS= read -r -d '' p; do log_files+=("$p"); n=$((n + 1)); done \
			< <(find "$lp" -type f -name "$e" -mmin "-${minutes}" -print0 2>/dev/null || true)
		cov+="        $lp: $n file(s) changed in the window"$'\n'
	done
	out=""
	[ -n "$cov" ] || out+="NO LOG SOURCE FOUND: none of the default, configured or given log paths exist; pass --log-dir"$'\n'
	for lp in ${user_logs[@]+"${user_logs[@]}"}; do
		[ -n "$lp" ] || continue
		if [ ! -e "$lp" ]; then out+="NOT FOUND: $lp (given in PHP2SHELL_LOG_PATHS / --log-dir)"$'\n'
		elif [ ! -r "$lp" ] || { [ -d "$lp" ] && [ ! -x "$lp" ]; }; then out+="NOT READABLE: $lp"$'\n'
		fi
	done

	out+=$( {
		if [ "${#log_files[@]}" -gt 0 ]; then
			printf '%s\0' "${log_files[@]}" | sort -zu \
				| if command -v zgrep >/dev/null 2>&1; then xargs -0 -r zgrep -HiE -e "$log_re"; else xargs -0 -r grep -HiE -e "$log_re"; fi 2>/dev/null \
				| tail -150
		fi
		if command -v journalctl >/dev/null 2>&1; then
			journalctl --since "$since" --no-pager -q -u 'nginx*' -u 'apache2*' -u 'httpd*' -u 'php*fpm*' 2>/dev/null \
				| grep -iE -e "$log_re" | tail -100
			journalctl -k --since "$since" --no-pager -q 2>/dev/null | grep -iE 'php.*(segfault|general protection|trap)' | tail -50
		else
			dmesg 2>/dev/null | grep -iE 'php.*(segfault|general protection|trap)' | tail -50
		fi
		} || true)
	out=${out%$'\n'}
	report 4 'Pod, web server, PHP-FPM, journald and kernel logs: out of memory while parsing the request ("Unknown on line 0"), crashed FPM workers, unusual session/input warnings' "$out"
	printf '      Log coverage (only what is listed was read):\n%s' "${cov:-        no log file or directory found$'\n'}"
	if command -v journalctl >/dev/null 2>&1; then
		printf '        journald: nginx*/apache2*/httpd*/php*fpm* units and kernel, since %s\n\n' "$since"
	else
		printf '        journald: not available, kernel log from dmesg\n\n'
	fi

	out=$(find /etc/cron* /var/spool/cron $(for p in $uppers; do printf '%s/etc/cron.d %s/var/spool/cron ' "$p" "$p"; done) \
		-type f -cmin "-${minutes}" -ls 2>/dev/null | head -100 || true)
	report 5 'Recently changed cron files (host and containers)' "$out"

	out=$(find /var/lib/php /tmp /var/tmp $uppers -type f -name 'sess_*' -cmin "-${minutes}" -print0 2>/dev/null \
		| xargs -0 -r grep -l 'upload_progress_' 2>/dev/null | head -50 || true)
	report 6 'Session files containing upload_progress data (host and containers)' "$out"

	# FPM still running an old binary that has been deleted/replaced (package upgraded, workers not restarted).
	out=$(for p in /proc/[0-9]*; do
			e=$(readlink "$p/exe" 2>/dev/null) || continue
			if [[ "$e" == *php*'(deleted)'* ]]; then echo "pid ${p#/proc/}: $e"; fi
		done | head -50)
	report 7 'PHP processes still running a replaced binary (restart needed)' "$out"

	echo 'Note: PASS only means nothing was found within the scope of a check; it does not prove the host is clean.'
	echo 'For any REVIEW item: save the output and compare it with deployments and legitimate logs before concluding.'
	[ "$review" -eq 0 ]
}

# Read X-Powered-By (a single HEAD request, nothing else). A hidden header proves nothing.
url_check() {
	local url="${1:-}" xp
	[ -n "$url" ] || { echo "missing URL" >&2; return 2; }
	xp=$(curl -sk -I -m 10 "$url" 2>/dev/null | tr -d '\r' | sed -n 's/^[Xx]-[Pp]owered-[Bb]y: *//p' | grep -i 'PHP/' | head -1 || true)
	if [ -z "$xp" ]; then
		echo "$(pad 'UNKNOWN' 11)$url does not expose a PHP version in X-Powered-By; check from inside the server"
		return 1
	fi
	echo "$(classify "${xp#*PHP/}")  [$url]"
}

case "${1:-}" in
	classify) shift; classify "$@" ;;
	crictl)   shift; crictl_scan "${1:-}" ;;
	audit)    shift; audit_scan "$@" ;;
	url)      shift; url_check "${1:-}" ;;
	-h|--help|"")
		sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
		;;
	*) echo "unknown mode: $1 (use classify | crictl | audit | url | -h)" >&2; exit 2 ;;
esac
