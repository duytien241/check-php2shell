#!/usr/bin/env bash
#
# check-nodejs-server.sh — kiểm tra Node.js trên server theo đợt vá bảo mật
# Node.js 21/10/2026 (CVE-2026-111497 Brotli RCE, lỗi TLS/DNS và 7 lỗi khác),
# kèm việc gỡ tin cậy CA eMudhra.
#
# Bản vá (nodejs.org, 21/10/2026):   22.23.4   24.22.1   26.12.1
# Nhánh 20 trở xuống và các nhánh lẻ (21, 23, 25) đã hết hỗ trợ: không có bản vá.
#
# Script làm 4 việc:
#   1. Tìm mọi bản Node đang cài: PATH, gói hệ điều hành, nvm, fnm, volta,
#      asdf, n, nodenv, snap, bản kèm VS Code Server, thư mục --search.
#   2. Kiểm tra từng process node ĐANG CHẠY: bản thật của binary, vai trò
#      (Next.js SSR, NestJS, pm2...), cổng đang nghe, và process đang chạy
#      binary cũ đã bị thay (cần restart).
#   3. Kiểm tra file CA thêm vào Node (NODE_EXTRA_CA_CERTS) có chứa CA
#      eMudhra/emSign không.
#   4. (--containers) chạy `node --version` trong từng container đang chạy
#      (docker hoặc crictl).
#
# CHỈ ĐỌC: không sửa file, không đổi cấu hình, không restart dịch vụ, không
# gửi gì ra mạng. Ưu tiên đọc phiên bản từ header/gói mà không chạy binary;
# nếu phải chạy `node --version` thì chạy bằng chính user sở hữu file.
# Process trong container: đọc header qua /proc/PID/root; KHÔNG chạy binary của
# container bằng root trên host, chỉ chạy qua docker exec / crictl exec.
# Cổng của container: chạy `ss` của host trong network namespace (nsenter -n).
# --containers vẫn chỉ đọc nhưng có chạm vào container prod: hỏi người phụ
# trách trước. Kết quả là dấu hiệu, không phải bảo đảm an toàn.
#
# Không chạy bằng root: chỉ thấy process của user hiện tại, và cả process của
# chính user đó cũng bị ẩn nếu chạy với group khác (vd. www-data) vì kernel
# không cho đọc /proc/PID/exe.
#
# Cách dùng:
#   sudo ./check-nodejs-server.sh                    # nên chạy bằng root
#   sudo ./check-nodejs-server.sh --containers       # thêm container (docker/crictl)
#   sudo ./check-nodejs-server.sh --search /srv      # tìm thêm node trong thư mục
#   sudo ./check-nodejs-server.sh --json             # output JSON để gom nhiều server
#   ./check-nodejs-server.sh --classify v20.11.1     # phân loại một phiên bản
#   CRI=crictl sudo -E ./check-nodejs-server.sh --containers   # node EKS/k8s
#
# Mã thoát: 0 ổn
#           1 CẦN XỬ LÝ: process/container ĐANG CHẠY bản chưa vá, hết hỗ trợ, hoặc cần restart
#           2 CẦN XEM LẠI: chưa rõ bản, CA eMudhra, hoặc bản Node cài nhưng không
#             process nào dùng / bản kèm VS Code-Cursor Server (cảnh báo)
#           3 không thấy Node | 64 sai tham số
#
# Cần bash 4+ (Linux). Không cần cài thêm gì; openssl/ss có thì dùng.
#
# Dựa trên bản check-nodejs-server.sh đầu tiên và node-hostcheck v0.1.0
# (Charlie-Netdevops, MIT, commit 604f164), đã đọc lại toàn bộ trước khi gộp.
#
set -o pipefail

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
	echo "Cần bash 4 trở lên (server Linux). macOS: chạy bằng bash cài qua Homebrew." >&2
	exit 64
fi

DATA_DATE="2026-10-22"
declare -A FIXED=([22]="22.23.4" [24]="24.22.1" [26]="26.12.1")
CVES="CVE-2026-111497|CVE-2026-105482|CVE-2026-105483|CVE-2026-106069|CVE-2026-105481|CVE-2026-106072|CVE-2026-106074|CVE-2026-106070|CVE-2026-106071|CVE-2026-106073"
CRI="${CRI:-}"

OUT_JSON=0
DO_CONTAINERS=0
SEARCH_DIRS=()

die() { echo "Lỗi: $*" >&2; exit 64; }
usage() { sed -n '2,/^set -o pipefail/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

# ------------------------------------------------------------ tiện ích ---

have() { command -v "$1" >/dev/null 2>&1; }
if have timeout; then T() { timeout 10 "$@"; }; else T() { "$@"; }; fi
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# Căn trái theo số KÝ TỰ (printf %-Ns đếm byte, lệch với tiếng Việt)
pad() {
	local s="$1" w="$2" n
	n=$((w - ${#s})); [ "$n" -gt 0 ] || n=0
	printf '%s%*s' "$s" "$n" ''
}

json_esc() {
	local s=$1
	s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}
	printf '%s' "$s"
}

NOTES=()
note() { NOTES+=("$1"); }

# true nếu $1 >= $2 (dạng X.Y.Z)
ver_ge() {
	local -a a b; local i
	IFS=. read -ra a <<<"$1"; IFS=. read -ra b <<<"$2"
	for i in 0 1 2; do
		local x=$((10#${a[$i]:-0})) y=$((10#${b[$i]:-0}))
		[ "$x" -gt "$y" ] && return 0
		[ "$x" -lt "$y" ] && return 1
	done
	return 0
}

shopt -s nullglob

# ---------------------------------------------------------- phân loại ---

pkg_owner() {
	if have dpkg-query; then dpkg-query -S "$1" 2>/dev/null | head -n1 | cut -d: -f1
	elif have rpm; then rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n1
	fi
}
pkg_version() {
	if have dpkg-query; then dpkg-query -W -f='${Version}' "$1" 2>/dev/null
	elif have rpm; then rpm -q --qf '%{VERSION}' "$1" 2>/dev/null
	fi
}

# Gói distro có ghi đã backport các CVE này không (changelog)
CHANGELOG_FOUND=0
backported() {
	local pkg=$1 f cl
	CHANGELOG_FOUND=0
	[ -z "$pkg" ] && return 1
	if ! have dpkg-query && have rpm; then
		cl=$(rpm -q --changelog "$pkg" 2>/dev/null)
		[ -n "$cl" ] && CHANGELOG_FOUND=1
		printf '%s\n' "$cl" | grep -qE "$CVES"
		return
	fi
	for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
		[ -f "$f" ] || continue
		CHANGELOG_FOUND=1
		zgrep -qE "$CVES" "$f" 2>/dev/null && return 0
	done
	return 1
}

# classify <phiên bản> [gói] -> C_STATUS, C_NOTE
# C_STATUS: ĐÃ VÁ | ĐÃ VÁ (BACKPORT) | CHƯA VÁ | HẾT HỖ TRỢ | HẾT HỖ TRỢ (BACKPORT) | KHÔNG RÕ
classify() {
	local v=$1 pkg=${2:-} major fixed
	C_STATUS="KHÔNG RÕ"; C_NOTE=""
	v=$(printf '%s' "$v" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
	if [ -z "$v" ]; then
		C_NOTE="không đọc được phiên bản, kiểm tra tay bằng node --version"; return
	fi
	major=${v%%.*}
	fixed=${FIXED[$major]:-}
	if [ -n "$fixed" ]; then
		if ver_ge "$v" "$fixed"; then C_STATUS="ĐÃ VÁ"; C_NOTE="$v >= $fixed"; return; fi
		if backported "$pkg"; then C_STATUS="ĐÃ VÁ (BACKPORT)"; C_NOTE="$v, gói $pkg ghi đã backport bản vá"; return; fi
		C_STATUS="CHƯA VÁ"; C_NOTE="$v: nâng lên >= $fixed rồi restart mọi process dùng bản này"
		[ "$CHANGELOG_FOUND" -eq 0 ] && [ -n "$pkg" ] && C_NOTE="$C_NOTE (không có changelog gói để kiểm tra backport)"
		return
	fi
	if [ "$major" -lt 22 ] || { [ $((major % 2)) -eq 1 ] && [ "$major" -lt 27 ]; }; then
		if backported "$pkg"; then
			C_STATUS="HẾT HỖ TRỢ (BACKPORT)"; C_NOTE="$v: distro có backport nhưng Node $major đã hết hỗ trợ, nên lên 24"; return
		fi
		C_STATUS="HẾT HỖ TRỢ"; C_NOTE="$v: nhánh $major không có bản vá, phải lên 22/24 (khuyến nghị 24)"; return
	fi
	C_NOTE="$v: Node $major mới hơn dữ liệu của script ($DATA_DATE), kiểm tra nodejs.org"
}

is_bad() { case "$1" in "CHƯA VÁ"|"HẾT HỖ TRỢ"|"CẦN RESTART") return 0 ;; esac; return 1; }

# Đọc phiên bản, cố KHÔNG chạy binary: header -> gói -> đường dẫn -> --version (bằng user sở hữu).
# Với process trong container: root=/proc/PID/root (đọc file trong container),
# pid=PID (chạy /proc/PID/exe, rồi nsenter vào mount namespace nếu cần).
get_version() {
	local path=$1 pkg=$2 root=${3:-} pid=${4:-} v="" dir hdr owner
	VSRC=""; GV_VER=""
	dir=$root$(dirname "$path")
	for hdr in "$dir/../include/node/node_version.h" "$dir/../../include/node/node_version.h"; do
		[ -f "$hdr" ] || continue
		v=$(awk '/^#define NODE_MAJOR_VERSION/{a=$3} /^#define NODE_MINOR_VERSION/{b=$3} /^#define NODE_PATCH_VERSION/{c=$3} END{if(a!="")print a"."b"."c}' "$hdr" 2>/dev/null)
		[ -n "$v" ] && { VSRC="header"; GV_VER=$v; return; }
	done
	if [ -n "$pkg" ]; then
		v=$(pkg_version "$pkg" | sed 's/^[0-9]*://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
		[ -n "$v" ] && { VSRC="gói $pkg"; GV_VER=$v; return; }
	fi
	v=$(printf '%s' "$path" | grep -oE '/v?[0-9]+\.[0-9]+\.[0-9]+/' | tail -n1 | tr -d '/v')
	[ -n "$v" ] && { VSRC="đường dẫn"; GV_VER=$v; return; }
	if [ -n "$pid" ]; then
		if [ -n "$root" ]; then
			# Process trong container: KHÔNG chạy binary của container bằng root trên host
			# (container có thể đã bị chiếm). Chỉ chạy qua docker exec, vẫn bị giới hạn
			# trong container (docker exec / crictl exec). Không có thì báo KHÔNG RÕ.
			[ -n "${CUR_CID:-}" ] && [ -n "${CUR_CRI:-}" ] && \
				v=$(T "$CUR_CRI" exec "$CUR_CID" "$path" --version 2>/dev/null | head -n1)
			v=$(printf '%s' "$v" | grep -oE '^v?[0-9]+\.[0-9]+\.[0-9]+' | tr -d v)
			[ -n "$v" ] && VSRC="docker exec"
		else
			# binary thật của process trên host (kể cả binary đã bị xóa/thay), chạy bằng user của process
			owner=$(stat -c %U "/proc/$pid" 2>/dev/null)
			if [ "$IS_ROOT" -eq 1 ] && [ -n "$owner" ] && [ "$owner" != root ] && have runuser; then
				v=$(T runuser -u "$owner" -- "/proc/$pid/exe" --version 2>/dev/null | head -n1)
			else
				v=$(T "/proc/$pid/exe" --version 2>/dev/null | head -n1)
			fi
			v=$(printf '%s' "$v" | grep -oE '^v?[0-9]+\.[0-9]+\.[0-9]+' | tr -d v)
			[ -n "$v" ] && VSRC="binary của process"
		fi
		GV_VER=$v
		return
	fi
	owner=$(stat -c %U "$path" 2>/dev/null)
	if [ "$IS_ROOT" -eq 1 ] && [ -n "$owner" ] && [ "$owner" != root ]; then
		if have runuser; then v=$(T runuser -u "$owner" -- "$path" --version 2>/dev/null | head -n1)
		elif have setpriv; then v=$(T setpriv --reuid="$owner" --regid="$(id -g "$owner")" --clear-groups "$path" --version 2>/dev/null | head -n1)
		fi
	else
		v=$(T "$path" --version 2>/dev/null | head -n1)
	fi
	v=$(printf '%s' "$v" | grep -oE '^v?[0-9]+\.[0-9]+\.[0-9]+' | tr -d v)
	[ -n "$v" ] && VSRC="node --version"
	GV_VER=$v
}

# ------------------------------------------------- 1. bản Node đang cài ---

declare -A SEEN STATUS_OF VER_OF
B_PATH=(); B_SRC=()
R_PATH=(); R_SRC=(); R_VER=(); R_VSRC=(); R_PKG=(); R_STATUS=(); R_NOTE=()

add_bin() {
	local p=$1 r
	[ -f "$p" ] && [ -x "$p" ] || return
	r=$(readlink -f "$p" 2>/dev/null || echo "$p")
	[ -n "${SEEN[$r]:-}" ] && return
	SEEN[$r]=1
	B_PATH+=("$r"); B_SRC+=("$2")
}

discover() {
	local p h d
	for p in $(type -ap node nodejs 2>/dev/null); do add_bin "$p" PATH; done
	for p in /usr/bin/node /usr/bin/nodejs /usr/local/bin/node /usr/bin/node[0-9]* \
		/usr/local/lib/nodejs/*/bin/node /opt/node*/bin/node /opt/*/bin/node \
		/usr/local/n/versions/node/*/bin/node /usr/local/nvm/versions/node/*/bin/node \
		/opt/nvm/versions/node/*/bin/node /snap/node/current/bin/node /usr/lib/code-server/lib/node; do
		add_bin "$p" "hệ thống"
	done
	for h in /root /home/*; do
		[ -d "$h" ] || continue
		for p in "$h"/.nvm/versions/node/*/bin/node; do add_bin "$p" nvm; done
		for p in "$h"/.local/share/fnm/node-versions/*/installation/bin/node "$h"/.fnm/node-versions/*/installation/bin/node; do add_bin "$p" fnm; done
		for p in "$h"/.volta/tools/image/node/*/bin/node; do add_bin "$p" volta; done
		for p in "$h"/.asdf/installs/nodejs/*/bin/node; do add_bin "$p" asdf; done
		for p in "$h"/.nodenv/versions/*/bin/node; do add_bin "$p" nodenv; done
		for p in "$h"/.n/bin/node "$h"/n/bin/node; do add_bin "$p" n; done
		for p in "$h"/.vscode-server/bin/*/node "$h"/.vscode-server/cli/servers/*/server/node \
			"$h"/.cursor-server/bin/*/node "$h"/.cursor-server/cli/servers/*/server/node \
			"$h"/.local/share/code-server/*/lib/node; do add_bin "$p" "editor-server"; done
	done
	for d in "${SEARCH_DIRS[@]}"; do
		while IFS= read -r p; do add_bin "$p" "--search"; done \
			< <(find "$d" -xdev -maxdepth 8 -type f \( -name node -o -name nodejs \) -perm -u+x 2>/dev/null)
	done
	[ "$IS_ROOT" -eq 0 ] && note "Không chạy bằng root: Node cài trong home của user khác (nvm, fnm, volta...) có thể bị bỏ sót."
}

check_one() {
	local path=$1 src=$2 pkg
	pkg=$(pkg_owner "$path")
	get_version "$path" "$pkg"
	classify "$GV_VER" "$pkg"
	R_PATH+=("$path"); R_SRC+=("$src"); R_VER+=("$GV_VER"); R_VSRC+=("$VSRC"); R_PKG+=("$pkg")
	R_STATUS+=("$C_STATUS"); R_NOTE+=("$C_NOTE")
	STATUS_OF[$path]=$C_STATUS; VER_OF[$path]=$GV_VER
}

check_installs() {
	local i
	for i in "${!B_PATH[@]}"; do check_one "${B_PATH[$i]}" "${B_SRC[$i]}"; done
}

# ------------------------------------------- 2. process node đang chạy ---

role_of() {
	case "$1" in
		*"next start"*|*next-server*|*.next/standalone*) echo "Next.js SSR" ;;
		*"nuxt start"*|*.output/server*) echo "Nuxt SSR" ;;
		*"PM2 v"*|*"God Daemon"*) echo "pm2 daemon" ;;
		*dist/main*|*"nest start"*) echo "NestJS?" ;;
		*npm\ *|*yarn\ *|*pnpm\ *) echo "npm/yarn" ;;
		*) echo "app" ;;
	esac
}

# Cổng đang nghe của một pid. Gọi ss một lần cho mỗi network namespace (container có
# netns riêng: vào bằng nsenter -n, chỉ đọc).
declare -A SS_CACHE
listen_ports() {
	local pid=$1 ns out
	have ss || return 0
	ns=$(readlink "/proc/$pid/ns/net" 2>/dev/null)
	[ -n "$ns" ] || ns=$HOST_NETNS   # không đọc được (không phải root): coi như host
	if [ -z "${SS_CACHE[$ns]+x}" ]; then
		if [ "$ns" = "$HOST_NETNS" ]; then out=$(ss -ltnpH 2>/dev/null)
		elif have nsenter; then out=$(T nsenter -t "$pid" -n ss -ltnpH 2>/dev/null)
		fi
		SS_CACHE[$ns]=$out
	fi
	printf '%s\n' "${SS_CACHE[$ns]}" | awk -v p="pid=$pid," 'index($0, p) { n = split($4, a, ":"); if (!seen[a[n]]++) { printf "%s%s", sep, a[n]; sep = "," } }'
}

# Container chứa pid. Đặt CUR_CID (container id), CUR_CRI (docker|crictl: công cụ biết
# container này, dùng để exec có giới hạn) và CUR_WHERE (tên hiển thị).
# Không dùng subshell để giữ biến; mỗi process chỉ inspect một lần.
CUR_CID=""; CUR_CRI=""; CUR_WHERE=""
declare -A SEEN_CID     # container đã thấy ở phần process (12 ký tự đầu của id)
container_of() {
	local cid name=""
	CUR_CID=""; CUR_CRI=""; CUR_WHERE="container"
	# docker: .../docker-<id>.scope hoặc /docker/<id>; containerd/EKS: cri-containerd-<id>.scope
	cid=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -n1)
	[ -z "$cid" ] && return
	CUR_CID=$cid
	SEEN_CID[${cid:0:12}]=1
	if have docker; then
		name=$(docker inspect -f '{{.Name}} ({{.Config.Image}})' "$cid" 2>/dev/null | sed 's#^/##')
		[ -n "$name" ] && CUR_CRI=docker
	fi
	if [ -z "$name" ] && have crictl; then
		name=$(T crictl inspect -o go-template --template '{{.status.metadata.name}} ({{.status.image.image}})' "$cid" 2>/dev/null)
		[ -n "$name" ] && CUR_CRI=crictl
	fi
	CUR_WHERE=${name:-container ${cid:0:12}}
}

P_PID=(); P_USER=(); P_EXE=(); P_VER=(); P_STATUS=(); P_ROLE=(); P_PORTS=(); P_CMD=(); P_WHERE=()
declare -A USED         # bản cài trên host đang có process dùng
EXTRA_CA=(); OS_STORE_PROCS=()
declare -A EXTRA_CA_SEEN
# Namespace của host: lấy từ PID 1, không phải root thì lấy của chính script
HOST_MNTNS=$(readlink /proc/1/ns/mnt 2>/dev/null || readlink /proc/self/ns/mnt 2>/dev/null)
HOST_NETNS=$(readlink /proc/1/ns/net 2>/dev/null || readlink /proc/self/ns/net 2>/dev/null)
HOST_NETNS=${HOST_NETNS:-host}

check_processes() {
	local d pid exe base user cmd st ver env_ca opts root where mnt
	if [ ! -d /proc/self ]; then note "Không có /proc: bỏ qua phần process đang chạy."; return; fi
	for d in /proc/[0-9]*; do
		pid=${d#/proc/}
		exe=$(readlink "$d/exe" 2>/dev/null) || continue
		base=$(basename "${exe% (deleted)}")
		case "$base" in node|nodejs|node[0-9]*) ;; *) continue ;; esac
		user=$(stat -c %U "$d" 2>/dev/null)
		cmd=$(tr '\0' ' ' <"$d/cmdline" 2>/dev/null | cut -c1-120)
		root=""; where="host"; CUR_CID=""
		mnt=$(readlink "$d/ns/mnt" 2>/dev/null)
		if [ -n "$mnt" ] && [ "$mnt" != "$HOST_MNTNS" ]; then
			# đường dẫn exe là đường dẫn TRONG container: đọc qua /proc/PID/root
			root="/proc/$pid/root"; container_of "$pid"; where=$CUR_WHERE
		fi
		if [ "${exe% (deleted)}" != "$exe" ]; then
			get_version "${exe% (deleted)}" "" "$root" "$pid"
			ver=$GV_VER; st="CẦN RESTART"
		elif [ -n "$root" ]; then
			get_version "$exe" "" "$root" "$pid"
			classify "$GV_VER" ""
			ver=$GV_VER; st=$C_STATUS
		else
			[ -z "${STATUS_OF[$exe]:-}" ] && { add_bin "$exe" process; check_one "$exe" process; }
			st=${STATUS_OF[$exe]}; ver=${VER_OF[$exe]}
			USED[$exe]=1
		fi
		P_PID+=("$pid"); P_USER+=("$user"); P_EXE+=("${exe% (deleted)}"); P_VER+=("$ver"); P_STATUS+=("$st")
		P_ROLE+=("$(role_of "$cmd")"); P_PORTS+=("$(listen_ports "$pid")"); P_CMD+=("$cmd"); P_WHERE+=("$where")

		# CA mà process này dùng (cần root để đọc process của user khác).
		# Đường dẫn CA của process trong container phải đọc qua /proc/PID/root.
		opts=""
		if [ -r "$d/environ" ]; then
			env_ca=$(tr '\0' '\n' <"$d/environ" 2>/dev/null | sed -n 's/^NODE_EXTRA_CA_CERTS=//p' | head -n1)
			[ -n "$env_ca" ] && env_ca="$root$env_ca"
			if [ -n "$env_ca" ] && [ -z "${EXTRA_CA_SEEN[$env_ca]:-}" ]; then EXTRA_CA_SEEN[$env_ca]=1; EXTRA_CA+=("$env_ca"); fi
			opts=$(tr '\0' '\n' <"$d/environ" 2>/dev/null | sed -n 's/^NODE_OPTIONS=//p' | head -n1)
		fi
		case "$cmd $opts" in *--use-openssl-ca*|*--use-system-ca*) OS_STORE_PROCS+=("PID $pid ($user)") ;; esac
	done
	[ "$IS_ROOT" -eq 0 ] && note "Không chạy bằng root: process node của user khác có thể bị bỏ sót."
}

# ------------------------------------------------------- 3. CA eMudhra ---

CA_BAD=()
check_ca_bundles() {
	local f line n
	if [ -r /etc/environment ]; then
		line=$(sed -n 's/^[[:space:]]*NODE_EXTRA_CA_CERTS=//p' /etc/environment | tr -d '"'"'" | head -n1)
		[ -n "$line" ] && [ -z "${EXTRA_CA_SEEN[$line]:-}" ] && { EXTRA_CA_SEEN[$line]=1; EXTRA_CA+=("$line"); }
	fi
	while IFS= read -r line; do
		[ -n "$line" ] && [ -z "${EXTRA_CA_SEEN[$line]:-}" ] && { EXTRA_CA_SEEN[$line]=1; EXTRA_CA+=("$line"); }
	done < <(grep -rhoE 'NODE_EXTRA_CA_CERTS=[^ "'"'"']+' /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null | cut -d= -f2- | sort -u)
	for f in "${EXTRA_CA[@]}"; do
		if [ ! -r "$f" ]; then note "NODE_EXTRA_CA_CERTS trỏ tới '$f' nhưng file không tồn tại hoặc không đọc được."; continue; fi
		if have openssl; then
			n=$(openssl crl2pkcs7 -nocrl -certfile "$f" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -ciE 'emsign|emudhra')
			[ "${n:-0}" -gt 0 ] && CA_BAD+=("$f ($n dòng chứng chỉ emSign/eMudhra)")
		else
			grep -qiE 'emsign|emudhra' "$f" 2>/dev/null && CA_BAD+=("$f")
		fi
	done
}

# ------------------------------------------------------- 4. container ---

CT_ID=(); CT_IMAGE=(); CT_VER=(); CT_STATUS=(); CT_PID1=()
check_containers() {
	local cri=$CRI ids id img out v pid1
	if [ -z "$cri" ]; then
		if have docker && docker ps -q >/dev/null 2>&1; then cri=docker
		elif have crictl; then cri=crictl
		fi
	fi
	if [ -z "$cri" ] || ! have "$cri"; then
		[ "$DO_CONTAINERS" -eq 1 ] && note "--containers: không có docker/crictl."
		return
	fi
	ids=$(T "$cri" ps -q 2>/dev/null)
	[ -z "$ids" ] && return
	if [ "$DO_CONTAINERS" -eq 0 ]; then
		note "Có $(printf '%s\n' "$ids" | wc -l | tr -d ' ') container đang chạy ($cri) chưa được kiểm tra. Chạy lại với --containers để xem bản Node bên trong."
		return
	fi
	for id in $ids; do
		# container đã hiện ở phần process thì bỏ qua, chỉ thêm container chưa có process node chạy
		[ -n "${SEEN_CID[${id:0:12}]:-}" ] && continue
		if [ "$cri" = docker ]; then
			img=$(docker inspect -f '{{.Config.Image}} {{.Name}}' "$id" 2>/dev/null)
		else
			img=$(crictl inspect "$id" 2>/dev/null | grep -m1 '"image":' | sed -E 's/.*"image": *"([^"]*)".*/\1/')
		fi
		out=$(T "$cri" exec "$id" sh -c 'command -v node >/dev/null 2>&1 && node --version; tr "\0" " " </proc/1/cmdline 2>/dev/null' 2>/dev/null || true)
		v=$(printf '%s\n' "$out" | grep -m1 -E '^v[0-9]' | tr -d 'v\r')
		[ -z "$v" ] && continue
		pid1=$(printf '%s\n' "$out" | grep -v -E '^v[0-9]' | head -1 | cut -c1-70)
		classify "$v" ""
		CT_ID+=("${id:0:12}"); CT_IMAGE+=("$img"); CT_VER+=("$v"); CT_STATUS+=("$C_STATUS"); CT_PID1+=("$pid1")
	done
}

# ---------------------------------------------------------------- tham số ---

while [ $# -gt 0 ]; do
	case "$1" in
		--json) OUT_JSON=1 ;;
		--containers) DO_CONTAINERS=1 ;;
		--search)
			[ -n "${2:-}" ] || die "--search cần một thư mục"
			[ -d "$2" ] || die "--search: '$2' không phải thư mục"
			SEARCH_DIRS+=("$2"); shift ;;
		--classify)
			[ -n "${2:-}" ] || die "--classify cần một chuỗi phiên bản"
			classify "$2" ""
			printf '%s %s\n' "$(pad "$C_STATUS" 12)" "$C_NOTE"
			is_bad "$C_STATUS" && exit 1
			exit 0 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "Tham số không hợp lệ: $1" >&2; usage >&2; exit 64 ;;
	esac
	shift
done

# ----------------------------------------------------------------- chạy ---

discover
check_installs
check_processes
check_ca_bundles
check_containers

# CẦN XỬ LÝ: chỉ tính cái đang CHẠY (process, container). Bản cài trên host mà không
# process nào dùng, hoặc bản kèm editor (VS Code/Cursor Server), chỉ là cảnh báo.
N_BAD=0; N_ATTN=0
for s in "${P_STATUS[@]}" "${CT_STATUS[@]}"; do
	if is_bad "$s"; then N_BAD=$((N_BAD + 1))
	elif [ "$s" = "KHÔNG RÕ" ] || [ "$s" = "HẾT HỖ TRỢ (BACKPORT)" ]; then N_ATTN=$((N_ATTN + 1))
	fi
done
R_USE=()
for i in "${!R_PATH[@]}"; do
	if [ -n "${USED[${R_PATH[$i]}]:-}" ]; then R_USE+=("đang chạy")
	elif [ "${R_SRC[$i]}" = "editor-server" ]; then R_USE+=("editor")
	else R_USE+=("không dùng")
	fi
	[ "${R_USE[$i]}" != "đang chạy" ] && { is_bad "${R_STATUS[$i]}" || [ "${R_STATUS[$i]}" = "KHÔNG RÕ" ]; } && N_ATTN=$((N_ATTN + 1))
done
[ ${#CA_BAD[@]} -gt 0 ] && N_ATTN=$((N_ATTN + 1))

if [ "$N_BAD" -gt 0 ]; then RESULT="CẦN XỬ LÝ"; EXIT=1
elif [ "$N_ATTN" -gt 0 ]; then RESULT="CẦN XEM LẠI"; EXIT=2
elif [ ${#R_PATH[@]} -eq 0 ] && [ ${#P_PID[@]} -eq 0 ] && [ ${#CT_ID[@]} -eq 0 ]; then RESULT="KHÔNG THẤY NODE"; EXIT=3
else RESULT="ỔN"; EXIT=0
fi

HOST=$(hostname 2>/dev/null || echo unknown)
OS=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || uname -sr)

# ---------------------------------------------------------- output JSON ---

if [ "$OUT_JSON" -eq 1 ]; then
	arr() { local sep="" x; for x in "$@"; do printf '%s"%s"' "$sep" "$(json_esc "$x")"; sep=", "; done; }
	printf '{\n  "host": "%s", "os": "%s", "root": %s, "checked_at": "%s", "data_date": "%s",\n' \
		"$(json_esc "$HOST")" "$(json_esc "$OS")" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" "$(date -u +%FT%TZ)" "$DATA_DATE"
	printf '  "result": "%s", "exit_code": %d,\n  "installs": [' "$RESULT" "$EXIT"
	sep=""
	for i in "${!R_PATH[@]}"; do
		printf '%s\n    {"path": "%s", "source": "%s", "version": "%s", "version_from": "%s", "package": "%s", "status": "%s", "in_use": "%s", "note": "%s"}' "$sep" \
			"$(json_esc "${R_PATH[$i]}")" "$(json_esc "${R_SRC[$i]}")" "${R_VER[$i]}" "$(json_esc "${R_VSRC[$i]}")" "$(json_esc "${R_PKG[$i]}")" "${R_STATUS[$i]}" "${R_USE[$i]}" "$(json_esc "${R_NOTE[$i]}")"
		sep=","
	done
	printf '\n  ],\n  "processes": ['
	sep=""
	for i in "${!P_PID[@]}"; do
		printf '%s\n    {"pid": %s, "user": "%s", "where": "%s", "exe": "%s", "version": "%s", "status": "%s", "role": "%s", "ports": "%s", "cmd": "%s"}' "$sep" \
			"${P_PID[$i]}" "$(json_esc "${P_USER[$i]}")" "$(json_esc "${P_WHERE[$i]}")" "$(json_esc "${P_EXE[$i]}")" "${P_VER[$i]}" "${P_STATUS[$i]}" "${P_ROLE[$i]}" "${P_PORTS[$i]}" "$(json_esc "${P_CMD[$i]}")"
		sep=","
	done
	printf '\n  ],\n  "containers": ['
	sep=""
	for i in "${!CT_ID[@]}"; do
		printf '%s\n    {"id": "%s", "image": "%s", "version": "%s", "status": "%s", "pid1": "%s"}' "$sep" \
			"${CT_ID[$i]}" "$(json_esc "${CT_IMAGE[$i]}")" "${CT_VER[$i]}" "${CT_STATUS[$i]}" "$(json_esc "${CT_PID1[$i]}")"
		sep=","
	done
	printf '\n  ],\n  "extra_ca_bundles": [%s],\n  "emudhra_in_ca": [%s],\n  "os_ca_store_procs": [%s],\n  "notes": [%s]\n}\n' \
		"$(arr "${EXTRA_CA[@]}")" "$(arr "${CA_BAD[@]}")" "$(arr "${OS_STORE_PROCS[@]}")" "$(arr "${NOTES[@]}")"
	exit "$EXIT"
fi

# ---------------------------------------------------------- output chữ ---

echo "check-nodejs-server — Node.js security release 21/10/2026 (bản vá 22.23.4 / 24.22.1 / 26.12.1)"
echo "Server: $HOST | $OS | root: $([ "$IS_ROOT" -eq 1 ] && echo có || echo không)"

echo
echo "== Process node đang chạy =="
if [ ${#P_PID[@]} -eq 0 ]; then
	echo "  Không có process node nào."
else
	for i in "${!P_PID[@]}"; do
		extra="${P_WHERE[$i]}, ${P_ROLE[$i]}"
		[ -n "${P_PORTS[$i]}" ] && extra="$extra, nghe cổng ${P_PORTS[$i]}"
		printf '  %s pid %s (%s)  Node %s  [%s]\n' "$(pad "${P_STATUS[$i]}" 12)" "${P_PID[$i]}" "${P_USER[$i]}" "${P_VER[$i]:-?}" "$extra"
		printf '      %s\n' "${P_CMD[$i]}"
		[ "${P_STATUS[$i]}" = "CẦN RESTART" ] && printf '      Binary đã bị thay trên đĩa, process vẫn chạy bản cũ: restart (pm2 reload / systemctl restart).\n'
	done
fi

echo
echo "== Bản Node đang cài =="
if [ ${#R_PATH[@]} -eq 0 ]; then
	echo "  Không thấy Node ở các vị trí thường gặp (thêm --search DIR nếu app kèm Node riêng)."
else
	for i in "${!R_PATH[@]}"; do
		case "${R_USE[$i]}" in
			"đang chạy") use="có process đang dùng" ;;
			editor) use="bản kèm editor từ xa, không phải app: CẢNH BÁO" ;;
			*) use="không process nào dùng: CẢNH BÁO, nên gỡ hoặc nâng" ;;
		esac
		printf '  %s %s  [%s, đọc từ %s]\n' "$(pad "${R_STATUS[$i]}" 12)" "${R_PATH[$i]}" "${R_SRC[$i]}" "${R_VSRC[$i]:-?}"
		printf '      %s (%s)\n' "${R_NOTE[$i]}" "$use"
	done
fi

if [ ${#CT_ID[@]} -gt 0 ]; then
	echo
	echo "== Container =="
	for i in "${!CT_ID[@]}"; do
		printf '  %s %s %s  Node %s  [PID 1: %s]\n' "$(pad "${CT_STATUS[$i]}" 12)" "${CT_ID[$i]}" "${CT_IMAGE[$i]}" "${CT_VER[$i]}" "${CT_PID1[$i]:-?}"
	done
	echo "  (Đổi bản Node trong container = build lại image với --pull rồi deploy. Chỉ restart là không đủ.)"
fi

if [ ${#CA_BAD[@]} -gt 0 ] || [ ${#OS_STORE_PROCS[@]} -gt 0 ]; then
	echo
	echo "== Chứng chỉ CA =="
	for f in "${CA_BAD[@]}"; do
		echo "  CẦN XEM LẠI  $f"
		echo "      NODE_EXTRA_CA_CERTS cộng thêm CA vào danh sách của Node, nâng Node không gỡ được. Bỏ CA eMudhra nếu không thật sự cần."
	done
	for f in "${OS_STORE_PROCS[@]}"; do
		echo "  THÔNG TIN    $f dùng kho CA của hệ điều hành: cập nhật gói ca-certificates rồi restart."
	done
fi

if [ "$N_BAD" -gt 0 ]; then
	echo
	echo "== Cần làm =="
	echo "  - Nâng lên 22.23.4 / 24.22.1 / 26.12.1. Node 20 trở xuống đã hết hỗ trợ: lên Node 24."
	echo "  - nvm/fnm/volta: cài bản vá, chuyển sang dùng, gỡ bản cũ mà service còn trỏ tới."
	echo "  - Restart mọi process node (pm2 update && pm2 reload all / systemctl restart <app>), rồi chạy lại script."
	echo "  - Container và file thực thi SEA mang Node riêng: build lại."
fi

if [ ${#NOTES[@]} -gt 0 ]; then
	echo
	echo "== Ghi chú =="
	for n in "${NOTES[@]}"; do echo "  - $n"; done
fi

echo
echo "KẾT LUẬN: $RESULT"
echo "(Đây là kiểm tra dấu hiệu. Kết quả ổn không có nghĩa server chắc chắn an toàn.)"
exit "$EXIT"
