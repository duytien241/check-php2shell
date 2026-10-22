# check-php2shell

A single Bash script to find PHP exposed to **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), check whether the interim mitigations are in place, and sweep a host for signs of exploitation. It is read-only: no exploit code, no attack traffic.

It was written for PHP-FPM running in Kubernetes pods, scanned from the node with `crictl`. The `classify`, `audit` and `url` modes also work on an ordinary Linux server.

A second script, [`mitigate-php2shell.sh`](#temporary-mitigation-mitigate-php2shellsh), applies the interim mitigations on a server (PHP-FPM or Apache mod_php) until PHP is upgraded.

## What PHP2Shell is

Two memory-safety bugs in PHP core, fixed on 2026-10-21. Both are reachable by an unauthenticated remote attacker.

| CVE | Root cause |
|---|---|
| CVE-2026-109618 | Memory runs out while request data is only partly initialised; the cleanup that follows treats that data as valid. |
| CVE-2026-109619 | Request state survives the freeing of its memory; a later request on the same worker reuses it. |

| Branch | Fixed in | This script reports |
|---|---|---|
| 8.5 / 8.4 / 8.3 / 8.2 | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | `PATCHED` at or above, `VULNERABLE` below |
| 7.4 / 8.0 / 8.1 | no release; source backports only ([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)) | `VULNERABLE` (unless a vendor backport is detected) |
| 5.4 – 7.3 | end-of-life, no fix | `VULNERABLE` |
| `-dev`, `alpha`, `beta`, `RC` builds of a fixed number | not a release | `VULNERABLE` |

## Requirements

- Bash 3.2+ and the usual coreutils, `grep`, `sed`, `awk`, `find`.
- `crictl` mode: root on a Kubernetes node with `crictl`. Use `CRI=docker` to try it against local Docker containers.
- `audit` mode: Linux with GNU `find` and `/proc`. Run it as root to see every process and container layer.
- `url` mode: `curl`.

## Usage

```bash
./check-php2shell.sh classify 8.3.35            # one version string
./check-php2shell.sh classify "$(php-fpm -v)"   # or the full -v banner
./check-php2shell.sh crictl [FILTER]            # on a node: every container with PHP
./check-php2shell.sh audit [HOURS]              # indicator sweep, default 48 hours
./check-php2shell.sh url https://example.com/   # passive X-Powered-By check
./check-php2shell.sh -h
```

Exit codes:

| Mode | `0` | `1` | `2` |
|---|---|---|---|
| `crictl` | every container with PHP is `PATCHED` | at least one is `VULNERABLE` or `UNKNOWN`, or `crictl` is missing / `crictl ps` failed | — |
| `audit` | every check is `PASS` | at least one `REVIEW` | invalid `HOURS` |
| `url` | version found (read the status) | version not disclosed | missing URL |
| `classify` | always (read the status) | — | — |

An unknown mode exits `2`.

### `classify`

```
$ ./check-php2shell.sh classify "PHP 8.2.10 (fpm-fcgi) (built: Sep  1 2023)"
VULNERABLE 8.2.10 (fixed in 8.2.35)
$ ./check-php2shell.sh classify 8.3.36RC1
VULNERABLE 8.3.36RC1 (pre-release of 8.3.36, not the fixed release)
$ ./check-php2shell.sh classify 7.4.33
VULNERABLE 7.4.33 (no fixed release; only source backport PHP-7.4-CVE-2026-109618-109619 or a patched vendor package)
```

### `crictl`

Run on each node. For every running container it execs one `sh` that reads the PHP-FPM version, the ini values FPM loads (`php-fpm -i`, not the CLI, which can read a different ini), the FPM pool overrides, and the installed packages. Containers without PHP are skipped, and so is `kube-system` unless you pass a `FILTER`.

```
PATCHED    my-app-7d9f8 / php-fpm
           image: registry.example.com/my-app:1.4.2
           PHP: 8.3.6 (vendor backport: php8.3-fpm 8.3.6-0ubuntu0.24.04.13 >= 8.3.6-0ubuntu0.24.04.13 (USN-8948-1))  [/usr/sbin/php-fpm8.3]
           packages: php8.3-common 8.3.6-0ubuntu0.24.04.13; php8.3-fpm 8.3.6-0ubuntu0.24.04.13
           mitigations: upload_progress=off (pool) [OK] | memory_limit=-1 (php_admin_value) [OK] | post_max_size=8M | upload_max_filesize=2M | pm.max_requests=500

VULNERABLE legacy-api-5c6b9 / php-fpm
           image: registry.example.com/legacy-api:2.0
           PHP: 7.3.33 (branch 7.3 is end-of-life, no fix exists)  [/usr/local/sbin/php-fpm]
           packages: (unavailable: no dpkg/apk in the image, or PHP built from source)
           mitigations: upload_progress=On [MISSING] | memory_limit=128M (php.ini) [MISSING] | post_max_size=100M [LOWER IT] | upload_max_filesize=2M | pm.max_requests=0

Scanned 2 container(s) with PHP.
```

Mitigation tags:

| Tag | Meaning |
|---|---|
| `[OK]` | Set the way the advisory recommends |
| `[WEAK]` | `memory_limit=-1` comes from php.ini, so an application can still lower it |
| `[MISSING]` | Not set |
| `[UNKNOWN]` | Could not be read (`php -i` gave nothing). Not treated as set: `session.upload_progress.enabled` defaults to On |
| `[LOWER IT]` | `post_max_size` is above 32M or unlimited |

A pool `php_admin_value[memory_limit]` overrides php.ini, so a container with `memory_limit=-1` in php.ini but `256M` in the pool is reported `[MISSING]`.

### `audit`

Seven read-only checks on the host. Container files are read through the overlay `upperdir` of each running container and container logs through `/var/log/pods`, so nothing is exec'd into containers. Host nginx / apache / httpd / PHP-FPM logs under `/var/log` are read too, for PHP running outside Kubernetes; custom log paths elsewhere are not.

| # | Check | Based on |
|---|---|---|
| 1 | A shell, downloader or compiler whose parent or grandparent is php-fpm / php-cgi / apache / httpd / nginx | WoYinDao Sigma process rule |
| 2 | PHP, `.user.ini`, `.htaccess` and PHP ini files changed in the window (ctime, which `touch` cannot fake). Laravel's `storage/framework` and `bootstrap/cache` are skipped | |
| 3 | Webshell-like calls in those PHP files; `auto_prepend_file` / `auto_append_file` set to a value in any `.ini`, `.user.ini`, `.conf` or `.htaccess` (any age, not only the window) | imsarah hardening guide |
| 4 | Logs changed in the window (`/var/log/pods`, `/var/log/nginx`, `/var/log/apache2`, `/var/log/httpd`, `/var/log/php*`, including uncompressed rotated files) and the kernel log: `Allowed memory size … in Unknown on line 0`, `exited on signal 6/7/11`, `SIGSEGV`/`SIGBUS`, PHP segfaults, `Input variables exceeded`, illegal session id warnings, `PHP_SESSION_UPLOAD_PROGRESS`, `upstream prematurely closed connection` | WoYinDao Sigma, php2shell-detect |
| 5 | Cron files changed in the window | |
| 6 | Session files containing `upload_progress_` data | |
| 7 | PHP processes running a binary that has been deleted or replaced (upgraded but not restarted) | m16a4666/php2shell-fix |

Any output marks the check `REVIEW`; it is never called an intrusion automatically. `PASS` only means nothing was found within the scope of that check.

### `url`

Sends one `HEAD` request and reads `X-Powered-By`. A hidden header (which is good practice) gives `UNKNOWN`; check from inside the server instead.

## Running it on an EKS node through SSM

The script is piped to `bash` as base64, so nothing is written to the node.

```bash
NODE=i-0123456789abcdef0
B64=$(base64 < check-php2shell.sh | tr -d '\n')
PARAMS=$(jq -nc --arg b "$B64" '{commands:[
  "export LANG=C.UTF-8",
  ("echo \($b) | base64 -d | bash -s -- crictl; echo \"[crictl exit=$?]\""),
  ("echo \($b) | base64 -d | bash -s -- audit 48; echo \"[audit exit=$?]\"")
], executionTimeout:["300"]}')
CID=$(aws ssm send-command --document-name AWS-RunShellScript --instance-ids "$NODE" \
  --parameters "$PARAMS" --query Command.CommandId --output text)
sleep 30
aws ssm get-command-invocation --command-id "$CID" --instance-id "$NODE" \
  --query '[Status,StandardOutputContent,StandardErrorContent]' --output text
```

The heaviest step is reading `/var/log/pods`, host web server logs and the kernel journal; expect a short CPU and disk spike on small nodes.

## Mitigations (from the php.net announcement)

Only an update is a complete fix. These reduce exposure:

- `memory_limit=-1`, set so applications cannot override it, e.g. `php_admin_value[memory_limit] = -1` in the FPM pool. Pair it with a container memory limit.
- `session.upload_progress.enabled=0` in php.ini or the pool. `ini_set()` and FPM `.user.ini` apply too late.
- `post_max_size = 8M` without uploads, `32M` with uploads; keep `upload_max_filesize` below it. Limit body size, field count and multipart parts at the proxy too.
- PHP 8.5 only: `fatal_error_backtraces=0`.
- Restart every worker afterwards.

## Temporary mitigation: `mitigate-php2shell.sh`

Applies the mitigations above on a server, at a level applications cannot override, and nothing else. It does not upgrade PHP, and it is not a fix.

| Setting | Value | Against |
|---|---|---|
| `session.upload_progress.enabled` | `off` | CVE-2026-109619 |
| `memory_limit` | `-1` | CVE-2026-109618 |
| `post_max_size` | `8M` (`--post-max 32M` if the app accepts uploads) | CVE-2026-109618 |
| `upload_max_filesize` | 3/4 of `post_max_size` (`--upload-max`) | |
| `fatal_error_backtraces` | `off`, PHP 8.5 only | CVE-2026-109619 |
| `pm.max_requests` (FPM) | `500` (`--max-requests`), never raised above a lower value the pool already has | |
| systemd `MemoryMax` + `OOMPolicy=continue` | only with `--memory-max 70%` (or `2G`) | needed because `memory_limit = -1` |

Supported layouts: Debian/Ubuntu `/etc/php/<ver>/fpm/pool.d` (including deb.sury.org), RHEL/Alma/Rocky/Amazon Linux `/etc/php-fpm.d`, Remi `/etc/opt/remi/php*/php-fpm.d`, and Apache with mod_php (`/etc/apache2/conf-available` or `/etc/httpd/conf.d`). Anything else: `--pool-dir DIR --fpm-bin BIN --service NAME`. Inside a container it changes nothing and prints the ini to bake into the image.

```bash
sudo ./mitigate-php2shell.sh plan                          # default: show the change, change nothing
sudo ./mitigate-php2shell.sh apply                         # write, config-test, print the restart command
sudo ./mitigate-php2shell.sh apply --memory-max 70% --restart
sudo ./mitigate-php2shell.sh verify                        # conflicts left? restarted since? MemoryMax?
sudo ./mitigate-php2shell.sh rollback --restart            # remove everything it added
```

How it changes the server:

- It adds one file, `zz-php2shell-mitigation.conf`, next to the existing config (and a systemd drop-in with `--memory-max`). It restarts nothing unless you pass `--restart`.
- **PHP-FPM keeps the first `php_admin_value` it reads for a setting**, so a later file cannot override a value a pool already sets. Those existing lines are commented out with the marker `;php2shell-disabled; `; `rollback` removes the marker and the original lines come back.
- The config directory is archived to `/var/backups/php2shell-*.tgz` first; no backup, no change.
- The service's own config test (`php-fpm -t`, `apachectl configtest`) must pass, otherwise everything is put back. If the script is stopped mid-change (error, Ctrl-C, kill) it undoes that change; after `kill -9` or a power loss, run `rollback`.
- Apache: a `php_admin_value` in a vhost wins over this server-level file. `plan` lists such lines; change them by hand.

After `apply` and a restart, confirm once with a temporary `phpinfo()` page served by the web server (the Local value column of the web SAPI, not the CLI), then delete that page.

Tested in Docker against Ubuntu 24.04 PHP-FPM 8.3, Ubuntu 24.04 Apache + mod_php 8.3 and Amazon Linux 2023 PHP-FPM 8.5: the values PHP reports through a real FastCGI/HTTP request change after `apply` + restart and return to the originals after `rollback`; a pool that already set `memory_limit = 256M` ends up at `-1`; a pool with a syntax error and a script killed mid-change both leave the files exactly as they were.

## Caveats

- **Distro backports.** Debian, Ubuntu, Alpine and other vendors may ship a fixed build under an older version number. The script recognises the Ubuntu packages listed in USN-8948-1; Debian 12/13 bumped the number (`8.2.35-1~deb12u1`, `8.4.27-1~deb13u1`). For anything else, including deb.sury.org packages, check the vendor changelog against the printed package version.
- **`php-fpm -i` reads the config on disk**, not the running workers. After changing ini files or a ConfigMap, restart the pods before trusting the result.
- **The audit is a heuristic.** Logs only cover what is still on the node; an attacker can remove files; a clean result is not proof.

## Testing

Tested locally with Docker: `php:7.3-fpm`, `php:8.3-fpm` with a mitigation ini, Ubuntu 24.04 with apt `php8.3-fpm` and a hardened pool, and a non-PHP container for `crictl`; Amazon Linux 2023 (gawk, GNU find) with planted indicators for every audit check, plus a clean run to confirm no false positives.

`crictl` mode was exercised through `CRI=docker`. On a real node it reads pod name and namespace with `crictl inspect -o go-template`; if your `crictl` does not support that, it falls back to the image name only. Run it on one node first and check the output before rolling it out.

## Not included on purpose

No proof-of-concept or active scanner. Active scanners for these CVEs send tens of MiB per request to trigger memory exhaustion, which is unsafe on production nodes without memory limits. Unverified "PoC" repositories for these CVEs are circulating and may carry malware; do not run them.

## Sources

- [php.net announcement, 2026-10-21](https://www.php.net/index.php#2026-10-21-5)
- PHP advisories [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [projectdiscovery/nuclei-templates CVE-2026-109618](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml)
- [WoYinDao/CVE-2026-109618-CVSS-9.2-Critical](https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical) (Sigma rules)
- [adityaaravind/php2shell-check](https://github.com/adityaaravind/php2shell-check)
- [m16a4666/php2shell-fix](https://github.com/m16a4666/php2shell-fix)
- [fufufuwa/php2shell-detect](https://github.com/fufufuwa/php2shell-detect)
- [imsarah/php2shell-hardening-for-agents](https://github.com/imsarah/php2shell-hardening-for-agents)
- [crowdsecurity/hub vpatch-CVE-2026-109618](https://github.com/crowdsecurity/hub)
