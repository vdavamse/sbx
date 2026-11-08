# sbx vs srt: results

```
date:     2026-11-08T15:26:43Z
kernel:   Linux 6.18.54.1-microsoft-standard-WSL2 x86_64
distro:   Ubuntu 24.04.2 LTS
bwrap:    bubblewrap 0.9.0
node:     v24.1.0
sbx:      sbx 0.1.0 (8fefdff1d13d34d0…)
srt:      0.0.81
srt tag:  c40cf14a65d025e3cd27f071f13a73c12b3b1f92
socat:    1.8.0.0
ripgrep:  ripgrep 14.1.0
sbx check: network mode: transparent (policies with network mode transparent, explicit or none can run)
runner:   8766b69
srt npm integrity: sha512-bjHDu87gjIR7+Oxy9jPiK3v8CvSELCzfpXa3fjqfSKdvlZET2iF51xcXILWPayTpowB3xtZeQVf2JR916nVW/w==
srt npm published versions on 2026-11-08: 77
```

| ID | scenario | sbx | srt |
|---|---|---|---|
| N1 | HTTPS to the allowed name (baseline) | allowed | allowed |
| N2 | HTTPS to a denied name | blocked | blocked |
| N3a | proxy env unset: curl to the allowed name | works | fails-closed |
| N3b | proxy env unset: curl to a denied name | blocked | blocked |
| N3c | raw socket + TLS to the allowed name | works | fails-closed |
| N3d | raw socket + TLS to a denied name | blocked | blocked |
| N3e | bash /dev/tcp to a denied name, port 80 | blocked | blocked |
| N4a | direct IP 1.1.1.1:443 (raw) | blocked | blocked |
| N4b | direct IP https://1.1.1.1/ (curl, proxy env kept) | blocked | blocked |
| N4c | raw DNS to 8.8.8.8:53/udp for a denied name | blocked | blocked |
| N4d | raw DNS to 8.8.8.8:53/tcp for a denied name | blocked | blocked |
| N5a | fronting: TCP to the allowed name, SNI+Host of another site (curl --connect-to) | blocked | LEAKED |
| N5b | fronting: raw TLS to the allowed name with a foreign SNI | blocked | blocked |
| N5c | fronting: SNI of the allowed name, foreign Host header | passed-uninspected | passed-uninspected |
| N6a | allowed name resolving to 127.0.0.1 (127.0.0.1.nip.io) | blocked | blocked |
| N6b | allowed name resolving to 169.254.169.254 | blocked | blocked |
| N6c | allowed name resolving to 10.0.0.1 (RFC1918) | blocked | blocked |
| N7a | host loopback service, raw connect to 127.0.0.1 | blocked | blocked |
| N7b | host loopback service by IP, proxy variables honoured (curl --noproxy '') | blocked | blocked |
| N7c | host loopback service by name (localhost) | blocked | blocked |
| N7d | host abstract unix socket | blocked | blocked |
| N8a | git over HTTPS to the allowed name | allowed | allowed |
| N8b | ssh to the allowed name, port 22 | blocked | blocked |
| N8c | git over ssh to the allowed name, port 22 | blocked | blocked |
| N8d | UDP datagram to the allowed name, port 443 | blocked | blocked |
| N8e | UDP datagram to an IP literal (1.1.1.1:443, no DNS needed) | blocked | blocked |
| F1 | write inside the rw dir (baseline) | allowed | allowed |
| F2 | write outside the rw dir (host /tmp) | blocked | blocked |
| F3 | write into the host $HOME | blocked | blocked |
| F4 | write to /usr | blocked | blocked |
| F5 | list ~/.ssh (names only) | blocked | blocked |
| F6 | read secrets from the environment | blocked | LEAKED |
| F7 | see a host process (/proc) | blocked | blocked |
| F8 | read the host /etc/passwd (the srt policy has to allow it, see V4) | blocked | LEAKED |
| F9 | plant a git hook in the rw checkout (.git/hooks/pre-commit) | planted | blocked |
| F10 | plant a shell rc file in the rw dir (.bashrc) | planted | blocked |

## srt without the two settings that match the sbx policy

| ID | case | srt |
|---|---|---|
| V1 | srt allow entry without :port, then git over ssh (port 22) | dialed |
| V2 | srt without deniedResolvedAddresses, name resolving to 10.0.0.1 | dialed |
| V3 | srt with denyRead ["/"] (allowRead as in the policy), HTTPS to the allowed name | broken |
| V4 | srt without /etc/passwd, /etc/group, /etc/hosts readable, git over ssh | broken |

## Ergonomics

| ID | case | sbx | srt |
|---|---|---|---|
| E1 | command exits 7 | `rc=7 t=40ms  ` | `rc=7 t=530ms  ` |
| E2 | command killed by its own SIGKILL | `rc=137 t=60ms  ` | `rc=137 t=360ms  ` |
| E3 | timeout 2 s (sbx --timeout; srt has no timeout, so coreutils timeout) | `rc=124 t=2030ms sbx run: timed out after 2s leftover: 0 ` | `rc=124 t=2020ms  leftover: 0 ` |
| E4 | SIGTERM to the tool during a run | `sbx run: terminated by SIGTERM rc=143 leftover: 0 ` | `rc=0 leftover: 0 ` |
| E5 | malformed policy file | `rc=125 t=0ms sbx run: EOF while parsing an object at line 2 column 0 ` | `rc=1 t=260ms Refusing to run with the built-in defaults, which would drop this file's rules (its denyRead, allowRead and credential entries included). ` |
| E6 | sandbox cannot start (bwrap missing) | `rc=125 t=10ms sbx run: cannot run "/no/such/bwrap" --version: No such file or directory (os error 2) ` | `rc=1 t=290ms Error: Sandbox dependencies not available: bubblewrap (bwrap) not executable at /no/such/bwrap ` |
| E7 | command not found | `rc=1 t=20ms bwrap: execvp /no/such/cmd: No such file or directory ` | `rc=127 t=520ms /usr/bin/bash: line 1: /no/such/cmd: No such file or directory ` |
| E8 | 5 MB of output (the sbx policy caps output at 1 MiB) | `bytes=1048576 sbx run: output truncated at 1048576 bytes (limits.output_bytes); audit output_truncated=true ` | `bytes=5000000 ` |
| E9 | persistent session (sbx run --keep-alive, then attach true) | `start: rc=0 t=40ms ; attach: rc=0 t=60ms ; attach curl of the resident: http=200 ` | `not in the CLI (each srt call starts its own proxies; the library's SandboxManager keeps them across wrapWithSandbox calls) ` |

```
startup latency, 20 runs of true, median (ms):
  bare true         median     1.0  min     1.0  max     1.3  (n=20)
  sbx run           median    20.6  min    13.7  max    23.9  (n=20)
  srt               median   508.2  min   317.6  max   704.3  (n=20)
  node -e 0         median    54.9  min    22.0  max    93.1  (n=20)
  srt --version     median   184.9  min   178.8  max   314.8  (n=20)
  srt, empty policy median   538.1  min   366.3  max   644.5  (n=20)
install footprint:
  sbx binary:        6.4M  (ELF 64-bit LSB pie executable, x86-64)
  srt package:       19M node_modules (5 top-level entries)
  node runtime:      122M (v24.1.0)
  socat:             448K   ripgrep: 5.1M
  bwrap:             72K -rwxr-xr-x root (setuid: no)
canaries left on the host after all runs: none
```

## Evidence

### N1 HTTPS to the allowed name (baseline) — sbx

```
$ c https://example.com/
--- output (rc=0)
connect=000 http=200 ip=198.18.0.1
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
connect allowed host=example.com sni=example.com port=443: allowed example.com via 172.66.147.243:443
exit code=0 outcome=exited
```

### N1 HTTPS to the allowed name (baseline) — srt

```
$ c https://example.com/
--- output (rc=0)
connect=200 http=200 ip=::1
--- srt log
Allowed by config rule: example.com:443
```

### N2 HTTPS to a denied name — sbx

```
$ c https://www.google.com/
--- output (rc=0)
curl: (6) Could not resolve host: www.google.com
connect=000 http=000 ip=
--- sbx log
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
exit code=0 outcome=exited
```

### N2 HTTPS to a denied name — srt

```
$ c https://www.google.com/
--- output (rc=0)
curl: (56) CONNECT tunnel failed, response 403
connect=403 http=000 ip=::1
--- srt log
Connection blocked to www.google.com:443
No matching rule, denying: www.google.com:443
```

### N3a proxy env unset: curl to the allowed name — sbx

```
$ noproxy c --noproxy "*" https://example.com/
--- output (rc=0)
connect=000 http=200 ip=198.18.0.1
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
connect allowed host=example.com sni=example.com port=443: allowed example.com via 172.66.147.243:443
exit code=0 outcome=exited
```

### N3a proxy env unset: curl to the allowed name — srt

```
$ noproxy c --noproxy "*" https://example.com/
--- output (rc=0)
curl: (6) Could not resolve host: example.com
connect=000 http=000 ip=
--- srt log
```

### N3b proxy env unset: curl to a denied name — sbx

```
$ noproxy c --noproxy "*" https://www.google.com/
--- output (rc=0)
curl: (6) Could not resolve host: www.google.com
connect=000 http=000 ip=
--- sbx log
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
exit code=0 outcome=exited
```

### N3b proxy env unset: curl to a denied name — srt

```
$ noproxy c --noproxy "*" https://www.google.com/
--- output (rc=0)
curl: (6) Could not resolve host: www.google.com
connect=000 http=000 ip=
--- srt log
```

### N3c raw socket + TLS to the allowed name — sbx

```
$ P tcp example.com 443 example.com
--- output (rc=0)
RESULT=handshake peer=198.18.0.1 sni=example.com cert_bytes=1002 status=b'HTTP/1.1 200 OK'
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
connect allowed host=example.com sni=example.com port=443: allowed example.com via 172.66.147.243:443
exit code=0 outcome=exited
```

### N3c raw socket + TLS to the allowed name — srt

```
$ P tcp example.com 443 example.com
--- output (rc=0)
RESULT=no-connect gaierror(Unknown error -3)
--- srt log
```

### N3d raw socket + TLS to a denied name — sbx

```
$ P tcp www.google.com 443 www.google.com
--- output (rc=0)
RESULT=no-connect gaierror(Unknown error -2)
--- sbx log
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
exit code=0 outcome=exited
```

### N3d raw socket + TLS to a denied name — srt

```
$ P tcp www.google.com 443 www.google.com
--- output (rc=0)
RESULT=no-connect gaierror(Unknown error -3)
--- srt log
```

### N3e bash /dev/tcp to a denied name, port 80 — sbx

```
$ RE=HTTP/ show timeout 10 bash -c "exec 3<>/dev/tcp/www.google.com/80 && printf \"HEAD / HTTP/1.0\r\n\r\n\" >&3 && head -c 12 <&3"
--- output (rc=0)
bash: line 1: www.google.com: Name or service not known
bash: line 1: /dev/tcp/www.google.com/80: Invalid argument
--- sbx log
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
exit code=0 outcome=exited
```

### N3e bash /dev/tcp to a denied name, port 80 — srt

```
$ RE=HTTP/ show timeout 10 bash -c "exec 3<>/dev/tcp/www.google.com/80 && printf \"HEAD / HTTP/1.0\r\n\r\n\" >&3 && head -c 12 <&3"
--- output (rc=0)
bash: line 1: www.google.com: Temporary failure in name resolution
bash: line 1: /dev/tcp/www.google.com/80: Invalid argument
--- srt log
```

### N4a direct IP 1.1.1.1:443 (raw) — sbx

```
$ P tcp 1.1.1.1 443 one.one.one.one
--- output (rc=0)
RESULT=no-handshake peer=1.1.1.1 sni=one.one.one.one SSLEOFError([SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000))
--- sbx log
deny denied host=None sni=None port=443: unknown fake IP 1.1.1.1 (no DNS-map entry)
exit code=0 outcome=exited
```

### N4a direct IP 1.1.1.1:443 (raw) — srt

```
$ P tcp 1.1.1.1 443 one.one.one.one
--- output (rc=0)
RESULT=no-connect OSError(Network is unreachable)
--- srt log
```

### N4b direct IP https://1.1.1.1/ (curl, proxy env kept) — sbx

```
$ c -k https://1.1.1.1/
--- output (rc=0)
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 1.1.1.1:443 
connect=000 http=000 ip=1.1.1.1
--- sbx log
deny denied host=None sni=None port=443: unknown fake IP 1.1.1.1 (no DNS-map entry)
exit code=0 outcome=exited
```

### N4b direct IP https://1.1.1.1/ (curl, proxy env kept) — srt

```
$ c -k https://1.1.1.1/
--- output (rc=0)
curl: (56) CONNECT tunnel failed, response 403
connect=403 http=000 ip=::1
--- srt log
Connection blocked to 1.1.1.1:443
No matching rule, denying: 1.1.1.1:443
```

### N4c raw DNS to 8.8.8.8:53/udp for a denied name — sbx

```
$ P dns 8.8.8.8 www.google.com udp
--- output (rc=0)
RESULT=refused udp 8.8.8.8:53 rcode=3 answers=0
--- sbx log
dns denied host=www.google.com sni=None port=None: www.google.com is not in the policy allow list
exit code=0 outcome=exited
```

### N4c raw DNS to 8.8.8.8:53/udp for a denied name — srt

```
$ P dns 8.8.8.8 www.google.com udp
--- output (rc=0)
RESULT=no-answer udp 8.8.8.8:53 OSError(Network is unreachable)
--- srt log
```

### N4d raw DNS to 8.8.8.8:53/tcp for a denied name — sbx

```
$ P dns 8.8.8.8 www.google.com tcp
--- output (rc=0)
RESULT=no-answer tcp 8.8.8.8:53 ConnectionResetError(Connection reset by peer)
--- sbx log
deny denied host=None sni=None port=53: port 53 is not in the policy port list
exit code=0 outcome=exited
```

### N4d raw DNS to 8.8.8.8:53/tcp for a denied name — srt

```
$ P dns 8.8.8.8 www.google.com tcp
--- output (rc=0)
RESULT=no-answer tcp 8.8.8.8:53 OSError(Network is unreachable)
--- srt log
```

### N5a fronting: TCP to the allowed name, SNI+Host of another site (curl --connect-to) — sbx

```
$ c --connect-to www.cloudflare.com:443:example.com:443 https://www.cloudflare.com/
--- output (rc=0)
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to www.cloudflare.com:443 
connect=000 http=000 ip=198.18.0.1
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
deny denied host=example.com sni=None port=443: SNI www.cloudflare.com does not match the DNS-map name example.com
exit code=0 outcome=exited
```

### N5a fronting: TCP to the allowed name, SNI+Host of another site (curl --connect-to) — srt

```
$ c --connect-to www.cloudflare.com:443:example.com:443 https://www.cloudflare.com/
--- output (rc=0)
connect=200 http=200 ip=::1
--- srt log
Allowed by config rule: example.com:443
```

### N5b fronting: raw TLS to the allowed name with a foreign SNI — sbx

```
$ P tcp example.com 443 www.cloudflare.com
--- output (rc=0)
RESULT=no-handshake peer=198.18.0.1 sni=www.cloudflare.com SSLEOFError([SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000))
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
deny denied host=example.com sni=None port=443: SNI www.cloudflare.com does not match the DNS-map name example.com
exit code=0 outcome=exited
```

### N5b fronting: raw TLS to the allowed name with a foreign SNI — srt

```
$ P tcp example.com 443 www.cloudflare.com
--- output (rc=0)
RESULT=no-connect gaierror(Unknown error -3)
--- srt log
```

### N5c fronting: SNI of the allowed name, foreign Host header — sbx

```
$ c https://example.com/ -H "Host: www.cloudflare.com"
--- output (rc=0)
connect=000 http=403 ip=198.18.0.1
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
connect allowed host=example.com sni=example.com port=443: allowed example.com via 172.66.147.243:443
exit code=0 outcome=exited
```

### N5c fronting: SNI of the allowed name, foreign Host header — srt

```
$ c https://example.com/ -H "Host: www.cloudflare.com"
--- output (rc=0)
connect=200 http=403 ip=::1
--- srt log
Allowed by config rule: example.com:443
```

### N6a allowed name resolving to 127.0.0.1 (127.0.0.1.nip.io) — sbx

```
$ c https://127.0.0.1.nip.io/
--- output (rc=0)
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 127.0.0.1.nip.io:443 
connect=000 http=000 ip=198.18.0.1
--- sbx log
dns answered host=127.0.0.1.nip.io sni=None port=None: answered 127.0.0.1.nip.io A 198.18.0.1
dns nodata host=127.0.0.1.nip.io sni=None port=None: NODATA for 127.0.0.1.nip.io type 28 (A only)
deny denied host=127.0.0.1.nip.io sni=None port=443: denied dial to 127.0.0.1:443: loopback address (127.0.0.0/8, ::1/128)
exit code=0 outcome=exited
```

### N6a allowed name resolving to 127.0.0.1 (127.0.0.1.nip.io) — srt

```
$ c https://127.0.0.1.nip.io/
--- output (rc=0)
curl: (56) CONNECT tunnel failed, response 403
connect=403 http=000 ip=::1
--- srt log
Allowed by config rule: 127.0.0.1.nip.io:443
CONNECT tunnel failed: Connection to 127.0.0.1.nip.io blocked: resolved to a loopback address
```

### N6b allowed name resolving to 169.254.169.254 — sbx

```
$ c https://169.254.169.254.nip.io/
--- output (rc=0)
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 169.254.169.254.nip.io:443 
connect=000 http=000 ip=198.18.0.1
--- sbx log
dns answered host=169.254.169.254.nip.io sni=None port=None: answered 169.254.169.254.nip.io A 198.18.0.1
dns nodata host=169.254.169.254.nip.io sni=None port=None: NODATA for 169.254.169.254.nip.io type 28 (A only)
deny denied host=169.254.169.254.nip.io sni=None port=443: denied dial to 169.254.169.254:443: link-local address (incl. cloud metadata 169.254.169.254)
exit code=0 outcome=exited
```

### N6b allowed name resolving to 169.254.169.254 — srt

```
$ c https://169.254.169.254.nip.io/
--- output (rc=0)
curl: (56) CONNECT tunnel failed, response 403
connect=403 http=000 ip=::1
--- srt log
Allowed by config rule: 169.254.169.254.nip.io:443
CONNECT tunnel failed: Connection to 169.254.169.254.nip.io blocked: resolved to a link-local address
```

### N6c allowed name resolving to 10.0.0.1 (RFC1918) — sbx

```
$ c https://10.0.0.1.nip.io/
--- output (rc=0)
curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 10.0.0.1.nip.io:443 
connect=000 http=000 ip=198.18.0.1
--- sbx log
dns answered host=10.0.0.1.nip.io sni=None port=None: answered 10.0.0.1.nip.io A 198.18.0.1
dns nodata host=10.0.0.1.nip.io sni=None port=None: NODATA for 10.0.0.1.nip.io type 28 (A only)
deny denied host=10.0.0.1.nip.io sni=None port=443: denied dial to 10.0.0.1:443: private-use address (RFC 1918)
exit code=0 outcome=exited
```

### N6c allowed name resolving to 10.0.0.1 (RFC1918) — srt

```
$ c https://10.0.0.1.nip.io/
--- output (rc=0)
curl: (56) CONNECT tunnel failed, response 403
connect=403 http=000 ip=::1
--- srt log
Allowed by config rule: 10.0.0.1.nip.io:443
CONNECT tunnel failed: Connection to 10.0.0.1.nip.io blocked: resolved to a listed address
```

### N7a host loopback service, raw connect to 127.0.0.1 — sbx

```
$ P tcp 127.0.0.1 60539
--- output (rc=0)
RESULT=no-connect ConnectionRefusedError(Connection refused)
--- sbx log
exit code=0 outcome=exited
```

### N7a host loopback service, raw connect to 127.0.0.1 — srt

```
$ P tcp 127.0.0.1 60539
--- output (rc=0)
RESULT=no-connect ConnectionRefusedError(Connection refused)
--- srt log
```

### N7b host loopback service by IP, proxy variables honoured (curl --noproxy '') — sbx

```
$ RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://127.0.0.1:60539/
--- output (rc=0)
curl: (7) Failed to connect to 127.0.0.1 port 60539 after 0 ms: Couldn't connect to server
--- sbx log
exit code=0 outcome=exited
```

### N7b host loopback service by IP, proxy variables honoured (curl --noproxy '') — srt

```
$ RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://127.0.0.1:60539/
--- output (rc=0)
Connection blocked by network allowlist
--- srt log
HTTP request blocked to 127.0.0.1:60539
No matching rule, denying: 127.0.0.1:60539
[proxy] deny: Connection blocked by network allowlist
```

### N7c host loopback service by name (localhost) — sbx

```
$ RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://localhost:60539/
--- output (rc=0)
curl: (7) Failed to connect to localhost port 60539 after 0 ms: Couldn't connect to server
--- sbx log
exit code=0 outcome=exited
```

### N7c host loopback service by name (localhost) — srt

```
$ RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://localhost:60539/
--- output (rc=0)
Connection blocked by network allowlist
--- srt log
HTTP request blocked to localhost:60539
No matching rule, denying: localhost:60539
[proxy] deny: Connection blocked by network allowlist
```

### N7d host abstract unix socket — sbx

```
$ P abstract sbx-bench-489cb273
--- output (rc=0)
RESULT=no-connect @sbx-bench-489cb273 ConnectionRefusedError(Connection refused)
--- sbx log
exit code=0 outcome=exited
```

### N7d host abstract unix socket — srt

```
$ P abstract sbx-bench-489cb273
--- output (rc=0)
RESULT=no-socket socket(AF_UNIX) PermissionError(Operation not permitted)
--- srt log
```

### N8a git over HTTPS to the allowed name — sbx

```
$ RE="not found|404|did not send" GIT_TERMINAL_PROMPT=0 show git ls-remote https://example.com/x.git
--- output (rc=0)
fatal: repository 'https://example.com/x.git/' not found
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
connect allowed host=example.com sni=example.com port=443: allowed example.com via 172.66.147.243:443
exit code=0 outcome=exited
```

### N8a git over HTTPS to the allowed name — srt

```
$ RE="not found|404|did not send" GIT_TERMINAL_PROMPT=0 show git ls-remote https://example.com/x.git
--- output (rc=0)
fatal: repository 'https://example.com/x.git/' not found
--- srt log
Allowed by config rule: example.com:443
```

### N8b ssh to the allowed name, port 22 — sbx

```
$ RE="SSH-2\.0|Permission denied \(publickey|Host key verification" show ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@example.com true
--- output (rc=0)
Connection closed by 198.18.0.1 port 22
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
deny denied host=None sni=None port=22: port 22 is not in the policy port list
exit code=0 outcome=exited
```

### N8b ssh to the allowed name, port 22 — srt

```
$ RE="SSH-2\.0|Permission denied \(publickey|Host key verification" show ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@example.com true
--- output (rc=0)
ssh: Could not resolve hostname example.com: Temporary failure in name resolution
--- srt log
```

### N8c git over ssh to the allowed name, port 22 — sbx

```
$ RE="SSH-2\.0|Permission denied \(publickey|Host key verification" GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8" show git ls-remote ssh://git@example.com/x.git
--- output (rc=0)
Connection closed by 198.18.0.1 port 22
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
dns nodata host=example.com sni=None port=None: NODATA for example.com type 28 (A only)
deny denied host=None sni=None port=22: port 22 is not in the policy port list
exit code=0 outcome=exited
```

### N8c git over ssh to the allowed name, port 22 — srt

```
$ RE="SSH-2\.0|Permission denied \(publickey|Host key verification" GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8" show git ls-remote ssh://git@example.com/x.git
--- output (rc=0)
2026/11/08 15:27:05 socat[8] E CONNECT example.com:22: host is not on the allow list
Connection closed by UNKNOWN port 65535
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
--- srt log
Connection blocked to example.com:22
No matching rule, denying: example.com:22
```

### N8d UDP datagram to the allowed name, port 443 — sbx

```
$ P udp example.com 443
--- output (rc=0)
RESULT=no-send PermissionError(Operation not permitted)
--- sbx log
dns answered host=example.com sni=None port=None: answered example.com A 198.18.0.1
exit code=0 outcome=exited
```

### N8d UDP datagram to the allowed name, port 443 — srt

```
$ P udp example.com 443
--- output (rc=0)
RESULT=no-send gaierror(Unknown error -3)
--- srt log
```

### N8e UDP datagram to an IP literal (1.1.1.1:443, no DNS needed) — sbx

```
$ P udp 1.1.1.1 443
--- output (rc=0)
RESULT=no-send PermissionError(Operation not permitted)
--- sbx log
exit code=0 outcome=exited
```

### N8e UDP datagram to an IP literal (1.1.1.1:443, no DNS needed) — srt

```
$ P udp 1.1.1.1 443
--- output (rc=0)
RESULT=no-send OSError(Network is unreachable)
--- srt log
```

### F1 write inside the rw dir (baseline) — sbx

```
$ echo ok > '<WORK>/rw/inside' && cat '<WORK>/rw/inside'
--- output (rc=0)
ok
--- sbx log
exit code=0 outcome=exited
```

### F1 write inside the rw dir (baseline) — srt

```
$ echo ok > '<WORK>/rw/inside' && cat '<WORK>/rw/inside'
--- output (rc=0)
ok
--- srt log
```

### F2 write outside the rw dir (host /tmp) — sbx

```
$ echo canary > '<WORK>/outside-canary'
--- output (rc=0)
--- sbx log
exit code=0 outcome=exited
host: write succeeded inside, but <WORK>/outside-canary is not on the host (the sandbox has its own mount there)
```

### F2 write outside the rw dir (host /tmp) — srt

```
$ echo canary > '<WORK>/outside-canary'
--- output (rc=0)
/usr/bin/bash: line 11: <WORK>/outside-canary: Read-only file system
--- srt log
```

### F3 write into the host $HOME — sbx

```
$ echo canary > '<HOME>/.sbx-bench-canary-489cb273'
--- output (rc=0)
/usr/bin/bash: line 11: <HOME>/.sbx-bench-canary-489cb273: No such file or directory
--- sbx log
exit code=0 outcome=exited
```

### F3 write into the host $HOME — srt

```
$ echo canary > '<HOME>/.sbx-bench-canary-489cb273'
--- output (rc=0)
/usr/bin/bash: line 11: <HOME>/.sbx-bench-canary-489cb273: No such file or directory
--- srt log
```

### F4 write to /usr — sbx

```
$ echo canary > /usr/sbx-bench-489cb273
--- output (rc=0)
/usr/bin/bash: line 11: /usr/sbx-bench-489cb273: Read-only file system
--- sbx log
exit code=0 outcome=exited
```

### F4 write to /usr — srt

```
$ echo canary > /usr/sbx-bench-489cb273
--- output (rc=0)
/usr/bin/bash: line 11: /usr/sbx-bench-489cb273: Read-only file system
--- srt log
```

### F5 list ~/.ssh (names only) — sbx

```
$ n=$(ls -A '<HOME>/.ssh' 2>&1) && echo "listed $(echo "$n" | grep -c .) entries" || { echo "$n"; false; }
--- output (rc=0)
ls: cannot access '<HOME>/.ssh': No such file or directory
--- sbx log
exit code=0 outcome=exited
```

### F5 list ~/.ssh (names only) — srt

```
$ n=$(ls -A '<HOME>/.ssh' 2>&1) && echo "listed $(echo "$n" | grep -c .) entries" || { echo "$n"; false; }
--- output (rc=0)
ls: cannot access '<HOME>/.ssh': No such file or directory
--- srt log
```

### F6 read secrets from the environment — sbx

```
$ printenv SBX_BENCH_SECRET && printenv AWS_SECRET_ACCESS_KEY
--- output (rc=0)
--- sbx log
exit code=0 outcome=exited
```

### F6 read secrets from the environment — srt

```
$ printenv SBX_BENCH_SECRET && printenv AWS_SECRET_ACCESS_KEY
--- output (rc=0)
canary-489cb273
canary-aws-489cb273
--- srt log
```

### F7 see a host process (/proc) — sbx

```
$ m=sbx-bench-decoy; m=$m-489cb273; n=0; f=1
   for p in /proc/[0-9]*; do n=$((n+1)); case "$(tr '\0' ' ' <$p/cmdline 2>/dev/null)" in *"$m"*) f=0; echo "found $p";; esac; done
   echo "visible pids: $n"; exit $f
--- output (rc=0)
visible pids: 3
--- sbx log
exit code=0 outcome=exited
```

### F7 see a host process (/proc) — srt

```
$ m=sbx-bench-decoy; m=$m-489cb273; n=0; f=1
   for p in /proc/[0-9]*; do n=$((n+1)); case "$(tr '\0' ' ' <$p/cmdline 2>/dev/null)" in *"$m"*) f=0; echo "found $p";; esac; done
   echo "visible pids: $n"; exit $f
--- output (rc=0)
visible pids: 3
--- srt log
```

### F8 read the host /etc/passwd (the srt policy has to allow it, see V4) — sbx

```
$ grep '^[^:]*:[^:]*:1000:' /etc/passwd | cut -d: -f1,3 | sed 's/^[^:]*/<host user>/' | grep .
--- output (rc=0)
--- sbx log
exit code=0 outcome=exited
```

### F8 read the host /etc/passwd (the srt policy has to allow it, see V4) — srt

```
$ grep '^[^:]*:[^:]*:1000:' /etc/passwd | cut -d: -f1,3 | sed 's/^[^:]*/<host user>/' | grep .
--- output (rc=0)
<host user>:1000
--- srt log
```

### F9 plant a git hook in the rw checkout (.git/hooks/pre-commit) — sbx

```
$ echo 'echo pwned' > '<WORK>/rw/.git/hooks/pre-commit'
--- output (rc=0)
--- sbx log
exit code=0 outcome=exited
host: <WORK>/rw/.git/hooks/pre-commit written (echo pwned)
```

### F9 plant a git hook in the rw checkout (.git/hooks/pre-commit) — srt

```
$ echo 'echo pwned' > '<WORK>/rw/.git/hooks/pre-commit'
--- output (rc=0)
/usr/bin/bash: line 11: <WORK>/rw/.git/hooks/pre-commit: Read-only file system
--- srt log
```

### F10 plant a shell rc file in the rw dir (.bashrc) — sbx

```
$ echo 'echo pwned' >> '<WORK>/rw/.bashrc'
--- output (rc=0)
--- sbx log
exit code=0 outcome=exited
host: <WORK>/rw/.bashrc written (echo pwned)
```

### F10 plant a shell rc file in the rw dir (.bashrc) — srt

```
$ echo 'echo pwned' >> '<WORK>/rw/.bashrc'
--- output (rc=0)
/usr/bin/bash: line 11: <WORK>/rw/.bashrc: Permission denied
--- srt log
```

### V1 srt allow entry without :port, then git over ssh (port 22) — srt

```
$ GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$GIT_SSH_COMMAND -o BatchMode=yes -o ConnectTimeout=8" timeout 20 git ls-remote ssh://git@example.com/x.git
--- output
2026/11/08 15:27:14 socat[6] E CONNECT example.com:22: Bad Gateway
Connection closed by UNKNOWN port 65535
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
--- srt log
Allowed by config rule: example.com:22
```

### V2 srt without deniedResolvedAddresses, name resolving to 10.0.0.1 — srt

```
$ c -m 8 https://10.0.0.1.nip.io/
--- output
curl: (28) Connection timed out after 8000 milliseconds
connect=000 http=000 ip=::1
--- srt log
Allowed by config rule: 10.0.0.1.nip.io:443
```

### V3 srt with denyRead ["/"] (allowRead as in the policy), HTTPS to the allowed name — srt

```
$ c https://example.com/
--- output
--- srt log
```

### V4 srt without /etc/passwd, /etc/group, /etc/hosts readable, git over ssh — srt

```
$ GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$GIT_SSH_COMMAND -o BatchMode=yes" git ls-remote ssh://git@example.com/x.git
--- output
No user exists for uid 1000
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
--- srt log
```

