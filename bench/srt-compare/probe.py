#!/usr/bin/python3
"""Raw network probes that ignore proxy environment variables.

Runs inside each sandbox (stdlib only, Python 3.8+). Every subcommand prints
one `RESULT=<word> <detail>` line and exits 0 when the probe reached its
target, 1 when it did not. "Reached" means bytes came back from the far end:
a TCP connect alone is not counted, because a transparent proxy accepts the
connect before it decides.

  tcp HOST PORT [SNI]      connect; with SNI, do a TLS handshake (no verify)
  dns SERVER NAME udp|tcp  send one A query straight to SERVER:53 (reached
                           only when the answer has records)
  udp HOST PORT            send a datagram, wait 3 s for any reply
  abstract NAME            connect to the abstract unix socket @NAME, read
  unix PATH                connect to the unix socket file PATH, read
"""
import os
import random
import socket
import ssl
import struct
import sys

TIMEOUT = 6


def out(word, detail, ok):
    print(f"RESULT={word} {detail}")
    sys.exit(0 if ok else 1)


def err(e):
    # An SSLError's errno is an OpenSSL code, not an errno: print the error.
    name = getattr(e, "errno", None)
    if isinstance(name, int) and not isinstance(e, ssl.SSLError):
        return f"{type(e).__name__}({os.strerror(name)})"
    return f"{type(e).__name__}({e})"


def tcp(host, port, sni=None):
    try:
        s = socket.create_connection((host, int(port)), timeout=TIMEOUT)
    except OSError as e:
        out("no-connect", err(e), False)
    peer = s.getpeername()[0]
    if not sni:
        # Plain TCP: send an HTTP request and see whether anything answers.
        try:
            s.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = s.recv(200)
        except OSError as e:
            out("no-reply", f"peer={peer} {err(e)}", False)
        if data:
            first = data.split(b"\r\n")[0][:80]
            out("reply", f"peer={peer} {first!r}", True)
        out("no-reply", f"peer={peer} closed without data", False)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t = ctx.wrap_socket(s, server_hostname=sni)
        der = t.getpeercert(binary_form=True)
        t.sendall(f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
        line = t.recv(200).split(b"\r\n")[0][:60]
    except (OSError, ssl.SSLError) as e:
        out("no-handshake", f"peer={peer} sni={sni} {err(e)}", False)
    out("handshake", f"peer={peer} sni={sni} cert_bytes={len(der or b'')} status={line!r}", True)


def dns(server, name, proto):
    qid = random.randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q += struct.pack(">HH", 1, 1)
    try:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(TIMEOUT)
            s.sendto(q, (server, 53))
            r = s.recv(512)
        else:
            s = socket.create_connection((server, 53), timeout=TIMEOUT)
            s.sendall(struct.pack(">H", len(q)) + q)
            r = s.recv(514)[2:]
    except OSError as e:
        out("no-answer", f"{proto} {server}:53 {err(e)}", False)
    if len(r) < 12 or struct.unpack(">H", r[:2])[0] != qid:
        out("no-answer", f"{proto} {server}:53 bad reply ({len(r)} bytes)", False)
    rcode = r[3] & 0xF
    ancount = struct.unpack(">H", r[6:8])[0]
    # An answer with records is a resolution; an NXDOMAIN or empty answer
    # (for example from a resolver that intercepts port 53) is not.
    ok = rcode == 0 and ancount > 0
    out("answer" if ok else "refused", f"{proto} {server}:53 rcode={rcode} answers={ancount}", ok)


def udp(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(b"\x00" * 32, (host, int(port)))
    except OSError as e:
        out("no-send", err(e), False)
    try:
        r = s.recv(512)
    except OSError as e:
        out("sent-no-reply", f"sendto ok, {err(e)} (cannot tell if it left)", False)
    out("reply", f"{len(r)} bytes", True)


def unix(addr, label):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as e:
        out("no-socket", f"socket(AF_UNIX) {err(e)}", False)
    s.settimeout(TIMEOUT)
    try:
        s.connect(addr)
        data = s.recv(100)
    except OSError as e:
        out("no-connect", f"{label} {err(e)}", False)
    out("reply", f"{label} {data[:60]!r}", True)


def main(a):
    if not a:
        sys.exit(__doc__)
    cmd, rest = a[0], a[1:]
    if cmd == "tcp":
        tcp(*rest)
    elif cmd == "dns":
        dns(*rest)
    elif cmd == "udp":
        udp(*rest)
    elif cmd == "abstract":
        unix("\0" + rest[0], "@" + rest[0])
    elif cmd == "unix":
        unix(rest[0], rest[0])
    else:
        sys.exit(__doc__)


main(sys.argv[1:])
