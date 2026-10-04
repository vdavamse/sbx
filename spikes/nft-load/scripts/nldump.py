#!/usr/bin/env python3
"""Raw NETLINK_NETFILTER dump for cross-checking the spike's rule encoding.

Adapted from the design-phase probe for issue #1. Runs INSIDE the target
netns (e.g. via `unshare -Urn` or `nsenter -t <pid> -n`). Dumps GETCHAIN and
GETRULE for a table with exact stored byte lengths — the authoritative
ground truth (see ../rules/ground-truth.md).

Usage:
    nldump.py [--table NAME] [--json]
"""
import argparse
import json
import socket
import struct
import sys

NETLINK_NETFILTER = 12
AF_NETLINK = 16
NLM_F_REQUEST = 1
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3
NFNL_SUBSYS_NFTABLES = 10
NFT_MSG_GETCHAIN = 4
NFT_MSG_GETRULE = 7


def enc_attr(t, data, nested=False):
    tt = t | (0x8000 if nested else 0)
    hdr = struct.pack("=HH", len(data) + 4, tt)
    pad = b"\0" * ((4 - ((len(data) + 4) % 4)) % 4)
    return hdr + data + pad


def walk(buf):
    pos = 0
    out = []
    while pos + 4 <= len(buf):
        ln, t = struct.unpack_from("=HH", buf, pos)
        if ln < 4 or pos + ln > len(buf):
            break
        out.append((t, buf[pos + 4:pos + ln]))
        pos += (ln + 3) & ~3
    return out


def hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def attr_json(t, data):
    node = {
        "type": t & 0x7FFF,
        "nested": bool(t & 0x8000),
        "len": len(data),
        "hex": hexs(data),
    }
    if len(data) == 4:
        node["u32be"] = struct.unpack("!I", data)[0]
        node["i32be"] = struct.unpack("!i", data)[0]
    if len(data) == 2:
        node["u16be"] = struct.unpack("!H", data)[0]
    stripped = data.rstrip(b"\0")
    if stripped and all(32 <= x < 127 for x in stripped):
        node["str"] = stripped.decode()
    if node["nested"]:
        node["attrs"] = tree_json(data)
    return node


def tree_json(buf):
    return [attr_json(t, d) for t, d in walk(buf)]


def dump_tree(buf, depth=1):
    for t, data in walk(buf):
        nested = bool(t & 0x8000)
        tt = t & 0x7FFF
        pad = "  " * depth
        if nested:
            print(f"{pad}attr type={tt} NESTED len={len(data)}")
            dump_tree(data, depth + 1)
        else:
            extra = ""
            if len(data) == 4:
                extra = (
                    f" (u32be={struct.unpack('!I', data)[0]}"
                    f" i32be={struct.unpack('!i', data)[0]})"
                )
            if len(data) == 2:
                extra = f" (u16be={struct.unpack('!H', data)[0]})"
            stripped = data.rstrip(b"\0")
            if stripped and all(32 <= x < 127 for x in stripped):
                extra += f" str={stripped!r}"
            print(f"{pad}attr type={tt} len={len(data)} bytes=[{hexs(data)}]{extra}")


def do_dump(msg_type, family, table, as_json):
    s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    s.bind((0, 0))
    payload = struct.pack("=BBH", family, 0, 0)  # nfgenmsg, res_id BE 0
    payload += enc_attr(1, table)  # NFTA_x_TABLE
    nltype = (NFNL_SUBSYS_NFTABLES << 8) | msg_type
    msg = (
        struct.pack("=IHHII", len(payload) + 16, nltype, NLM_F_REQUEST | NLM_F_DUMP, 42, 0)
        + payload
    )
    s.sendto(msg, (0, 0))
    msgs = []
    n = 0
    while True:
        buf = s.recv(65536)
        pos = 0
        done = False
        while pos + 16 <= len(buf):
            ln, mtype, flags, seq, pid = struct.unpack_from("=IHHII", buf, pos)
            if ln < 16:
                done = True
                break
            body = buf[pos + 16:pos + ln]
            pos += (ln + 3) & ~3
            if mtype == NLMSG_DONE:
                done = True
                break
            if mtype == NLMSG_ERROR:
                errno_ = struct.unpack_from("=i", body, 0)[0]
                if errno_ != 0:
                    print(f"NETLINK ERROR errno={-errno_}", file=sys.stderr)
                    if as_json:
                        msgs.append({"error": -errno_})
                done = True
                break
            n += 1
            nfgen = body[:4]
            header = {
                "family": nfgen[0],
                "version": nfgen[1],
                "res_id": struct.unpack("!H", nfgen[2:4])[0],
            }
            if as_json:
                msgs.append(
                    {
                        "msg_type": mtype,
                        "subsys": mtype >> 8,
                        "op": mtype & 0xFF,
                        "nfgenmsg": header,
                        "attrs": tree_json(body[4:]),
                    }
                )
            else:
                print(
                    f"--- msg #{n} type={mtype} (subsys={mtype>>8}, op={mtype&0xff}) ---"
                )
                print(
                    f"nfgenmsg family={header['family']} ver={header['version']}"
                    f" res_id={header['res_id']}"
                )
                dump_tree(body[4:])
        if done:
            break
    s.close()
    return msgs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--table", default="sbx")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    table = args.table.encode() + b"\0"
    out = {}
    if not args.json:
        print("======== uid_map in ns ========")
        print(open("/proc/self/uid_map").read().strip())
        print(open("/proc/self/gid_map").read().strip())
        print(f"======== GETCHAIN dump (family=AF_INET, table {args.table}) ========")
    out["getchain"] = do_dump(NFT_MSG_GETCHAIN, 2, table, args.json)
    if not args.json:
        print(f"======== GETRULE dump (family=AF_INET, table {args.table}) ========")
    out["getrule"] = do_dump(NFT_MSG_GETRULE, 2, table, args.json)
    if args.json:
        json.dump(out, sys.stdout, indent=1)
        print()


if __name__ == "__main__":
    main()
