# nftables netlink ground truth (issue #1 spike)

Byte-exact reference for the rules the Rust binary hand-encodes. Captured on
WSL2 kernel 6.18.40.1 with `nft` v1.0.9 inside `unshare -Urn`, from
[`reference.nft`](reference.nft). Two independent views agree:

1. `nft --debug=netlink` — symbolic decode of what `nft` sends.
2. Raw `NETLINK_NETFILTER` GETCHAIN/GETRULE dump (`scripts/nldump.py`) —
   stored bytes *after* the kernel parsed them. This is the authoritative
   byte source the Rust encoder is written against.

The Rust binary reproduces these bytes with `netlink-bindings` typed pushers
for every attribute except `redir`, which has no generated type (the bundled
kernel YAML spec contains zero `redir` occurrences) and is hand-encoded via the
public `Pusher` escape hatch. See `FINDINGS.md`.

## Capture environment

```
$ uname -r
6.18.40.1-microsoft-standard-WSL2
$ nft --version
nftables v1.0.9 (...)
$ id -u   # inside unshare -Urn, after uid_map "0 <uid> 1"
0
```

Reproduce with:

```sh
unshare -Urn bash -c '
  ip link set lo up
  ip addr add 10.255.255.1/32 dev lo
  ip route add default dev lo src 10.255.255.1
  nft --debug=netlink -f rules/reference.nft
  nft list ruleset
  python3 scripts/nldump.py'
```

## 1. `nft --debug=netlink -f reference.nft` (symbolic)

```
ip sbx nat_out
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000006 ]
  [ fib daddr type => reg 1 ]
  [ cmp neq reg 1 0x00000002 ]
  [ immediate reg 1 0x0000993a ]
  [ redir proto_min reg 1 flags 0x2 ]

ip sbx nat_out
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000011 ]
  [ payload load 2b @ transport header + 2 => reg 1 ]
  [ cmp eq reg 1 0x00003500 ]
  [ redir ]

ip sbx filter_out
  [ meta load oifname => reg 1 ]
  [ cmp eq reg 1 0x00006f6c 0x00000000 0x00000000 0x00000000 ]
  [ fib daddr type => reg 1 ]
  [ cmp eq reg 1 0x00000002 ]
  [ immediate reg 0 accept ]
```

## 2. `nft list ruleset` (round-trip)

```
table ip sbx {
	chain nat_out {
		type nat hook output priority dstnat; policy accept;
		meta l4proto tcp fib daddr type != local redirect to :15001
		udp dport 53 redirect
	}

	chain filter_out {
		type filter hook output priority filter; policy drop;
		oifname "lo" fib daddr type local accept
	}
}
```

## 3. Message envelope (all messages)

| Field | Value | Notes |
|---|---|---|
| `nfgenmsg.nfgen_family` | `2` (AF_INET) | table is `ip` family |
| `nfgenmsg.version` | `0` | NFNETLINK_V0 |
| `nfgenmsg.res_id` (request) | `0` | per-op messages |
| `nfgenmsg.res_id` (batch begin/end) | `10` | NFNL_SUBSYS_NFTABLES |
| `nfgenmsg.res_id` (dump replies) | `2` | kernel echoes; not sent by us |

Batch order (single `writev`): `BATCH_BEGIN(+genid)` → `NEWTABLE sbx` →
`NEWCHAIN nat_out` → `NEWCHAIN filter_out` → `NEWRULE×3` (CREATE|APPEND) →
`BATCH_END`.

## 4. GETCHAIN dump — raw bytes

### chain `nat_out`

| NFTA_CHAIN_* | type | len | bytes | meaning |
|---|---|---|---|---|
| TABLE | 1 | 4 | `73 62 78 00` | `"sbx\0"` |
| NAME | 3 | 8 | `6e 61 74 5f 6f 75 74 00` | `"nat_out\0"` |
| HANDLE | 2 | 8 | `00 00 00 00 00 00 00 01` | handle 1 (kernel-assigned) |
| HOOK | 4 | 16 | `08 00 01 00 00 00 00 03` `08 00 02 00 ff ff ff 9c` | nest: HOOKNUM(1)=3, PRIORITY(2)=`0xffffff9c`=−100 i32be |
| POLICY | 5 | 4 | `00 00 00 01` | 1 = NF_ACCEPT |
| TYPE | 7 | 4 | `6e 61 74 00` | `"nat\0"` |
| FLAGS | 10 | 4 | `00 00 00 01` | (kernel) |
| USE | 6 | 4 | `00 00 00 02` | refcount (kernel) |

### chain `filter_out`

| NFTA_CHAIN_* | type | len | bytes | meaning |
|---|---|---|---|---|
| TABLE | 1 | 4 | `73 62 78 00` | `"sbx\0"` |
| NAME | 3 | 11 | `66 69 6c 74 65 72 5f 6f 75 74 00` | `"filter_out\0"` |
| HANDLE | 2 | 8 | `00 00 00 00 00 00 00 02` | handle 2 |
| HOOK | 4 | 16 | `08 00 01 00 00 00 00 03` `08 00 02 00 00 00 00 00` | nest: HOOKNUM(1)=3, PRIORITY(2)=0 |
| POLICY | 5 | 4 | `00 00 00 00` | 0 = NF_DROP |
| TYPE | 7 | 7 | `66 69 6c 74 65 72 00` | `"filter\0"` |
| FLAGS | 10 | 4 | `00 00 00 01` | (kernel) |
| USE | 6 | 4 | `00 00 00 01` | refcount |

> No `NFTA_CHAIN_COUNTERS` attribute appears in the dump on this kernel
> (empirical fact **F5**): chain counters are therefore logged opportunistically
> by `verify_dump`, never asserted.

## 5. GETRULE dump — raw bytes

Rule attrs: TABLE(1)=`"sbx\0"`, CHAIN(2)=chain name, HANDLE(3), POSITION(6,
rule2 only), EXPRESSIONS(4)=list of NFTA_LIST_ELEM(1).

### Rule 1 — `nat_out` TCP → redirect :15001 (EXPRESSIONS len=252)

Per-expression `NFTA_LIST_ELEM(1)` → `NFTA_EXPR_NAME(1)` + `NFTA_EXPR_DATA(2)`
nest. Attribute order within a nest is irrelevant to the kernel (parsed by
type); `nft` happens to emit META KEY before DREG.

| # | name | DATA nest (type=value) |
|---|---|---|
| 1 | `meta` | KEY(2)=16 (L4PROTO), DREG(1)=1 |
| 2 | `cmp` | SREG(1)=1, OP(2)=0 (EQ), DATA(3){ VALUE(1)=`06` len5 } |
| 3 | `fib` | DREG(1)=1, **RESULT(2)=3 (raw)** , FLAGS(3)=2 (DADDR) |
| 4 | `cmp` | SREG(1)=1, OP(2)=1 (NEQ), DATA(3){ VALUE(1)=`02` len5 } |
| 5 | `immediate` | DREG(1)=1, DATA(2){ VALUE(1)=`3a 99` len6 } (15001 BE) |
| 6 | `redir` *(hand)* | DATA(2){ REG_PROTO_MIN(1)=1, REG_PROTO_MAX(2)=1, FLAGS(3)=2 } |

fib expr bytes (`1c 00 02 00` = DATA len 28):
`08 00 01 00 00 00 00 01` (DREG=1) · `08 00 02 00 00 00 00 03` (**RESULT=3**) ·
`08 00 03 00 00 00 00 02` (FLAGS=2).

> **F11 (enum off-by-one trap):** the generated `FibResult` enum is
> `Oif=0, Oifname=1, Addrtype=2` because the bundled YAML spec omits the
> kernel's `NFT_FIB_RESULT_UNSPEC=0`. The kernel stores `addrtype` as **3**.
> The encoder pushes raw `3u32` (with a comment), never `FibResult::Addrtype`.
> `verify_dump` asserts `RESULT==3`.

redir expr bytes (`1c 00 02 00` = DATA len 28):
`08 00 01 00 00 00 00 01` (MIN=1) · `08 00 02 00 00 00 00 01` (MAX=1) ·
`08 00 03 00 00 00 00 02` (FLAGS=2, NF_NAT_RANGE_PROTO_SPECIFIED).

### Rule 2 — `nat_out` UDP/53 → redirect (keep port) (EXPRESSIONS len=196)

| # | name | DATA nest |
|---|---|---|
| 1 | `meta` | KEY(2)=16, DREG(1)=1 |
| 2 | `cmp` | SREG(1)=1, OP(2)=0, DATA{ VALUE(1)=`11` len5 } (UDP) |
| 3 | `payload` | DREG(1)=1, BASE(2)=2 (TH), OFFSET(3)=2, LEN(4)=2 |
| 4 | `cmp` | SREG(1)=1, OP(2)=0, DATA{ VALUE(1)=`00 35` len6 } (53 BE) |
| 5 | `redir` *(hand)* | DATA(2)=**empty nest** (`04 00 02 00`) |

> The bare `redirect` (no `to :port`) produces an **empty** NFTA_EXPR_DATA
> nest — the kernel defaults REG_PROTO_MIN/MAX to "keep original port". The
> encoder pushes `push_name(c"redir")` + `push_nested_header(2)` immediately
> finalized, byte-for-byte identical to `nft`.

### Rule 3 — `filter_out` accept `oifname lo fib daddr type local` (EXPRESSIONS len=224)

| # | name | DATA nest |
|---|---|---|
| 1 | `meta` | KEY(2)=7 (OIFNAME), DREG(1)=1 |
| 2 | `cmp` | SREG(1)=1, OP(2)=0, DATA{ VALUE(1)=16B `6c 6f 00`+13×`00` len20 } (`"lo\0"` padded) |
| 3 | `fib` | DREG(1)=1, RESULT(2)=3 (raw), FLAGS(3)=2 |
| 4 | `cmp` | SREG(1)=1, OP(2)=0, DATA{ VALUE(1)=`02` len8 } |
| 5 | `immediate` | DREG(1)=**0** (RegVerdict), DATA(2){ VERDICT(2){ CODE(1)=1 (Accept) } } |

immediate/verdict bytes (`10 00 02 00` = DATA len 16 → `0c 00 02 00` VERDICT
len 12 → `08 00 01 00 00 00 00 01` CODE=1).

> Register discipline (design D-level): data regs = `Reg1`; verdict reg =
> `Reg0`. The `cmp` VALUE for rule 3 differs in padded length (len 8 vs len 5)
> from rule 1 purely due to NLA alignment of the preceding 16-byte `oifname`
> compare; the significant bytes are `02`. `verify_dump` compares the leading
> value bytes, not the padded length.

## 6. Register / constant quick reference

| Constant | Value | Source |
|---|---|---|
| NF_INET_LOCAL_OUT (hooknum) | 3 | netfilter hook |
| dstnat priority | −100 (`ff ff ff 9c`) | `nft` symbolic `priority dstnat` (F2) |
| filter priority | 0 | `priority filter` |
| NF_ACCEPT / NF_DROP | 1 / 0 | chain policy |
| MetaKeys::L4Proto | 16 | generated enum |
| MetaKeys::Oifname | 7 | generated enum |
| PayloadBase::TransportHeader | 2 | generated enum |
| CmpOps::Eq / Neq | 0 / 1 | generated enum |
| fib RESULT (addrtype) | **3 raw** | kernel; generated enum says 2 (F11) |
| fib FLAGS (DADDR) | 2 | `FibFlags::Daddr = 1<<1` |
| RTN_LOCAL | 2 | rtnetlink route type |
| VerdictCode::Accept | 1 | generated enum |
| Registers::RegVerdict / Reg1 | 0 / 1 | generated enum |
| NF_NAT_RANGE_PROTO_SPECIFIED | 2 | redir flags |
