//! The socket-family seccomp filter handed to bwrap via `--seccomp FD`
//! (issue #34).
//!
//! **Threat.** `socket(2)` succeeds for every family the kernel knows, and
//! only the network namespace (AF_INET/AF_INET6 egress) is confined by
//! `sbx __init`. `AF_VSOCK` is not network-namespaced: on VM-backed hosts
//! (WSL2 / Hyper-V `hv_sock`, Kata, Firecracker, cloud VMs) a payload with a
//! vsock socket has a channel to the host or hypervisor that bypasses the
//! netns, nftables and both proxies. The same holds for other families that
//! reach outside the namespace (`AF_PACKET`, `AF_XDP`, `AF_BLUETOOTH`, …).
//!
//! **Policy.** A classic-BPF program that allow-lists exactly four socket
//! families — `AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK` — for the
//! `socket` and `socketpair` syscalls. Any other family fails with
//! `EAFNOSUPPORT`. The filter also closes the other ways to reach the same
//! kernel code:
//!
//! - **Architecture.** The program checks `seccomp_data.arch` first; any
//!   value other than the native `AUDIT_ARCH_*` kills the process. This
//!   covers the i386 `int 0x80` compat entry and its `socketcall(2)` path
//!   (and arm32 compat on aarch64): 32-bit payloads are unsupported in
//!   `sbx run` (documented).
//! - **x32 ABI (x86_64 only).** Syscall numbers with bit 30 set are killed.
//!   x32 is a second syscall ABI on x86_64 (kernels built with
//!   `CONFIG_X86_X32_ABI`); where it is enabled, `socket` is reachable
//!   through it, so the whole ABI is refused.
//! - **`io_uring`.** `io_uring_setup`/`enter`/`register` return `ENOSYS`.
//!   `IORING_OP_SOCKET` (kernel 5.19+) would create sockets without
//!   `socket(2)`. The application sees `ENOSYS` from `io_uring_setup`;
//!   libuv falls back on any setup error, and liburing callers see the
//!   error and can fall back.
//! - **Low word only.** The kernel's `SYSCALL_DEFINE3(socket, int family…)`
//!   truncates the first argument to `int`, so `(1 << 32) | AF_VSOCK` is
//!   `AF_VSOCK` to the kernel. The filter decides on the low 32 bits of
//!   `args[0]` alone, which is exactly the value the kernel acts on: there is
//!   no gap between what is checked and what is created. A full 64-bit
//!   comparison would deny harmless spellings such as `(1 << 32) | AF_UNIX`
//!   and would not be a stricter check of the kernel's behaviour.
//!
//! **Syscall deny-list (issue #42).** A conservative set of syscalls that
//! widen the kernel attack surface and that ordinary tools do not need fails
//! with `EPERM` (the answer Docker's default profile gives, so callers
//! degrade the same way): see [`DENIED_SYSCALLS`]. It covers the kernel
//! keyring (`keyctl`, `add_key`, `request_key`), `bpf`, `perf_event_open`,
//! `userfaultfd`, `kexec_*`, kernel modules, `open_by_handle_at`, the old
//! and new mount APIs (through `open_tree_attr`, Linux 6.15),
//! `quotactl_fd`, `syslog`, swap, `reboot`, `acct` and (x86_64)
//! `iopl`/`ioperm`. Many of these already fail without capabilities; the
//! filter refuses them before the kernel looks at any argument.
//! `personality(2)` is allowed only for Docker's set of personas
//! ([`ALLOWED_PERSONAS`], low word of `args[0]`; the kernel takes an
//! `unsigned int`), so `ADDR_NO_RANDOMIZE` and `READ_IMPLIES_EXEC` are
//! refused with `EPERM`.
//!
//! Not filtered, by design: `ptrace` (cBPF cannot compare the target with
//! the caller, and gdb/strace need it; the payload is in its own pid
//! namespace and every process in it, pid 1 included, carries this filter),
//! and namespace flags of `clone`/`unshare`/`setns` (bwrap's
//! `--disable-userns` and `--cap-drop ALL` already refuse them, and
//! `clone3`'s flags are behind a pointer cBPF cannot read).
//!
//! Every other syscall is allowed (`SECCOMP_RET_ALLOW`): this is a
//! deny-list, not a syscall allow-list.
//!
//! **Encoding.** The program is a `struct sock_filter[]` in *native*
//! endianness, 8 bytes per instruction; bwrap reads it verbatim
//! (`len % 8 == 0`, required). [`program_memfd`] writes the bytes into a
//! sealed memfd and rewinds it, the transport `sbx run` hands to bwrap and
//! `sbx __init` re-verifies byte-for-byte against [`native_program_bytes`]
//! (the same binary is the producer and the verifier).
//!
//! The constants are defined here, not taken from `libc::SYS_*`, so both
//! architecture programs can be built and unit-tested on any host (the
//! aarch64 program is exercised through the in-module interpreter; no
//! aarch64 runner exists in CI). Native-table agreement with `libc` is pinned
//! by `native_table_matches_libc`.
//!
//! Intentionally brittle: the golden listings and byte encodings pin every
//! instruction. Any change to the program is a deliberate, reviewed change.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

// --- cBPF opcodes (linux/bpf_common.h, linux/filter.h) ---
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

// --- seccomp ABI (linux/seccomp.h, linux/audit.h, asm-generic/errno-base.h) ---
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `__AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE | EM_X86_64`.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `__AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE | EM_AARCH64`.
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// `__X32_SYSCALL_BIT`: set in the syscall number of x32-ABI calls.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `offsetof(struct seccomp_data, nr)`.
const OFF_NR: u32 = 0;
/// `offsetof(struct seccomp_data, arch)`.
const OFF_ARCH: u32 = 4;
/// `offsetof(struct seccomp_data, args[0])`: the LOW word on little-endian
/// hosts (the only ones this program is built for; `args[0]` high word at
/// offset 20 is never read).
const OFF_ARG0_LO: u32 = 16;

const EPERM: u32 = 1;
const EAFNOSUPPORT: u32 = 97;
const ENOSYS: u32 = 38;

/// Address families allowed for `socket(2)` and `socketpair(2)`.
pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const AF_NETLINK: u32 = 16;
/// The allow-list, in listing order (the program's compare chain).
pub const ALLOWED_FAMILIES: [u32; 4] = [AF_UNIX, AF_INET, AF_INET6, AF_NETLINK];

/// The seccomp ABI's errno values (asm-generic, identical on both arches).
pub const ERRNO_EPERM: u32 = EPERM;
pub const ERRNO_EAFNOSUPPORT: u32 = EAFNOSUPPORT;
pub const ERRNO_ENOSYS: u32 = ENOSYS;

/// One deny-listed syscall: its name and its number on x86_64 and on
/// aarch64 (`None` where the syscall does not exist on that architecture).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeniedSyscall {
    pub name: &'static str,
    pub x86_64: Option<u32>,
    pub aarch64: Option<u32>,
}

const fn both(name: &'static str, x86_64: u32, aarch64: u32) -> DeniedSyscall {
    DeniedSyscall {
        name,
        x86_64: Some(x86_64),
        aarch64: Some(aarch64),
    }
}

/// Syscalls that fail with `EPERM` (issue #42), in listing order (the
/// program's compare chain). x86_64 numbers are from
/// `arch/x86/entry/syscalls/syscall_64.tbl`, aarch64 from
/// `include/uapi/asm-generic/unistd.h`.
pub const DENIED_SYSCALLS: [DeniedSyscall; 31] = [
    // Kernel keyring: not namespaced per sandbox.
    both("keyctl", 250, 219),
    both("add_key", 248, 217),
    both("request_key", 249, 218),
    // Kernel attack surface with a long CVE history.
    both("bpf", 321, 280),
    both("perf_event_open", 298, 241),
    both("userfaultfd", 323, 282),
    // Kernel replacement and modules.
    both("kexec_load", 246, 104),
    both("kexec_file_load", 320, 294),
    both("init_module", 175, 105),
    both("finit_module", 313, 273),
    both("delete_module", 176, 106),
    // File handles bypass path-based confinement ("shocker").
    both("open_by_handle_at", 304, 265),
    // Mount APIs, old and new.
    both("mount", 165, 40),
    both("umount2", 166, 39),
    both("pivot_root", 155, 41),
    both("open_tree", 428, 428),
    both("move_mount", 429, 429),
    both("fsopen", 430, 430),
    both("fsconfig", 431, 431),
    both("fsmount", 432, 432),
    both("fspick", 433, 433),
    both("mount_setattr", 442, 442),
    both("open_tree_attr", 467, 467),
    both("quotactl_fd", 443, 443),
    // Host-wide state.
    both("syslog", 103, 116),
    both("swapon", 167, 224),
    both("swapoff", 168, 225),
    both("reboot", 169, 142),
    both("acct", 163, 89),
    // x86 I/O port access.
    DeniedSyscall {
        name: "iopl",
        x86_64: Some(172),
        aarch64: None,
    },
    DeniedSyscall {
        name: "ioperm",
        x86_64: Some(173),
        aarch64: None,
    },
];

/// `personality(2)` values allowed (Docker's default profile). Anything else
/// fails with `EPERM`.
pub const ALLOWED_PERSONAS: [u32; 5] = [
    0x0000_0000, // PER_LINUX
    0x0000_0008, // PER_LINUX32
    0x0002_0000, // UNAME26
    0x0002_0008, // PER_LINUX32 | UNAME26
    0xffff_ffff, // query only
];

/// Architectures with a filter program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Every architecture with a program (both are built and tested on
    /// every host).
    pub const ALL: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

    /// The architecture this binary was compiled for, or `None` when no
    /// program exists for it (the runtime refusal path, D12).
    pub fn native() -> Option<Arch> {
        // Both programs assume a little-endian host (the `args[0]` low-word
        // offset, and the native-endian `sock_filter` encoding).
        if cfg!(all(target_endian = "little", target_arch = "x86_64")) {
            Some(Arch::X86_64)
        } else if cfg!(all(target_endian = "little", target_arch = "aarch64")) {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    fn table(self) -> SyscallTable {
        match self {
            Arch::X86_64 => SyscallTable {
                audit_arch: AUDIT_ARCH_X86_64,
                x32_check: true,
                socket: 41,
                socketpair: 53,
                io_uring: [425, 426, 427],
                personality: 135,
            },
            Arch::Aarch64 => SyscallTable {
                audit_arch: AUDIT_ARCH_AARCH64,
                x32_check: false,
                socket: 198,
                socketpair: 199,
                io_uring: [425, 426, 427],
                personality: 92,
            },
        }
    }

    /// This architecture's deny-listed syscall numbers, in listing order.
    pub fn denied_numbers(self) -> impl Iterator<Item = u32> {
        DENIED_SYSCALLS.iter().filter_map(move |s| match self {
            Arch::X86_64 => s.x86_64,
            Arch::Aarch64 => s.aarch64,
        })
    }
}

/// The per-architecture numbers the program depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SyscallTable {
    audit_arch: u32,
    /// Whether the x32 ABI bit exists (x86_64 only).
    x32_check: bool,
    socket: u32,
    socketpair: u32,
    io_uring: [u32; 3],
    personality: u32,
}

/// One `struct sock_filter`: `{ u16 code; u8 jt; u8 jf; u32 k; }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Symbolic jump targets, placed by [`Asm::place`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Kill,
    Enosys,
    Check,
    Allow,
    Eperm,
    Persona,
}

const LABELS: usize = 6;

fn label_slot(label: Label) -> usize {
    match label {
        Label::Kill => 0,
        Label::Enosys => 1,
        Label::Check => 2,
        Label::Allow => 3,
        Label::Eperm => 4,
        Label::Persona => 5,
    }
}

/// A pending instruction whose jump targets are still symbolic.
struct Pending {
    code: u16,
    jt: Option<Label>,
    jf: Option<Label>,
    k: u32,
}

/// A tiny assembler: instructions in order, labels placed at the current
/// position, all jumps resolved (forward-only) at the end.
#[derive(Default)]
struct Asm {
    insns: Vec<Pending>,
    placed: [Option<usize>; LABELS],
}

impl Asm {
    fn push(&mut self, code: u16, jt: Option<Label>, jf: Option<Label>, k: u32) {
        self.insns.push(Pending { code, jt, jf, k });
    }

    fn place(&mut self, label: Label) {
        self.placed[label_slot(label)] = Some(self.insns.len());
    }

    fn finish(self) -> Vec<Insn> {
        let resolve = |pc: usize, target: Option<Label>| -> u8 {
            let Some(label) = target else { return 0 };
            let abs = self.placed[label_slot(label)].expect("every label is placed");
            assert!(
                abs > pc,
                "cBPF jumps are forward-only ({label:?} at {abs}, pc {pc})"
            );
            u8::try_from(abs - pc - 1).expect("cBPF jump offsets fit in u8")
        };
        self.insns
            .iter()
            .enumerate()
            .map(|(pc, p)| Insn {
                code: p.code,
                jt: resolve(pc, p.jt),
                jf: resolve(pc, p.jf),
                k: p.k,
            })
            .collect()
    }
}

/// The filter program for `arch`. Pure: no I/O, deterministic.
///
/// The listing (x86_64, 58 instructions; aarch64 is the same without the
/// x32 check at index 3 and without `iopl`/`ioperm`, 55) is pinned by
/// `golden_listing_*`.
pub fn program(arch: Arch) -> Vec<Insn> {
    let t = arch.table();
    let mut a = Asm::default();

    // Architecture gate: anything but the native audit arch is killed.
    a.push(BPF_LD | BPF_W | BPF_ABS, None, None, OFF_ARCH);
    a.push(
        BPF_JMP | BPF_JEQ | BPF_K,
        None,
        Some(Label::Kill),
        t.audit_arch,
    );

    // Syscall number dispatch.
    a.push(BPF_LD | BPF_W | BPF_ABS, None, None, OFF_NR);
    if t.x32_check {
        a.push(
            BPF_JMP | BPF_JSET | BPF_K,
            Some(Label::Kill),
            None,
            X32_SYSCALL_BIT,
        );
    }
    a.push(
        BPF_JMP | BPF_JEQ | BPF_K,
        Some(Label::Check),
        None,
        t.socket,
    );
    a.push(
        BPF_JMP | BPF_JEQ | BPF_K,
        Some(Label::Check),
        None,
        t.socketpair,
    );
    for nr in t.io_uring {
        a.push(BPF_JMP | BPF_JEQ | BPF_K, Some(Label::Enosys), None, nr);
    }
    for nr in arch.denied_numbers() {
        a.push(BPF_JMP | BPF_JEQ | BPF_K, Some(Label::Eperm), None, nr);
    }
    a.push(
        BPF_JMP | BPF_JEQ | BPF_K,
        Some(Label::Persona),
        None,
        t.personality,
    );
    a.push(BPF_RET | BPF_K, None, None, SECCOMP_RET_ALLOW);

    // Family check on the low word of args[0].
    a.place(Label::Check);
    a.push(BPF_LD | BPF_W | BPF_ABS, None, None, OFF_ARG0_LO);
    for family in ALLOWED_FAMILIES {
        a.push(BPF_JMP | BPF_JEQ | BPF_K, Some(Label::Allow), None, family);
    }
    a.push(
        BPF_RET | BPF_K,
        None,
        None,
        SECCOMP_RET_ERRNO | EAFNOSUPPORT,
    );

    // personality(2): allowed personas on the low word of args[0], the rest
    // falls through to EPERM.
    a.place(Label::Persona);
    a.push(BPF_LD | BPF_W | BPF_ABS, None, None, OFF_ARG0_LO);
    for persona in ALLOWED_PERSONAS {
        a.push(BPF_JMP | BPF_JEQ | BPF_K, Some(Label::Allow), None, persona);
    }
    a.place(Label::Eperm);
    a.push(BPF_RET | BPF_K, None, None, SECCOMP_RET_ERRNO | EPERM);

    a.place(Label::Allow);
    a.push(BPF_RET | BPF_K, None, None, SECCOMP_RET_ALLOW);
    a.place(Label::Enosys);
    a.push(BPF_RET | BPF_K, None, None, SECCOMP_RET_ERRNO | ENOSYS);
    a.place(Label::Kill);
    a.push(BPF_RET | BPF_K, None, None, SECCOMP_RET_KILL_PROCESS);

    a.finish()
}

/// Encode a program as the `struct sock_filter[]` bytes bwrap reads
/// (native endianness, 8 bytes per instruction).
pub fn encode(prog: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prog.len() * 8);
    for insn in prog {
        out.extend_from_slice(&insn.code.to_ne_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_ne_bytes());
    }
    out
}

/// The encoded program for this binary's architecture, or `None` when the
/// build has no program (D12).
pub fn native_program_bytes() -> Option<Vec<u8>> {
    Arch::native().map(|arch| encode(&program(arch)))
}

/// Create the sealed program memfd handed to bwrap.
///
/// `MFD_CLOEXEC` keeps it out of every exec except where the caller clears
/// it deliberately (the spawn window). `MFD_NOEXEC_SEAL` is requested so the
/// file is not executable under `vm.memfd_noexec=2`; kernels before 6.3
/// reject the flag with `EINVAL`, and then the flag is dropped (the content
/// is data, not code, so the fallback is safe). The content is written,
/// then sealed against modification and resizing, and the offset is rewound:
/// bwrap reads from the current offset until EOF, and an unrewound memfd
/// makes it die with `EINVAL`.
///
/// Fails with [`io::ErrorKind::Unsupported`] when there is no program for
/// this architecture.
pub fn program_memfd() -> io::Result<OwnedFd> {
    let bytes = native_program_bytes().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "seccomp filter not available for this architecture",
        )
    })?;
    let fd = create_memfd()?;
    write_all(&fd, &bytes)?;
    // SAFETY: F_ADD_SEALS on a valid memfd we own.
    let sealed = unsafe {
        libc::fcntl(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            libc::F_ADD_SEALS,
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
        )
    };
    if sealed != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: lseek on a valid fd we own.
    if unsafe { libc::lseek(std::os::fd::AsRawFd::as_raw_fd(&fd), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn create_memfd() -> io::Result<OwnedFd> {
    let name = c"sbx-seccomp";
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    // SAFETY: memfd_create with a valid NUL-terminated name.
    let mut raw = unsafe { libc::memfd_create(name.as_ptr(), base | libc::MFD_NOEXEC_SEAL) };
    if raw < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // Pre-6.3 kernels: MFD_NOEXEC_SEAL is unknown.
        // SAFETY: as above.
        raw = unsafe { libc::memfd_create(name.as_ptr(), base) };
    }
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a fresh fd we exclusively own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    while !bytes.is_empty() {
        // SAFETY: write from a valid buffer of the stated length.
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// The interpreter's view of `struct seccomp_data` (64 bytes on both
    /// arches): nr at 0, arch at 4, instruction pointer at 8 (zero), args
    /// as u64 at 16 + 8*i (little-endian).
    fn seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        data
    }

    /// A minimal cBPF interpreter over the subset the program may use:
    /// `LD|W|ABS`, `JMP|JEQ|K`, `JMP|JSET|K`, `RET|K`. Anything else
    /// panics, as do out-of-range or misaligned loads, a jump past the
    /// end, and falling off the program. Termination is therefore proven
    /// per path (jumps are forward-only, so every path is finite).
    fn interp(prog: &[Insn], data: &[u8; 64]) -> u32 {
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        loop {
            let insn = *prog.get(pc).expect("pc stays inside the program");
            match insn.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let off = insn.k as usize;
                    assert!(off % 4 == 0 && off + 4 <= data.len(), "bad load at {off}");
                    acc = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += 1 + usize::from(if acc & insn.k != 0 { insn.jt } else { insn.jf });
                }
                c if c == BPF_RET | BPF_K => return insn.k,
                other => panic!("opcode {other:#06x} is outside the expected subset"),
            }
        }
    }

    fn run(arch: Arch, nr: u32, a0: u64) -> u32 {
        let data = seccomp_data(nr, arch.table().audit_arch, [a0, 0, 0, 0, 0, 0]);
        interp(&program(arch), &data)
    }

    fn denied(family_result: u32) -> bool {
        family_result == SECCOMP_RET_ERRNO | EAFNOSUPPORT
    }

    #[test]
    fn exhaustive_families_socket_and_socketpair() {
        for arch in Arch::ALL {
            let t = arch.table();
            for nr in [t.socket, t.socketpair] {
                for family in (0..=1024u64).chain([u64::from(u32::MAX)]) {
                    let low = family as u32;
                    let want = if ALLOWED_FAMILIES.contains(&low) {
                        SECCOMP_RET_ALLOW
                    } else {
                        SECCOMP_RET_ERRNO | EAFNOSUPPORT
                    };
                    assert_eq!(
                        run(arch, nr, family),
                        want,
                        "{arch:?} nr {nr} family {family}"
                    );
                    // High word ignored: the kernel truncates to int.
                    assert_eq!(run(arch, nr, family | (0xdead_beef << 32)), want);
                }
            }
        }
    }

    #[test]
    fn vsock_and_friends_are_eafnosupport() {
        // AF_VSOCK (40), AF_PACKET (17), AF_XDP (44), AF_BLUETOOTH (31),
        // AF_ALG (38), AF_CAN (29), AF_TIPC (30), AF_RDS (21), AF_UNSPEC (0),
        // a family above AF_MAX (255), and the high-word trick for VSOCK.
        for arch in Arch::ALL {
            for family in [40u64, 17, 44, 31, 38, 29, 30, 21, 0, 255, (1 << 32) | 40] {
                assert!(
                    denied(run(arch, arch.table().socket, family)),
                    "{arch:?} {family}"
                );
            }
        }
    }

    #[test]
    fn io_uring_is_enosys() {
        for arch in Arch::ALL {
            for nr in arch.table().io_uring {
                assert_eq!(
                    run(arch, nr, 0),
                    SECCOMP_RET_ERRNO | ENOSYS,
                    "{arch:?} nr {nr}"
                );
            }
        }
    }

    #[test]
    fn other_syscalls_are_allowed() {
        for arch in Arch::ALL {
            let t = arch.table();
            for nr in 0..1024u32 {
                if nr == t.socket
                    || nr == t.socketpair
                    || t.io_uring.contains(&nr)
                    || nr == t.personality
                    || arch.denied_numbers().any(|d| d == nr)
                {
                    continue;
                }
                assert_eq!(run(arch, nr, 40), SECCOMP_RET_ALLOW, "{arch:?} nr {nr}");
            }
        }
        // getuid (102) on x86_64: pins that i386 socketcall's number is not
        // denied natively; the arch gate is what closes that path.
        assert_eq!(run(Arch::X86_64, 102, 0), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn denied_syscalls_are_eperm() {
        // Issue #42: every deny-listed number, whatever its arguments.
        for arch in Arch::ALL {
            let mut count = 0;
            for nr in arch.denied_numbers() {
                for a0 in [0u64, 1, 40, u64::MAX] {
                    assert_eq!(
                        run(arch, nr, a0),
                        SECCOMP_RET_ERRNO | EPERM,
                        "{arch:?} nr {nr}"
                    );
                }
                count += 1;
            }
            let want = match arch {
                Arch::X86_64 => DENIED_SYSCALLS.len(),
                Arch::Aarch64 => DENIED_SYSCALLS.len() - 2,
            };
            assert_eq!(count, want, "{arch:?}");
        }
    }

    #[test]
    fn denied_table_is_consistent() {
        for arch in Arch::ALL {
            let t = arch.table();
            let nrs: Vec<u32> = arch.denied_numbers().collect();
            let mut unique = nrs.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), nrs.len(), "{arch:?}: duplicate number");
            for nr in nrs {
                assert!(
                    nr != t.socket
                        && nr != t.socketpair
                        && nr != t.personality
                        && !t.io_uring.contains(&nr),
                    "{arch:?}: {nr} overlaps a special-cased syscall"
                );
            }
        }
        let mut names: Vec<&str> = DENIED_SYSCALLS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), DENIED_SYSCALLS.len(), "duplicate name");
    }

    #[test]
    fn personality_allows_only_listed_personas() {
        const ADDR_NO_RANDOMIZE: u64 = 0x0004_0000;
        const READ_IMPLIES_EXEC: u64 = 0x0040_0000;
        for arch in Arch::ALL {
            let nr = arch.table().personality;
            for persona in ALLOWED_PERSONAS {
                assert_eq!(
                    run(arch, nr, u64::from(persona)),
                    SECCOMP_RET_ALLOW,
                    "{arch:?} {persona:#x}"
                );
                // High word ignored: the kernel takes an unsigned int.
                assert_eq!(
                    run(arch, nr, u64::from(persona) | (0xdead_beef << 32)),
                    SECCOMP_RET_ALLOW
                );
            }
            for persona in [
                ADDR_NO_RANDOMIZE,
                READ_IMPLIES_EXEC,
                ADDR_NO_RANDOMIZE | 0x0002_0000,
                1,
                0xffff_fffe,
                (1 << 32) | ADDR_NO_RANDOMIZE,
            ] {
                assert_eq!(
                    run(arch, nr, persona),
                    SECCOMP_RET_ERRNO | EPERM,
                    "{arch:?} {persona:#x}"
                );
            }
        }
    }

    #[test]
    fn wrong_arch_kills() {
        const I386: u32 = 0x4000_0003;
        const ARM: u32 = 0x4000_0028;
        for arch in Arch::ALL {
            let t = arch.table();
            let prog = program(arch);
            let others = [
                I386,
                ARM,
                AUDIT_ARCH_X86_64,
                AUDIT_ARCH_AARCH64,
                0,
                u32::MAX,
            ];
            for bad in others.into_iter().filter(|&a| a != t.audit_arch) {
                for nr in [t.socket, t.socketpair, 0, 102] {
                    let data = seccomp_data(nr, bad, [1, 0, 0, 0, 0, 0]);
                    assert_eq!(
                        interp(&prog, &data),
                        SECCOMP_RET_KILL_PROCESS,
                        "{arch:?} {bad:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn x32_syscalls_kill_on_x86_64() {
        let prog = program(Arch::X86_64);
        let arch = AUDIT_ARCH_X86_64;
        for nr in [X32_SYSCALL_BIT | 41, X32_SYSCALL_BIT | 39, 0x7fff_ffff] {
            let data = seccomp_data(nr, arch, [40, 0, 0, 0, 0, 0]);
            assert_eq!(interp(&prog, &data), SECCOMP_RET_KILL_PROCESS, "nr {nr:#x}");
        }
    }

    #[test]
    fn interpreter_edge_cases_are_denied_or_allowed_by_low_word() {
        // nr with bit 31 set (not the x32 bit): an unknown syscall, ALLOW.
        let prog = program(Arch::X86_64);
        let data = seccomp_data(0x8000_0029, AUDIT_ARCH_X86_64, [40, 0, 0, 0, 0, 0]);
        assert_eq!(interp(&prog, &data), SECCOMP_RET_ALLOW);
        // Families whose low word is not on the list, in several spellings:
        // 0x8000_0028 (a high bit only), 296 (no collision with 40 or 10),
        // and -4294967256 as u64 (high word all ones, low word 40 = AF_VSOCK).
        for family in [0x8000_0028u64, 296, (-4_294_967_256i64) as u64] {
            assert_eq!(
                run(Arch::X86_64, 41, family),
                SECCOMP_RET_ERRNO | EAFNOSUPPORT,
                "family {family:#x}"
            );
        }
        // And the same negative spelling of an allowed family is allowed:
        // -4294967295 as u64 has low word 1 (AF_UNIX).
        assert_eq!(
            run(Arch::X86_64, 41, (-4_294_967_295i64) as u64),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn aarch64_has_no_x32_special_case() {
        // Without the x32 bit check, a high-bit number is just an unknown
        // syscall to the program (ALLOW; the kernel answers ENOSYS).
        let prog = program(Arch::Aarch64);
        let data = seccomp_data(
            X32_SYSCALL_BIT | 198,
            AUDIT_ARCH_AARCH64,
            [40, 0, 0, 0, 0, 0],
        );
        assert_eq!(interp(&prog, &data), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn programs_are_well_formed() {
        for arch in Arch::ALL {
            let prog = program(arch);
            assert!(prog.len() <= 4096, "BPF_MAXINSNS");
            assert_eq!(prog.last().unwrap().code, BPF_RET | BPF_K, "ends in a RET");
            for (pc, insn) in prog.iter().enumerate() {
                // Every jump lands inside the program.
                if insn.code & 0x07 == BPF_JMP {
                    assert!(
                        pc + 1 + usize::from(insn.jt) < prog.len(),
                        "{arch:?} jt at {pc}"
                    );
                    assert!(
                        pc + 1 + usize::from(insn.jf) < prog.len(),
                        "{arch:?} jf at {pc}"
                    );
                }
            }
        }
    }

    fn listing(prog: &[Insn]) -> Vec<(u16, u8, u8, u32)> {
        prog.iter().map(|i| (i.code, i.jt, i.jf, i.k)).collect()
    }

    #[test]
    fn golden_listing_x86_64() {
        let want: Vec<(u16, u8, u8, u32)> = vec![
            (0x0020, 0, 0, 4),
            (0x0015, 0, 55, 0xC000_003E),
            (0x0020, 0, 0, 0),
            (0x0045, 53, 0, 0x4000_0000),
            (0x0015, 37, 0, 41),
            (0x0015, 36, 0, 53),
            (0x0015, 49, 0, 425),
            (0x0015, 48, 0, 426),
            (0x0015, 47, 0, 427),
            (0x0015, 44, 0, 250),
            (0x0015, 43, 0, 248),
            (0x0015, 42, 0, 249),
            (0x0015, 41, 0, 321),
            (0x0015, 40, 0, 298),
            (0x0015, 39, 0, 323),
            (0x0015, 38, 0, 246),
            (0x0015, 37, 0, 320),
            (0x0015, 36, 0, 175),
            (0x0015, 35, 0, 313),
            (0x0015, 34, 0, 176),
            (0x0015, 33, 0, 304),
            (0x0015, 32, 0, 165),
            (0x0015, 31, 0, 166),
            (0x0015, 30, 0, 155),
            (0x0015, 29, 0, 428),
            (0x0015, 28, 0, 429),
            (0x0015, 27, 0, 430),
            (0x0015, 26, 0, 431),
            (0x0015, 25, 0, 432),
            (0x0015, 24, 0, 433),
            (0x0015, 23, 0, 442),
            (0x0015, 22, 0, 467),
            (0x0015, 21, 0, 443),
            (0x0015, 20, 0, 103),
            (0x0015, 19, 0, 167),
            (0x0015, 18, 0, 168),
            (0x0015, 17, 0, 169),
            (0x0015, 16, 0, 163),
            (0x0015, 15, 0, 172),
            (0x0015, 14, 0, 173),
            (0x0015, 7, 0, 135),
            (0x0006, 0, 0, 0x7fff_0000),
            (0x0020, 0, 0, 16),
            (0x0015, 11, 0, 1),
            (0x0015, 10, 0, 2),
            (0x0015, 9, 0, 10),
            (0x0015, 8, 0, 16),
            (0x0006, 0, 0, 0x0005_0061),
            (0x0020, 0, 0, 16),
            (0x0015, 5, 0, 0),
            (0x0015, 4, 0, 8),
            (0x0015, 3, 0, 0x0002_0000),
            (0x0015, 2, 0, 0x0002_0008),
            (0x0015, 1, 0, 0xFFFF_FFFF),
            (0x0006, 0, 0, 0x0005_0001),
            (0x0006, 0, 0, 0x7fff_0000),
            (0x0006, 0, 0, 0x0005_0026),
            (0x0006, 0, 0, 0x8000_0000),
        ];
        assert_eq!(listing(&program(Arch::X86_64)), want);
    }

    #[test]
    fn golden_listing_aarch64() {
        let want: Vec<(u16, u8, u8, u32)> = vec![
            (0x0020, 0, 0, 4),
            (0x0015, 0, 52, 0xC000_00B7),
            (0x0020, 0, 0, 0),
            (0x0015, 35, 0, 198),
            (0x0015, 34, 0, 199),
            (0x0015, 47, 0, 425),
            (0x0015, 46, 0, 426),
            (0x0015, 45, 0, 427),
            (0x0015, 42, 0, 219),
            (0x0015, 41, 0, 217),
            (0x0015, 40, 0, 218),
            (0x0015, 39, 0, 280),
            (0x0015, 38, 0, 241),
            (0x0015, 37, 0, 282),
            (0x0015, 36, 0, 104),
            (0x0015, 35, 0, 294),
            (0x0015, 34, 0, 105),
            (0x0015, 33, 0, 273),
            (0x0015, 32, 0, 106),
            (0x0015, 31, 0, 265),
            (0x0015, 30, 0, 40),
            (0x0015, 29, 0, 39),
            (0x0015, 28, 0, 41),
            (0x0015, 27, 0, 428),
            (0x0015, 26, 0, 429),
            (0x0015, 25, 0, 430),
            (0x0015, 24, 0, 431),
            (0x0015, 23, 0, 432),
            (0x0015, 22, 0, 433),
            (0x0015, 21, 0, 442),
            (0x0015, 20, 0, 467),
            (0x0015, 19, 0, 443),
            (0x0015, 18, 0, 116),
            (0x0015, 17, 0, 224),
            (0x0015, 16, 0, 225),
            (0x0015, 15, 0, 142),
            (0x0015, 14, 0, 89),
            (0x0015, 7, 0, 92),
            (0x0006, 0, 0, 0x7fff_0000),
            (0x0020, 0, 0, 16),
            (0x0015, 11, 0, 1),
            (0x0015, 10, 0, 2),
            (0x0015, 9, 0, 10),
            (0x0015, 8, 0, 16),
            (0x0006, 0, 0, 0x0005_0061),
            (0x0020, 0, 0, 16),
            (0x0015, 5, 0, 0),
            (0x0015, 4, 0, 8),
            (0x0015, 3, 0, 0x0002_0000),
            (0x0015, 2, 0, 0x0002_0008),
            (0x0015, 1, 0, 0xFFFF_FFFF),
            (0x0006, 0, 0, 0x0005_0001),
            (0x0006, 0, 0, 0x7fff_0000),
            (0x0006, 0, 0, 0x0005_0026),
            (0x0006, 0, 0, 0x8000_0000),
        ];
        assert_eq!(listing(&program(Arch::Aarch64)), want);
    }

    #[test]
    fn golden_bytes_are_native_endian() {
        // First instruction: LD|W|ABS arch => code 0x0020, jt 0, jf 0, k 4.
        let bytes = encode(&program(Arch::X86_64));
        assert_eq!(bytes.len(), 58 * 8);
        let mut first = Vec::new();
        first.extend_from_slice(&0x0020u16.to_ne_bytes());
        first.extend_from_slice(&[0, 0]);
        first.extend_from_slice(&4u32.to_ne_bytes());
        assert_eq!(&bytes[..8], &first[..]);
        // Last instruction: RET KILL_PROCESS.
        let mut last = Vec::new();
        last.extend_from_slice(&0x0006u16.to_ne_bytes());
        last.extend_from_slice(&[0, 0]);
        last.extend_from_slice(&SECCOMP_RET_KILL_PROCESS.to_ne_bytes());
        assert_eq!(&bytes[bytes.len() - 8..], &last[..]);
        // Length is a multiple of 8 (bwrap rejects anything else).
        assert_eq!(encode(&program(Arch::Aarch64)).len(), 55 * 8);
    }

    /// The full byte encoding, one 8-byte instruction (16 hex digits) per
    /// line. The #34 layout was validated against the prototype's binaries
    /// (`prog-*.bin`, bwrap 0.9.0); the #42 additions shift its jump
    /// offsets, and are exercised end to end by `seccomp-denylist-eperm`.
    const GOLDEN_X86_64_HEX: &[&str] = &[
        "2000000004000000",
        "150000373e0000c0",
        "2000000000000000",
        "4500350000000040",
        "1500250029000000",
        "1500240035000000",
        "15003100a9010000",
        "15003000aa010000",
        "15002f00ab010000",
        "15002c00fa000000",
        "15002b00f8000000",
        "15002a00f9000000",
        "1500290041010000",
        "150028002a010000",
        "1500270043010000",
        "15002600f6000000",
        "1500250040010000",
        "15002400af000000",
        "1500230039010000",
        "15002200b0000000",
        "1500210030010000",
        "15002000a5000000",
        "15001f00a6000000",
        "15001e009b000000",
        "15001d00ac010000",
        "15001c00ad010000",
        "15001b00ae010000",
        "15001a00af010000",
        "15001900b0010000",
        "15001800b1010000",
        "15001700ba010000",
        "15001600d3010000",
        "15001500bb010000",
        "1500140067000000",
        "15001300a7000000",
        "15001200a8000000",
        "15001100a9000000",
        "15001000a3000000",
        "15000f00ac000000",
        "15000e00ad000000",
        "1500070087000000",
        "060000000000ff7f",
        "2000000010000000",
        "15000b0001000000",
        "15000a0002000000",
        "150009000a000000",
        "1500080010000000",
        "0600000061000500",
        "2000000010000000",
        "1500050000000000",
        "1500040008000000",
        "1500030000000200",
        "1500020008000200",
        "15000100ffffffff",
        "0600000001000500",
        "060000000000ff7f",
        "0600000026000500",
        "0600000000000080",
    ];
    const GOLDEN_AARCH64_HEX: &[&str] = &[
        "2000000004000000",
        "15000034b70000c0",
        "2000000000000000",
        "15002300c6000000",
        "15002200c7000000",
        "15002f00a9010000",
        "15002e00aa010000",
        "15002d00ab010000",
        "15002a00db000000",
        "15002900d9000000",
        "15002800da000000",
        "1500270018010000",
        "15002600f1000000",
        "150025001a010000",
        "1500240068000000",
        "1500230026010000",
        "1500220069000000",
        "1500210011010000",
        "150020006a000000",
        "15001f0009010000",
        "15001e0028000000",
        "15001d0027000000",
        "15001c0029000000",
        "15001b00ac010000",
        "15001a00ad010000",
        "15001900ae010000",
        "15001800af010000",
        "15001700b0010000",
        "15001600b1010000",
        "15001500ba010000",
        "15001400d3010000",
        "15001300bb010000",
        "1500120074000000",
        "15001100e0000000",
        "15001000e1000000",
        "15000f008e000000",
        "15000e0059000000",
        "150007005c000000",
        "060000000000ff7f",
        "2000000010000000",
        "15000b0001000000",
        "15000a0002000000",
        "150009000a000000",
        "1500080010000000",
        "0600000061000500",
        "2000000010000000",
        "1500050000000000",
        "1500040008000000",
        "1500030000000200",
        "1500020008000200",
        "15000100ffffffff",
        "0600000001000500",
        "060000000000ff7f",
        "0600000026000500",
        "0600000000000080",
    ];

    fn hex_of(bytes: &[u8]) -> Vec<String> {
        bytes
            .chunks(8)
            .map(|c| c.iter().map(|b| format!("{b:02x}")).collect())
            .collect()
    }

    #[test]
    fn golden_bytes_x86_64_full() {
        assert_eq!(hex_of(&encode(&program(Arch::X86_64))), GOLDEN_X86_64_HEX);
    }

    #[test]
    fn golden_bytes_aarch64_full() {
        assert_eq!(hex_of(&encode(&program(Arch::Aarch64))), GOLDEN_AARCH64_HEX);
    }

    #[test]
    fn native_bytes_match_native_program() {
        match Arch::native() {
            Some(arch) => assert_eq!(native_program_bytes(), Some(encode(&program(arch)))),
            None => assert!(native_program_bytes().is_none()),
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn native_table_matches_libc_x86_64() {
        let t = Arch::X86_64.table();
        assert_eq!(t.socket, libc::SYS_socket as u32);
        assert_eq!(t.socketpair, libc::SYS_socketpair as u32);
        assert_eq!(
            t.io_uring,
            [
                libc::SYS_io_uring_setup as u32,
                libc::SYS_io_uring_enter as u32,
                libc::SYS_io_uring_register as u32
            ]
        );
        assert_eq!(
            ALLOWED_FAMILIES,
            [
                libc::AF_UNIX as u32,
                libc::AF_INET as u32,
                libc::AF_INET6 as u32,
                libc::AF_NETLINK as u32
            ]
        );
        assert_eq!(ERRNO_EAFNOSUPPORT as i32, libc::EAFNOSUPPORT);
        assert_eq!(ERRNO_ENOSYS as i32, libc::ENOSYS);
        assert_eq!(ERRNO_EPERM as i32, libc::EPERM);
        assert_eq!(t.personality, libc::SYS_personality as u32);
        assert_eq!(
            Arch::X86_64.denied_numbers().collect::<Vec<_>>(),
            native_denied_from_libc()
        );
    }

    /// The deny-list in listing order, from `libc::SYS_*` for this target
    /// (`iopl`/`ioperm` on x86_64 only).
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn native_denied_from_libc() -> Vec<u32> {
        // libc's musl aarch64 module has no `SYS_kexec_file_load`; 294 is
        // the asm-generic number (glibc aarch64 libc agrees).
        #[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
        const KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;
        #[cfg(all(target_arch = "aarch64", target_env = "musl"))]
        const KEXEC_FILE_LOAD: libc::c_long = 294;
        let mut nrs = vec![
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_kexec_load,
            KEXEC_FILE_LOAD,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_open_by_handle_at,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            // open_tree_attr (Linux 6.15) is not in libc yet; 467 on both.
            467,
            libc::SYS_quotactl_fd,
            libc::SYS_syslog,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_reboot,
            libc::SYS_acct,
        ];
        #[cfg(target_arch = "x86_64")]
        nrs.extend([libc::SYS_iopl, libc::SYS_ioperm]);
        nrs.into_iter().map(|n| n as u32).collect()
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn native_table_matches_libc_aarch64() {
        let t = Arch::Aarch64.table();
        assert_eq!(t.socket, libc::SYS_socket as u32);
        assert_eq!(t.socketpair, libc::SYS_socketpair as u32);
        assert_eq!(
            t.io_uring,
            [
                libc::SYS_io_uring_setup as u32,
                libc::SYS_io_uring_enter as u32,
                libc::SYS_io_uring_register as u32
            ]
        );
        assert_eq!(ERRNO_EAFNOSUPPORT as i32, libc::EAFNOSUPPORT);
        assert_eq!(ERRNO_ENOSYS as i32, libc::ENOSYS);
        assert_eq!(ERRNO_EPERM as i32, libc::EPERM);
        assert_eq!(t.personality, libc::SYS_personality as u32);
        assert_eq!(
            Arch::Aarch64.denied_numbers().collect::<Vec<_>>(),
            native_denied_from_libc()
        );
    }

    #[test]
    fn memfd_roundtrip_is_sealed_and_rewound() {
        let fd = match program_memfd() {
            Ok(fd) => fd,
            Err(e) if Arch::native().is_none() => {
                assert_eq!(e.kind(), io::ErrorKind::Unsupported);
                return;
            }
            Err(e) => panic!("program_memfd failed: {e}"),
        };
        let raw = fd.as_raw_fd();
        // SAFETY: fcntl F_GET_SEALS on a valid fd.
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        let want = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
        assert_eq!(seals & want, want, "seals {seals:#x}");
        // SAFETY: lseek with SEEK_CUR reads the offset without moving it.
        assert_eq!(unsafe { libc::lseek(raw, 0, libc::SEEK_CUR) }, 0, "rewound");
        let Some(expected) = native_program_bytes() else {
            return;
        };
        let mut buf = vec![0u8; expected.len() + 1];
        // SAFETY: pread into a buffer we own; leaves the offset unchanged.
        let n = unsafe { libc::pread(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert_eq!(usize::try_from(n).unwrap(), expected.len());
        assert_eq!(&buf[..expected.len()], &expected[..]);
        // SAFETY: a one-byte write to a sealed memfd must fail.
        let w = unsafe { libc::write(raw, [0u8].as_ptr().cast(), 1) };
        assert_eq!(w, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }
}
