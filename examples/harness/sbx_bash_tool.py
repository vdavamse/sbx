#!/usr/bin/env python3
"""A bash tool for an agent harness, where every call is one `sbx run`.

Reference wrapper for skills/sbx/references/harness-bash-tool.md. Standard
library only, Python 3.8+.

    tool = SbxBashTool(sbx="sbx", policy="policy.json",
                       root="/var/lib/agent/sbx", conversation="conv-42")
    result = tool.run("pytest -q", timeout_s=120)
    reply_to_model(result.for_model())

Each conversation gets one session directory (ROOT/sessions/<conversation>),
so /work, /root and /tmp persist across calls. Shell state does not: every
call is a new `bash`. The wrapper therefore tracks the working directory
itself (an EXIT trap writes $PWD to /tmp/.sbx-tool-cwd.<token>, a fresh name
per call, which is S/tmp/.sbx-tool-cwd.<token> on the host) and replays the
exports it was given. One conversation must be owned by one SbxBashTool: its
lock serializes the calls, and the audit rows after a call's offset are then
that call's.

Run `python3 sbx_bash_tool.py --selftest [SBX]` to exercise it against a real
sbx binary (CI does this).
"""

import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_CWD = "/work"
CWD_FILE = ".sbx-tool-cwd."  # + a per-call token, in the session's /tmp
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
CONVERSATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# The command arrives as $1 and the per-call token as $2. Both are moved out
# of the positional parameters so the command sees $# = 0, as under a plain
# `bash -c CMD`. Its stdout and stderr are merged into sbx's stdout. The EXIT
# trap records the final working directory even when the command calls
# `exit`, and even when the output was truncated (a file, not a stream under
# limits.output_bytes). A fresh file name per call means nothing the command
# plants under /tmp can make the host-side read or cleanup fail. A command
# that replaces the trap or ends in `exec` keeps the previous cwd.
SCRIPT = (
    '__sbx_cmd=$1 __sbx_tok=$2; set --\n'
    "trap 'printf %s \"$PWD\" > \"/tmp/" + CWD_FILE + "$__sbx_tok\" 2>/dev/null' EXIT\n"
    '{ eval "$__sbx_cmd"; } 2>&1\n'
)


@dataclass
class ToolResult:
    status: str  # "exited" | "timeout" | "killed" | "sandbox_error"
    exit_code: int
    output: str
    truncated: bool = False
    sandbox_message: str = ""
    audit_outcome: Optional[str] = None

    def for_model(self) -> str:
        """The text the model sees as the tool result."""
        out = self.output
        if self.truncated:
            out += "\n[output truncated by the sandbox output limit]"
        if self.status == "timeout":
            return out + "\n[command timed out and was killed]"
        if self.status == "killed":
            # The sandbox itself was killed (for example by the OOM killer).
            return out + "\n[the sandbox was killed: %s]" % self.sandbox_message
        if self.status == "sandbox_error":
            # Not the command's failure: the sandbox could not run it.
            return "[sandbox error, the command did not run as given] " + self.sandbox_message
        if self.exit_code != 0:
            out += "\n[exit code %d]" % self.exit_code
        return out


@dataclass
class SbxBashTool:
    sbx: str
    policy: str
    root: str
    conversation: str
    env: Dict[str, str] = field(default_factory=dict)
    cwd: str = DEFAULT_CWD
    # One `sbx run` per session at a time: serialize calls of this conversation.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if not CONVERSATION_ID.match(self.conversation):
            raise ValueError("invalid conversation id: %r" % self.conversation)

    @property
    def session_dir(self) -> str:
        return os.path.join(self.root, "sessions", self.conversation)

    @property
    def audit_path(self) -> str:
        # Outside the session directory and outside every policy bind.
        return os.path.join(self.root, "audit", self.conversation + ".jsonl")

    def run(self, command: str, timeout_s: int = 120) -> ToolResult:
        if type(timeout_s) is not int or timeout_s < 1:
            raise ValueError("timeout_s must be a whole number of seconds >= 1")
        for name in self.env:
            if not ENV_NAME.match(name):
                raise ValueError("invalid environment variable name: %r" % name)
        with self._lock:
            return self._run(command, timeout_s)

    def _run(self, command: str, timeout_s: int) -> ToolResult:
        os.makedirs(os.path.join(self.root, "sessions"), mode=0o700, exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_path), mode=0o700, exist_ok=True)
        exports = "".join(
            "export %s=%s\n" % (k, shlex.quote(v)) for k, v in sorted(self.env.items())
        )
        token = secrets.token_hex(8)
        cwd_file = os.path.join(self.session_dir, "tmp", CWD_FILE + token)
        try:
            audit_offset = os.path.getsize(self.audit_path)
        except FileNotFoundError:
            audit_offset = 0
        argv = [
            self.sbx, "run",
            "--policy", self.policy,
            "--session-dir", self.session_dir,
            "--cwd", self.cwd,
            "--timeout", "%ds" % timeout_s,
            "--audit", self.audit_path,
            "--", "bash", "-c", SCRIPT, "sbx-bash-tool", exports + command, token,
        ]
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,  # no TTY inside; never let bash wait on stdin
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_s + 60,  # backstop only: sbx enforces --timeout itself
            )
        except subprocess.TimeoutExpired:
            return ToolResult("sandbox_error", -1, "", False,
                              "sbx did not return within %ds of the call's timeout" % 60)
        output = proc.stdout.decode("utf-8", "replace")
        diagnostics: List[str] = []
        truncated = False
        for line in proc.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("sbx run: output truncated"):
                truncated = True
            elif line.startswith("sbx run: notice:") or not line.strip():
                continue  # e.g. the explicit-mode fallback notice on every run
            else:
                diagnostics.append(line)
        exit_row = self._exit_row(audit_offset)
        outcome = exit_row.get("outcome") if exit_row else None
        if exit_row and exit_row.get("output_truncated"):
            truncated = True
        rc = proc.returncode
        message = "\n".join(diagnostics)

        def result(status: str, msg: str = "") -> ToolResult:
            return ToolResult(status, rc, output, truncated, msg, outcome)

        new_cwd = self._read_cwd(cwd_file)
        try:
            os.unlink(cwd_file)
        except OSError:
            pass  # best effort: the sandbox controls /tmp

        # A refused run writes no exit row, so another caller's row could be
        # misread as this call's: classify this refusal before reading rows.
        if rc == 125 and any("session directory is in use" in l for l in diagnostics):
            return result("sandbox_error", message)
        # The audit outcome is authoritative; stderr is only a fallback.
        if outcome == "timeout":
            return result("timeout", message)
        if outcome in ("failed", "terminated"):
            return result("sandbox_error", message)
        if outcome == "signaled":
            return result("killed", message or "signal %s" % exit_row.get("signal"))
        if outcome is None:
            # No exit row: sbx refused or failed before the command ran under audit.
            if rc == 124 and "timed out" in message:
                return result("timeout", message)
            return result("sandbox_error", message or "sbx exited %d without an audit exit row" % rc)
        if rc == 1 and any(l.startswith("bwrap: ") for l in diagnostics):
            # bwrap's own setup failure (outcome "exited"), e.g. the tracked
            # cwd no longer exists: reset it so the next call can run.
            self.cwd = DEFAULT_CWD
            return result("sandbox_error", message)
        if new_cwd:
            self.cwd = new_cwd
        if message:
            output += ("\n" if output and not output.endswith("\n") else "") + message
        return result("exited")

    @staticmethod
    def _read_cwd(path: str) -> Optional[str]:
        """The cwd the EXIT trap wrote. The sandbox controls this file, so it
        is opened without following a symlink and must be a small regular file
        holding an absolute path."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
                return None
            value = os.read(fd, 4096).decode("utf-8", "replace")
        finally:
            os.close(fd)
        if value.startswith("/") and "\n" not in value and "\0" not in value:
            return value
        return None

    def _exit_row(self, offset: int) -> Optional[dict]:
        """The exit row this call appended (calls of a session are serialized)."""
        try:
            with open(self.audit_path, "rb") as f:
                f.seek(offset)
                rows = f.read().decode("utf-8", "replace").splitlines()
        except FileNotFoundError:
            return None
        for line in reversed(rows):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("event") == "exit":
                return row
        return None


def selftest(sbx: str) -> int:
    failures = []

    def check(name: str, cond: bool, detail: object) -> None:
        print(("ok    " if cond else "FAIL  ") + name)
        if not cond:
            failures.append(name)
            print("      " + repr(detail))

    with tempfile.TemporaryDirectory(prefix="sbx-harness-py.") as tmp:
        policy = os.path.join(tmp, "policy.json")
        with open(policy, "w") as f:
            json.dump({
                "version": 1,
                "filesystem": {"ro": ["/usr"], "rw": [], "deny": []},
                "network": {"mode": "none", "allow": [], "ports": []},
                "env": {"pass": [], "set": {}},
                "limits": {"timeout": "60s", "output_bytes": 4096},
            }, f)
        tool = SbxBashTool(sbx=sbx, policy=policy, root=os.path.join(tmp, "root"),
                           conversation="conv-1", env={"GREETING": "it's $(not) run"})

        r = tool.run('echo "$GREETING"; echo to-stderr >&2; pwd; echo "argc=$#"')
        check("echo, stderr merged, default cwd, no positional args",
              r.status == "exited" and r.exit_code == 0
              and r.output == "it's $(not) run\nto-stderr\n/work\nargc=0\n", r)
        r = tool.run("echo persisted > /work/note; echo cached > /root/c; exit 3")
        check("command exit code", r.status == "exited" and r.exit_code == 3, r)
        r = tool.run("cat /work/note /root/c")
        check("/work and /root persist across calls", r.output == "persisted\ncached\n", r)
        tool.run("mkdir -p /tmp/proj && cd /tmp/proj")
        r = tool.run("pwd")
        check("cwd tracked across calls", r.output == "/tmp/proj\n" and tool.cwd == "/tmp/proj", r)
        tool.run("cd /root; exit 5")
        check("cwd tracked through exit", tool.cwd == "/root", tool.cwd)
        r = tool.run("cd /tmp && seq 1 100000")
        check("output truncated at limits.output_bytes", r.status == "exited" and r.truncated
              and len(r.output) <= 4096, (r.status, r.truncated, len(r.output)))
        check("cwd tracked through truncated output", tool.cwd == "/tmp", tool.cwd)
        tool.run("trap - EXIT; cd /; mkdir -p /tmp/" + CWD_FILE + "x; chmod 500 /tmp")
        r = tool.run("chmod 700 /tmp; pwd")
        check("planted entries and an unwritable /tmp do not break the tool",
              r.status == "exited" and r.output == "/tmp\n" and tool.cwd == "/tmp", r)
        tool.run("mkdir -p /tmp/gone && cd /tmp/gone")
        tool.run("rmdir /tmp/gone")
        r = tool.run("pwd")
        check("stale cwd is a sandbox error and resets to /work",
              r.status == "sandbox_error" and "chdir" in r.sandbox_message
              and tool.cwd == DEFAULT_CWD, r)
        r = tool.run("sleep 30", timeout_s=1)
        check("timeout", r.status == "timeout" and r.exit_code == 124
              and r.audit_outcome == "timeout", r)
        r = tool.run("getent hosts example.com; echo rc=$?")
        check("no network in mode none", "rc=2" in r.output, r)
        try:
            SbxBashTool(sbx=sbx, policy=policy, root=tool.root, conversation="conv-1",
                        env={"X;id": "1"}).run("true")
            check("invalid env name rejected", False, "no error")
        except ValueError:
            check("invalid env name rejected", True, None)
        try:
            SbxBashTool(sbx=sbx, policy=policy, root=tool.root, conversation="../x")
            check("invalid conversation id rejected", False, "no error")
        except ValueError:
            check("invalid conversation id rejected", True, None)

        # A second run on the same session while one is running: sbx refuses
        # with 125 ("session directory is in use"). Separate tool objects
        # sharing a conversation bypass the per-tool lock, as two harness
        # processes would.
        other = SbxBashTool(sbx=sbx, policy=policy, root=tool.root, conversation="conv-1")
        holder = threading.Thread(target=other.run, args=("sleep 5",))
        holder.start()
        time.sleep(1.5)
        r = tool.run("true")
        holder.join()
        check("concurrent call on one session is a sandbox error",
              r.status == "sandbox_error" and r.exit_code == 125
              and "session directory is in use" in r.sandbox_message, r)
        print(r.for_model())

        results = {}
        threads = [threading.Thread(target=lambda w=w: results.__setitem__(w, tool.run("echo " + w)))
                   for w in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("calls on one tool are serialized",
              results["a"].output == "a\n" and results["b"].output == "b\n", results)

    print("selftest: %d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        sys.exit(selftest(sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SBX", "sbx")))
    print(__doc__)
