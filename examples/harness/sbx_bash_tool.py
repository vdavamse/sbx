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
itself (a marker line on sbx's stderr) and replays the exports it was given.

Run `python3 sbx_bash_tool.py --selftest [SBX]` to exercise it against a real
sbx binary (CI does this).
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

CWD_MARKER = "__SBX_TOOL_CWD__="
DEFAULT_CWD = "/work"

# The payload runs inside `{ eval "$1"; } 2>&1`, so its stdout and stderr
# arrive interleaved on sbx's stdout. sbx's stderr then carries only sbx's
# and bwrap's own diagnostics plus the cwd marker.
SCRIPT = (
    '{ eval "$1"; } 2>&1\n'
    "__sbx_rc=$?\n"
    "printf '\\n%s%s\\n' '" + CWD_MARKER + "' \"$PWD\" >&2\n"
    'exit "$__sbx_rc"\n'
)


@dataclass
class ToolResult:
    status: str  # "exited" | "timeout" | "sandbox_error"
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

    @property
    def session_dir(self) -> str:
        return os.path.join(self.root, "sessions", self.conversation)

    @property
    def audit_path(self) -> str:
        # Outside the session directory and outside every policy bind.
        return os.path.join(self.root, "audit", self.conversation + ".jsonl")

    def run(self, command: str, timeout_s: int = 120) -> ToolResult:
        with self._lock:
            return self._run(command, timeout_s)

    def _run(self, command: str, timeout_s: int) -> ToolResult:
        os.makedirs(os.path.join(self.root, "sessions"), mode=0o700, exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_path), mode=0o700, exist_ok=True)
        exports = "".join(
            "export %s=%s\n" % (k, shlex.quote(v)) for k, v in sorted(self.env.items())
        )
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
            "--", "bash", "-c", SCRIPT, "sbx-bash-tool", exports + command,
        ]
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,  # no TTY inside; never let bash wait on stdin
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s + 60,  # backstop only: sbx enforces --timeout itself
        )
        output = proc.stdout.decode("utf-8", "replace")
        diagnostics: List[str] = []
        truncated = False
        for line in proc.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith(CWD_MARKER):
                self.cwd = line[len(CWD_MARKER):]
            elif line.startswith("sbx run: output truncated"):
                truncated = True
            elif line.strip():
                diagnostics.append(line)
        exit_row = self._exit_row(audit_offset)
        outcome = exit_row.get("outcome") if exit_row else None
        if exit_row and exit_row.get("output_truncated"):
            truncated = True
        rc = proc.returncode
        message = "\n".join(diagnostics)
        if outcome == "timeout" or (outcome is None and rc == 124 and "timed out" in message):
            return ToolResult("timeout", rc, output, truncated, message, outcome)
        if outcome == "failed" or (rc == 125 and message.startswith("sbx ")):
            return ToolResult("sandbox_error", rc, output, truncated, message, outcome)
        if rc == 1 and message.startswith("bwrap: "):
            # bwrap's own setup failure, e.g. the tracked cwd no longer exists.
            self.cwd = DEFAULT_CWD
            return ToolResult("sandbox_error", rc, output, truncated, message, outcome)
        if message:
            output += ("\n" if output and not output.endswith("\n") else "") + message
        return ToolResult("exited", rc, output, truncated, "", outcome)

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
                           conversation="conv-1", env={"GREETING": "hello world"})

        r = tool.run('echo "$GREETING"; echo to-stderr >&2; pwd')
        check("echo, stderr merged, default cwd", r.status == "exited" and r.exit_code == 0
              and r.output == "hello world\nto-stderr\n/work\n", r)
        r = tool.run("echo persisted > /work/note; echo cached > /root/c; exit 3")
        check("command exit code", r.status == "exited" and r.exit_code == 3, r)
        r = tool.run("cat /work/note /root/c")
        check("/work and /root persist across calls", r.output == "persisted\ncached\n", r)
        r = tool.run("mkdir -p /tmp/proj && cd /tmp/proj")
        r = tool.run("pwd")
        check("cwd tracked across calls", r.output == "/tmp/proj\n" and tool.cwd == "/tmp/proj", r)
        r = tool.run("cd /; rmdir /tmp/proj")
        tool.cwd = "/tmp/proj"  # simulate a stale cwd the harness still holds
        r = tool.run("pwd")
        check("stale cwd is a sandbox error and resets to /work",
              r.status == "sandbox_error" and "chdir" in r.sandbox_message
              and tool.cwd == DEFAULT_CWD, r)
        r = tool.run("sleep 30", timeout_s=1)
        check("timeout", r.status == "timeout" and r.exit_code == 124
              and r.audit_outcome == "timeout", r)
        r = tool.run("seq 1 100000")
        check("output truncated at limits.output_bytes", r.status == "exited" and r.truncated
              and len(r.output) <= 4096, (r.status, r.truncated, len(r.output)))
        r = tool.run("getent hosts example.com; echo rc=$?")
        check("no network in mode none", "rc=2" in r.output, r)

        # A second run on the same session while one is running: sbx refuses
        # with 125 ("session directory is in use"). Separate tool objects
        # sharing a conversation bypass the per-tool lock, as two harness
        # processes would.
        other = SbxBashTool(sbx=sbx, policy=policy, root=tool.root, conversation="conv-1")
        holder = threading.Thread(target=other.run, args=("sleep 3",))
        holder.start()
        time.sleep(1)
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
