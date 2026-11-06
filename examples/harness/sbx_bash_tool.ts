// A bash tool for an agent harness, where every call is one `sbx run`.
//
// Reference wrapper for skills/sbx/references/harness-bash-tool.md. Node's
// standard library only. The file uses erasable TypeScript syntax, so Node 22.6+
// runs it directly:
//
//   node --experimental-strip-types sbx_bash_tool.ts --selftest [SBX]
//
// Each conversation gets one session directory (ROOT/sessions/<conversation>),
// so /work, /root and /tmp persist across calls. Shell state does not: every
// call is a new `bash`. The wrapper therefore tracks the working directory
// itself (a marker line on sbx's stderr) and replays the exports it was given.

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const CWD_MARKER = "__SBX_TOOL_CWD__=";
const DEFAULT_CWD = "/work";

// The payload runs inside `{ eval "$1"; } 2>&1`, so its stdout and stderr
// arrive interleaved on sbx's stdout. sbx's stderr then carries only sbx's and
// bwrap's own diagnostics plus the cwd marker.
const SCRIPT =
  '{ eval "$1"; } 2>&1\n' +
  "__sbx_rc=$?\n" +
  "printf '\\n%s%s\\n' '" + CWD_MARKER + "' \"$PWD\" >&2\n" +
  'exit "$__sbx_rc"\n';

export type ToolStatus = "exited" | "timeout" | "sandbox_error";

export interface ToolResult {
  status: ToolStatus;
  exitCode: number;
  output: string;
  truncated: boolean;
  sandboxMessage: string;
  auditOutcome: string | null;
}

export function forModel(r: ToolResult): string {
  let out = r.output;
  if (r.truncated) out += "\n[output truncated by the sandbox output limit]";
  if (r.status === "timeout") return out + "\n[command timed out and was killed]";
  if (r.status === "sandbox_error") {
    // Not the command's failure: the sandbox could not run it.
    return "[sandbox error, the command did not run as given] " + r.sandboxMessage;
  }
  if (r.exitCode !== 0) out += `\n[exit code ${r.exitCode}]`;
  return out;
}

function shQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

export class SbxBashTool {
  sbx: string;
  policy: string;
  root: string;
  conversation: string;
  env: Record<string, string>;
  cwd: string = DEFAULT_CWD;
  // One `sbx run` per session at a time: calls of this conversation are chained.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: { sbx: string; policy: string; root: string; conversation: string; env?: Record<string, string> }) {
    this.sbx = opts.sbx;
    this.policy = opts.policy;
    this.root = opts.root;
    this.conversation = opts.conversation;
    this.env = opts.env ?? {};
  }

  get sessionDir(): string {
    return path.join(this.root, "sessions", this.conversation);
  }

  get auditPath(): string {
    // Outside the session directory and outside every policy bind.
    return path.join(this.root, "audit", this.conversation + ".jsonl");
  }

  run(command: string, timeoutS = 120): Promise<ToolResult> {
    const next = this.queue.then(() => this.runOnce(command, timeoutS));
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async runOnce(command: string, timeoutS: number): Promise<ToolResult> {
    fs.mkdirSync(path.join(this.root, "sessions"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(this.auditPath), { recursive: true, mode: 0o700 });
    const exports = Object.keys(this.env)
      .sort()
      .map((k) => `export ${k}=${shQuote(this.env[k])}\n`)
      .join("");
    let auditOffset = 0;
    try {
      auditOffset = fs.statSync(this.auditPath).size;
    } catch {
      auditOffset = 0;
    }
    const argv = [
      "run",
      "--policy", this.policy,
      "--session-dir", this.sessionDir,
      "--cwd", this.cwd,
      "--timeout", `${timeoutS}s`,
      "--audit", this.auditPath,
      "--", "bash", "-c", SCRIPT, "sbx-bash-tool", exports + command,
    ];
    const { rc, stdout, stderr } = await new Promise<{ rc: number; stdout: string; stderr: string }>(
      (resolve, reject) => {
        // stdin "ignore": no TTY inside; never let bash wait on stdin.
        const child = spawn(this.sbx, argv, { stdio: ["ignore", "pipe", "pipe"] });
        const out: Buffer[] = [];
        const err: Buffer[] = [];
        child.stdout.on("data", (b: Buffer) => out.push(b));
        child.stderr.on("data", (b: Buffer) => err.push(b));
        // Backstop only: sbx enforces --timeout itself.
        const backstop = setTimeout(() => child.kill("SIGTERM"), (timeoutS + 60) * 1000);
        child.on("error", reject);
        child.on("close", (code: number | null, signal: string | null) => {
          clearTimeout(backstop);
          resolve({
            rc: code ?? 128 + (signal === "SIGTERM" ? 15 : 9),
            stdout: Buffer.concat(out).toString("utf8"),
            stderr: Buffer.concat(err).toString("utf8"),
          });
        });
      },
    );

    let output = stdout;
    let truncated = false;
    const diagnostics: string[] = [];
    for (const line of stderr.split("\n")) {
      if (line.startsWith(CWD_MARKER)) this.cwd = line.slice(CWD_MARKER.length);
      else if (line.startsWith("sbx run: output truncated")) truncated = true;
      else if (line.trim() !== "") diagnostics.push(line);
    }
    const exitRow = this.exitRow(auditOffset);
    const outcome: string | null = exitRow?.outcome ?? null;
    if (exitRow?.output_truncated) truncated = true;
    const message = diagnostics.join("\n");
    const result = (status: ToolStatus, sandboxMessage = ""): ToolResult => ({
      status, exitCode: rc, output, truncated, sandboxMessage, auditOutcome: outcome,
    });
    if (outcome === "timeout" || (outcome === null && rc === 124 && message.includes("timed out"))) {
      return result("timeout", message);
    }
    if (outcome === "failed" || (rc === 125 && message.startsWith("sbx "))) {
      return result("sandbox_error", message);
    }
    if (rc === 1 && message.startsWith("bwrap: ")) {
      // bwrap's own setup failure, e.g. the tracked cwd no longer exists.
      this.cwd = DEFAULT_CWD;
      return result("sandbox_error", message);
    }
    if (message) output += (output && !output.endsWith("\n") ? "\n" : "") + message;
    return result("exited");
  }

  // The exit row this call appended (calls of a session are serialized).
  private exitRow(offset: number): { outcome?: string; output_truncated?: boolean } | null {
    let text: string;
    try {
      const fd = fs.openSync(this.auditPath, "r");
      try {
        const size = fs.fstatSync(fd).size;
        const buf = Buffer.alloc(Math.max(0, size - offset));
        fs.readSync(fd, buf, 0, buf.length, offset);
        text = buf.toString("utf8");
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return null;
    }
    const rows = text.split("\n").reverse();
    for (const line of rows) {
      try {
        const row = JSON.parse(line);
        if (row.event === "exit") return row;
      } catch {
        // not a complete row
      }
    }
    return null;
  }
}

async function selftest(sbx: string): Promise<number> {
  const failures: string[] = [];
  const check = (name: string, cond: boolean, detail: unknown): void => {
    console.log((cond ? "ok    " : "FAIL  ") + name);
    if (!cond) {
      failures.push(name);
      console.log("      " + JSON.stringify(detail));
    }
  };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-harness-ts."));
  try {
    const policy = path.join(tmp, "policy.json");
    fs.writeFileSync(policy, JSON.stringify({
      version: 1,
      filesystem: { ro: ["/usr"], rw: [], deny: [] },
      network: { mode: "none", allow: [], ports: [] },
      env: { pass: [], set: {} },
      limits: { timeout: "60s", output_bytes: 4096 },
    }));
    const root = path.join(tmp, "root");
    const tool = new SbxBashTool({ sbx, policy, root, conversation: "conv-1", env: { GREETING: "hello world" } });

    let r = await tool.run('echo "$GREETING"; echo to-stderr >&2; pwd');
    check("echo, stderr merged, default cwd",
      r.status === "exited" && r.exitCode === 0 && r.output === "hello world\nto-stderr\n/work\n", r);
    r = await tool.run("echo persisted > /work/note; echo cached > /root/c; exit 3");
    check("command exit code", r.status === "exited" && r.exitCode === 3, r);
    r = await tool.run("cat /work/note /root/c");
    check("/work and /root persist across calls", r.output === "persisted\ncached\n", r);
    await tool.run("mkdir -p /tmp/proj && cd /tmp/proj");
    r = await tool.run("pwd");
    check("cwd tracked across calls", r.output === "/tmp/proj\n" && tool.cwd === "/tmp/proj", r);
    await tool.run("cd /; rmdir /tmp/proj");
    tool.cwd = "/tmp/proj"; // simulate a stale cwd the harness still holds
    r = await tool.run("pwd");
    check("stale cwd is a sandbox error and resets to /work",
      r.status === "sandbox_error" && r.sandboxMessage.includes("chdir") && tool.cwd === DEFAULT_CWD, r);
    r = await tool.run("sleep 30", 1);
    check("timeout", r.status === "timeout" && r.exitCode === 124 && r.auditOutcome === "timeout", r);
    r = await tool.run("seq 1 100000");
    check("output truncated at limits.output_bytes",
      r.status === "exited" && r.truncated && r.output.length <= 4096,
      [r.status, r.truncated, r.output.length]);
    r = await tool.run("getent hosts example.com; echo rc=$?");
    check("no network in mode none", r.output.includes("rc=2"), r);

    // Calls on one tool are queued, so they never collide. A second tool on the
    // same conversation (as a second harness process would) is refused by sbx
    // with 125 ("session directory is in use").
    const other = new SbxBashTool({ sbx, policy, root, conversation: "conv-1" });
    const holder = other.run("sleep 3");
    await new Promise((res) => setTimeout(res, 1000));
    r = await tool.run("true");
    await holder;
    check("concurrent call on one session is a sandbox error",
      r.status === "sandbox_error" && r.exitCode === 125 && r.sandboxMessage.includes("session directory is in use"), r);
    console.log(forModel(r));
    const [a, b] = await Promise.all([tool.run("echo a"), tool.run("echo b")]);
    check("calls on one tool are serialized", a.output === "a\n" && b.output === "b\n", [a, b]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`selftest: ${failures.length} failure(s)`);
  return failures.length ? 1 : 0;
}

if (process.argv[2] === "--selftest") {
  selftest(process.argv[3] ?? process.env.SBX ?? "sbx").then((code) => process.exit(code));
}
