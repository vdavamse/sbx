# Running an agent inside the sandbox

The whole agent process (Claude Code, or another coding CLI) runs under `sbx run`. Every
command it starts inherits the same mounts, network allow list and limits. The agent
can then only read what the policy binds, write to the session directory and the `rw`
paths, and reach the allow-listed hosts.

## Policy template

```json
{
  "version": 1,
  "filesystem": {
    "ro": ["/usr", "/home/me/.local/share/claude/versions/2.1.319"],
    "rw": ["/home/me/project"],
    "deny": []
  },
  "network": {
    "mode": "transparent",
    "allow": ["=api.anthropic.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"],
    "ports": [443]
  },
  "env": {
    "pass": ["ANTHROPIC_API_KEY"],
    "set": {
      "SHELL": "/bin/bash",
      "DISABLE_AUTOUPDATER": "1",
      "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
    }
  },
  "limits": { "timeout": "30m", "output_bytes": 10485760 }
}
```

- **`ro` `/usr`.** The shell, coreutils, `git`, `python3` and the TLS roots (`/etc/ssl`
  is always bound by sbx).
- **The project.** Use `rw` so the agent can edit it, or `ro` for a review-only run. Never
  bind your whole home directory: it exposes `~/.ssh`, cloud credentials, and sockets such
  as ssh-agent.
- **Allow list.** Add the model API host (`=api.anthropic.com` for Claude) and the package
  registries the task needs, nothing else. Telemetry and update hosts that are not listed
  appear as denied `dns` rows in the audit log. That is harmless, and the agent's own
  switches (as in `env.set` above) silence them.
- **`env.pass` and secrets.** `env.pass` copies the variable from the environment that
  runs `sbx run`. If it is unset there, it is simply absent. **A passed key is readable
  by every process in the sandbox**, including the commands the agent runs and any
  package install script. Such a process can send the key to any allow-listed host. Use
  a scoped, revocable key with a spending limit, and keep the allow list short.

## The agent's own binary must be visible

Only bound paths exist inside the sandbox, so the agent's executable and its runtime
must be under a bound path:

- **Installed under `/usr`** (a distro package, or `npm -g` with prefix `/usr`): binding
  `/usr` is enough.
- **Native installer** (`~/.local/bin/claude` is a symlink): `readlink -f
  ~/.local/bin/claude` gives the binary itself, for example
  `…/.local/share/claude/versions/2.1.319` (a file). Bind that file `ro` and run it by
  that path, as in the template. Binding the symlink works too, but the binary then
  appears at the link's path. A symlink *inside* a bound tree whose target is not bound
  dangles.
- **Node from nvm** (or another per-user runtime): bind its install directory `ro` and
  put its `bin` first in `PATH` through `env.set`, for example
  `"PATH": "/home/me/.nvm/versions/node/v24.1.0/bin:/usr/bin:/bin"`.

Check with a trivial command first:
`sbx run --policy P --session-dir S -- /path/to/agent --version`.

## Headless only

There is no TTY inside (see SKILL.md), so run the agent's non-interactive mode and
close stdin:

```sh
sbx run --policy agent.json --session-dir ~/.cache/sbx/agent-task-42 \
  --cwd /home/me/project --audit ~/.cache/sbx/audit/task-42.jsonl \
  -- /home/me/.local/share/claude/versions/2.1.319 -p "fix the failing test in tests/" </dev/null
```

Interactive TUI use is not supported.

## State lives in the session directory

`HOME` is `/root`, which is `S/home` on the host. The agent's config, login state, cache
and history (for Claude Code, `/root/.claude.json` and `/root/.claude/`) are written there,
never to your real home directory.

- **Reuse `S`** to keep that state (a resumed conversation, a warm cache).
- **Use a fresh `S`** for a clean, reproducible run.
- Your host config is not visible unless you bind it. To seed config, copy files into
  `S/home/` before the run instead of binding your real `~/.claude`.

## Bounds and review

- **Time.** `limits.timeout` (or a shorter `--timeout`) kills the whole sandbox:
  rc 124, audit `outcome` `timeout`.
- **Output.** `limits.output_bytes` caps what reaches your terminal or log. The agent
  keeps running past the cap.
- **Review.** Use `--audit` with a file outside `S` and outside every bind. Afterwards,
  `jq 'select(.verdict=="denied" or .verdict=="teardown")'` lists what the agent tried
  and was refused.
- **Cleanup.** `sbx gc --older-than 7d ~/.cache/sbx` removes the idle session
  directories directly under `~/.cache/sbx`.
