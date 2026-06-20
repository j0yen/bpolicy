# bpolicy

A write-enforcer for the file system, in two halves: a BPF-LSM `file_open` hook in the kernel that denies write-opens outside an allow-list, and this Rust CLI that loads it, sets the policy, and tears it down. The kernel decides; bpolicy is how you arm and steer it.

bpolicy replaces the original Python control plane (`reference/bpolicy.py`, kept for diffing). The early subcommands produce byte-identical JSON to it; later additions (mode, deadman, policy) are additive fields the Python output never had.

## Why it exists

An agent that can write anywhere can break anything — overwrite its own binary, scribble in `~/.config`, corrupt a repo. Confining it in userspace is unreliable: the agent runs the same code that would have to police itself. So the rule lives in the kernel. The BPF-LSM hook checks every write-open against an allow-list the agent cannot reach, and the only way out is `bpolicy unload`, which the agent's own policy can forbid it from running.

Two failure modes shaped the design. Arming the wrong policy can lock you out of your own filesystem — so a bare `load` defaults to a 30-minute deadman timer that auto-unloads, and an enforce-mode arm on a TTY refuses without `--yes`. And you rarely know in advance exactly what a workload writes — so `--audit` evaluates and counts denials without blocking a single write, letting you watch what a profile *would* deny against a live workload first.

## Subcommands

```
bpolicy load [--profile NAME] [--audit] [--ttl SECS] [--yes]
                                      load + attach the BPF object, apply policy, arm the deadman
bpolicy unload                        detach, remove pins, cancel the deadman
bpolicy enforce --pid PID [--pid …]   add PIDs to the protected set
bpolicy release --pid PID [--pid …]   remove PIDs from the protected set
bpolicy renew [--ttl SECS]            push the deadman expiry forward and re-arm
bpolicy status                        JSON: loaded state, mode, protected PIDs, stats, TTL
bpolicy policy show [--profile NAME]  print the resolved allow-list (defaults + profile)
bpolicy policy check <path> [--profile NAME]   would a write to this path be allowed? (no BPF)
bpolicy doctor [--format human|json|docket]    why is the enforcer inert? read-only probes
bpolicy log [-n N]                    tail the kernel trace_pipe for bpolicy lines
```

### load options

- `--profile NAME` — apply a named profile from `~/.config/bpolicy/policy.toml`. Default is `tight`: the compiled defaults only.
- `--audit` — evaluate and count denials but always allow the write. Never prompts (it blocks nothing). `status` then reports `"mode": "audit"`.
- `--ttl SECS` — deadman TTL. A bare `load` defaults to 1800 (30m) so a bad arm self-heals; `--ttl 0` arms permanently.
- `--yes` — proceed with an enforce-mode arm without the interactive confirmation. Required for an enforce arm on a TTY; headless callers should always pass it.

## Policy profiles

The allow-list is data, not baked-in BPF constants. `~/.config/bpolicy/policy.toml` holds named profiles, each listing path prefixes allowed for write-opens **on top of** the compiled defaults. A profile can add prefixes; it cannot remove the defaults.

```toml
[profile.workspace]
description = "agent jailed to its wintermute + claude workspace"
allow = [
  "/home/jsy/wintermute",
  "/home/jsy/.claude",
]

[profile.tight]
description = "tmp + dev only — the compiled default, named"
allow = []
```

Compiled defaults (always allowed): `/tmp/`, `/dev/null`, `/dev/tty`, `/dev/std{in,out,err}`, `/dev/pts/`.

Matching is longest-prefix: a prefix `P` matches path `T` iff `T == P` or `T` starts with `P` followed by `/`. The BPF hook (`bpf/bpolicy.bpf.c:path_allowed_dynamic`) and `src/policy.rs` implement the same spec and are cross-referenced in both files — change one, change the other. Use `policy check <path>` to evaluate a path against a profile in userspace, with no BPF interaction.

## Status JSON shape

Unloaded:
```json
{"loaded": false}
```

Loaded:
```json
{
  "loaded": true,
  "mode": "enforce",
  "protected_pids": [100, 1234, 5678],
  "stats": { "checked": 999, "allowed": 990, "denied": 9, "forked_in": 3 },
  "ttl_remaining_s": 1740,
  "profile": "workspace"
}
```

`mode`, `ttl_remaining_s`, and `profile` are additive — older consumers (and the warden-home golden test) tolerate their presence. `ttl_remaining_s` is `null` for a permanent arm; `profile` is absent when unknown (treat as `tight`).

## doctor — why is it inert?

`bpolicy status` showing `"loaded": false` doesn't tell you *why*. `doctor` probes each precondition for the LSM hook to arm — BPF on the active LSM list, kernel BTF, `CAP_BPF`/`CAP_SYS_ADMIN` — and reports each as `ok | gap | unknown` with the observed value. It is read-only: it never mutates state. `--format docket` emits a single `docket report` line for the first gap found.

## Install

```sh
cargo build --release
install -m755 target/release/bpolicy ~/.local/bin/bpolicy
```

This replaces the Python script at the same path; nothing else needs to change.

## BPF object

The binary reads the compiled object from `~/.local/src/bpolicy/bpolicy.bpf.o` by default. Override with `BPOLICY_OBJ`:

```sh
BPOLICY_OBJ=bpf/bpolicy.bpf.o bpolicy load
```

To compile the BPF source yourself:

```sh
cd bpf && ./build.sh
```

Requires `clang` with BPF target support. `build.sh` compiles to a temp object and refuses to promote it on a clang failure, so a broken object can never land green. The pre-compiled `.bpf.o` can be used directly without recompiling.

## License

MIT OR Apache-2.0
