# Changelog

## v0.3.0 — 2026-06-02

warden-deadman — arming the enforcer cannot strand you

Adds two blast-radius controls so `bpolicy load` stops being a cliff:

- **Audit mode (`--audit`)**: a `bpolicy_config` BPF map (`mode` field) the
  `file_open` hook reads. In audit mode it runs the same allow/deny evaluation
  and bumps `stats.denied`, but returns 0 (allow) — watch what a profile would
  deny against a live workload without blocking a single write. `status` reports
  `"mode": "audit" | "enforce"` (additive; absent ⇒ enforce).
- **Deadman timer (`--ttl`, `renew`)**: `load --ttl <secs>` records expiry in
  `~/.config/bpolicy/deadman.json` and arms a `systemd-run --user` transient
  unit that auto-runs `bpolicy unload` at expiry. `renew` pushes expiry forward
  and re-arms (one live watchdog); `unload` cancels it. A bare `load` defaults
  to 30m; `--ttl 0` arms permanently (`status` shows `ttl_remaining_s: null`).
- **Safety interlock (`--yes`)**: an enforce-mode arm on an interactive TTY
  refuses without `--yes`, printing the would-deny summary + TTL. Audit never
  prompts; headless callers pass `--yes`.

Coexists with warden-policy's `--profile` allow-list (load populates the
allowlist map, applies the audit mode, then arms the deadman). The BPF config
map is named `bpolicy_config` to avoid a vmlinux.h `config` typedef collision.
Clock/watchdog are injected so timer logic is unit-tested with no real sleeps.

## v0.2.1 — 2026-06-02

Bugfix: the v0.2.0 BPF object never compiled — `bpf/bpolicy.bpf.c` exceeded
the 512-byte BPF stack limit at `file_open_check` (a 256-byte `struct
allowlist_key` candidate key on the stack alongside the 256-byte `bpf_d_path`
buffer), producing ~20 clang errors. The feature was inert (bpolicy was never
loadable). This release makes the enforcer actually buildable.

- `bpf/bpolicy.bpf.c`: moved the allowlist candidate key off the stack into a
  new per-cpu `BPF_MAP_TYPE_PERCPU_ARRAY` scratch map (`key_scratch`);
  `path_allowed_dynamic` now looks up / fills the key via the scratch slot
  instead of a stack-resident struct. Userspace map set (`protected_pids`,
  `allowlist`) is unchanged — the scratch map is BPF-internal.
- `bpf/build.sh`: propagate clang's exit code explicitly — compile to a temp
  object, refuse to promote on failure (no stale `bpolicy.bpf.o` left behind),
  and verify a non-empty object was produced. A clang failure can no longer
  land green (the original masking bug that let the broken object integrate).
- Verified: `build.sh` exits 0 with object on success, exits 1 with no stale
  object on an injected compile error; 40+ cargo tests still green.

## v0.2.0 — 2026-06-02

## warden-policy — declarative allow-list (v0.2.0)

Moves the bpolicy allow-list from baked BPF constants to a runtime
`~/.config/bpolicy/policy.toml` with named profiles.

- `src/policy.rs`: TOML loader, `prefix_matches` / `is_allowed` evaluator,
  `ResolvedAllowList`, `cmd_policy_show`, `cmd_policy_check`
- `bpf/bpolicy.bpf.c`: `allowlist` HASH map (`struct allowlist_key`),
  `path_allowed_dynamic` (bounded prefix walk + map lookup); BPF/userspace
  spec cross-referenced in both files
- `src/bpf.rs`: `PINNED_MAP_ALLOWLIST`, `prefix_to_key_bytes`,
  `allowlist_add_prefix` in `BpfOps`, `cmd_load --profile` populates map
- `src/main.rs`: `load --profile`, `policy show`, `policy check` subcommands
- `src/status.rs`: additive `"profile"` field (back-compat: absent = tight)
- 40 unit + 19 integration tests green; `cargo clippy -D warnings` clean
