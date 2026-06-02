# Changelog

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
