# bpolicy

Userspace control-plane CLI for the BPF-LSM `file_open` write enforcer.

**Behavioral contract:** same surface, new home — this Rust binary produces
byte-identical JSON output to the original `reference/bpolicy.py`.

## Subcommands

```
bpolicy load                          load + auto-attach the .bpf.o, pin maps
bpolicy unload                        detach and remove pins
bpolicy enforce --pid PID [--pid …]   add PIDs to the protected set
bpolicy release --pid PID [--pid …]   remove PIDs from the protected set
bpolicy status                        JSON: loaded state, protected PIDs, stats
bpolicy log [-n N]                    tail kernel trace_pipe for bpolicy: lines
```

## Install

```sh
cargo build --release
install -m755 target/release/bpolicy ~/.local/bin/bpolicy
```

This replaces the Python script at the same path. No other changes are needed
— `CLAUDE_SELF.md`, toolkit memory, and the `drift` skill continue to work.

## BPF object path

The binary reads the BPF object from `~/.local/src/bpolicy/bpolicy.bpf.o` by
default (the existing installed location). Override with `BPOLICY_OBJ`:

```sh
BPOLICY_OBJ=bpf/bpolicy.bpf.o bpolicy load
```

## Compile the BPF source

```sh
cd bpf && ./build.sh
```

Requires `clang` with BPF target support. The pre-compiled `.bpf.o` from
`~/.local/src/bpolicy/` can be used directly without recompiling.

## Status JSON shape

Unloaded:
```json
{"loaded": false}
```

Loaded:
```json
{
  "loaded": true,
  "protected_pids": [100, 1234, 5678],
  "stats": {
    "checked": 999,
    "allowed": 990,
    "denied": 9,
    "forked_in": 3
  }
}
```

## Reference

`reference/bpolicy.py` is the original Python control plane, kept for diffing.
The Rust binary is a drop-in replacement with identical CLI and JSON surface.

## License

MIT OR Apache-2.0
