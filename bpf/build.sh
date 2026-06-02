#!/usr/bin/env bash
# build.sh — compile bpolicy.bpf.c to bpolicy.bpf.o
#
# Usage:
#   cd bpf/ && ./build.sh
#
# Requirements:
#   clang (with BPF target support), vmlinux.h in this directory
#
# Output:
#   bpolicy.bpf.o   — BTF-annotated BPF object suitable for bpftool prog loadall

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v clang >/dev/null 2>&1; then
    echo "build.sh: clang not found — skipping BPF compile (deferred AC8)" >&2
    exit 0
fi

echo "build.sh: compiling bpolicy.bpf.c → bpolicy.bpf.o"
# Compile to a temp object, then atomically promote ONLY on success so a clang
# failure can never leave a stale-but-present bpolicy.bpf.o behind. Explicitly
# check clang's exit code (belt-and-braces with `set -e`): a clang failure here
# was previously masked, letting broken BPF integrate green.
tmp_obj="$(mktemp "bpolicy.bpf-XXXXXXXX.o.tmp")"
trap 'rm -f "$tmp_obj"' EXIT

if ! clang -O2 -g -target bpf -I. \
        -c bpolicy.bpf.c \
        -o "$tmp_obj"; then
    echo "build.sh: clang FAILED to compile bpolicy.bpf.c" >&2
    exit 1
fi

if [ ! -s "$tmp_obj" ]; then
    echo "build.sh: clang produced no object — refusing to land" >&2
    exit 1
fi

mv -f "$tmp_obj" bpolicy.bpf.o
trap - EXIT
echo "build.sh: done — bpolicy.bpf.o produced"
