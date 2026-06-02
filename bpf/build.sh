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
clang -O2 -g -target bpf -I. \
    -c bpolicy.bpf.c \
    -o bpolicy.bpf.o

echo "build.sh: done"
