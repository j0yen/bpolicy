#!/usr/bin/env python3
"""bpolicy — userspace control for the BPF-LSM file_open enforcer.

  bpolicy load                          load + auto-attach the .bpf.o, pin maps
  bpolicy unload                        detach and remove pins
  bpolicy enforce --pid PID [--pid ...] add PIDs to the protected set
  bpolicy release --pid PID [--pid ...] remove PIDs
  bpolicy status                        list protected PIDs + stats
  bpolicy log [-n N]                    tail kernel trace_pipe for bpolicy: lines

The enforcer denies file_open with FMODE_WRITE outside /tmp, /dev/{null,tty,std*,pts},
and /proc/self/ for any PID in the protected set (descendants tracked via fork).
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

BPF_ROOT = Path("/sys/fs/bpf/bpolicy")
SRC_DIR = Path.home() / ".local/src/bpolicy"
PINNED_MAP = BPF_ROOT / "protected_pids"
STATS_MAP = BPF_ROOT / "stats"


def sh(*args, check=True, capture=True):
    r = subprocess.run(args, capture_output=capture, text=True)
    if check and r.returncode != 0:
        sys.exit(f"{args[0]}: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def pid_to_key_bytes(pid):
    return ["%d" % b for b in struct.pack("<I", pid)]


def loaded():
    # /sys/fs/bpf is mode 1700 root:root — must use sudo to introspect.
    r = subprocess.run(["sudo", "-n", "test", "-e", str(BPF_ROOT / "file_open_check")])
    return r.returncode == 0


def cmd_load(_args):
    if loaded():
        print(json.dumps({"already_loaded": True}))
        return
    obj = SRC_DIR / "bpolicy.bpf.o"
    if not obj.exists():
        sys.exit(f"missing {obj} — compile first")
    sh("sudo", "-n", "mkdir", "-p", str(BPF_ROOT))
    sh("sudo", "-n", "bpftool", "prog", "loadall",
       str(obj), str(BPF_ROOT), "autoattach", "pinmaps", str(BPF_ROOT))
    print(json.dumps({"loaded": True, "path": str(BPF_ROOT)}))


def cmd_unload(_args):
    if not loaded():
        print(json.dumps({"already_unloaded": True}))
        return
    sh("sudo", "-n", "rm", "-rf", str(BPF_ROOT))
    print(json.dumps({"unloaded": True}))


def _require_loaded():
    if not loaded():
        sys.exit("bpolicy not loaded — run: bpolicy load")


def cmd_enforce(args):
    _require_loaded()
    if not args.pid:
        sys.exit("provide --pid PID [--pid PID...]")
    for pid in args.pid:
        kb = pid_to_key_bytes(pid)
        sh("sudo", "-n", "bpftool", "map", "update",
           "pinned", str(PINNED_MAP),
           "key", *kb, "value", "1")
    print(json.dumps({"enforcing": args.pid}))


def cmd_release(args):
    _require_loaded()
    if not args.pid:
        sys.exit("provide --pid PID [--pid PID...]")
    for pid in args.pid:
        kb = pid_to_key_bytes(pid)
        sh("sudo", "-n", "bpftool", "map", "delete",
           "pinned", str(PINNED_MAP), "key", *kb, check=False)
    print(json.dumps({"released": args.pid}))


def cmd_status(_args):
    if not loaded():
        print(json.dumps({"loaded": False}))
        return
    pids_raw = sh("sudo", "-n", "bpftool", "-j", "map", "dump",
                   "pinned", str(PINNED_MAP), check=False)
    stats_raw = sh("sudo", "-n", "bpftool", "-j", "map", "dump",
                    "pinned", str(STATS_MAP), check=False)
    def _fmt(e):
        # bpftool -j includes a "formatted" sub-object with decoded scalars.
        f = e.get("formatted", {})
        return f.get("key"), f.get("value")
    try:
        pids = sorted(_fmt(e)[0] for e in json.loads(pids_raw)) if pids_raw else []
    except (json.JSONDecodeError, KeyError):
        pids = []
    labels = ["checked", "allowed", "denied", "forked_in"]
    stats = {}
    try:
        for e in json.loads(stats_raw) if stats_raw else []:
            k, v = _fmt(e)
            if k is not None and 0 <= k < len(labels):
                stats[labels[k]] = v
    except (json.JSONDecodeError, KeyError):
        pass
    out = {"loaded": True, "protected_pids": pids, "stats": stats}
    print(json.dumps(out, indent=2))


def cmd_log(args):
    sh_args = ["sudo", "-n", "cat", "/sys/kernel/tracing/trace_pipe"]
    try:
        proc = subprocess.Popen(sh_args, stdout=subprocess.PIPE, text=True)
        n = 0
        for line in proc.stdout:
            if "bpolicy" in line:
                sys.stdout.write(line)
                sys.stdout.flush()
                n += 1
                if args.n and n >= args.n:
                    proc.terminate()
                    return
    except KeyboardInterrupt:
        proc.terminate()


def main():
    p = argparse.ArgumentParser(prog="bpolicy")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("load").set_defaults(fn=cmd_load)
    sub.add_parser("unload").set_defaults(fn=cmd_unload)
    sub.add_parser("status").set_defaults(fn=cmd_status)

    e = sub.add_parser("enforce")
    e.add_argument("--pid", type=int, action="append", required=True)
    e.set_defaults(fn=cmd_enforce)

    r = sub.add_parser("release")
    r.add_argument("--pid", type=int, action="append", required=True)
    r.set_defaults(fn=cmd_release)

    lg = sub.add_parser("log")
    lg.add_argument("-n", type=int, default=0, help="stop after N lines (0=tail forever)")
    lg.set_defaults(fn=cmd_log)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
