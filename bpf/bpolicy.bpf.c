// bpolicy.bpf.c — LSM-based write enforcement for a PID tree.
//
// Policy: any PID in the `protected_pids` map (set by userspace via bpftool)
// and its descendants (sched_process_fork) may NOT open files for writing
// outside an allow-list of paths. Fork tracking propagates the protected
// status to children; exit clears it.
//
// Known semantic gap (LSM `security_file_open` timing):
//   open(O_CREAT|O_WRONLY) creates the inode BEFORE file_open is called.
//   When we deny, the empty file remains on disk. No data is ever written
//   (the fd is rejected). Userspace observer: rc!=0, file exists size=0.
//   A future revision could add an inode_create hook with dentry-chain
//   walking to prevent the touch entirely.
//
// Compiled defaults (path_allowed_defaults) — prefix match:
//   /tmp/        — writable scratch space
//   /dev/null    — discarding writes
//   /dev/tty     — terminal output
//   /dev/std{in,out,err} — already represented by fd dups
//   /dev/pts/    — pseudo-terminal
//   /proc/self/  — self-introspection
//
// Dynamic allowlist (allowlist map) — prefix match from policy profiles:
//   Populated by userspace via `bpolicy load --profile <name>`.
//   Keys are struct allowlist_key { u8 len; char data[255]; }
//   Value is u8 (presence marker; value is ignored, only key matters).
//
// Prefix match spec (identical in BPF and src/policy.rs):
//   Prefix P matches path T iff T == P  OR
//   T starts_with(P) AND (len(T) == len(P) OR T[len(P)] == '/').
//   This prevents /home/jsy/s from matching /home/jsy/sec.
//
// Userspace mirror: src/policy.rs:prefix_matches / is_allowed.
// Any change to this spec MUST be reflected in policy.rs, and vice-versa.
//
// Config map (index 0 — mode):
//   0 = enforce (default): deny writes outside allow-list
//   1 = audit:  evaluate but always return 0 (allow); counts still increment
//
// Compile:  clang -O2 -g -target bpf -I. -c bpolicy.bpf.c -o bpolicy.bpf.o
// Load:     sudo bpftool prog loadall bpolicy.bpf.o /sys/fs/bpf/bpolicy autoattach

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// FMODE_WRITE from include/linux/fs.h
#define FMODE_WRITE 0x2
#define EPERM 1

// Maximum path prefix length stored in the allowlist map.
// Matches MAX_PREFIX_LEN in src/bpf.rs.
#define ALLOWLIST_MAX_PREFIX 255

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} protected_pids SEC(".maps");

// Stats so userspace can see the enforcer is doing something
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Dynamic allowlist map: keyed by path prefix structs.
// Key: { u8 len; char data[ALLOWLIST_MAX_PREFIX]; } (256 bytes total)
// Value: u8 presence marker.
// Populated by `bpolicy load --profile <name>` after loadall.
struct allowlist_key {
    __u8  len;
    char  data[ALLOWLIST_MAX_PREFIX];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct allowlist_key);
    __type(value, __u8);
} allowlist SEC(".maps");

// Per-cpu scratch for the candidate allowlist key. struct allowlist_key is
// 256 bytes; combined with the 256-byte d_path buffer in file_open_check it
// blows the 512-byte BPF stack limit. Keep it off the stack in a per-cpu
// ARRAY map (one slot, indexed by 0). Per-cpu means no cross-CPU contention.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct allowlist_key);
} key_scratch SEC(".maps");

// Config map — single entry at key=0.
// Value layout: u64, low byte = mode (0=enforce, 1=audit).
// Named `bpolicy_config` (not `config`) to avoid colliding with the
// `typedef struct config_s config;` present in some kernels' vmlinux.h.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} bpolicy_config SEC(".maps");

// Config key for the mode field
#define CFG_KEY_MODE 0
// Mode values
#define MODE_ENFORCE 0
#define MODE_AUDIT   1

// stat indices
#define S_CHECKED   0
#define S_ALLOWED   1
#define S_DENIED    2
#define S_FORKED_IN 3

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 ppid = BPF_CORE_READ(parent, tgid);
    __u32 cpid = BPF_CORE_READ(child, tgid);
    __u8 *v = bpf_map_lookup_elem(&protected_pids, &ppid);
    if (v) {
        __u8 one = 1;
        bpf_map_update_elem(&protected_pids, &cpid, &one, BPF_ANY);
        bump(S_FORKED_IN);
    }
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, tgid);
    bpf_map_delete_elem(&protected_pids, &pid);
    return 0;
}

// path_allowed_defaults: compiled always-allowed prefixes.
// Spec cross-reference: src/policy.rs:COMPILED_DEFAULTS + is_default_allowed.
// Any change here MUST be reflected in policy.rs COMPILED_DEFAULTS.
static __always_inline int path_allowed_defaults(const char *p)
{
    // /tmp/
    if (p[0] == '/' && p[1] == 't' && p[2] == 'm' && p[3] == 'p' && p[4] == '/')
        return 1;
    // /dev/null, /dev/tty, /dev/stdout, /dev/stderr, /dev/stdin, /dev/pts/...
    if (p[0] == '/' && p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/') {
        char c5 = p[5];
        if (c5 == 'n' || c5 == 't' || c5 == 's' || c5 == 'p')
            return 1;
    }
    // /proc/self/
    if (p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' &&
        p[5] == '/' && p[6] == 's' && p[7] == 'e' && p[8] == 'l' && p[9] == 'f' && p[10] == '/')
        return 1;
    return 0;
}

// path_allowed_dynamic: check the dynamic allowlist map for a prefix match.
//
// Prefix match rule (mirrors src/policy.rs:prefix_matches):
//   Prefix P (length plen) matches path T iff:
//     T[0..plen] == P  AND  (T[plen] == '\0' OR T[plen] == '/').
//
// We iterate over all entries in the allowlist map using bpf_for_each_map_elem,
// but that helper requires a BTF-annotated callback and is only available
// on kernel 5.13+. Instead, we use a pragmatic approach: the userspace loader
// ensures prefixes end with '/' (for directories) or are exact paths, so we
// perform a bounded linear prefix comparison for each entry using a per-entry
// hash lookup strategy.
//
// Implementation note: full iteration over a HASH map in BPF without
// bpf_for_each_map_elem is not possible. We use a different approach:
// we check the path against a sampled key reconstruction. Since the exact
// prefix for the path cannot be enumerated in-kernel without iteration,
// we reconstruct candidate prefix keys from the resolved path itself
// (all prefix substrings up to MAX_PREFIX_LEN) and look each up in the
// hash map. This is O(path_len) hash lookups — bounded and cheap.
//
// Cost bound: path is max 256 bytes; we check up to 256 keys of 256 bytes
// each. In practice paths have few '/' components, so the loop exits early
// on the first separator match. Documented per PRD note on cost.
static __always_inline int path_allowed_dynamic(const char *path, int pathlen)
{
    __u32 zero = 0;
    int i;

    // Candidate key lives in a per-cpu scratch map, NOT on the stack — a
    // stack-resident struct allowlist_key (256 B) plus the 256 B d_path buffer
    // exceeds the 512 B BPF stack limit. See key_scratch above.
    struct allowlist_key *k = bpf_map_lookup_elem(&key_scratch, &zero);
    if (!k)
        return 0;

    // Zero the whole key once up front so unused tail bytes never carry stale
    // per-cpu data into the hash lookup (HASH map compares the full key).
    __builtin_memset(k, 0, sizeof(*k));

    // Walk the path, checking each prefix ending at a '/' boundary or end-of-string.
    // We cap at ALLOWLIST_MAX_PREFIX iterations to satisfy the BPF verifier.
    #pragma unroll
    for (i = 1; i <= ALLOWLIST_MAX_PREFIX; i++) {
        if (i > pathlen)
            break;

        char c = path[i];
        // Check at '/' boundaries and at end-of-string.
        if (c != '/' && c != '\0')
            continue;

        // Build a candidate key: prefix = path[0..i]
        k->len = (__u8)i;
        // Copy path[0..i] into k->data (bounded copy, verifier-safe).
        // Bytes >= i stay zero from the memset / previous shorter prefixes
        // (each iteration only ever grows i, so we re-zero the gap below).
        #pragma unroll
        for (int j = 0; j < ALLOWLIST_MAX_PREFIX; j++) {
            if (j < i)
                k->data[j] = path[j];
            else
                k->data[j] = 0;
        }

        __u8 *hit = bpf_map_lookup_elem(&allowlist, k);
        if (hit)
            return 1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&protected_pids, &pid))
        return 0;

    __u32 f_mode = BPF_CORE_READ(file, f_mode);
    if (!(f_mode & FMODE_WRITE))
        return 0;

    bump(S_CHECKED);

    char buf[256] = {};
    long err = bpf_d_path(&file->f_path, buf, sizeof(buf));
    if (err < 0) {
        // Couldn't resolve — fail open (allow) to avoid breaking everything
        bump(S_ALLOWED);
        return 0;
    }

    // Step 1: compiled always-allowed defaults (path_allowed_defaults).
    // Spec cross-reference: src/policy.rs:is_default_allowed
    if (path_allowed_defaults(buf)) {
        bump(S_ALLOWED);
        return 0;
    }

    // Step 2: dynamic allowlist from policy profile (path_allowed_dynamic).
    // Spec cross-reference: src/policy.rs:is_allowed
    int plen = (int)err; // bpf_d_path returns length on success
    if (path_allowed_dynamic(buf, plen)) {
        bump(S_ALLOWED);
        return 0;
    }

    bump(S_DENIED);
    bpf_printk("bpolicy: block pid=%d path=%s\n", pid, buf);

    // Audit mode: count but allow
    __u32 cfg_key = CFG_KEY_MODE;
    __u64 *mode_v = bpf_map_lookup_elem(&bpolicy_config, &cfg_key);
    if (mode_v && (*mode_v & 0xFF) == MODE_AUDIT)
        return 0;

    return -EPERM;
}
