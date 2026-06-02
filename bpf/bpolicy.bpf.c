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
// Allow list (prefix match on the first few bytes of d_path):
//   /tmp/        — writable scratch space
//   /dev/null    — discarding writes
//   /dev/tty     — terminal output
//   /dev/std{in,out,err} — already represented by fd dups
//   /proc/self/  — self-introspection
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

static __always_inline int path_allowed(const char *p)
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

    if (path_allowed(buf)) {
        bump(S_ALLOWED);
        return 0;
    }

    bump(S_DENIED);
    bpf_printk("bpolicy: block pid=%d path=%s\n", pid, buf);
    return -EPERM;
}
