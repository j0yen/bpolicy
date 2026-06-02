//! AC8 mock — deferred hardware AC.
//!
//! AC8 (SHOULD): bpf/build.sh compiles bpf/bpolicy.bpf.c to bpolicy.bpf.o.
//!
//! Deferred: real compile requires clang + bpftool, not available in all build
//! environments. This mock verifies:
//! - bpf/build.sh exists and is executable (type-level check)
//! - bpf/bpolicy.bpf.c exists (the source is present to compile)
//! - bpf/vmlinux.h exists (required include)
//!
//! The mock complements a real `bpf/build.sh` smoke run; it is not a
//! substitute for actually loading the produced .o on a live kernel.

#[test]
fn test_build_sh_exists_and_executable() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let build_sh = manifest.join("bpf/build.sh");
    assert!(build_sh.exists(), "bpf/build.sh should exist at {build_sh:?}");

    // Check executable bit
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&build_sh).expect("metadata bpf/build.sh");
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "bpf/build.sh should be executable");
    }
}

#[test]
fn test_bpf_source_exists() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let c_src = manifest.join("bpf/bpolicy.bpf.c");
    assert!(c_src.exists(), "bpf/bpolicy.bpf.c should exist at {c_src:?}");
}

#[test]
fn test_vmlinux_h_exists() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vmlinux = manifest.join("bpf/vmlinux.h");
    assert!(vmlinux.exists(), "bpf/vmlinux.h should exist at {vmlinux:?}");
}
