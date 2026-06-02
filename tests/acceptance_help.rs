//! AC1: bpolicy --help lists exactly six subcommands: load, unload, enforce,
//! release, status, log.
//! AC6: reference/bpolicy.py exists and README.md exists.

use std::process::Command;

fn bpolicy_bin() -> std::path::PathBuf {
    // Use the binary built in the same workspace
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/bpolicy");
    p
}

#[test]
fn test_help_lists_six_subcommands() {
    let output = Command::new(bpolicy_bin())
        .arg("--help")
        .output()
        .expect("failed to run bpolicy --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    let subcommands = ["load", "unload", "enforce", "release", "status", "log"];
    for sub in &subcommands {
        assert!(
            combined.contains(sub),
            "help output missing subcommand '{sub}'. Got:\n{combined}"
        );
    }
}

#[test]
fn test_reference_py_exists() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let py = manifest.join("reference/bpolicy.py");
    assert!(
        py.exists(),
        "reference/bpolicy.py missing at {py:?}"
    );
}

#[test]
fn test_readme_exists() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme = manifest.join("README.md");
    assert!(
        readme.exists(),
        "README.md missing at {readme:?}"
    );
}

#[test]
fn test_readme_mentions_bpolicy_obj() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme = manifest.join("README.md");
    let contents = std::fs::read_to_string(&readme)
        .unwrap_or_default();
    assert!(
        contents.contains("BPOLICY_OBJ"),
        "README.md should document the BPOLICY_OBJ override"
    );
}
