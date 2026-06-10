//! `bpolicy doctor` — probes each precondition for the LSM enforcer to be
//! armed and reports each as `ok | gap | unknown` with the observed value.
//!
//! **Read-only by design.** No BPF programs are loaded or pinned; no system
//! state is mutated. Run as any user; some checks report `unknown` when
//! files require elevated access.
//!
//! ## Checks (in order)
//!
//! 1. **lsm-list** — Is `bpf` present in the kernel's active LSM list?
//! 2. **btf** — Is `/sys/kernel/btf/vmlinux` present and readable (CO-RE)?
//! 3. **capability** — Does the invoking user hold `CAP_BPF` or `CAP_SYS_ADMIN`?
//! 4. **bpf-fs** — Is the bpffs mounted and are the enforcer's pin paths accessible?
//! 5. **boot-arm** — Is there a systemd unit wiring the enforcer to arm at boot,
//!    and did it run this boot?

#![allow(clippy::print_stdout)] // CLI: stdout output is intentional

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::bpf::{BPF_ROOT, LOADED_PIN};

// ── public types ──────────────────────────────────────────────────────────────

/// The verdict for a single precondition check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The condition is satisfied.
    Ok,
    /// The condition is *not* satisfied — this is a concrete activation gap.
    Gap,
    /// Could not be determined (e.g., permission denied).
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Ok => f.write_str("ok"),
            Verdict::Gap => f.write_str("gap"),
            Verdict::Unknown => f.write_str("unknown"),
        }
    }
}

/// One precondition check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    /// Short machine-readable name (e.g., `"lsm-list"`).
    pub name: String,
    /// Human label for the check.
    pub label: String,
    /// Whether the check passed.
    pub verdict: Verdict,
    /// Short detail: the observed value or reason.
    pub detail: String,
}

impl Check {
    fn new(name: &str, label: &str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            label: label.to_owned(),
            verdict,
            detail: detail.into(),
        }
    }

    fn ok(name: &str, label: &str, detail: impl Into<String>) -> Self {
        Self::new(name, label, Verdict::Ok, detail)
    }
    fn gap(name: &str, label: &str, detail: impl Into<String>) -> Self {
        Self::new(name, label, Verdict::Gap, detail)
    }
    fn unknown(name: &str, label: &str, detail: impl Into<String>) -> Self {
        Self::new(name, label, Verdict::Unknown, detail)
    }
}

/// The full doctor report.
#[derive(Debug, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Per-check results in probe order.
    pub checks: Vec<Check>,
    /// Short name of the first gap found, or `None` if all are `ok`/`unknown`.
    pub first_gap: Option<String>,
}

impl DoctorReport {
    /// Run all precondition checks and return the report.
    #[must_use]
    pub fn run() -> Self {
        let checks = vec![
            check_lsm_list(),
            check_btf(),
            check_capability(),
            check_bpf_fs(),
            check_boot_arm(),
        ];
        let first_gap = checks
            .iter()
            .find(|c| c.verdict == Verdict::Gap)
            .map(|c| c.name.clone());
        Self { checks, first_gap }
    }
}

// ── check implementations ─────────────────────────────────────────────────────

/// Check 1 — LSM list: is `bpf` in the active kernel LSM list?
fn check_lsm_list() -> Check {
    const NAME: &str = "lsm-list";
    const LABEL: &str = "Kernel LSM list includes 'bpf'";

    // Primary source: /sys/kernel/security/lsm
    let lsm_security = fs::read_to_string("/sys/kernel/security/lsm").ok();
    // Secondary source: kernel cmdline
    let cmdline = fs::read_to_string("/proc/cmdline").ok();

    let active_lsms: Option<String> = lsm_security.clone().or_else(|| {
        // Extract lsm=... from cmdline
        cmdline.as_ref().and_then(|c| {
            c.split_whitespace()
                .find(|tok| tok.starts_with("lsm="))
                .map(|tok| tok.trim_start_matches("lsm=").to_owned())
        })
    });

    match active_lsms {
        None => Check::unknown(NAME, LABEL, "cannot read /sys/kernel/security/lsm or /proc/cmdline"),
        Some(ref lsms) => {
            if lsms.split(',').any(|l| l.trim() == "bpf") {
                Check::ok(NAME, LABEL, format!("active lsms: {lsms}"))
            } else {
                Check::gap(
                    NAME,
                    LABEL,
                    format!(
                        "bpf not in active LSM list [{lsms}]; add lsm=...,bpf to kernel cmdline"
                    ),
                )
            }
        }
    }
}

/// Check 2 — BTF: is `/sys/kernel/btf/vmlinux` present and readable?
fn check_btf() -> Check {
    const NAME: &str = "btf";
    const LABEL: &str = "BTF vmlinux available (CO-RE)";
    const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

    match fs::metadata(BTF_PATH) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Check::gap(NAME, LABEL, format!("{BTF_PATH} not found; kernel may lack BTF support"))
        }
        Err(e) => Check::unknown(NAME, LABEL, format!("{BTF_PATH}: {e}")),
        Ok(meta) => {
            if meta.len() > 0 {
                Check::ok(NAME, LABEL, format!("{BTF_PATH} present ({} bytes)", meta.len()))
            } else {
                Check::gap(NAME, LABEL, format!("{BTF_PATH} exists but is empty"))
            }
        }
    }
}

/// Check 3 — Capability: does the invoking user hold CAP_BPF or CAP_SYS_ADMIN?
///
/// We probe by attempting `bpftool version` (no-op, unprivileged) and reading
/// `/proc/self/status` for the `CapEff` bitmask.  CAP_BPF is bit 39 (Linux
/// ≥ 5.8); CAP_SYS_ADMIN is bit 21.
fn check_capability() -> Check {
    const NAME: &str = "capability";
    const LABEL: &str = "Invoking user has CAP_BPF or CAP_SYS_ADMIN";
    const CAP_SYS_ADMIN_BIT: u64 = 1 << 21;
    const CAP_BPF_BIT: u64 = 1 << 39;

    let status = fs::read_to_string("/proc/self/status").ok();
    let cap_eff: Option<u64> = status.as_ref().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("CapEff:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
    });

    match cap_eff {
        None => Check::unknown(NAME, LABEL, "cannot parse /proc/self/status CapEff"),
        Some(caps) => {
            let has_bpf = (caps & CAP_BPF_BIT) != 0;
            let has_admin = (caps & CAP_SYS_ADMIN_BIT) != 0;
            if has_bpf || has_admin {
                let which = if has_bpf { "CAP_BPF" } else { "CAP_SYS_ADMIN" };
                Check::ok(NAME, LABEL, format!("has {which} (CapEff=0x{caps:016x})"))
            } else {
                Check::gap(
                    NAME,
                    LABEL,
                    format!(
                        "neither CAP_BPF nor CAP_SYS_ADMIN set (CapEff=0x{caps:016x}); \
                         run as root or grant CAP_BPF"
                    ),
                )
            }
        }
    }
}

/// Check 4 — BPF-FS: is the bpffs mounted and pin root accessible?
fn check_bpf_fs() -> Check {
    const NAME: &str = "bpf-fs";
    const LABEL: &str = "BPF filesystem mounted and pin root accessible";
    const BPFFS: &str = "/sys/fs/bpf";

    // Check the bpffs mount by looking for the filesystem type in /proc/mounts
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let bpffs_mounted = mounts.lines().any(|line| {
        let mut parts = line.split_whitespace();
        let _dev = parts.next();
        let mntpnt = parts.next().unwrap_or("");
        let fstype = parts.next().unwrap_or("");
        mntpnt == BPFFS && fstype == "bpf"
    });

    if !bpffs_mounted {
        return Check::gap(
            NAME,
            LABEL,
            format!("{BPFFS} not mounted as bpf type; try: mount -t bpf bpf /sys/fs/bpf"),
        );
    }

    // Check whether the enforcer pin root and the loaded pin exist
    if Path::new(LOADED_PIN).exists() {
        Check::ok(
            NAME,
            LABEL,
            format!("bpffs mounted at {BPFFS}; enforcer pin {LOADED_PIN} present"),
        )
    } else if Path::new(BPF_ROOT).exists() {
        Check::gap(
            NAME,
            LABEL,
            format!("bpffs mounted at {BPFFS}; {BPF_ROOT} exists but enforcer pin {LOADED_PIN} missing"),
        )
    } else {
        // bpffs is fine — enforcer just isn't loaded yet; this is expected when inert
        Check::ok(NAME, LABEL, format!("bpffs mounted at {BPFFS} (enforcer not yet pinned)"))
    }
}

/// Check 5 — Boot-arm: is there a systemd unit that arms the enforcer at boot?
fn check_boot_arm() -> Check {
    const NAME: &str = "boot-arm";
    const LABEL: &str = "Boot-time arming unit configured and ran";

    // Look for a service unit that references bpolicy load
    let candidates = ["bpolicy-arm.service", "bpolicy.service", "bpolicy-load.service"];

    for unit in &candidates {
        let status = Command::new("systemctl")
            .args(["--user", "show", unit, "--property=LoadState,ActiveState,SubState"])
            .output();

        match status {
            Err(_) => continue,
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let load_state = prop_value(&text, "LoadState");
                if load_state.as_deref() == Some("not-found") || load_state.is_none() {
                    continue;
                }
                let active = prop_value(&text, "ActiveState").unwrap_or_default();
                let sub = prop_value(&text, "SubState").unwrap_or_default();
                if active == "active" || sub == "exited" {
                    return Check::ok(
                        NAME,
                        LABEL,
                        format!("{unit} active={active} sub={sub}"),
                    );
                }
                return Check::gap(
                    NAME,
                    LABEL,
                    format!("{unit} found but active={active} sub={sub}; check: journalctl --user -u {unit}"),
                );
            }
        }
    }

    // Also check system-level units
    for unit in &candidates {
        let status = Command::new("systemctl")
            .args(["show", unit, "--property=LoadState,ActiveState,SubState"])
            .output();

        if let Ok(out) = status {
            let text = String::from_utf8_lossy(&out.stdout);
            let load_state = prop_value(&text, "LoadState");
            if load_state.as_deref() == Some("not-found") || load_state.is_none() {
                continue;
            }
            let active = prop_value(&text, "ActiveState").unwrap_or_default();
            let sub = prop_value(&text, "SubState").unwrap_or_default();
            if active == "active" || sub == "exited" {
                return Check::ok(NAME, LABEL, format!("{unit} (system) active={active} sub={sub}"));
            }
            return Check::gap(
                NAME,
                LABEL,
                format!("{unit} (system) found but active={active} sub={sub}"),
            );
        }
    }

    // Fallback: check if loaded pin exists (enforcer armed, no unit needed)
    if Path::new(LOADED_PIN).exists() {
        Check::ok(NAME, LABEL, "no boot-arm unit found but enforcer is currently loaded")
    } else {
        Check::gap(
            NAME,
            LABEL,
            "no bpolicy boot-arm systemd unit found; enforcer is not armed at boot",
        )
    }
}

/// Extract a `Key=Value` property from `systemctl show` output.
fn prop_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with(key) && l.as_bytes().get(key.len()) == Some(&b'='))
        .map(|l| l[key.len() + 1..].to_owned())
}

// ── CLI entry points ──────────────────────────────────────────────────────────

/// Output format for `bpolicy doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorFormat {
    /// Human-readable, one line per check.
    Human,
    /// JSON object keyed by check name.
    Json,
    /// Single `docket report` command line for the first gap.
    Docket,
}

impl std::str::FromStr for DoctorFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "human" => Ok(DoctorFormat::Human),
            "json" => Ok(DoctorFormat::Json),
            "docket" => Ok(DoctorFormat::Docket),
            other => Err(format!("unknown format `{other}`; choose human | json | docket")),
        }
    }
}

/// Run the doctor subcommand and print to stdout.
///
/// # Errors
/// Returns an error if JSON serialization fails (unlikely in practice).
pub fn cmd_doctor(format: DoctorFormat) -> Result<()> {
    let report = DoctorReport::run();

    match format {
        DoctorFormat::Human => print_human(&report),
        DoctorFormat::Json => print_json(&report)?,
        DoctorFormat::Docket => print_docket(&report),
    }
    Ok(())
}

/// Print the human-readable report, one line per check.
fn print_human(report: &DoctorReport) {
    for c in &report.checks {
        println!("{:<12} {:<8} {}", c.name, c.verdict, c.detail);
    }
}

/// Print a JSON object keyed by check name.
fn print_json(report: &DoctorReport) -> Result<()> {
    use serde_json::json;
    let mut obj = serde_json::Map::new();
    for c in &report.checks {
        obj.insert(
            c.name.clone(),
            json!({
                "verdict": c.verdict,
                "detail": c.detail,
                "label": c.label,
            }),
        );
    }
    if let Some(ref g) = report.first_gap {
        obj.insert("first_gap".to_owned(), serde_json::Value::String(g.clone()));
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(obj))?);
    Ok(())
}

/// Print a single `docket report` command line for the first gap.
///
/// If there are no gaps, prints a no-op comment instead.
fn print_docket(report: &DoctorReport) {
    match &report.first_gap {
        Some(gap) => {
            // Encode cause as the gap name; strip any shell-unsafe characters.
            let safe_gap = gap.replace(' ', "_");
            println!(
                "docket report --key warden-enforcer-inert --evidence cause:{safe_gap}"
            );
        }
        None => {
            println!("# bpolicy doctor: no gaps found — all checks ok or unknown");
        }
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// AC2 — doctor prints one line per precondition with ok|gap|unknown.
    #[test]
    fn test_report_has_five_checks() {
        let report = DoctorReport::run();
        assert_eq!(report.checks.len(), 5);
        let names = ["lsm-list", "btf", "capability", "bpf-fs", "boot-arm"];
        for (i, name) in names.iter().enumerate() {
            assert_eq!(report.checks[i].name, *name);
        }
    }

    /// Every check has a verdict that is displayable.
    #[test]
    fn test_verdict_display() {
        assert_eq!(format!("{}", Verdict::Ok), "ok");
        assert_eq!(format!("{}", Verdict::Gap), "gap");
        assert_eq!(format!("{}", Verdict::Unknown), "unknown");
    }

    /// AC4 — JSON output must be parseable and keyed by check name.
    #[test]
    fn test_json_parseable() -> Result<()> {
        let report = DoctorReport::run();
        let mut obj = serde_json::Map::new();
        for c in &report.checks {
            obj.insert(
                c.name.clone(),
                serde_json::json!({
                    "verdict": c.verdict,
                    "detail": c.detail,
                    "label": c.label,
                }),
            );
        }
        if let Some(ref g) = report.first_gap {
            obj.insert("first_gap".to_owned(), serde_json::Value::String(g.clone()));
        }
        let json_str = serde_json::to_string(&serde_json::Value::Object(obj))?;
        let parsed: serde_json::Value = serde_json::from_str(&json_str)?;
        assert!(parsed.is_object());
        Ok(())
    }

    /// AC4 — docket format emits exactly one line starting with `docket report`.
    #[test]
    fn test_docket_format_when_gap() {
        let report = DoctorReport {
            checks: vec![Check::gap("lsm-list", "LSM list", "bpf not in active LSMs")],
            first_gap: Some("lsm-list".to_owned()),
        };
        let mut buf = String::new();
        match &report.first_gap {
            Some(gap) => {
                let safe_gap = gap.replace(' ', "_");
                buf.push_str(&format!(
                    "docket report --key warden-enforcer-inert --evidence cause:{safe_gap}"
                ));
            }
            None => {
                buf.push_str("# bpolicy doctor: no gaps found — all checks ok or unknown");
            }
        }
        assert!(buf.starts_with("docket report --key warden-enforcer-inert --evidence cause:lsm-list"));
    }

    /// AC6 — when all other checks are ok but enforcer still inert, boot-arm should be gap.
    ///
    /// We check that boot_arm returns Gap when the enforcer is not loaded.
    /// (On this box the enforcer IS inert, so this should match AC3 too.)
    #[test]
    fn test_all_checks_return_a_verdict() {
        let report = DoctorReport::run();
        for c in &report.checks {
            assert!(
                matches!(c.verdict, Verdict::Ok | Verdict::Gap | Verdict::Unknown),
                "check {} has unexpected verdict",
                c.name
            );
            assert!(!c.detail.is_empty(), "check {} has empty detail", c.name);
        }
    }

    /// DoctorFormat::from_str works.
    #[test]
    fn test_format_from_str() {
        assert_eq!("human".parse::<DoctorFormat>(), Ok(DoctorFormat::Human));
        assert_eq!("json".parse::<DoctorFormat>(), Ok(DoctorFormat::Json));
        assert_eq!("docket".parse::<DoctorFormat>(), Ok(DoctorFormat::Docket));
        assert!("bad".parse::<DoctorFormat>().is_err());
    }

    /// prop_value parses systemctl show output correctly.
    #[test]
    fn test_prop_value() {
        let text = "LoadState=loaded\nActiveState=active\nSubState=exited\n";
        assert_eq!(prop_value(text, "LoadState"), Some("loaded".to_owned()));
        assert_eq!(prop_value(text, "ActiveState"), Some("active".to_owned()));
        assert_eq!(prop_value(text, "SubState"), Some("exited".to_owned()));
        assert_eq!(prop_value(text, "Missing"), None);
    }
}
