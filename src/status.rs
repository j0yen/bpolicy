//! Status JSON assembly — back-compat with the Python bpolicy status output.
//!
//! Extended output (loaded case):
//! ```json
//! {
//!   "loaded": true,
//!   "mode": "enforce" | "audit",
//!   "protected_pids": [...sorted ascending...],
//!   "stats": {
//!     "checked": N,
//!     "allowed": N,
//!     "denied": N,
//!     "forked_in": N
//!   },
//!   "ttl_remaining_s": N | null
//! }
//! ```
//!
//! Unloaded: `{"loaded": false}`.
//!
//! warden-policy extension: an additive `"profile"` field is included in the
//! loaded case when known. Absent ⇒ treat as `"tight"` (compiled defaults
//! only). warden-deadman extension: the `mode` and `ttl_remaining_s` fields are
//! additive. All existing keys are untouched so warden-home golden tests pass.

#![allow(clippy::print_stdout)] // CLI: stdout is intentional

use anyhow::Result;
use serde_json::{json, Value};

use crate::audit::{mode_label, parse_mode, PINNED_MAP_CONFIG};
use crate::bpf::{BpfOps, PINNED_MAP_PIDS, PINNED_MAP_STATS};
use crate::deadman::{read_state, ttl_remaining, SystemClock};

/// Assemble the status JSON from raw `bpftool -j map dump` output strings.
///
/// `pids_raw`, `stats_raw`, and `config_raw` are the stdout of
/// `bpftool -j map dump pinned …`. An empty string or invalid JSON is treated
/// as an empty map.
///
/// Includes the warden-deadman `mode` and `ttl_remaining_s` fields. To also
/// surface the warden-policy `profile` field, use
/// [`assemble_status_with_profile`].
#[must_use]
pub fn assemble_status(pids_raw: &str, stats_raw: &str, config_raw: &str) -> Value {
    assemble_status_with_profile(pids_raw, stats_raw, config_raw, None)
}

/// Assemble the status JSON, including an optional additive `"profile"` field.
///
/// The `mode` and `ttl_remaining_s` fields (warden-deadman) are always present.
/// The `profile` field (warden-policy) is included only when `profile` is
/// `Some`; otherwise the output matches [`assemble_status`] (back-compat with
/// warden-home's golden test, which tolerates the additive fields).
#[must_use]
pub fn assemble_status_with_profile(
    pids_raw: &str,
    stats_raw: &str,
    config_raw: &str,
    profile: Option<&str>,
) -> Value {
    let pids = parse_pids(pids_raw);
    let stats = parse_stats(stats_raw);
    let mode_val = parse_mode(config_raw).unwrap_or(crate::audit::MODE_ENFORCE);
    let mode = mode_label(mode_val);

    let clock = SystemClock;
    let ttl_remaining_s: Value = read_state()
        .and_then(|s| ttl_remaining(&s, &clock))
        .map_or(Value::Null, |secs| Value::Number(serde_json::Number::from(secs)));

    let mut out = json!({
        "loaded": true,
        "mode": mode,
        "protected_pids": pids,
        "stats": stats,
        "ttl_remaining_s": ttl_remaining_s,
    });
    if let Some(p) = profile {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("profile".to_owned(), Value::String(p.to_owned()));
        }
    }
    out
}

/// Parse the PIDs map dump into a sorted list of integers.
fn parse_pids(raw: &str) -> Vec<Value> {
    if raw.is_empty() {
        return vec![];
    }
    let entries: Vec<Value> = serde_json::from_str(raw).unwrap_or_default();
    let mut pids: Vec<i64> = entries
        .iter()
        .filter_map(|e| {
            e.get("formatted")
                .and_then(|f| f.get("key"))
                .and_then(Value::as_i64)
        })
        .collect();
    pids.sort_unstable();
    pids.into_iter().map(Value::from).collect()
}

/// Parse the stats map dump. Returns a JSON object with keys:
/// `checked`, `allowed`, `denied`, `forked_in`.
fn parse_stats(raw: &str) -> Value {
    let labels = ["checked", "allowed", "denied", "forked_in"];
    let mut stats = serde_json::Map::new();

    if raw.is_empty() {
        return Value::Object(stats);
    }
    let entries: Vec<Value> = serde_json::from_str(raw).unwrap_or_default();
    for entry in &entries {
        if let Some(fmt) = entry.get("formatted") {
            let k = fmt.get("key").and_then(Value::as_u64);
            let v = fmt.get("value").cloned();
            if let (Some(idx), Some(val)) = (k, v) {
                let idx_usize = usize::try_from(idx).unwrap_or(usize::MAX);
                if let Some(&label) = labels.get(idx_usize) {
                    stats.insert(label.to_owned(), val);
                }
            }
        }
    }
    Value::Object(stats)
}

/// Print the status JSON to stdout.
///
/// # Errors
/// Returns an error if serialization fails (should never happen in practice).
pub fn cmd_status(ops: &dyn BpfOps) -> Result<()> {
    if !ops.is_loaded() {
        println!("{}", json!({"loaded": false}));
        return Ok(());
    }
    let pids_raw = ops.map_dump_json(PINNED_MAP_PIDS);
    let stats_raw = ops.map_dump_json(PINNED_MAP_STATS);
    let config_raw = ops.map_dump_json(PINNED_MAP_CONFIG);
    let status = assemble_status(&pids_raw, &stats_raw, &config_raw);
    // Python uses json.dumps(out, indent=2)
    let pretty = serde_json::to_string_pretty(&status)?;
    println!("{pretty}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pids_sorted_ascending() {
        let pids_raw = r#"[
            {"formatted": {"key": 500, "value": 1}},
            {"formatted": {"key": 100, "value": 1}},
            {"formatted": {"key": 300, "value": 1}}
        ]"#;
        let stats_raw = r#"[
            {"formatted": {"key": 0, "value": 42}},
            {"formatted": {"key": 1, "value": 40}},
            {"formatted": {"key": 2, "value": 2}},
            {"formatted": {"key": 3, "value": 5}}
        ]"#;
        let out = assemble_status(pids_raw, stats_raw, "");
        let pids = out["protected_pids"].as_array().expect("protected_pids");
        assert_eq!(pids.len(), 3);
        assert_eq!(pids[0].as_i64(), Some(100));
        assert_eq!(pids[1].as_i64(), Some(300));
        assert_eq!(pids[2].as_i64(), Some(500));
    }

    #[test]
    fn test_stats_keys() {
        let pids_raw = "[]";
        let stats_raw = r#"[
            {"formatted": {"key": 0, "value": 10}},
            {"formatted": {"key": 1, "value": 8}},
            {"formatted": {"key": 2, "value": 2}},
            {"formatted": {"key": 3, "value": 1}}
        ]"#;
        let out = assemble_status(pids_raw, stats_raw, "");
        assert_eq!(out["stats"]["checked"].as_i64(), Some(10));
        assert_eq!(out["stats"]["allowed"].as_i64(), Some(8));
        assert_eq!(out["stats"]["denied"].as_i64(), Some(2));
        assert_eq!(out["stats"]["forked_in"].as_i64(), Some(1));
    }

    #[test]
    fn test_empty_raw_gives_empty_maps() {
        let out = assemble_status("", "", "");
        assert_eq!(out["loaded"], json!(true));
        assert_eq!(out["protected_pids"].as_array().map(Vec::len), Some(0));
    }

    /// AC7 (policy): assemble_status (no profile arg) does NOT include a
    /// "profile" field — back-compat with warden-home golden test.
    #[test]
    fn test_ac7_backcompat_no_profile_field() {
        let out = assemble_status("[]", "[]", "");
        assert!(out.get("profile").is_none(), "profile field absent in back-compat output");
    }

    /// AC7 (policy): assemble_status_with_profile adds the "profile" field when Some.
    #[test]
    fn test_ac7_with_profile_field_present() {
        let out = assemble_status_with_profile("[]", "[]", "", Some("workspace"));
        assert_eq!(out["profile"], "workspace");
    }

    /// assemble_status_with_profile(None) matches assemble_status output.
    #[test]
    fn test_with_profile_none_matches_base() {
        let base = assemble_status("[]", "[]", "");
        let extended = assemble_status_with_profile("[]", "[]", "", None);
        assert_eq!(base, extended);
    }

    #[test]
    fn test_mode_enforce_default() {
        // When config_raw is empty (no map data), mode defaults to "enforce".
        let out = assemble_status("[]", "[]", "");
        assert_eq!(out["mode"].as_str(), Some("enforce"));
    }

    #[test]
    fn test_mode_audit_from_config_map() {
        let config_raw = r#"[{"formatted": {"key": 0, "value": 1}}]"#;
        let out = assemble_status("[]", "[]", config_raw);
        assert_eq!(out["mode"].as_str(), Some("audit"));
    }

    #[test]
    fn test_mode_enforce_from_config_map() {
        let config_raw = r#"[{"formatted": {"key": 0, "value": 0}}]"#;
        let out = assemble_status("[]", "[]", config_raw);
        assert_eq!(out["mode"].as_str(), Some("enforce"));
    }
}
