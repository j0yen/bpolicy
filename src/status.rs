//! Status JSON assembly — back-compat with the Python bpolicy status output.
//!
//! Python reference output (loaded case):
//! ```json
//! {
//!   "loaded": true,
//!   "protected_pids": [...sorted ascending...],
//!   "stats": {
//!     "checked": N,
//!     "allowed": N,
//!     "denied": N,
//!     "forked_in": N
//!   }
//! }
//! ```
//!
//! Unloaded: `{"loaded": false}`.

#![allow(clippy::print_stdout)] // CLI: stdout is intentional

use anyhow::Result;
use serde_json::{json, Value};

use crate::bpf::{BpfOps, PINNED_MAP_PIDS, PINNED_MAP_STATS};

/// Assemble the status JSON from raw `bpftool -j map dump` output strings.
///
/// `pids_raw` and `stats_raw` are the stdout of `bpftool -j map dump pinned …`.
/// An empty string or invalid JSON is treated as an empty map.
#[must_use]
pub fn assemble_status(pids_raw: &str, stats_raw: &str) -> Value {
    let pids = parse_pids(pids_raw);
    let stats = parse_stats(stats_raw);
    json!({
        "loaded": true,
        "protected_pids": pids,
        "stats": stats,
    })
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
    let status = assemble_status(&pids_raw, &stats_raw);
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
        let out = assemble_status(pids_raw, stats_raw);
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
        let out = assemble_status(pids_raw, stats_raw);
        assert_eq!(out["stats"]["checked"].as_i64(), Some(10));
        assert_eq!(out["stats"]["allowed"].as_i64(), Some(8));
        assert_eq!(out["stats"]["denied"].as_i64(), Some(2));
        assert_eq!(out["stats"]["forked_in"].as_i64(), Some(1));
    }

    #[test]
    fn test_empty_raw_gives_empty_maps() {
        let out = assemble_status("", "");
        assert_eq!(out["loaded"], json!(true));
        assert_eq!(out["protected_pids"].as_array().map(Vec::len), Some(0));
    }
}
