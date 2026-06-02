//! Audit-mode helpers — set/get the `config` BPF map's mode field.
//!
//! The `config` BPF array map has a single entry at key 0.  The low byte of
//! its `u64` value encodes the mode:
//!   * `0` → enforce (default, blocks writes)
//!   * `1` → audit   (evaluates and counts, but always returns 0 / allow)
//!
//! Userspace sets the mode *before* the BPF object is attached (via
//! `bpftool map update`) so the kernel program reads the correct value from
//! the first call.  The `BpfOps::map_update` helper is reused; value bytes
//! come from the u64 little-endian encoding of the mode constant.

/// Map mode value for full enforcement (blocks writes).
pub const MODE_ENFORCE: u64 = 0;
/// Map mode value for audit-only (counts but allows writes).
pub const MODE_AUDIT: u64 = 1;

/// Pinned path for the `bpolicy_config` BPF array map.
///
/// The map is named `bpolicy_config` in the BPF object (not `config`) to avoid
/// colliding with the `typedef … config;` present in some kernels' vmlinux.h;
/// bpftool pins maps by their C symbol name, so the pin path must match.
pub const PINNED_MAP_CONFIG: &str = "/sys/fs/bpf/bpolicy/bpolicy_config";

/// Encode a `u64` mode value as the `bpftool map update … key 0 0 0 0 value …`
/// byte sequence.  Both key and value are 4-byte little-endian in this map
/// (key u32 = 0, value u64 treated as 8 bytes).
///
/// Returns `(key_bytes, value_bytes)` as `Vec<String>` slices matching
/// `bpftool`'s hex-or-decimal byte syntax.
#[must_use]
pub fn mode_map_bytes(mode: u64) -> (Vec<String>, Vec<String>) {
    // key = u32(0) in LE
    let key: Vec<String> = 0u32
        .to_le_bytes()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    // value = u64(mode) in LE
    let val: Vec<String> = mode
        .to_le_bytes()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    (key, val)
}

/// Return `"audit"` or `"enforce"` for the mode constant.
#[must_use]
pub const fn mode_label(mode: u64) -> &'static str {
    if mode == MODE_AUDIT { "audit" } else { "enforce" }
}

/// Parse a raw `bpftool -j map dump` output for the config map into the mode
/// value.  Returns `None` if parsing fails (treat as enforce).
#[must_use]
pub fn parse_mode(raw: &str) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    let entries: Vec<serde_json::Value> = serde_json::from_str(raw).ok()?;
    for entry in &entries {
        // bpftool JSON: {"formatted": {"key": 0, "value": N}}
        if let Some(fmt) = entry.get("formatted") {
            let k = fmt.get("key").and_then(serde_json::Value::as_u64);
            let v = fmt.get("value").and_then(serde_json::Value::as_u64);
            if k == Some(0) {
                return v;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_map_bytes_enforce() {
        let (key, val) = mode_map_bytes(MODE_ENFORCE);
        assert_eq!(key, vec!["0", "0", "0", "0"]);
        // u64(0) LE = 8 zero bytes
        assert_eq!(val, vec!["0", "0", "0", "0", "0", "0", "0", "0"]);
    }

    #[test]
    fn test_mode_map_bytes_audit() {
        let (key, val) = mode_map_bytes(MODE_AUDIT);
        assert_eq!(key, vec!["0", "0", "0", "0"]);
        // u64(1) LE = 1 followed by 7 zeros
        assert_eq!(val, vec!["1", "0", "0", "0", "0", "0", "0", "0"]);
    }

    #[test]
    fn test_mode_label() {
        assert_eq!(mode_label(MODE_ENFORCE), "enforce");
        assert_eq!(mode_label(MODE_AUDIT), "audit");
        assert_eq!(mode_label(99), "enforce"); // unknown → enforce
    }

    #[test]
    fn test_parse_mode_audit() {
        let raw = r#"[{"formatted": {"key": 0, "value": 1}}]"#;
        assert_eq!(parse_mode(raw), Some(1));
    }

    #[test]
    fn test_parse_mode_enforce() {
        let raw = r#"[{"formatted": {"key": 0, "value": 0}}]"#;
        assert_eq!(parse_mode(raw), Some(0));
    }

    #[test]
    fn test_parse_mode_empty() {
        assert_eq!(parse_mode(""), None);
    }

    #[test]
    fn test_parse_mode_invalid_json() {
        assert_eq!(parse_mode("not json"), None);
    }
}
