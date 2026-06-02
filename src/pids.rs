//! PID → little-endian u32 key bytes, matching the Python `pid_to_key_bytes`.
//!
//! The Python implementation:
//! ```python
//! def pid_to_key_bytes(pid):
//!     return ["%d" % b for b in struct.pack("<I", pid)]
//! ```
//! This returns a `Vec<String>` of decimal-formatted bytes, e.g. PID 1000
//! → `["232", "3", "0", "0"]`.

/// Convert a PID to the list of decimal-string bytes that `bpftool map update key …` expects.
///
/// Matches the Python `pid_to_key_bytes` exactly.
#[must_use]
pub fn pid_to_key_bytes(pid: u32) -> Vec<String> {
    pid.to_le_bytes()
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_zero() {
        assert_eq!(pid_to_key_bytes(0), vec!["0", "0", "0", "0"]);
    }

    #[test]
    fn test_pid_one() {
        assert_eq!(pid_to_key_bytes(1), vec!["1", "0", "0", "0"]);
    }

    #[test]
    fn test_pid_1000() {
        // 1000 = 0x000003E8 → LE bytes: E8 03 00 00 → 232 3 0 0
        assert_eq!(pid_to_key_bytes(1000), vec!["232", "3", "0", "0"]);
    }

    #[test]
    fn test_pid_65535() {
        // 65535 = 0x0000FFFF → LE bytes: FF FF 00 00 → 255 255 0 0
        assert_eq!(pid_to_key_bytes(65_535), vec!["255", "255", "0", "0"]);
    }

    #[test]
    fn test_pid_4194304() {
        // 4194304 = 0x00400000 → LE bytes: 00 00 40 00 → 0 0 64 0
        assert_eq!(pid_to_key_bytes(4_194_304), vec!["0", "0", "64", "0"]);
    }
}
