//! AC4: enforce/release translate a PID to the same little-endian u32 key bytes
//! the Python pid_to_key_bytes produces.
//!
//! Python reference:
//!   def pid_to_key_bytes(pid):
//!       return ["%d" % b for b in struct.pack("<I", pid)]

use bpolicy::pids::pid_to_key_bytes;

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
    // 1000 = 0x000003E8 → LE bytes: E8 03 00 00 → "232" "3" "0" "0"
    assert_eq!(pid_to_key_bytes(1000), vec!["232", "3", "0", "0"]);
}

#[test]
fn test_pid_65535() {
    // 65535 = 0x0000FFFF → LE: FF FF 00 00 → "255" "255" "0" "0"
    assert_eq!(pid_to_key_bytes(65535), vec!["255", "255", "0", "0"]);
}

#[test]
fn test_pid_4194304() {
    // 4194304 = 0x00400000 → LE: 00 00 40 00 → "0" "0" "64" "0"
    assert_eq!(pid_to_key_bytes(4_194_304), vec!["0", "0", "64", "0"]);
}

#[test]
fn test_pid_max() {
    // u32::MAX = 0xFFFFFFFF → LE: FF FF FF FF → "255" "255" "255" "255"
    assert_eq!(pid_to_key_bytes(u32::MAX), vec!["255", "255", "255", "255"]);
}
