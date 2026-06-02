//! Deadman timer — arm a `systemd-run --user` watchdog that auto-unloads
//! the enforcer if the arm is not renewed within a TTL.
//!
//! ## State file
//! `~/.config/bpolicy/deadman.json`:
//! ```json
//! {
//!   "loaded_at":   <unix-secs>,
//!   "ttl_secs":    <u64 or null for permanent>,
//!   "expires_at":  <unix-secs or null for permanent>,
//!   "pid_of_arm":  <u32>
//! }
//! ```
//!
//! ## Watchdog unit
//! A transient `systemd-run --user --on-active=<secs>` one-shot unit whose
//! `ExecStart` is `bpolicy unload`.  The unit name is deterministic:
//! `bpolicy-deadman.service`.  On `renew`, we stop the old unit and rearm.
//! On `unload`, we stop the unit and remove the state file.
//!
//! ## Clock injection
//! All functions that deal with time accept a `Clock` impl so tests never
//! call `sleep` or depend on wall time.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default TTL for a bare `bpolicy load` (30 minutes).
pub const DEFAULT_TTL_SECS: u64 = 30 * 60;
/// Permanent arm sentinel: TTL = 0 means no expiry.
pub const TTL_PERMANENT: u64 = 0;
/// Name of the transient systemd unit used as the watchdog.
pub const WATCHDOG_UNIT: &str = "bpolicy-deadman.service";

/// Persisted state for the deadman timer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadmanState {
    /// Unix timestamp (seconds) when the enforcer was loaded.
    pub loaded_at: u64,
    /// TTL in seconds; `None` means permanent (no auto-unload).
    pub ttl_secs: Option<u64>,
    /// Unix timestamp (seconds) when the watchdog fires; `None` if permanent.
    pub expires_at: Option<u64>,
    /// PID of the process that armed the enforcer.
    pub pid_of_arm: u32,
}

/// Abstraction over wall-clock operations, injectable for testing.
pub trait Clock: Send + Sync {
    /// Return current Unix time in seconds.
    fn now_secs(&self) -> u64;
}

/// Production clock using `std::time::SystemTime`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Abstraction over the `systemd-run` invocation, injectable for testing.
pub trait Watchdog: Send + Sync {
    /// Arm (or re-arm) the watchdog to fire after `ttl_secs` seconds.
    /// Must cancel any existing `WATCHDOG_UNIT` first (idempotent re-arm).
    ///
    /// # Errors
    /// Returns an error if systemd-run fails to spawn.
    fn arm(&self, ttl_secs: u64) -> Result<()>;

    /// Cancel the watchdog unit if running (idempotent).
    ///
    /// # Errors
    /// Returns an error if systemctl cannot be spawned.
    fn cancel(&self) -> Result<()>;
}

/// Production watchdog using `systemd-run --user`.
pub struct SystemdWatchdog;

impl Watchdog for SystemdWatchdog {
    fn arm(&self, ttl_secs: u64) -> Result<()> {
        // Cancel any running instance first (idempotent).
        self.cancel()?;
        // systemd-run --user --on-active=<N> --unit=bpolicy-deadman -- bpolicy unload
        let on_active = format!("{ttl_secs}s");
        let status = Command::new("systemd-run")
            .args([
                "--user",
                "--on-active",
                &on_active,
                &format!("--unit={WATCHDOG_UNIT}"),
                "--",
                "bpolicy",
                "unload",
            ])
            .status()
            .context("systemd-run --user")?;
        if !status.success() {
            bail!("systemd-run failed to arm watchdog (ttl={ttl_secs}s)");
        }
        Ok(())
    }

    fn cancel(&self) -> Result<()> {
        // Best-effort; if the unit doesn't exist, systemctl returns error which we ignore.
        let _ = Command::new("systemctl")
            .args(["--user", "stop", WATCHDOG_UNIT])
            .status();
        Ok(())
    }
}

/// Return the path of the deadman state file.
///
/// Respects `BPOLICY_STATE_DIR` env var for testing; falls back to
/// `~/.config/bpolicy/deadman.json`.
#[must_use]
pub fn state_path() -> PathBuf {
    std::env::var("BPOLICY_STATE_DIR").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
            PathBuf::from(home)
                .join(".config")
                .join("bpolicy")
                .join("deadman.json")
        },
        |dir| PathBuf::from(dir).join("deadman.json"),
    )
}

/// Read a `DeadmanState` from the given path.  Returns `None` if absent or unreadable.
#[must_use]
pub fn read_state_from(path: &Path) -> Option<DeadmanState> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Read the current state file using the default path.  Returns `None` if absent.
#[must_use]
pub fn read_state() -> Option<DeadmanState> {
    read_state_from(&state_path())
}

/// Write (atomically via a temp file + rename) the deadman state to the given path.
///
/// # Errors
/// Returns an error if writing fails.
pub fn write_state_to(path: &Path, s: &DeadmanState) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("create bpolicy config dir")?;
    }
    let json = serde_json::to_string_pretty(s).context("serialize deadman state")?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json).context("write deadman state tmp")?;
    std::fs::rename(&tmp, path).context("rename deadman state")?;
    Ok(())
}

/// Write the deadman state to the default path.
///
/// # Errors
/// Returns an error if writing fails.
pub fn write_state(s: &DeadmanState) -> Result<()> {
    write_state_to(&state_path(), s)
}

/// Remove the deadman state file at the given path (idempotent).
///
/// # Errors
/// Returns an error only if removal fails for a reason other than `ENOENT`.
pub fn remove_state_at(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove deadman state"),
    }
}

/// Remove the deadman state file at the default path (idempotent).
///
/// # Errors
/// Returns an error only if removal fails for a reason other than `ENOENT`.
pub fn remove_state() -> Result<()> {
    remove_state_at(&state_path())
}

/// Arm the deadman timer after loading the enforcer.
///
/// * `ttl_secs = 0` → permanent arm (no watchdog, no state file expiry).
/// * `ttl_secs > 0` → sets `expires_at = now + ttl_secs` and arms the watchdog.
///
/// The state is written to `state_file` (pass `&state_path()` for production).
///
/// # Errors
/// Returns an error if writing the state file or arming the watchdog fails.
pub fn arm_to(
    ttl_secs: u64,
    state_file: &Path,
    clock: &dyn Clock,
    watchdog: &dyn Watchdog,
) -> Result<()> {
    let now = clock.now_secs();
    let pid = std::process::id();

    let (ttl_opt, expires_opt) = if ttl_secs == TTL_PERMANENT {
        (None, None)
    } else {
        (Some(ttl_secs), Some(now.saturating_add(ttl_secs)))
    };

    let state = DeadmanState {
        loaded_at: now,
        ttl_secs: ttl_opt,
        expires_at: expires_opt,
        pid_of_arm: pid,
    };
    write_state_to(state_file, &state)?;

    if ttl_secs != TTL_PERMANENT {
        watchdog.arm(ttl_secs)?;
    }
    Ok(())
}

/// Arm the deadman timer using the default state path.
///
/// # Errors
/// Returns an error if writing the state file or arming the watchdog fails.
pub fn arm(ttl_secs: u64, clock: &dyn Clock, watchdog: &dyn Watchdog) -> Result<()> {
    arm_to(ttl_secs, &state_path(), clock, watchdog)
}

/// Renew the deadman timer, pushing `expires_at` forward.
///
/// If `new_ttl_secs` is `None` (or `Some(0)`), reuses the TTL already stored.
/// Pass `Some(n)` with `n > 0` to change the TTL.
///
/// Reads/writes state at `state_file`.
///
/// # Errors
/// Returns an error if no state exists, or if writing or re-arming fails.
pub fn renew_at(
    new_ttl_secs: Option<u64>,
    state_file: &Path,
    clock: &dyn Clock,
    watchdog: &dyn Watchdog,
) -> Result<()> {
    let mut state =
        read_state_from(state_file).context("no deadman state — enforcer not loaded")?;

    let ttl = match new_ttl_secs {
        Some(t) if t > 0 => t,
        _ => state.ttl_secs.unwrap_or(DEFAULT_TTL_SECS),
    };

    if ttl == TTL_PERMANENT {
        // Already permanent; nothing to update.
        return Ok(());
    }

    let now = clock.now_secs();
    state.ttl_secs = Some(ttl);
    state.expires_at = Some(now.saturating_add(ttl));
    write_state_to(state_file, &state)?;
    watchdog.arm(ttl)?;
    Ok(())
}

/// Renew using the default state path.
///
/// # Errors
/// Returns an error if the state file is missing or renewal fails.
pub fn renew(new_ttl_secs: Option<u64>, clock: &dyn Clock, watchdog: &dyn Watchdog) -> Result<()> {
    renew_at(new_ttl_secs, &state_path(), clock, watchdog)
}

/// Disarm the deadman timer (called from `bpolicy unload`).
///
/// Cancels the watchdog unit and removes the state file. Idempotent.
///
/// # Errors
/// Returns an error if watchdog cancel or state removal fails.
pub fn disarm_at(state_file: &Path, watchdog: &dyn Watchdog) -> Result<()> {
    watchdog.cancel()?;
    remove_state_at(state_file)?;
    Ok(())
}

/// Disarm using the default state path.
///
/// # Errors
/// Returns an error if watchdog cancel or state removal fails.
pub fn disarm(watchdog: &dyn Watchdog) -> Result<()> {
    disarm_at(&state_path(), watchdog)
}

/// Return the number of seconds remaining until expiry, or `None` if permanent.
///
/// Returns `Some(0)` if already expired.
#[must_use]
pub fn ttl_remaining(state: &DeadmanState, clock: &dyn Clock) -> Option<u64> {
    let expires = state.expires_at?;
    let now = clock.now_secs();
    Some(expires.saturating_sub(now))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fake clock with a fixed "now" value.
    struct FakeClock(u64);
    impl Clock for FakeClock {
        fn now_secs(&self) -> u64 {
            self.0
        }
    }

    /// Fake watchdog that records calls.
    #[derive(Default)]
    struct FakeWatchdog {
        arms: std::sync::Mutex<Vec<u64>>,
        cancels: std::sync::Mutex<u32>,
    }
    impl Watchdog for FakeWatchdog {
        fn arm(&self, ttl_secs: u64) -> Result<()> {
            // Production arm() calls cancel() first; mirror that here.
            *self.cancels.lock().unwrap() += 1;
            self.arms.lock().unwrap().push(ttl_secs);
            Ok(())
        }
        fn cancel(&self) -> Result<()> {
            *self.cancels.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[test]
    fn test_arm_with_ttl() {
        let dir = std::env::temp_dir().join("bpolicy-test-arm-ttl");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");
        let clock = FakeClock(1_000_000);
        let wd = FakeWatchdog::default();

        arm_to(900, &sf, &clock, &wd).expect("arm");

        let state = read_state_from(&sf).expect("state written");
        assert_eq!(state.loaded_at, 1_000_000);
        assert_eq!(state.ttl_secs, Some(900));
        assert_eq!(state.expires_at, Some(1_000_900));
        assert_eq!(wd.arms.lock().unwrap().as_slice(), &[900u64]);
    }

    #[test]
    fn test_arm_permanent() {
        let dir = std::env::temp_dir().join("bpolicy-test-arm-perm");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");
        let clock = FakeClock(2_000_000);
        let wd = FakeWatchdog::default();

        arm_to(TTL_PERMANENT, &sf, &clock, &wd).expect("arm permanent");

        let state = read_state_from(&sf).expect("state written");
        assert_eq!(state.ttl_secs, None);
        assert_eq!(state.expires_at, None);
        // No arm() call for permanent
        assert!(wd.arms.lock().unwrap().is_empty());
    }

    #[test]
    fn test_renew_updates_expiry() {
        let dir = std::env::temp_dir().join("bpolicy-test-renew");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");

        // Initial arm at t=1000
        let clock1 = FakeClock(1_000);
        let wd = FakeWatchdog::default();
        arm_to(600, &sf, &clock1, &wd).expect("arm");

        // Renew at t=1300 with a new TTL of 300
        let clock2 = FakeClock(1_300);
        renew_at(Some(300), &sf, &clock2, &wd).expect("renew");

        let state = read_state_from(&sf).expect("state after renew");
        assert_eq!(state.ttl_secs, Some(300));
        assert_eq!(state.expires_at, Some(1_600));
    }

    #[test]
    fn test_renew_twice_leaves_separate_arm_calls() {
        let dir = std::env::temp_dir().join("bpolicy-test-renew2");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");

        let clock = FakeClock(1_000);
        let wd = FakeWatchdog::default();
        arm_to(600, &sf, &clock, &wd).expect("arm");

        renew_at(None, &sf, &clock, &wd).expect("renew 1");
        renew_at(None, &sf, &clock, &wd).expect("renew 2");

        // arm_to: 1 arm call; each renew: 1 arm call each = 3 total
        let arms = wd.arms.lock().unwrap();
        assert_eq!(arms.len(), 3, "initial arm + 2 renews = 3 arm calls");
    }

    #[test]
    fn test_disarm_removes_state() {
        let dir = std::env::temp_dir().join("bpolicy-test-disarm");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");

        let clock = FakeClock(1_000);
        let wd = FakeWatchdog::default();
        arm_to(600, &sf, &clock, &wd).expect("arm");
        assert!(read_state_from(&sf).is_some());

        disarm_at(&sf, &wd).expect("disarm");
        assert!(read_state_from(&sf).is_none());
    }

    #[test]
    fn test_disarm_idempotent() {
        let dir = std::env::temp_dir().join("bpolicy-test-disarm2");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sf = dir.join("deadman.json");
        let wd = FakeWatchdog::default();
        // Disarm without ever arming — should not error
        disarm_at(&sf, &wd).expect("disarm idempotent");
    }

    #[test]
    fn test_ttl_remaining_counts_down() {
        let state = DeadmanState {
            loaded_at: 1000,
            ttl_secs: Some(600),
            expires_at: Some(1600),
            pid_of_arm: 42,
        };
        let clock = FakeClock(1_200);
        assert_eq!(ttl_remaining(&state, &clock), Some(400));
    }

    #[test]
    fn test_ttl_remaining_expired() {
        let state = DeadmanState {
            loaded_at: 1000,
            ttl_secs: Some(60),
            expires_at: Some(1060),
            pid_of_arm: 42,
        };
        let clock = FakeClock(2_000);
        assert_eq!(ttl_remaining(&state, &clock), Some(0));
    }

    #[test]
    fn test_ttl_remaining_permanent() {
        let state = DeadmanState {
            loaded_at: 1000,
            ttl_secs: None,
            expires_at: None,
            pid_of_arm: 42,
        };
        let clock = FakeClock(9_999_999);
        assert_eq!(ttl_remaining(&state, &clock), None);
    }

    #[test]
    fn test_state_json_round_trip() {
        let state = DeadmanState {
            loaded_at: 1_234_567,
            ttl_secs: Some(1800),
            expires_at: Some(1_236_367),
            pid_of_arm: 9999,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let back: DeadmanState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, back);
    }
}
