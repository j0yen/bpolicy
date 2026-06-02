//! AC5: load and unload are idempotent.
//!
//! Second load when already loaded → {"already_loaded": true}
//! Second unload when not loaded → {"already_unloaded": true}
//! Tested against a mock that toggles the pin-exists check.

use anyhow::Result;
use bpolicy::bpf::{cmd_load, cmd_unload, BpfOps, LoadOpts};
use bpolicy::deadman::{Clock, Watchdog};
use std::cell::Cell;

/// Mock that tracks load/unload state.
struct TogglingMock {
    loaded: Cell<bool>,
    load_called: Cell<u32>,
    unload_called: Cell<u32>,
}

impl TogglingMock {
    fn new(initially_loaded: bool) -> Self {
        Self {
            loaded: Cell::new(initially_loaded),
            load_called: Cell::new(0),
            unload_called: Cell::new(0),
        }
    }
}

impl BpfOps for TogglingMock {
    fn is_loaded(&self) -> bool {
        self.loaded.get()
    }

    fn load_prog(&self, _obj: &str, _root: &str) -> Result<()> {
        self.load_called.set(self.load_called.get() + 1);
        self.loaded.set(true);
        Ok(())
    }

    fn unload_prog(&self, _root: &str) -> Result<()> {
        self.unload_called.set(self.unload_called.get() + 1);
        self.loaded.set(false);
        Ok(())
    }

    fn map_update(&self, _: &str, _: &[String]) -> Result<()> {
        Ok(())
    }
    fn map_update_kv(&self, _: &str, _: &[String], _: &[String]) -> Result<()> {
        Ok(())
    }
    fn map_delete(&self, _: &str, _: &[String]) -> Result<()> {
        Ok(())
    }
    fn map_dump_json(&self, _: &str) -> String {
        String::new()
    }
    fn tail_trace_pipe(&self, _: usize) -> Result<()> {
        Ok(())
    }
    fn allowlist_add_prefix(&self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
}

/// Fake clock for test injection.
struct FakeClock(u64);
impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

/// Fake watchdog that accepts arm/cancel without spawning systemd.
struct NoopWatchdog;
impl Watchdog for NoopWatchdog {
    fn arm(&self, _ttl_secs: u64) -> Result<()> {
        Ok(())
    }
    fn cancel(&self) -> Result<()> {
        Ok(())
    }
}

/// Build a LoadOpts that uses the fake clock/watchdog and a temp state file.
fn make_opts<'a>(clock: &'a FakeClock, wd: &'a NoopWatchdog) -> LoadOpts<'a> {
    LoadOpts {
        profile_name: None,
        audit: false,
        ttl_secs: bpolicy::deadman::DEFAULT_TTL_SECS,
        assume_yes: true,
        clock,
        watchdog: wd,
    }
}

#[test]
fn test_load_idempotent() {
    let clock = FakeClock(1_000_000);
    let wd = NoopWatchdog;
    let load_opts = make_opts(&clock, &wd);

    // Start: already loaded
    let mock = TogglingMock::new(true);
    // First load call: already loaded, should NOT call load_prog
    cmd_load(&mock, &load_opts).expect("cmd_load 1");
    assert_eq!(
        mock.load_called.get(),
        0,
        "load_prog should not be called when already loaded"
    );

    // Second load call: still already loaded
    cmd_load(&mock, &load_opts).expect("cmd_load 2");
    assert_eq!(
        mock.load_called.get(),
        0,
        "load_prog should still not be called"
    );
}

#[test]
fn test_unload_idempotent() {
    let wd = NoopWatchdog;

    // Start: not loaded
    let mock = TogglingMock::new(false);
    // Unload when not loaded: should NOT call unload_prog
    cmd_unload(&mock, &wd).expect("cmd_unload 1");
    assert_eq!(
        mock.unload_called.get(),
        0,
        "unload_prog should not be called when not loaded"
    );

    // Second unload: still not loaded
    cmd_unload(&mock, &wd).expect("cmd_unload 2");
    assert_eq!(
        mock.unload_called.get(),
        0,
        "unload_prog should still not be called"
    );
}

#[test]
fn test_load_then_unload() {
    let clock = FakeClock(1_000_000);
    let wd = NoopWatchdog;
    let load_opts = make_opts(&clock, &wd);

    // Start: not loaded, perform load then unload
    let mock = TogglingMock::new(false);
    cmd_load(&mock, &load_opts).expect("load");
    assert!(mock.loaded.get(), "should be loaded after cmd_load");
    assert_eq!(mock.load_called.get(), 1);

    cmd_unload(&mock, &wd).expect("unload");
    assert!(!mock.loaded.get(), "should not be loaded after cmd_unload");
    assert_eq!(mock.unload_called.get(), 1);
}
