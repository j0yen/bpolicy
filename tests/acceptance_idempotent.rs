//! AC5: load and unload are idempotent.
//!
//! Second load when already loaded → {"already_loaded": true}
//! Second unload when not loaded → {"already_unloaded": true}
//! Tested against a mock that toggles the pin-exists check.

use anyhow::Result;
use bpolicy::bpf::{BpfOps, cmd_load, cmd_unload};
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
    fn is_loaded(&self) -> bool { self.loaded.get() }

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

    fn map_update(&self, _: &str, _: &[String]) -> Result<()> { Ok(()) }
    fn map_delete(&self, _: &str, _: &[String]) -> Result<()> { Ok(()) }
    fn map_dump_json(&self, _: &str) -> String { String::new() }
    fn tail_trace_pipe(&self, _: usize) -> Result<()> { Ok(()) }
}

#[test]
fn test_load_idempotent() {
    // Start: already loaded
    let mock = TogglingMock::new(true);
    // First load call: already loaded, should NOT call load_prog
    cmd_load(&mock).expect("cmd_load 1");
    assert_eq!(mock.load_called.get(), 0, "load_prog should not be called when already loaded");

    // Second load call: still already loaded
    cmd_load(&mock).expect("cmd_load 2");
    assert_eq!(mock.load_called.get(), 0, "load_prog should still not be called");
}

#[test]
fn test_unload_idempotent() {
    // Start: not loaded
    let mock = TogglingMock::new(false);
    // Unload when not loaded: should NOT call unload_prog
    cmd_unload(&mock).expect("cmd_unload 1");
    assert_eq!(mock.unload_called.get(), 0, "unload_prog should not be called when not loaded");

    // Second unload: still not loaded
    cmd_unload(&mock).expect("cmd_unload 2");
    assert_eq!(mock.unload_called.get(), 0, "unload_prog should still not be called");
}

#[test]
fn test_load_then_unload() {
    // Start: not loaded, perform load then unload
    let mock = TogglingMock::new(false);
    cmd_load(&mock).expect("load");
    assert!(mock.loaded.get(), "should be loaded after cmd_load");
    assert_eq!(mock.load_called.get(), 1);

    cmd_unload(&mock).expect("unload");
    assert!(!mock.loaded.get(), "should not be loaded after cmd_unload");
    assert_eq!(mock.unload_called.get(), 1);
}
