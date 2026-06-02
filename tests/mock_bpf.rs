//! Shared mock BpfOps implementation for integration tests.
//!
//! Tests import this via `mod mock_bpf;` to get a `MockBpf` that never
//! invokes sudo or bpftool.

#![allow(dead_code)]

use anyhow::Result;
use bpolicy::bpf::BpfOps;
use std::cell::Cell;

/// Mock BpfOps that tracks calls and returns configurable canned data.
pub struct MockBpf {
    /// Whether `is_loaded()` returns true.
    pub loaded: Cell<bool>,
    /// Raw JSON returned by `map_dump_json(PINNED_MAP_PIDS)`.
    pub pids_json: String,
    /// Raw JSON returned by `map_dump_json(PINNED_MAP_STATS)`.
    pub stats_json: String,
    /// Tracks whether `load_prog` was called.
    pub load_called: Cell<bool>,
    /// Tracks whether `unload_prog` was called.
    pub unload_called: Cell<bool>,
    /// Accumulated map_update key_bytes calls.
    pub updated_keys: std::cell::RefCell<Vec<Vec<String>>>,
    /// Accumulated map_delete key_bytes calls.
    pub deleted_keys: std::cell::RefCell<Vec<Vec<String>>>,
}

impl MockBpf {
    /// Construct with loaded=false and empty maps.
    pub fn not_loaded() -> Self {
        Self {
            loaded: Cell::new(false),
            pids_json: String::new(),
            stats_json: String::new(),
            load_called: Cell::new(false),
            unload_called: Cell::new(false),
            updated_keys: std::cell::RefCell::new(Vec::new()),
            deleted_keys: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Construct with loaded=true and provided canned JSON.
    pub fn loaded_with(pids_json: impl Into<String>, stats_json: impl Into<String>) -> Self {
        Self {
            loaded: Cell::new(true),
            pids_json: pids_json.into(),
            stats_json: stats_json.into(),
            load_called: Cell::new(false),
            unload_called: Cell::new(false),
            updated_keys: std::cell::RefCell::new(Vec::new()),
            deleted_keys: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl BpfOps for MockBpf {
    fn is_loaded(&self) -> bool {
        self.loaded.get()
    }

    fn load_prog(&self, _obj_path: &str, _bpf_root: &str) -> Result<()> {
        self.load_called.set(true);
        self.loaded.set(true);
        Ok(())
    }

    fn unload_prog(&self, _bpf_root: &str) -> Result<()> {
        self.unload_called.set(true);
        self.loaded.set(false);
        Ok(())
    }

    fn map_update(&self, _pinned: &str, key_bytes: &[String]) -> Result<()> {
        self.updated_keys.borrow_mut().push(key_bytes.to_vec());
        Ok(())
    }

    fn map_delete(&self, _pinned: &str, key_bytes: &[String]) -> Result<()> {
        self.deleted_keys.borrow_mut().push(key_bytes.to_vec());
        Ok(())
    }

    fn map_dump_json(&self, pinned: &str) -> String {
        if pinned.contains("protected_pids") {
            self.pids_json.clone()
        } else {
            self.stats_json.clone()
        }
    }

    fn tail_trace_pipe(&self, _n: usize) -> Result<()> {
        Ok(())
    }

    fn allowlist_add_prefix(&self, _pinned: &str, _prefix: &str) -> Result<()> {
        Ok(())
    }
}
