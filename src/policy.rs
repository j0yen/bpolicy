//! Policy file loader and userspace allow-list evaluator.
//!
//! # Policy file format
//!
//! `~/.config/bpolicy/policy.toml` holds named profiles. Each profile lists
//! additional path prefixes that are allowed for write opens, **on top of**
//! the always-allowed compiled defaults. The defaults cannot be removed by a
//! profile (they are enforced in the BPF hook as well as here).
//!
//! ## Example
//!
//! ```toml
//! [profile.workspace]
//! description = "agent jailed to its wintermute + claude workspace"
//! allow = [
//!   "/home/jsy/wintermute",
//!   "/home/jsy/.claude",
//! ]
//!
//! [profile.tight]
//! description = "tmp + dev only — the compiled default, named"
//! allow = []
//! ```
//!
//! # Prefix matching — BPF/userspace spec
//!
//! Both the BPF hook and this module implement the same rule:
//!
//! 1. Check the path against the **compiled defaults** first.
//! 2. If no match, check against the **profile prefixes** by longest-prefix
//!    match (the most specific prefix that is a prefix of the target path wins).
//! 3. Allow on any hit; deny otherwise.
//!
//! The BPF hook mirrors this spec in `bpf/bpolicy.bpf.c:path_allowed_dynamic`.
//! Any change to the match logic here MUST be reflected there, and vice-versa.
//!
//! Prefix matching rules (identical in BPF and userspace):
//! - A prefix `P` matches path `T` iff `T == P` or `T` starts with `P`
//!   followed by `/`. This prevents `/home/jsy/sec` from matching a profile
//!   that only allows `/home/jsy/s`.

#![allow(clippy::print_stdout)] // CLI: stdout output is intentional for cmd_policy_*

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Compiled defaults ──────────────────────────────────────────────────────

/// Always-allowed path prefixes baked into the BPF hook.
///
/// A profile can only ADD to these; it can never remove them.
///
/// Spec cross-reference: `bpf/bpolicy.bpf.c:path_allowed_defaults`.
/// Any change here MUST be reflected in the BPF C file, and vice-versa.
pub const COMPILED_DEFAULTS: &[&str] = &[
    "/tmp/",
    "/dev/null",
    "/dev/tty",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/pts/",
    "/proc/self/",
];

// ── Data types ─────────────────────────────────────────────────────────────

/// A single named profile from `policy.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    /// Human-readable description of the profile's purpose.
    #[serde(default)]
    pub description: String,

    /// Additional writable path prefixes (on top of compiled defaults).
    #[serde(default)]
    pub allow: Vec<String>,
}

/// The deserialized `policy.toml`.
#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    profile: HashMap<String, Profile>,
}

/// Loaded policy with all profiles available.
#[derive(Debug, Clone)]
pub struct Policy {
    profiles: HashMap<String, Profile>,
    /// Canonical path the policy was loaded from.
    pub source_path: PathBuf,
}

impl Policy {
    /// Return the default policy path: `~/.config/bpolicy/policy.toml`.
    ///
    /// # Errors
    /// Returns an error if `$HOME` is not set.
    pub fn default_path() -> Result<PathBuf> {
        let home =
            std::env::var("HOME").context("$HOME is not set; cannot locate policy.toml")?;
        Ok(PathBuf::from(home).join(".config/bpolicy/policy.toml"))
    }

    /// Load a policy from the given path. Returns `None` if the file does not
    /// exist (not an error — just means no extra profiles are defined).
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load_opt(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy file {}", path.display()))?;
        let pf: PolicyFile = toml::from_str(&contents)
            .with_context(|| format!("parsing policy file {}", path.display()))?;
        Ok(Some(Self {
            profiles: pf.profile,
            source_path: path.to_owned(),
        }))
    }

    /// Load from path, treating a missing file as an empty policy.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load_or_empty(path: &Path) -> Result<Self> {
        Ok(Self::load_opt(path)?.unwrap_or_else(|| Self {
            profiles: HashMap::new(),
            source_path: path.to_owned(),
        }))
    }

    /// List all known profile names (sorted for deterministic output).
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.profiles.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the profile with the given name, or an error listing known ones.
    ///
    /// # Errors
    /// Returns an error if the profile name is unknown.
    pub fn get_profile(&self, name: &str) -> Result<&Profile> {
        self.profiles.get(name).ok_or_else(|| {
            let known = self.profile_names().join(", ");
            let known_msg = if known.is_empty() {
                "(no profiles defined)".to_owned()
            } else {
                format!("known: {known}")
            };
            anyhow::anyhow!("unknown profile '{name}'; {known_msg}")
        })
    }

    /// Return the profile if `name` is `Some`, or `None` (tight/default) if `None`.
    ///
    /// # Errors
    /// Returns an error if the profile name is unknown.
    pub fn resolve_profile(&self, name: Option<&str>) -> Result<Option<&Profile>> {
        match name {
            Some(n) => Ok(Some(self.get_profile(n)?)),
            None => Ok(None),
        }
    }
}

// ── Prefix-match evaluator ─────────────────────────────────────────────────
// Spec cross-reference: bpf/bpolicy.bpf.c:path_allowed_defaults +
//                       bpf/bpolicy.bpf.c:path_allowed_dynamic
//
// A prefix P matches path T iff:
//   T == P  OR  T starts_with P  AND  (T.len()==P.len() OR T[P.len()]=='/').
//
// The BPF side implements the same rule for each entry in the allowlist map.

/// Return `true` if `prefix` is a prefix match of `path` according to the
/// boundary rule described in the module doc.
///
/// Rules:
/// - Exact match: `path == prefix`
/// - Prefix already ends with `/` (directory prefix): `path.starts_with(prefix)`
///   e.g. `/tmp/` matches `/tmp/foo` because `/tmp/` already has the boundary `/`.
/// - Prefix without trailing `/`: require `path[prefix.len()] == '/'`
///   e.g. `/home/jsy` matches `/home/jsy/x` but NOT `/home/jsyevil`.
#[must_use]
pub fn prefix_matches(prefix: &str, path: &str) -> bool {
    if path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        // Prefix already ends with '/': any path that starts with it is a sub-path.
        return path.starts_with(prefix);
    }
    // Prefix without trailing '/': the next char in path must be '/' (directory boundary).
    if let Some(rest) = path.strip_prefix(prefix) {
        return rest.starts_with('/');
    }
    false
}

/// Check whether `path` is allowed under the compiled defaults.
#[must_use]
pub fn is_default_allowed(path: &str) -> bool {
    COMPILED_DEFAULTS.iter().any(|d| prefix_matches(d, path))
}

/// Resolve the longest-matching prefix from `prefixes` for `path`.
/// Returns `Some(prefix)` if any prefix matches, `None` otherwise.
#[must_use]
pub fn longest_prefix_match<'a>(prefixes: &[&'a str], path: &str) -> Option<&'a str> {
    prefixes
        .iter()
        .filter(|&&p| prefix_matches(p, path))
        .max_by_key(|&&p| p.len())
        .copied()
}

/// Full allow check: compiled defaults OR longest-prefix match from profile.
///
/// This is the userspace mirror of the BPF hook decision logic.
/// Spec cross-reference: `bpf/bpolicy.bpf.c:file_open_check` (policy-aware path).
#[must_use]
pub fn is_allowed(path: &str, profile: Option<&Profile>) -> bool {
    if is_default_allowed(path) {
        return true;
    }
    if let Some(p) = profile {
        let refs: Vec<&str> = p.allow.iter().map(String::as_str).collect();
        return longest_prefix_match(&refs, path).is_some();
    }
    false
}

// ── Resolved allow list ────────────────────────────────────────────────────

/// The fully-resolved allow-list for a profile: defaults + profile prefixes.
#[derive(Debug, Serialize)]
pub struct ResolvedAllowList {
    /// Profile name (or `"tight"` for the compiled default).
    pub profile: String,
    /// Always-allowed compiled defaults.
    pub compiled_defaults: Vec<String>,
    /// Profile-specific additional prefixes.
    pub profile_prefixes: Vec<String>,
}

impl ResolvedAllowList {
    /// Build the resolved list for the given profile (or `tight` if `None`).
    #[must_use]
    pub fn build(profile_name: Option<&str>, profile: Option<&Profile>) -> Self {
        Self {
            profile: profile_name.unwrap_or("tight").to_owned(),
            compiled_defaults: COMPILED_DEFAULTS.iter().map(|s| (*s).to_owned()).collect(),
            profile_prefixes: profile
                .map(|p| p.allow.clone())
                .unwrap_or_default(),
        }
    }
}

// ── Command handlers ───────────────────────────────────────────────────────

/// `bpolicy policy show [--profile <name>]`
///
/// # Errors
/// Returns an error if the policy file cannot be parsed or the profile is unknown.
pub fn cmd_policy_show(profile_name: Option<&str>) -> Result<()> {
    let path = Policy::default_path()?;
    let policy = Policy::load_or_empty(&path)?;
    let profile = policy.resolve_profile(profile_name)?;
    let resolved = ResolvedAllowList::build(profile_name, profile);
    let json = serde_json::to_string_pretty(&resolved).context("serializing allow list")?;
    println!("{json}");
    Ok(())
}

/// `bpolicy policy check <path> [--profile <name>]`
///
/// # Errors
/// Returns an error if the policy file cannot be parsed or the profile is unknown.
pub fn cmd_policy_check(path: &str, profile_name: Option<&str>) -> Result<()> {
    let policy_path = Policy::default_path()?;
    let policy = Policy::load_or_empty(&policy_path)?;
    let profile = policy.resolve_profile(profile_name)?;
    let allowed = is_allowed(path, profile);
    let result = serde_json::json!({
        "path": path,
        "profile": profile_name.unwrap_or("tight"),
        "allowed": allowed,
    });
    println!("{}", serde_json::to_string_pretty(&result).context("serializing check result")?);
    Ok(())
}

/// Validate that a profile name exists in the policy.
///
/// # Errors
/// Returns an error if the policy file cannot be parsed or the profile is unknown.
pub fn validate_profile(profile_name: &str) -> Result<()> {
    let path = Policy::default_path()?;
    let policy = Policy::load_or_empty(&path)?;
    policy.get_profile(profile_name)?;
    Ok(())
}

/// Load the allow prefixes for a profile from the default policy path.
///
/// Returns the list of extra prefixes (not including compiled defaults).
///
/// # Errors
/// Returns an error if the policy file cannot be parsed or the profile is unknown.
pub fn load_profile_prefixes(profile_name: &str) -> Result<Vec<String>> {
    let path = Policy::default_path()?;
    let policy = Policy::load_or_empty(&path)?;
    let profile = policy.get_profile(profile_name)?;
    Ok(profile.allow.clone())
}

/// Validate that a path prefix is safe to add to the BPF allowlist.
///
/// # Errors
/// Returns an error if the prefix is empty or not an absolute path.
pub fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        bail!("allow prefix must not be empty");
    }
    if !prefix.starts_with('/') {
        bail!("allow prefix '{prefix}' must be an absolute path (start with '/')");
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── prefix_matches ──────────────────────────────────────────────────────

    #[test]
    fn test_prefix_exact_match() {
        assert!(prefix_matches("/tmp", "/tmp"));
    }

    #[test]
    fn test_prefix_slash_suffix() {
        assert!(prefix_matches("/tmp/", "/tmp/foo"));
        assert!(prefix_matches("/tmp/", "/tmp/a/b/c"));
    }

    #[test]
    fn test_prefix_no_partial_name() {
        // "/home/jsy/s" must NOT match "/home/jsy/sec"
        assert!(!prefix_matches("/home/jsy/s", "/home/jsy/sec"));
    }

    #[test]
    fn test_prefix_directory_boundary() {
        assert!(prefix_matches("/home/jsy/wintermute", "/home/jsy/wintermute/foo"));
        assert!(!prefix_matches("/home/jsy/wintermute", "/home/jsy/wintermute_evil"));
    }

    #[test]
    fn test_prefix_path_separator() {
        // Prefix without trailing slash must match subpaths via '/' boundary
        assert!(prefix_matches("/home/jsy", "/home/jsy/x"));
        assert!(!prefix_matches("/home/jsy", "/home/jsyevil"));
    }

    // ── is_default_allowed ──────────────────────────────────────────────────

    #[test]
    fn test_default_tmp() {
        assert!(is_default_allowed("/tmp/foo"));
        assert!(is_default_allowed("/tmp/nested/path"));
    }

    #[test]
    fn test_default_dev_null() {
        assert!(is_default_allowed("/dev/null"));
    }

    #[test]
    fn test_default_dev_pts() {
        assert!(is_default_allowed("/dev/pts/0"));
    }

    #[test]
    fn test_default_proc_self() {
        assert!(is_default_allowed("/proc/self/fd/1"));
    }

    #[test]
    fn test_default_denied_home() {
        assert!(!is_default_allowed("/home/jsy/wintermute/foo"));
    }

    #[test]
    fn test_default_denied_etc() {
        assert!(!is_default_allowed("/etc/passwd"));
    }

    // ── is_allowed with profile ─────────────────────────────────────────────

    fn workspace_profile() -> Profile {
        Profile {
            description: "test workspace".to_owned(),
            allow: vec![
                "/home/jsy/wintermute".to_owned(),
                "/home/jsy/.claude".to_owned(),
                "/home/jsy/.cache".to_owned(),
                "/home/jsy/.config/bpolicy".to_owned(),
            ],
        }
    }

    /// AC3: bpolicy policy check path --profile workspace
    #[test]
    fn test_ac3_allowed_paths() {
        let p = workspace_profile();

        // Allowed via profile
        assert!(is_allowed("/home/jsy/wintermute/x/y", Some(&p)));
        // Allowed via compiled defaults
        assert!(is_allowed("/tmp/z", Some(&p)));
        assert!(is_allowed("/dev/null", Some(&p)));
    }

    /// AC3: denied paths
    #[test]
    fn test_ac3_denied_paths() {
        let p = workspace_profile();
        assert!(!is_allowed("/home/jsy/Documents/secret", Some(&p)));
        assert!(!is_allowed("/etc/passwd", Some(&p)));
    }

    /// AC3: table-driven with >=8 paths across allow/deny
    #[test]
    fn test_ac3_table_driven() {
        let p = workspace_profile();
        let cases: &[(&str, bool)] = &[
            ("/home/jsy/wintermute/x/y", true),
            ("/tmp/z", true),
            ("/dev/null", true),
            ("/dev/pts/3", true),
            ("/proc/self/fd/1", true),
            ("/home/jsy/.claude/settings.json", true),
            ("/home/jsy/.cache/something", true),
            ("/home/jsy/.config/bpolicy/policy.toml", true),
            ("/home/jsy/Documents/secret", false),
            ("/etc/passwd", false),
            ("/root/.ssh/id_rsa", false),
            ("/home/jsy/wintermute_evil/x", false), // boundary check
        ];
        for &(path, expected) in cases {
            assert_eq!(
                is_allowed(path, Some(&p)),
                expected,
                "path={path} expected={expected}"
            );
        }
    }

    // ── longest_prefix_match ────────────────────────────────────────────────

    /// AC4: overlapping prefixes resolve to the longest match
    #[test]
    fn test_ac4_longest_prefix() {
        let prefixes = &["/home/jsy", "/home/jsy/wintermute", "/home"];
        let matched = longest_prefix_match(prefixes, "/home/jsy/wintermute/foo");
        assert_eq!(matched, Some("/home/jsy/wintermute"));
    }

    #[test]
    fn test_ac4_no_match() {
        let prefixes = &["/home/jsy/wintermute"];
        let matched = longest_prefix_match(prefixes, "/etc/passwd");
        assert!(matched.is_none());
    }

    // ── tight profile (no extra prefixes) ──────────────────────────────────

    #[test]
    fn test_tight_profile_only_defaults() {
        let tight = Profile {
            description: "tight".to_owned(),
            allow: vec![],
        };
        // Only compiled defaults are allowed
        assert!(is_allowed("/tmp/x", Some(&tight)));
        assert!(!is_allowed("/home/jsy/wintermute/x", Some(&tight)));
    }

    // ── validate_prefix ─────────────────────────────────────────────────────

    #[test]
    fn test_validate_prefix_ok() {
        assert!(validate_prefix("/home/jsy").is_ok());
        assert!(validate_prefix("/tmp/").is_ok());
    }

    #[test]
    fn test_validate_prefix_empty() {
        assert!(validate_prefix("").is_err());
    }

    #[test]
    fn test_validate_prefix_relative() {
        assert!(validate_prefix("home/jsy").is_err());
    }

    // ── Policy file loading ─────────────────────────────────────────────────

    #[test]
    fn test_load_policy_from_toml() {
        let toml = r#"
[profile.workspace]
description = "workspace profile"
allow = ["/home/jsy/wintermute", "/home/jsy/.claude"]

[profile.tight]
description = "tmp + dev only"
allow = []
"#;
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let p = tmpdir.path().join("policy.toml");
        std::fs::write(&p, toml).expect("write policy");
        let policy = Policy::load_opt(&p).expect("load_opt").expect("Some");
        let profile = policy.get_profile("workspace").expect("workspace profile");
        assert_eq!(profile.allow.len(), 2);
        assert_eq!(profile.allow[0], "/home/jsy/wintermute");
    }

    /// AC1: unknown profile name errors with listing known profiles
    #[test]
    fn test_ac1_unknown_profile_error() {
        let toml = r#"
[profile.workspace]
allow = ["/home/jsy/wintermute"]
"#;
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let p = tmpdir.path().join("policy.toml");
        std::fs::write(&p, toml).expect("write policy");
        let policy = Policy::load_opt(&p).expect("load_opt").expect("Some");
        let err = policy.get_profile("nonexistent").expect_err("should error");
        let msg = err.to_string();
        assert!(msg.contains("nonexistent"), "error mentions unknown name");
        assert!(msg.contains("workspace"), "error lists known profiles");
    }

    /// AC2: show includes compiled defaults even when profile allow is empty
    #[test]
    fn test_ac2_resolved_list_includes_defaults() {
        let empty_profile = Profile {
            description: "tight".to_owned(),
            allow: vec![],
        };
        let resolved = ResolvedAllowList::build(Some("tight"), Some(&empty_profile));
        assert!(!resolved.compiled_defaults.is_empty(), "defaults present");
        assert!(
            resolved.compiled_defaults.contains(&"/tmp/".to_owned()),
            "/tmp/ in defaults"
        );
        assert!(resolved.profile_prefixes.is_empty(), "empty profile_prefixes");
    }

    /// AC2: show for workspace includes both defaults and workspace prefixes
    #[test]
    fn test_ac2_workspace_show_has_both() {
        let p = workspace_profile();
        let resolved = ResolvedAllowList::build(Some("workspace"), Some(&p));
        assert!(!resolved.compiled_defaults.is_empty());
        assert!(resolved.profile_prefixes.contains(&"/home/jsy/wintermute".to_owned()));
    }
}
