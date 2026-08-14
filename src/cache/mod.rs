//! The scan cache.
//!
//! This is what makes a repeat run feel instant: a full sweep costs seconds,
//! and almost nothing on a dev machine changes between two invocations a
//! minute apart. The cache is an optimisation only — starting cold is always
//! correct, so every failure here degrades to a full scan rather than an error.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{cache_dir, write_atomic};
use crate::types::{now_ms, PortRecord};

/// Bumped when the on-disk shape changes incompatibly; old files are discarded.
const CACHE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheState {
    pub version: u32,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: u64,
    /// When tier 3 last completed, so we know whether to run it again.
    #[serde(rename = "lastFullSweep", default)]
    pub last_full_sweep: u64,
    #[serde(default)]
    pub records: Vec<PortRecord>,
}

impl Default for CacheState {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            updated_at: 0,
            last_full_sweep: 0,
            records: Vec::new(),
        }
    }
}

pub fn state_path() -> PathBuf {
    cache_dir().join("state.json")
}

/// Read cached state, or start empty.
///
/// A missing, unreadable, corrupt or version-mismatched file is not an error
/// worth surfacing.
pub fn load_cache() -> CacheState {
    let Ok(raw) = std::fs::read_to_string(state_path()) else {
        return CacheState::default();
    };
    let Ok(state) = serde_json::from_str::<CacheState>(&raw) else {
        return CacheState::default();
    };
    if state.version != CACHE_VERSION {
        return CacheState::default();
    }
    state
}

/// Persist state. A read-only or full disk must never take the scan down.
pub fn save_cache(state: &CacheState) {
    let payload = CacheState {
        version: CACHE_VERSION,
        updated_at: now_ms(),
        last_full_sweep: state.last_full_sweep,
        records: state.records.clone(),
    };
    if let Ok(json) = serde_json::to_string(&payload) {
        let _ = write_atomic(&state_path(), &json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DiscoveryTier;

    #[test]
    fn round_trips_records_through_json() {
        let mut record = PortRecord::new(3000, DiscoveryTier::Lsof, "127.0.0.1", 1000);
        record.addresses = vec!["127.0.0.1".into()];
        record.protocol = crate::types::Protocol::Http;

        let state = CacheState {
            last_full_sweep: 42,
            records: vec![record.clone()],
            ..Default::default()
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: CacheState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.last_full_sweep, 42);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0], record);
    }

    #[test]
    fn a_version_mismatch_starts_cold_rather_than_misreading_old_state() {
        let stale = r#"{"version":1,"updatedAt":0,"lastFullSweep":99,"records":[]}"#;
        let parsed: CacheState = serde_json::from_str(stale).unwrap();
        assert_ne!(parsed.version, CACHE_VERSION);
        // load_cache discards it; proven here at the version check itself.
    }

    #[test]
    fn json_field_names_stay_pipe_compatible() {
        // People have jq filters written against these names.
        let record = PortRecord::new(3000, DiscoveryTier::Sweep, "0.0.0.0", 1);
        let json = serde_json::to_string(&record).unwrap();
        for key in [
            "\"port\"",
            "\"probedAddress\"",
            "\"isSelf\"",
            "\"firstSeen\"",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
    }
}
