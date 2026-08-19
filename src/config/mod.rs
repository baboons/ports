pub mod bindings;
pub mod curation;
pub mod trust;

use std::path::{Path, PathBuf};

/// The user's home directory.
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        // Falling back to the working directory keeps a broken environment from
        // taking the whole scan down; at worst the cache lands somewhere odd.
        .unwrap_or_else(|| PathBuf::from("."))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => home().join(fallback),
    }
}

/// Hand-editable configuration: what to hide, which domains are bound.
///
/// Deliberately XDG on macOS too, rather than ~/Library/Application Support.
/// These are files people are expected to open and edit, and a developer tool's
/// dotfiles belong where their other dotfiles are.
pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("ports")
}

/// Regenerable state: the scan cache.
pub fn cache_dir() -> PathBuf {
    xdg("XDG_CACHE_HOME", ".cache").join("ports")
}

/// Generated assets we would rather not regenerate: TLS leaf certificates.
pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share").join("ports")
}

/// Write a file atomically.
///
/// Writing to a sibling temp file and renaming means a crash mid-write leaves
/// the previous contents intact instead of a truncated file. The temp name
/// includes the pid so two instances cannot clobber each other's partial write.
pub fn write_atomic(target: &Path, contents: &str) -> std::io::Result<()> {
    let Some(parent) = target.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target has no parent directory",
        ));
    };
    std::fs::create_dir_all(parent)?;

    // Unique per call, not per process: two threads writing at once would
    // otherwise share a temp path, and one would rename it out from under the
    // other mid-write.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ticket = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = target.with_extension(format!("{}.{ticket}.tmp", std::process::id()));
    match std::fs::write(&tmp, contents).and_then(|_| std::fs::rename(&tmp, target)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honours_xdg_overrides() {
        // Serialised implicitly: these are the only tests touching these vars.
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg-config");
        assert_eq!(config_dir(), PathBuf::from("/tmp/xdg-config/ports"));
        std::env::remove_var("XDG_CONFIG_HOME");

        // Unset falls back under the home directory, never to ~/Library.
        assert!(config_dir().ends_with(".config/ports"));
    }

    #[test]
    fn atomic_write_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state.json");

        write_atomic(&target, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"a\":1}");

        // Overwriting replaces cleanly rather than appending or leaving debris.
        write_atomic(&target, "{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"a\":2}");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind");
    }

    #[test]
    fn concurrent_writes_do_not_collide() {
        // Same process, many threads: a temp name keyed only on the pid would
        // have them renaming each other's files away.
        let dir = tempfile::tempdir().unwrap();
        let target = std::sync::Arc::new(dir.path().join("state.json"));

        let handles: Vec<_> = (0..16)
            .map(|index| {
                let target = std::sync::Arc::clone(&target);
                std::thread::spawn(move || write_atomic(&target, &format!("{{\"n\":{index}}}")))
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().expect("every write should succeed");
        }

        // Whoever won, the file is one complete write, never a mixture.
        let contents = std::fs::read_to_string(target.as_path()).unwrap();
        assert!(
            serde_json::from_str::<serde_json::Value>(&contents).is_ok(),
            "left a torn file: {contents}"
        );

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind");
    }

    #[test]
    fn atomic_write_creates_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested/deeper/state.json");
        write_atomic(&target, "ok").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "ok");
    }
}
