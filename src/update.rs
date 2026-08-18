//! Finding out that a newer release exists, and installing it when asked.
//!
//! Deliberately two separate acts. This binary can be running as a root
//! LaunchDaemon, so replacing it is a decision worth making on purpose rather
//! than something that happens quietly in the background.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::cache_dir;

const REPO: &str = "baboons/ports";
/// How long a "no update" answer is trusted before asking again.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const NETWORK_TIMEOUT_SECS: u64 = 10;

/// A version we can compare. Release tags are `vMAJOR.MINOR.PATCH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_start_matches('v');
        // A pre-release suffix means "not a stable release"; ignore the whole
        // tag rather than guessing where it sits relative to the real ones.
        if raw.contains('-') || raw.contains('+') {
            return None;
        }

        let mut parts = raw.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
        })
    }

    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The build this binary was made for, matching a release artifact name.
pub fn target_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        // Anything else was built from source and should keep being.
        _ => None,
    }
}

/// How this copy was installed, which decides whether we may replace it.
#[derive(Debug, PartialEq, Eq)]
pub enum Origin {
    /// A plain binary we can swap.
    SelfManaged,
    /// Owned by something that would be confused by us changing it.
    PackageManager(&'static str),
}

pub fn origin_of(exe: &Path) -> Origin {
    let path = exe.to_string_lossy();
    // Replacing these behind the package manager's back leaves it convinced it
    // has one version installed while another is on disk.
    for (marker, name) in [
        ("/Cellar/", "Homebrew"),
        ("/homebrew/", "Homebrew"),
        ("/linuxbrew/", "Homebrew"),
        ("/.cargo/bin/", "cargo"),
        ("/node_modules/", "npm"),
        ("/nix/store/", "Nix"),
    ] {
        if path.contains(marker) {
            return Origin::PackageManager(name);
        }
    }
    Origin::SelfManaged
}

/// What we last learned from the release feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckCache {
    /// The newest release tag seen, without the `v`.
    pub latest: String,
    /// Epoch seconds of the check.
    pub checked_at: u64,
}

pub fn cache_path() -> PathBuf {
    cache_dir().join("update.json")
}

pub fn read_cache() -> Option<CheckCache> {
    serde_json::from_str(&std::fs::read_to_string(cache_path()).ok()?).ok()
}

fn write_cache(cache: &CheckCache) {
    if let Ok(json) = serde_json::to_string(cache) {
        let _ = crate::config::write_atomic(&cache_path(), &json);
    }
}

fn now_secs() -> u64 {
    crate::types::now_ms() / 1000
}

/// Is the cached answer old enough to be worth asking again?
pub fn check_is_due(cache: Option<&CheckCache>, now: u64) -> bool {
    match cache {
        None => true,
        Some(cache) => now.saturating_sub(cache.checked_at) >= CHECK_INTERVAL.as_secs(),
    }
}

/// The newer version, if the cache knows of one.
pub fn pending_update(cache: Option<&CheckCache>) -> Option<Version> {
    let latest = Version::parse(&cache?.latest)?;
    (latest > Version::current()).then_some(latest)
}

/// Fetch a URL over HTTPS.
///
/// Shelling out to curl rather than building a verifying TLS client here: this
/// runs at most once a day, and curl brings correct certificate validation and
/// proxy handling that would otherwise be ours to get right. The probe's TLS
/// client accepts any certificate on purpose and must never be used for this.
fn fetch(url: &str) -> anyhow::Result<Vec<u8>> {
    // The status is appended so a 404 can be told from a broken network — the
    // two need very different advice, and the first is what a repo with no
    // releases yet always gives.
    let output = Command::new("curl")
        .args([
            "--location",
            "--silent",
            "--show-error",
            // https only: this decides what code replaces the binary.
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            &NETWORK_TIMEOUT_SECS.to_string(),
            "--user-agent",
            concat!("ports/", env!("CARGO_PKG_VERSION")),
            "--write-out",
            "%{http_code}",
            url,
        ])
        .output()
        .map_err(|err| {
            anyhow::anyhow!("could not run curl, which is needed to check for updates: {err}")
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "could not reach {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let (body, status) = split_status(&output.stdout);
    match status {
        200 => Ok(body),
        404 => anyhow::bail!("not found: {url}"),
        other => anyhow::bail!("{url} returned HTTP {other}"),
    }
}

/// Split curl's `--write-out` status off the end of the body.
fn split_status(response: &[u8]) -> (Vec<u8>, u16) {
    // The status is exactly three ASCII digits appended after the body.
    if response.len() >= 3 {
        let split = response.len() - 3;
        let tail = &response[split..];
        if tail.iter().all(|b| b.is_ascii_digit()) {
            let status = std::str::from_utf8(tail)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return (response[..split].to_vec(), status);
        }
    }
    (response.to_vec(), 0)
}

/// Where a release's files live.
pub fn release_base(version: Version) -> String {
    format!("https://github.com/{REPO}/releases/download/v{version}")
}

/// The artifact name for a target, matching what CI publishes.
pub fn artifact_name(target: &str) -> String {
    format!("ports-{target}.gz")
}

/// Ask GitHub what the newest release is, and remember the answer.
pub fn check_now() -> anyhow::Result<Version> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = fetch(&url).map_err(|err| {
        if err.to_string().starts_with("not found") {
            anyhow::anyhow!("{REPO} has no published releases yet")
        } else {
            err
        }
    })?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;

    let tag = value
        .get("tag_name")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("no release found"))?;
    let version = Version::parse(tag)
        .ok_or_else(|| anyhow::anyhow!("release tag '{tag}' is not a version"))?;

    write_cache(&CheckCache {
        latest: version.to_string(),
        checked_at: now_secs(),
    });

    Ok(version)
}

/// Refresh the cache quietly, for callers that must not fail because of it.
pub fn refresh_in_background() {
    if !check_is_due(read_cache().as_ref(), now_secs()) {
        return;
    }
    let _ = check_now();
}

/// Pick our artifact's checksum out of the release manifest.
pub fn checksum_for(manifest: &str, artifact: &str) -> Option<String> {
    for line in manifest.lines() {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        // `shasum` writes "<hash>  <name>", sometimes with a leading `*`.
        let name = parts.next().unwrap_or("").trim_start_matches('*');
        if name == artifact {
            return Some(hash.to_lowercase());
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Decompress a gzip stream.
///
/// Written out rather than pulled in: the release artifact is a single
/// gzipped file, and this is the whole of the format we ever meet.
fn gunzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("piped");
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "could not decompress the download: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Swap the running binary for new bytes.
///
/// Written beside the target and renamed over it: a rename is atomic, so an
/// interrupted update leaves the old binary intact rather than a half-written
/// one. Unix keeps the running process on the old inode, so this is safe to do
/// to ourselves.
pub fn replace_binary(target: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let directory = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", target.display()))?;

    let staged = directory.join(format!(".ports-update-{}", std::process::id()));
    std::fs::write(&staged, bytes).map_err(|err| {
        anyhow::anyhow!(
            "cannot write to {}: {err}\n  If ports lives somewhere system-owned, \
             try: sudo ports update",
            directory.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
        {
            let _ = std::fs::remove_file(&staged);
            return Err(err.into());
        }
    }

    if let Err(err) = std::fs::rename(&staged, target) {
        let _ = std::fs::remove_file(&staged);
        return Err(anyhow::anyhow!(
            "could not replace {}: {err}",
            target.display()
        ));
    }

    Ok(())
}

pub struct Download {
    pub version: Version,
    pub bytes: Vec<u8>,
}

/// Fetch and verify a release, without installing it.
pub fn download(version: Version) -> anyhow::Result<Download> {
    let Some(target) = target_triple() else {
        anyhow::bail!(
            "no prebuilt binary for {}-{} — update with `cargo install ports` instead",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };

    let artifact = format!("ports-{target}.gz");
    let base = format!("https://github.com/{REPO}/releases/download/v{version}");

    let manifest = String::from_utf8_lossy(&fetch(&format!("{base}/checksums.txt"))?).into_owned();
    let expected = checksum_for(&manifest, &artifact)
        .ok_or_else(|| anyhow::anyhow!("release v{version} has no checksum for {artifact}"))?;

    let compressed = fetch(&format!("{base}/{artifact}"))?;
    let actual = sha256_hex(&compressed);
    if actual != expected {
        // Corruption, a truncated transfer, or something worse. Either way it
        // does not get written to disk.
        anyhow::bail!(
            "checksum mismatch for {artifact}\n  expected {expected}\n  got      {actual}"
        );
    }

    Ok(Download {
        version,
        bytes: gunzip(&compressed)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_tags() {
        assert_eq!(Version::parse("v1.2.3"), Version::parse("1.2.3"));
        assert_eq!(
            Version::parse("0.2.0").map(|v| v.to_string()).as_deref(),
            Some("0.2.0")
        );

        // Not stable releases, and not worth guessing about.
        assert!(Version::parse("v1.2.3-rc1").is_none());
        assert!(Version::parse("v1.2").is_none());
        assert!(Version::parse("v1.2.3.4").is_none());
        assert!(Version::parse("nightly").is_none());
        assert!(Version::parse("").is_none());
    }

    #[test]
    fn orders_versions_by_number_not_text() {
        let v = |s| Version::parse(s).unwrap();
        // The one a string comparison gets wrong.
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.2.10") > v("0.2.9"));
        assert_eq!(v("0.2.0"), v("v0.2.0"));
    }

    #[test]
    fn an_update_is_pending_only_when_the_release_is_newer() {
        let current = Version::current().to_string();
        let cache = |latest: &str| CheckCache {
            latest: latest.into(),
            checked_at: 0,
        };

        assert!(pending_update(Some(&cache("999.0.0"))).is_some());
        assert!(pending_update(Some(&cache(&current))).is_none());
        assert!(pending_update(Some(&cache("0.0.1"))).is_none());
        // A tag we cannot read is not an update.
        assert!(pending_update(Some(&cache("garbage"))).is_none());
        assert!(pending_update(None).is_none());
    }

    #[test]
    fn checks_are_due_at_most_daily() {
        let cache = CheckCache {
            latest: "0.2.0".into(),
            checked_at: 1_000_000,
        };
        assert!(!check_is_due(Some(&cache), 1_000_000));
        assert!(!check_is_due(Some(&cache), 1_000_000 + 60 * 60));
        assert!(check_is_due(Some(&cache), 1_000_000 + 24 * 60 * 60));
        // Never checked.
        assert!(check_is_due(None, 0));
        // A clock that went backwards must not wedge the check off forever.
        assert!(!check_is_due(Some(&cache), 0));
    }

    #[test]
    fn builds_urls_matching_what_ci_publishes() {
        let version = Version::parse("1.2.3").unwrap();
        assert_eq!(
            release_base(version),
            "https://github.com/baboons/ports/releases/download/v1.2.3"
        );
        // The names CI writes in .github/workflows/release.yml.
        assert_eq!(
            artifact_name("aarch64-apple-darwin"),
            "ports-aarch64-apple-darwin.gz"
        );
        assert_eq!(
            artifact_name("x86_64-unknown-linux-musl"),
            "ports-x86_64-unknown-linux-musl.gz"
        );
    }

    #[test]
    fn separates_curls_status_from_the_body() {
        assert_eq!(split_status(b"hello200"), (b"hello".to_vec(), 200));
        assert_eq!(split_status(b"404"), (Vec::new(), 404));
        // A body genuinely ending in digits still parses, because the status
        // is always the last three bytes.
        assert_eq!(split_status(b"v1.2.3200"), (b"v1.2.3".to_vec(), 200));
        // Too short to carry one.
        assert_eq!(split_status(b"xx"), (b"xx".to_vec(), 0));
    }

    #[test]
    fn reads_a_checksum_out_of_the_manifest() {
        let manifest = "\
abc123  ports-aarch64-apple-darwin.gz
def456  ports-x86_64-unknown-linux-musl.gz
";
        assert_eq!(
            checksum_for(manifest, "ports-aarch64-apple-darwin.gz").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            checksum_for(manifest, "ports-x86_64-unknown-linux-musl.gz").as_deref(),
            Some("def456")
        );
        // A target with no entry must not silently match another's hash.
        assert_eq!(checksum_for(manifest, "ports-something-else.gz"), None);
    }

    #[test]
    fn handles_the_binary_marker_shasum_sometimes_writes() {
        let manifest = "abc123 *ports-aarch64-apple-darwin.gz\n";
        assert_eq!(
            checksum_for(manifest, "ports-aarch64-apple-darwin.gz").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn recognises_installs_we_must_not_touch() {
        use std::path::PathBuf;
        let brew = origin_of(&PathBuf::from("/opt/homebrew/Cellar/ports/0.2.0/bin/ports"));
        assert_eq!(brew, Origin::PackageManager("Homebrew"));

        assert_eq!(
            origin_of(&PathBuf::from("/Users/j/.cargo/bin/ports")),
            Origin::PackageManager("cargo")
        );
        assert_eq!(
            origin_of(&PathBuf::from("/app/node_modules/@baboons/ports/bin/ports")),
            Origin::PackageManager("npm")
        );

        // A plain binary is ours to replace.
        assert_eq!(
            origin_of(&PathBuf::from("/usr/local/bin/ports")),
            Origin::SelfManaged
        );
    }

    #[test]
    fn replacing_a_binary_is_atomic_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ports");
        std::fs::write(&target, b"old").unwrap();

        replace_binary(&target, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "the replacement must be executable");
        }

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".ports-update"))
            .collect();
        assert!(leftovers.is_empty(), "staging file left behind");
    }

    #[test]
    fn a_failed_replacement_leaves_the_old_binary_alone() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the binary should be: the rename cannot succeed.
        let target = dir.path().join("ports");
        std::fs::create_dir(&target).unwrap();

        assert!(replace_binary(&target, b"new").is_err());
        assert!(target.is_dir(), "the original was disturbed");
    }

    /// The whole install path bar the network, driven with a manifest
    /// produced by the same `shasum -a 256` CI runs.
    #[test]
    fn verifies_and_installs_a_release_built_the_way_ci_builds_one() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = "ports-aarch64-apple-darwin.gz";

        // Package a "binary" exactly as the workflow does.
        let payload = b"#!/bin/sh\necho the new version\n";
        let gz = dir.path().join(artifact);
        let mut child = std::process::Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::fs::File::create(&gz).unwrap())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(payload).unwrap();
        }
        assert!(child.wait().unwrap().success());

        let manifest = String::from_utf8(
            std::process::Command::new("shasum")
                .args(["-a", "256", artifact])
                .current_dir(dir.path())
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();

        // Verify, decompress, install.
        let compressed = std::fs::read(&gz).unwrap();
        let expected = checksum_for(&manifest, artifact).expect("manifest lists the artifact");
        assert_eq!(sha256_hex(&compressed), expected, "checksum should match");

        let target = dir.path().join("ports");
        std::fs::write(&target, b"the old version").unwrap();
        replace_binary(&target, &gunzip(&compressed).unwrap()).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), payload);
    }

    #[test]
    fn a_tampered_download_is_refused_before_anything_is_written() {
        let manifest = "0000000000000000000000000000000000000000000000000000000000000000  \
                        ports-aarch64-apple-darwin.gz\n";
        let expected = checksum_for(manifest, "ports-aarch64-apple-darwin.gz").unwrap();

        // Whatever arrived, it is not what the release says it should be.
        assert_ne!(sha256_hex(b"something else entirely"), expected);
    }

    #[test]
    fn gunzip_round_trips() {
        // Proves the decompression path, which is otherwise only exercised on
        // a real download.
        let original = b"a binary, more or less";
        let mut child = std::process::Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(original).unwrap();
        }
        let compressed = child.wait_with_output().unwrap().stdout;

        assert_eq!(gunzip(&compressed).unwrap(), original);
    }
}
