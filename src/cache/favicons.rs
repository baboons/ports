//! Content-addressed favicon cache.
//!
//! Icons are fetched once and stored under their content hash, so the index
//! page can serve them from this machine rather than pointing the browser at a
//! dev server that may have stopped since.

use std::path::PathBuf;
use std::time::Duration;

use sha1::{Digest, Sha1};

use crate::config::cache_dir;

/// Icons are small. Anything larger is not an icon, whatever it claims.
const MAX_ICON_BYTES: usize = 256 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_millis(1500);

pub fn favicon_dir() -> PathBuf {
    cache_dir().join("favicons")
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A hash is a filename, so it must not be able to name anything else.
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Guess a content type from the bytes themselves.
///
/// The `Content-Type` a dev server puts on `/favicon.ico` is wrong often enough
/// that sniffing is more reliable, and the set of formats is tiny.
pub fn sniff_content_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"\x00\x00\x01\x00") {
        "image/x-icon"
    } else if bytes.starts_with(b"GIF8") {
        "image/gif"
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        "image/webp"
    } else {
        // SVG is text and can lead with a comment, a doctype or the tag.
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).to_lowercase();
        if head.contains("<svg") {
            "image/svg+xml"
        } else {
            "application/octet-stream"
        }
    }
}

/// Do the bytes look like an image at all?
///
/// A dev server with SPA routing answers `/favicon.ico` with its index page and
/// a 200, so without this the cache fills with copies of index.html.
fn looks_like_an_icon(bytes: &[u8]) -> bool {
    !bytes.is_empty() && sniff_content_type(bytes) != "application/octet-stream"
}

pub struct CachedIcon {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

pub fn read_favicon(hash: &str) -> Option<CachedIcon> {
    if !is_valid_hash(hash) {
        return None;
    }
    let bytes = std::fs::read(favicon_dir().join(hash)).ok()?;
    let content_type = sniff_content_type(&bytes);
    Some(CachedIcon {
        bytes,
        content_type,
    })
}

/// Fetch an icon and store it under its content hash.
///
/// Returns the hash, or None for anything that did not turn out to be an image.
pub async fn cache_favicon(url: &str) -> Option<String> {
    let bytes = fetch_bytes(url).await?;
    if !looks_like_an_icon(&bytes) {
        return None;
    }

    let hash = hash_bytes(&bytes);
    let dir = favicon_dir();
    let path = dir.join(&hash);

    // Content-addressed: identical bytes are already the same file.
    if path.exists() {
        return Some(hash);
    }
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(&path, &bytes).ok()?;
    Some(hash)
}

/// GET a URL and return at most `MAX_ICON_BYTES` of body.
async fn fetch_bytes(url: &str) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;

    let parsed: hyper::Uri = url.parse().ok()?;
    // Only loopback: a page can declare any favicon URL it likes, and fetching
    // an arbitrary remote one on its say-so is not our business.
    let host = parsed.host()?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let is_local = bare == "localhost"
        || bare.ends_with(".localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if !is_local {
        return None;
    }
    // TLS to a dev server's self-signed cert is a whole handshake for an icon.
    if parsed.scheme_str() == Some("https") {
        return None;
    }

    let port = parsed.port_u16().unwrap_or(80);
    let stream = tokio::time::timeout(FETCH_TIMEOUT, tokio::net::TcpStream::connect((bare, port)))
        .await
        .ok()?
        .ok()?;

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .ok()?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .uri(parsed.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
        .header("host", format!("{host}:{port}"))
        .header("accept", "image/*")
        .header("connection", "close")
        .body(String::new())
        .ok()?;

    let response = tokio::time::timeout(FETCH_TIMEOUT, sender.send_request(request))
        .await
        .ok()?
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Some(chunk) = frame.data_ref() {
            let room = MAX_ICON_BYTES.saturating_sub(collected.len());
            if room == 0 {
                break;
            }
            collected.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    (!collected.is_empty()).then_some(collected)
}

/// Delete cached icons nothing refers to any more.
pub fn prune(live: &std::collections::HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(favicon_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !live.contains(&name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";

    #[test]
    fn sniffs_the_formats_favicons_actually_use() {
        assert_eq!(sniff_content_type(PNG), "image/png");
        assert_eq!(
            sniff_content_type(b"\x00\x00\x01\x00\x01\x00"),
            "image/x-icon"
        );
        assert_eq!(sniff_content_type(b"GIF89a"), "image/gif");
        assert_eq!(sniff_content_type(&[0xFF, 0xD8, 0xFF, 0xE0]), "image/jpeg");
        assert_eq!(
            sniff_content_type(b"<?xml version=\"1.0\"?><svg xmlns=\"...\">"),
            "image/svg+xml"
        );
    }

    #[test]
    fn rejects_an_html_page_masquerading_as_an_icon() {
        // A dev server with SPA routing answers /favicon.ico with index.html
        // and a 200. Caching that would fill the cache with web pages.
        let html = b"<!doctype html><html><head><title>App</title></head></html>";
        assert!(!looks_like_an_icon(html));
        assert!(!looks_like_an_icon(b""));
        assert!(looks_like_an_icon(PNG));
    }

    #[test]
    fn hashes_are_content_addressed_and_stable() {
        let first = hash_bytes(PNG);
        assert_eq!(first, hash_bytes(PNG));
        assert_ne!(first, hash_bytes(b"different bytes"));
        assert!(is_valid_hash(&first), "{first} should be a valid hash");
    }

    #[test]
    fn rejects_hashes_that_could_name_another_file() {
        for hostile in [
            "../../etc/passwd",
            "not-hex-at-all!!",
            "",
            "abc",
            "0123456789abcdef0", // one too long
        ] {
            assert!(!is_valid_hash(hostile), "{hostile:?} should be refused");
            assert!(read_favicon(hostile).is_none());
        }
    }

    #[tokio::test]
    async fn refuses_to_fetch_icons_from_off_this_machine() {
        // A page declares its own favicon URL. Following one that points off
        // the box would make the scanner into someone else's HTTP client.
        assert!(fetch_bytes("http://example.com/favicon.ico")
            .await
            .is_none());
        assert!(fetch_bytes("http://8.8.8.8/favicon.ico").await.is_none());
    }

    #[tokio::test]
    async fn fetches_and_stores_a_real_icon() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CACHE_HOME", temp.path());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = socket.read(&mut scratch).await;
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        PNG.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(PNG);
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let hash = cache_favicon(&format!("http://127.0.0.1:{port}/favicon.png"))
            .await
            .expect("should cache the icon");

        let read_back = read_favicon(&hash).expect("should read it back");
        assert_eq!(read_back.bytes, PNG);
        assert_eq!(read_back.content_type, "image/png");

        std::env::remove_var("XDG_CACHE_HOME");
    }
}
