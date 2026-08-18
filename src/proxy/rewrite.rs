//! Header surgery on the way through.
//!
//! A reverse proxy that forwards requests unchanged produces apps that
//! generate the wrong URLs and redirects that throw you out of the proxy.

use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// Hop-by-hop headers, which belong to a single connection and must not be
/// forwarded to the next one (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name.to_lowercase().as_str())
}

/// Tell the upstream who the client really was and how they arrived.
///
/// The original `Host` is preserved rather than rewritten to the upstream's
/// address: frameworks build absolute URLs from it, and rewriting would make
/// every generated link point at `127.0.0.1:4000` instead of the name the user
/// typed.
pub fn add_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: Option<std::net::IpAddr>,
    host: &str,
    scheme: &str,
    port: u16,
) {
    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    };

    set(headers, "x-forwarded-proto", scheme.to_string());
    set(headers, "x-forwarded-host", host.to_string());
    set(headers, "x-forwarded-port", port.to_string());

    if let Some(ip) = client_ip {
        // Append rather than replace: a chain of proxies is a list.
        let existing = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!("{v}, "))
            .unwrap_or_default();
        set(headers, "x-forwarded-for", format!("{existing}{ip}"));
    }
}

/// Point a redirect back at the proxy when it names the upstream directly.
///
/// A dev server that answers `/` with a 302 to `http://127.0.0.1:4000/login`
/// would otherwise walk the browser straight off the proxy and onto the raw
/// port, losing the hostname and every cookie scoped to it.
pub fn rewrite_location(location: &str, upstream: &str, public_origin: &str) -> Option<String> {
    let candidates = [
        format!("http://{upstream}"),
        format!("https://{upstream}"),
        // The same host said the other common way.
        format!("http://localhost:{}", upstream.rsplit(':').next()?),
        format!("https://localhost:{}", upstream.rsplit(':').next()?),
    ];

    for prefix in candidates {
        if let Some(rest) = location.strip_prefix(&prefix) {
            return Some(format!("{public_origin}{rest}"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_hop_by_hop_headers_case_insensitively() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(is_hop_by_hop("UPGRADE"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("host"));
    }

    #[test]
    fn forwarded_headers_describe_the_public_request() {
        let mut headers = HeaderMap::new();
        add_forwarded_headers(
            &mut headers,
            Some("127.0.0.1".parse().unwrap()),
            "myapp.localhost",
            "http",
            80,
        );

        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-host"], "myapp.localhost");
        assert_eq!(headers["x-forwarded-port"], "80");
        assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
    }

    #[test]
    fn forwarded_for_appends_rather_than_replacing() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        add_forwarded_headers(
            &mut headers,
            Some("127.0.0.1".parse().unwrap()),
            "myapp.localhost",
            "http",
            80,
        );
        assert_eq!(headers["x-forwarded-for"], "10.0.0.1, 127.0.0.1");
    }

    #[test]
    fn rewrites_a_redirect_that_names_the_upstream() {
        assert_eq!(
            rewrite_location(
                "http://127.0.0.1:4000/login",
                "127.0.0.1:4000",
                "http://myapp.localhost"
            )
            .as_deref(),
            Some("http://myapp.localhost/login")
        );

        // The same server named as localhost rather than by address.
        assert_eq!(
            rewrite_location(
                "http://localhost:4000/dashboard?next=/",
                "127.0.0.1:4000",
                "http://myapp.localhost"
            )
            .as_deref(),
            Some("http://myapp.localhost/dashboard?next=/")
        );
    }

    #[test]
    fn leaves_redirects_that_are_not_about_the_upstream_alone() {
        // Relative redirects already work through the proxy.
        assert_eq!(
            rewrite_location("/login", "127.0.0.1:4000", "http://myapp.localhost"),
            None
        );
        // An external redirect is the app's intent, not an accident.
        assert_eq!(
            rewrite_location(
                "https://accounts.google.com/o/oauth2/auth",
                "127.0.0.1:4000",
                "http://myapp.localhost"
            ),
            None
        );
        // A different local port is a different service.
        assert_eq!(
            rewrite_location(
                "http://127.0.0.1:9999/x",
                "127.0.0.1:4000",
                "http://myapp.localhost"
            ),
            None
        );
    }
}
