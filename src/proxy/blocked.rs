//! Recognise a dev server refusing an unfamiliar `Host` header.
//!
//! Every modern dev server rejects requests whose Host it does not recognise,
//! as protection against DNS rebinding. That is correct behaviour and the
//! proxy cannot and should not work around it — but landing on a blank
//! "Blocked request" page with no idea why is a miserable first five minutes,
//! so we name the stack and print the exact line that fixes it.

/// A dev server's host check, and how to satisfy it.
pub struct BlockedHost {
    pub stack: &'static str,
    /// The config change that allows the new hostname.
    pub fix: &'static str,
    /// Where that change goes.
    pub file: &'static str,
}

/// Look for a host-check rejection in a response.
///
/// Matched on the body rather than the status, because the statuses used vary
/// (403, 421, 500) and overlap with ordinary application errors.
pub fn detect(status: u16, body: &str) -> Option<BlockedHost> {
    // A successful response is not a rejection, whatever it happens to contain.
    if (200..300).contains(&status) {
        return None;
    }

    let haystack = body.to_lowercase();

    if haystack.contains("blocked request") && haystack.contains("host") {
        return Some(BlockedHost {
            stack: "Vite",
            fix: "server: { allowedHosts: ['.localhost'] }",
            file: "vite.config.ts",
        });
    }
    if haystack.contains("invalid host header") {
        return Some(BlockedHost {
            stack: "webpack-dev-server",
            fix: "devServer: { allowedHosts: 'all' }",
            file: "webpack.config.js",
        });
    }
    if haystack.contains("blocked hosts") || haystack.contains("blocked host:") {
        return Some(BlockedHost {
            stack: "Rails",
            fix: "config.hosts << '.localhost'",
            file: "config/environments/development.rb",
        });
    }
    if haystack.contains("disallowedhost") || haystack.contains("invalid http_host header") {
        return Some(BlockedHost {
            stack: "Django",
            fix: "ALLOWED_HOSTS = ['.localhost']",
            file: "settings.py",
        });
    }
    if haystack.contains("invalid server actions request") {
        return Some(BlockedHost {
            stack: "Next.js",
            fix: "experimental: { serverActions: { allowedOrigins: ['myapp.localhost'] } }",
            file: "next.config.js",
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_vite() {
        let body = "Blocked request. This host (\"myapp.localhost\") is not allowed.";
        let blocked = detect(403, body).expect("should detect Vite");
        assert_eq!(blocked.stack, "Vite");
        assert!(blocked.fix.contains("allowedHosts"));
    }

    #[test]
    fn recognises_the_other_common_stacks() {
        assert_eq!(
            detect(403, "Invalid Host header").map(|b| b.stack),
            Some("webpack-dev-server")
        );
        assert_eq!(
            detect(403, "Blocked hosts: myapp.localhost").map(|b| b.stack),
            Some("Rails")
        );
        assert_eq!(
            detect(400, "DisallowedHost at /").map(|b| b.stack),
            Some("Django")
        );
    }

    #[test]
    fn a_successful_response_is_never_a_block() {
        // A page that merely discusses blocked requests is not one.
        assert!(detect(200, "Blocked request. This host is not allowed.").is_none());
    }

    #[test]
    fn an_ordinary_error_page_is_not_mistaken_for_a_block() {
        assert!(detect(404, "<html><body>Not Found</body></html>").is_none());
        assert!(detect(500, "Internal Server Error").is_none());
    }
}
