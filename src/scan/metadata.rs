//! Everything we can learn about a service from its HTML head and response
//! headers: what it calls itself, what it looks like, and what built it.

use scraper::{Html, Selector};
use url::Url;

use crate::types::PageMeta;

/// Entities common enough in a `<title>` to be worth handling without pulling
/// in a full entity table.
fn named_entity(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => " ",
        _ => return None,
    })
}

pub fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != '&' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }

        // Find the terminating semicolon within a plausible entity length.
        let end = (i + 1..bytes.len().min(i + 12)).find(|&j| bytes[j] == ';');
        let Some(end) = end else {
            out.push('&');
            i += 1;
            continue;
        };

        let entity: String = bytes[i + 1..end].iter().collect();
        let decoded = if let Some(named) = named_entity(&entity) {
            Some(named.to_string())
        } else if let Some(hex) = entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
        {
            u32::from_str_radix(hex, 16)
                .ok()
                .and_then(char::from_u32)
                .map(String::from)
        } else if let Some(dec) = entity.strip_prefix('#') {
            dec.parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(String::from)
        } else {
            None
        };

        match decoded {
            Some(text) => {
                out.push_str(&text);
                i = end + 1;
            }
            None => {
                // Not an entity we recognise; leave it exactly as written.
                out.push('&');
                i += 1;
            }
        }
    }

    out
}

/// Normalise a scraped string, or drop it if it carries no information.
fn clean(value: &str) -> Option<String> {
    let decoded = decode_entities(value);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    // Descriptions can be essays; nothing downstream renders more than a line.
    if collapsed.chars().count() > 300 {
        let truncated: String = collapsed.chars().take(297).collect();
        return Some(format!("{truncated}..."));
    }
    Some(collapsed)
}

fn resolve_url(href: &str, base: &str) -> Option<String> {
    let base = Url::parse(base).ok()?;
    base.join(href).ok().map(|u| u.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct FaviconCandidate {
    pub href: String,
    pub score: f64,
}

/// Rank declared icons so the best one can be shown without fetching them all.
///
/// SVG wins outright — it scales to any size we might render at. Among rasters,
/// bigger is better, since downscaling looks fine and upscaling does not.
pub fn rank_favicons(html: &str, base_url: &str) -> Vec<FaviconCandidate> {
    let document = Html::parse_document(html);
    let Ok(selector) = Selector::parse("link") else {
        return Vec::new();
    };
    let mut out: Vec<FaviconCandidate> = Vec::new();

    for element in document.select(&selector) {
        let attr =
            |name: &str| -> Option<String> { element.value().attr(name).map(|v| v.to_string()) };

        let rel = attr("rel").unwrap_or_default().to_lowercase();
        let rels: Vec<&str> = rel.split_whitespace().collect();
        let is_icon = rels.iter().any(|r| {
            matches!(
                *r,
                "icon"
                    | "shortcut"
                    | "apple-touch-icon"
                    | "apple-touch-icon-precomposed"
                    | "mask-icon"
            )
        });
        if !is_icon {
            continue;
        }

        let Some(href) = attr("href") else { continue };
        let href = href.trim();
        if href.is_empty() {
            continue;
        }

        let mut score = 10.0f64;

        let type_attr = attr("type").unwrap_or_default().to_lowercase();
        if type_attr.contains("svg") || href.to_lowercase().ends_with(".svg") {
            score += 100.0;
        }
        if rels.contains(&"apple-touch-icon") || rels.contains(&"apple-touch-icon-precomposed") {
            score += 5.0;
        }
        if rels.contains(&"mask-icon") {
            // A monochrome Safari pinned-tab glyph, not a real icon.
            score -= 5.0;
        }

        if let Some(sizes) = attr("sizes") {
            let sizes = sizes.trim().to_lowercase();
            if sizes == "any" {
                score += 50.0;
            } else if let Some(width) = sizes
                .split(['x', ' '])
                .next()
                .and_then(|w| w.trim().parse::<f64>().ok())
            {
                score += (width / 4.0).min(60.0);
            }
        }

        if let Some(resolved) = resolve_url(href, base_url) {
            out.push(FaviconCandidate {
                href: resolved,
                score,
            });
        }
    }

    // Stable, so equally-scored icons keep document order — the author's own
    // ordering is the best tiebreak available.
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// Scrape the head for everything that helps identify a service.
pub fn extract_meta(html: &str, base_url: &str) -> PageMeta {
    let mut meta = PageMeta::default();
    let document = Html::parse_document(html);

    if let Ok(selector) = Selector::parse("title") {
        if let Some(element) = document.select(&selector).next() {
            meta.title = clean(&element.text().collect::<String>());
        }
    }

    let Ok(meta_selector) = Selector::parse("meta") else {
        return meta;
    };

    for element in document.select(&meta_selector) {
        let attr =
            |name: &str| -> Option<String> { element.value().attr(name).map(|v| v.to_string()) };

        let Some(key) = attr("name").or_else(|| attr("property")) else {
            continue;
        };
        let Some(content) = attr("content") else {
            continue;
        };

        // First tag of a given kind wins; duplicates are usually a template bug.
        match key.to_lowercase().as_str() {
            "description" => meta.description = meta.description.or_else(|| clean(&content)),
            "og:title" => meta.og_title = meta.og_title.or_else(|| clean(&content)),
            "og:description" => {
                meta.og_description = meta.og_description.or_else(|| clean(&content))
            }
            "og:image" => {
                meta.og_image = meta
                    .og_image
                    .or_else(|| resolve_url(content.trim(), base_url))
            }
            "theme-color" => meta.theme_color = meta.theme_color.or_else(|| clean(&content)),
            _ => {}
        }
    }

    let icons = rank_favicons(html, base_url);
    meta.favicon_url = icons
        .first()
        .map(|c| c.href.clone())
        // Every server has one at the root whether it declares it or not.
        .or_else(|| resolve_url("/favicon.ico", base_url));

    // OpenGraph is a reasonable stand-in when the page omits the plain tags.
    if meta.title.is_none() {
        meta.title = meta.og_title.clone();
    }
    if meta.description.is_none() {
        meta.description = meta.og_description.clone();
    }

    meta
}

/// Name the framework from response headers.
///
/// Purpose-built fingerprint headers are checked before `Server`, because a
/// Next.js app behind nginx should read as Next.js, not nginx.
pub fn detect_framework(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    let get = |key: &str| headers.get(key).map(|s| s.as_str());

    if get("x-nextjs-cache").is_some()
        || get("x-nextjs-prerender").is_some()
        || get("x-nextjs-stale-time").is_some()
    {
        return Some("Next.js".into());
    }
    if get("x-remix-response").is_some() {
        return Some("Remix".into());
    }
    if get("x-sveltekit-page").is_some() {
        return Some("SvelteKit".into());
    }
    if get("x-turbo-charged-by").is_some() {
        return Some("Turbo".into());
    }

    if let Some(powered) = get("x-powered-by") {
        let lower = powered.to_lowercase();
        return Some(if lower.contains("express") {
            "Express".into()
        } else if lower.contains("next.js") {
            "Next.js".into()
        } else if lower.contains("nuxt") {
            "Nuxt".into()
        } else if lower.contains("php") {
            // "PHP/8.3.1" reads better as "PHP 8.3.1".
            let version = powered.trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == '/');
            format!("PHP {version}").trim().to_string()
        } else if lower.contains("asp.net") {
            "ASP.NET".into()
        } else {
            // An unrecognised x-powered-by still names something real.
            powered.to_string()
        });
    }

    let server = get("server")?;
    let lower = server.to_lowercase();
    let name = if lower.starts_with("gunicorn") {
        "Gunicorn"
    } else if lower.starts_with("uvicorn") {
        "Uvicorn"
    } else if lower.starts_with("werkzeug") {
        "Flask"
    } else if lower.starts_with("webrick") {
        "Ruby"
    } else if lower.starts_with("puma") {
        "Puma"
    } else if lower.starts_with("nginx") {
        "nginx"
    } else if lower.starts_with("apache") {
        "Apache"
    } else if lower.starts_with("caddy") {
        "Caddy"
    } else if lower.starts_with("vite") {
        "Vite"
    } else {
        return None;
    };
    Some(name.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn pulls_title_description_and_theme_colour() {
        // Doubled hashes: the colour literal contains a `"#` that would
        // otherwise close a single-hash raw string.
        let html = r##"<html><head>
            <title>  Ports   Test  </title>
            <meta name="description" content="Scans &amp; indexes local servers">
            <meta name="theme-color" content="#ff6600">
        </head></html>"##;

        let meta = extract_meta(html, "http://127.0.0.1:3000/");
        assert_eq!(meta.title.as_deref(), Some("Ports Test"));
        assert_eq!(
            meta.description.as_deref(),
            Some("Scans & indexes local servers")
        );
        assert_eq!(meta.theme_color.as_deref(), Some("#ff6600"));
    }

    #[test]
    fn falls_back_to_og_tags() {
        let html = r#"<html><head>
            <meta property="og:title" content="From OpenGraph">
            <meta property="og:description" content="Fallback description">
        </head></html>"#;

        let meta = extract_meta(html, "http://127.0.0.1:3000/");
        assert_eq!(meta.title.as_deref(), Some("From OpenGraph"));
        assert_eq!(meta.description.as_deref(), Some("Fallback description"));
    }

    #[test]
    fn defaults_to_root_favicon_when_none_is_declared() {
        let meta = extract_meta("<html><head></head></html>", "http://127.0.0.1:8080/app/");
        // Root-absolute, not relative to /app/.
        assert_eq!(
            meta.favicon_url.as_deref(),
            Some("http://127.0.0.1:8080/favicon.ico")
        );
    }

    #[test]
    fn prefers_svg_then_the_largest_declared_raster() {
        let html = r#"<html><head>
            <link rel="icon" href="/small.png" sizes="16x16">
            <link rel="apple-touch-icon" href="/big.png" sizes="180x180">
            <link rel="icon" type="image/svg+xml" href="/vector.svg">
        </head></html>"#;

        let ranked = rank_favicons(html, "http://127.0.0.1:1/");
        assert_eq!(ranked[0].href, "http://127.0.0.1:1/vector.svg");
        assert_eq!(ranked[1].href, "http://127.0.0.1:1/big.png");
    }

    #[test]
    fn resolves_relative_hrefs_against_the_page_url() {
        let html = r#"<link rel="icon" href="assets/icon.png">"#;
        let ranked = rank_favicons(html, "http://127.0.0.1:3000/dash/");
        assert_eq!(ranked[0].href, "http://127.0.0.1:3000/dash/assets/icon.png");
    }

    #[test]
    fn handles_single_quotes_and_unquoted_attributes() {
        let ranked = rank_favicons("<link rel='icon' href=/a.png>", "http://127.0.0.1:1/");
        assert_eq!(ranked[0].href, "http://127.0.0.1:1/a.png");
    }

    #[test]
    fn reads_fingerprint_headers_ahead_of_the_server_header() {
        assert_eq!(
            detect_framework(&headers(&[("x-nextjs-cache", "HIT"), ("server", "nginx")])),
            Some("Next.js".into())
        );
        assert_eq!(
            detect_framework(&headers(&[("x-powered-by", "Express")])),
            Some("Express".into())
        );
        assert_eq!(
            detect_framework(&headers(&[("server", "uvicorn")])),
            Some("Uvicorn".into())
        );
        assert_eq!(
            detect_framework(&headers(&[("server", "Werkzeug/3.0.1 Python/3.12")])),
            Some("Flask".into())
        );
        assert_eq!(detect_framework(&headers(&[])), None);
    }

    #[test]
    fn decodes_the_entities_that_actually_show_up_in_titles() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_entities("caf&#233;"), "café");
        assert_eq!(decode_entities("&#x2F;path"), "/path");
        // Not an entity: left exactly as written rather than mangled.
        assert_eq!(decode_entities("Q&A"), "Q&A");
    }

    #[test]
    fn truncates_essay_length_descriptions() {
        let long = "x".repeat(500);
        let html = format!(r#"<meta name="description" content="{long}">"#);
        let meta = extract_meta(&html, "http://127.0.0.1:1/");
        let description = meta.description.unwrap();
        assert_eq!(description.chars().count(), 300);
        assert!(description.ends_with("..."));
    }
}
