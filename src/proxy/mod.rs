//! The reverse proxy: `myapp.localhost` in, `127.0.0.1:4000` out.

pub mod blocked;
pub mod index;
pub mod rewrite;
pub mod tls;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, HOST, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::config::bindings::{bindings_path, load_bindings_from, Bindings};
use crate::proxy::rewrite::{add_forwarded_headers, is_hop_by_hop, rewrite_location};

/// A body we can return from every path, whether it came from upstream or was
/// generated here.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

fn full(text: impl Into<Bytes>) -> ProxyBody {
    Full::new(text.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Shared, hot-reloadable state.
pub struct ProxyState {
    pub bindings: RwLock<Bindings>,
    /// What the background scan last saw, for the index page.
    pub records: RwLock<Vec<crate::types::PortRecord>>,
    /// The file this daemon reads and writes.
    ///
    /// Held rather than looked up globally so a test can point it at a
    /// scratch file instead of the running user's real configuration.
    pub bindings_path: std::path::PathBuf,
}

impl ProxyState {
    pub fn new(bindings: Bindings) -> Self {
        Self::with_path(bindings, bindings_path())
    }

    pub fn with_path(bindings: Bindings, bindings_path: std::path::PathBuf) -> Self {
        Self {
            bindings: RwLock::new(bindings),
            records: RwLock::new(Vec::new()),
            bindings_path,
        }
    }
}

/// Keep a picture of what is running, for the index page to show.
///
/// Deliberately the same cache the CLI reads and writes, so a `ports` run in a
/// terminal and the daemon do not each pay for their own sweep.
pub async fn watch_ports(state: Arc<ProxyState>) {
    use crate::cache::{load_cache, save_cache, CacheState};
    use crate::scan::scanner::{scan, ScanOptions};
    use crate::scan::scheduler::is_sweep_due;
    use crate::types::now_ms;

    // Seed from whatever the last CLI run left behind, so the index has
    // something to show before the first scan finishes.
    let cached = load_cache();
    *state.records.write().await = cached.records.clone();
    let mut last_full_sweep = cached.last_full_sweep;

    loop {
        let prior = state.records.read().await.clone();
        let self_port = state.bindings.read().await.http_port;

        // The full sweep is the expensive tier; run it only when its TTL says
        // so, exactly as the CLI does.
        let deep = is_sweep_due(last_full_sweep, now_ms());

        let result = scan(
            ScanOptions {
                deep,
                prior: prior.clone(),
                self_port: Some(self_port),
                fetch_favicons: true,
                ..Default::default()
            },
            |_| {},
        )
        .await;

        if result.swept_fully {
            last_full_sweep = now_ms();
        }

        // Ports this pass did not look at keep their last known state: a
        // skipped sweep must make the answer cheaper, never smaller.
        let observed: std::collections::HashSet<u16> =
            result.records.iter().map(|r| r.port).collect();
        let mut merged: Vec<crate::types::PortRecord> = prior
            .into_iter()
            .filter(|r| !observed.contains(&r.port))
            .map(|r| crate::types::PortRecord { stale: true, ..r })
            .chain(result.records)
            .collect();
        merged.sort_by_key(|r| r.port);

        save_cache(&CacheState {
            last_full_sweep,
            records: merged.clone(),
            ..Default::default()
        });

        let live: std::collections::HashSet<String> = merged
            .iter()
            .filter_map(|r| r.meta.as_ref()?.favicon_hash.clone())
            .collect();
        crate::cache::favicons::prune(&live);

        *state.records.write().await = merged;

        // Cheap: it does nothing unless a day has passed since the last look.
        tokio::task::spawn_blocking(crate::update::refresh_in_background);

        // Long enough to be invisible on a dev machine's load, short enough
        // that a server started a minute ago is on the index.
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

/// Reload the binding table whenever the file on disk changes.
///
/// Polling an mtime rather than exposing a control socket: the table is
/// ordinary user config, and this keeps the privileged half of the daemon out
/// of the business of authenticating and parsing commands.
pub async fn watch_bindings(state: Arc<ProxyState>) {
    let path = state.bindings_path.clone();
    let mut last: Option<SystemTime> = std::fs::metadata(&path).and_then(|m| m.modified()).ok();

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let current = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if current == last {
            continue;
        }
        last = current;

        // A half-written or mis-edited file must not take working routes down.
        // Keep serving the table we have and say why we did not swap it.
        match load_bindings_from(&path) {
            Ok(reloaded) => {
                let count = reloaded.bindings.len();
                *state.bindings.write().await = reloaded;
                println!(
                    "  reloaded {count} binding{}",
                    if count == 1 { "" } else { "s" }
                );
            }
            Err(err) => eprintln!("  keeping the previous bindings: {err}"),
        }
    }
}

fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false)
}

/// Claim a port.
///
/// Separate from serving so a privileged port can be bound while we still have
/// the rights to, and the rights given up before a single request is handled.
pub async fn bind_listener(host: &str, port: u16) -> std::io::Result<TcpListener> {
    let address: IpAddr = host.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{host}' is not an IP address to listen on"),
        )
    })?;
    TcpListener::bind(SocketAddr::from((address, port))).await
}

/// Bind and serve. Used by tests; the daemon binds separately.
pub async fn serve_http(state: Arc<ProxyState>, port: u16) -> anyhow::Result<()> {
    let listener = bind_listener("127.0.0.1", port).await?;
    serve_on(listener, state, port).await
}

/// Serve plain HTTP on an already-bound listener.
pub async fn serve_on(
    listener: TcpListener,
    state: Arc<ProxyState>,
    port: u16,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // One failed accept (fd exhaustion, a client vanishing mid-handshake)
            // must not take the whole proxy down.
            Err(_) => continue,
        };
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { handle(req, state, peer.ip(), "http", port).await }
            });

            let _ = http1::Builder::new()
                // Required for WebSocket passthrough; without it Vite's HMR
                // socket never establishes and the page silently stops
                // hot-reloading.
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}

/// Serve HTTPS on an already-bound listener, terminating TLS with leaves minted
/// per hostname from the local CA.
pub async fn serve_tls_on(
    listener: TcpListener,
    state: Arc<ProxyState>,
    port: u16,
    certs: Arc<tls::CertStore>,
) -> anyhow::Result<()> {
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certs);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            // A failed handshake is one client's problem — a browser that has
            // not been told to trust the CA, most likely — not the server's.
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };

            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { handle(req, state, peer.ip(), "https", port).await }
            });

            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    client_ip: IpAddr,
    scheme: &'static str,
    listen_port: u16,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let host_header = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let bindings = state.bindings.read().await;
    let is_index = index::is_index_host(&bindings, &host_header);
    let resolved = bindings.resolve(&host_header).map(|b| b.target.clone());
    let tld = bindings.primary().to_string();
    drop(bindings);

    // The index owns its own routes wherever it is served, which is the
    // reserved name and every hostname nothing is bound to.
    let path = req.uri().path().to_string();
    if path.starts_with("/_ports/") && (is_index || resolved.is_none()) {
        return Ok(serve_index_route(req, &state, &path, scheme, listen_port, client_ip).await);
    }

    let Some(upstream) = resolved else {
        return Ok(index_page(&state, &host_header, is_index, client_ip).await);
    };
    if is_index {
        // Someone bound over the reserved name; the index still wins, or there
        // would be no way back to it.
        return Ok(index_page(&state, &host_header, true, client_ip).await);
    }

    // The origin as the browser knows it, for rewriting redirects back.
    let public_host = host_header
        .split(':')
        .next()
        .unwrap_or(&host_header)
        .to_string();
    let public_origin =
        if (scheme == "http" && listen_port == 80) || (scheme == "https" && listen_port == 443) {
            format!("{scheme}://{public_host}")
        } else {
            format!("{scheme}://{public_host}:{listen_port}")
        };

    match forward(
        req,
        &upstream,
        client_ip,
        &host_header,
        scheme,
        listen_port,
        &public_origin,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(err) => Ok(upstream_unreachable_page(
            &upstream,
            &public_host,
            &tld,
            &err,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    mut req: Request<Incoming>,
    upstream: &str,
    client_ip: IpAddr,
    host_header: &str,
    scheme: &'static str,
    listen_port: u16,
    public_origin: &str,
) -> anyhow::Result<Response<ProxyBody>> {
    let stream = TcpStream::connect(upstream).await?;
    // Dev servers are chatty and latency-sensitive; Nagle would add up to 40ms
    // to every small write for no benefit on loopback.
    let _ = stream.set_nodelay(true);

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

    // The connection task must outlive this function for upgrades to work.
    let connection = connection.with_upgrades();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let upgrading = is_upgrade(&req);
    // Must be taken before the request is consumed by the forward.
    let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));

    let (parts, body) = req.into_parts();
    let mut upstream_req = Request::builder().method(parts.method.clone()).uri(
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"),
    );

    {
        let headers = upstream_req.headers_mut().expect("builder has headers");
        for (name, value) in parts.headers.iter() {
            // Hop-by-hop headers belong to our connection with the client, not
            // to the one we are about to open — except on an upgrade, where
            // Connection and Upgrade are the whole point.
            if is_hop_by_hop(name.as_str())
                && !(upgrading && matches!(name.as_str(), "connection" | "upgrade"))
            {
                continue;
            }
            headers.insert(name, value.clone());
        }
        // Preserved deliberately: frameworks build absolute URLs from Host, so
        // rewriting it here would make every generated link point at the raw
        // port instead of the name the user typed.
        headers.insert(HOST, HeaderValue::from_str(host_header)?);
        add_forwarded_headers(headers, Some(client_ip), host_header, scheme, listen_port);
    }

    let upstream_req = upstream_req.body(body)?;
    let mut upstream_res = sender.send_request(upstream_req).await?;

    if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_res);

        if let Some(client_upgrade) = client_upgrade {
            tokio::spawn(async move {
                let (Ok(client), Ok(server)) = tokio::join!(client_upgrade, upstream_upgrade)
                else {
                    return;
                };
                // From here the proxy is a dumb pipe: this is a WebSocket, or
                // whatever else the two ends negotiated.
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(client),
                    &mut TokioIo::new(server),
                )
                .await;
            });
        }

        let mut response = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        if let Some(headers) = response.headers_mut() {
            for (name, value) in upstream_res.headers() {
                headers.insert(name, value.clone());
            }
        }
        return Ok(response.body(empty())?);
    }

    let (mut parts, body) = upstream_res.into_parts();

    // A redirect naming the upstream directly would walk the browser off the
    // proxy and onto the raw port, losing the hostname and its cookies.
    if let Some(location) = parts.headers.get(LOCATION).and_then(|v| v.to_str().ok()) {
        if let Some(rewritten) = rewrite_location(location, upstream, public_origin) {
            if let Ok(value) = HeaderValue::from_str(&rewritten) {
                parts.headers.insert(LOCATION, value);
            }
        }
    }

    for name in ["connection", "keep-alive", "transfer-encoding"] {
        parts.headers.remove(name);
    }

    // Streamed straight through, never collected: an SSE endpoint or a
    // streaming download must not be buffered here.
    Ok(Response::from_parts(parts, body.boxed()))
}

fn page(status: StatusCode, title: &str, body: String) -> Response<ProxyBody> {
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{title}</title>\
         <style>body{{font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;\
         max-width:34rem;margin:12vh auto;padding:0 1.5rem;color:#e6e6e6;background:#141414}}\
         h1{{font-size:1rem;font-weight:600;margin:0 0 1rem}}a{{color:#7aa2f7}}\
         code{{background:#1f1f1f;padding:.1rem .35rem;border-radius:3px}}\
         ul{{padding-left:1.2rem}}li{{margin:.3rem 0}}p{{color:#a0a0a0}}\
         @media(prefers-color-scheme:light){{body{{color:#1a1a1a;background:#fff}}\
         code{{background:#f0f0f0}}p{{color:#555}}}}</style>{body}"
    );

    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        // Lets `ports bind` recognise the proxy when it probes a target port,
        // so it can refuse to bind the proxy to itself. Checking the configured
        // port is not enough: `ports serve --http-port` can override it, and
        // then config and reality disagree.
        .header(SELF_MARKER, "1")
        .body(full(html))
        .expect("static response builds")
}

/// Header the proxy stamps on pages it generates itself.
pub const SELF_MARKER: &str = "x-ports-proxy";

/// The index: what is bound, what is running, and one click between them.
async fn index_page(
    state: &Arc<ProxyState>,
    host: &str,
    canonical: bool,
    client_ip: IpAddr,
) -> Response<ProxyBody> {
    let bindings = state.bindings.read().await;
    let records = state.records.read().await;
    let snapshot = index::snapshot(&bindings, &records, writes_allowed_from(client_ip));

    // Arriving at a name nothing is bound to is not an error worth a 404 in
    // the console, but it is worth saying which name you asked for.
    let missing = (!canonical).then(|| host.split(':').next().unwrap_or(host));
    let html = index::render(&snapshot, missing);

    Response::builder()
        .status(if canonical {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        })
        .header("content-type", "text/html; charset=utf-8")
        .header(SELF_MARKER, "1")
        .body(full(html))
        .expect("static response builds")
}

/// Does this request come from the page we served, rather than another site?
///
/// Any page in the browser can POST to localhost, so a state-changing request
/// needs proof of origin. `Origin` must match the request's own origin exactly;
/// absent is refused too, since a same-origin `fetch` always sends it.
fn origin_is_self(
    req: &Request<Incoming>,
    host_header: &str,
    scheme: &str,
    listen_port: u16,
) -> bool {
    let Some(origin) = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    let host = host_header.split(':').next().unwrap_or(host_header);
    let default_port =
        (scheme == "http" && listen_port == 80) || (scheme == "https" && listen_port == 443);

    let expected = if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{listen_port}")
    };

    origin.eq_ignore_ascii_case(&expected)
}

/// May a request from this address change the bindings?
///
/// Only from the machine itself. Off-loopback the Origin check buys nothing —
/// it defends against another *website* in a browser, and anything on the
/// network can set a header to whatever it likes with one curl flag. So when
/// the proxy is reachable from elsewhere the listing stays readable, but
/// changing it is something you do on the box, with `ports bind`.
pub fn writes_allowed_from(client_ip: IpAddr) -> bool {
    client_ip.is_loopback()
}

fn json(status: StatusCode, body: &serde_json::Value) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header(SELF_MARKER, "1")
        .body(full(body.to_string()))
        .expect("static response builds")
}

/// The index's own endpoints: data, icons, and the two mutations.
async fn serve_index_route(
    req: Request<Incoming>,
    state: &Arc<ProxyState>,
    path: &str,
    scheme: &'static str,
    listen_port: u16,
    client_ip: IpAddr,
) -> Response<ProxyBody> {
    use crate::cache::favicons::read_favicon;

    if let Some(hash) = path.strip_prefix("/_ports/favicon/") {
        return match read_favicon(hash) {
            Some(icon) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", icon.content_type)
                // Content-addressed, so it can never go stale.
                .header("cache-control", "public, max-age=31536000, immutable")
                .body(full(icon.bytes))
                .expect("static response builds"),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(empty())
                .expect("static response builds"),
        };
    }

    if path == "/_ports/data" {
        let bindings = state.bindings.read().await;
        let records = state.records.read().await;
        let snapshot = index::snapshot(&bindings, &records, writes_allowed_from(client_ip));
        return json(
            StatusCode::OK,
            &serde_json::to_value(&snapshot).unwrap_or_default(),
        );
    }

    let mutation = matches!(
        path,
        "/_ports/bind"
            | "/_ports/unbind"
            | "/_ports/domain/add"
            | "/_ports/domain/remove"
            | "/_ports/domain/primary"
    );
    if !mutation {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({ "error": "no such endpoint" }),
        );
    }

    if req.method() != hyper::Method::POST {
        return json(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({ "error": "POST only" }),
        );
    }

    let host_header = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    if !writes_allowed_from(client_ip) {
        return json(
            StatusCode::FORBIDDEN,
            &serde_json::json!({
                "error": "read-only from off this machine — bind from the machine itself, \
                          with `ports bind`"
            }),
        );
    }

    if !origin_is_self(&req, &host_header, scheme, listen_port) {
        return json(
            StatusCode::FORBIDDEN,
            &serde_json::json!({ "error": "cross-origin requests are refused" }),
        );
    }

    // A JSON content-type forces a CORS preflight, which a page from another
    // origin cannot satisfy. Belt to the Origin check's braces.
    let is_json = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        return json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &serde_json::json!({ "error": "expected application/json" }),
        );
    }

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": "unreadable body" }),
            )
        }
    };

    let mut bindings = state.bindings.write().await;
    let domain_request = |body: &[u8]| {
        serde_json::from_slice::<index::DomainRequest>(body).map_err(|err| err.to_string())
    };

    let outcome = match path {
        "/_ports/bind" => serde_json::from_slice::<index::BindRequest>(&body)
            .map_err(|err| err.to_string())
            .and_then(|request| index::apply_bind(&mut bindings, &request)),
        "/_ports/unbind" => serde_json::from_slice::<index::UnbindRequest>(&body)
            .map_err(|err| err.to_string())
            .and_then(|request| index::apply_unbind(&mut bindings, &request)),
        "/_ports/domain/add" => {
            domain_request(&body).and_then(|r| index::apply_add_domain(&mut bindings, &r))
        }
        "/_ports/domain/remove" => {
            domain_request(&body).and_then(|r| index::apply_remove_domain(&mut bindings, &r))
        }
        _ => domain_request(&body).and_then(|r| index::apply_primary_domain(&mut bindings, &r)),
    };

    match outcome {
        Ok(name) => {
            if let Err(err) =
                crate::config::bindings::save_bindings_to(&state.bindings_path, &bindings)
            {
                return json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({ "error": err.to_string() }),
                );
            }
            json(StatusCode::OK, &serde_json::json!({ "ok": name }))
        }
        Err(error) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": error }),
        ),
    }
}

/// The binding exists but the port behind it is not answering.
fn unknown_host_target(target: &str) -> String {
    html_escape(target)
}

fn upstream_unreachable_page(
    upstream: &str,
    host: &str,
    _tld: &str,
    err: &anyhow::Error,
) -> Response<ProxyBody> {
    page(
        StatusCode::BAD_GATEWAY,
        "Upstream down",
        format!(
            "<h1>{} is bound, but nothing is listening</h1>\
             <p><code>{}</code> did not answer: {}</p>\
             <p>Start the server, or re-point the binding with \
             <code>ports bind {} &lt;port&gt;</code>.</p>",
            html_escape(host),
            unknown_host_target(upstream),
            html_escape(&err.to_string()),
            html_escape(host.split('.').next().unwrap_or(host)),
        ),
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_in_untrusted_host_headers() {
        // The Host header is attacker-controlled; it lands in an error page.
        let escaped = html_escape("<script>alert(1)</script>");
        assert!(!escaped.contains('<'));
        assert_eq!(escaped, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn only_the_machine_itself_may_change_bindings() {
        // Loopback is the machine; anything else came over a network, where a
        // forged Origin header costs one curl flag.
        assert!(writes_allowed_from("127.0.0.1".parse().unwrap()));
        assert!(writes_allowed_from("::1".parse().unwrap()));

        // A LAN peer, the machine's own LAN address, and the wider internet.
        assert!(!writes_allowed_from("192.168.1.42".parse().unwrap()));
        assert!(!writes_allowed_from("10.0.0.5".parse().unwrap()));
        assert!(!writes_allowed_from("8.8.8.8".parse().unwrap()));
        assert!(!writes_allowed_from("fd00::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn an_unbound_hostname_gets_the_index_and_a_404() {
        let mut bindings = Bindings::default();
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);
        let state = Arc::new(ProxyState::new(bindings));

        let response = index_page(
            &state,
            "nope.localhost",
            false,
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        // The index, but still a 404: nothing is bound to what was asked for.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_reserved_name_gets_the_index_and_a_200() {
        let state = Arc::new(ProxyState::new(Bindings::default()));
        let response = index_page(
            &state,
            "ports.localhost",
            true,
            "127.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
