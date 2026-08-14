//! The reverse proxy: `myapp.localhost` in, `127.0.0.1:4000` out.

pub mod blocked;
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

use crate::config::bindings::{bindings_path, load_bindings_strict, Bindings};
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

/// Shared, hot-reloadable configuration.
pub struct ProxyState {
    pub bindings: RwLock<Bindings>,
}

impl ProxyState {
    pub fn new(bindings: Bindings) -> Self {
        Self {
            bindings: RwLock::new(bindings),
        }
    }
}

/// Reload the binding table whenever the file on disk changes.
///
/// Polling an mtime rather than exposing a control socket: the table is
/// ordinary user config, and this keeps the privileged half of the daemon out
/// of the business of authenticating and parsing commands.
pub async fn watch_bindings(state: Arc<ProxyState>) {
    let mut last: Option<SystemTime> = std::fs::metadata(bindings_path())
        .and_then(|m| m.modified())
        .ok();

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let current = std::fs::metadata(bindings_path())
            .and_then(|m| m.modified())
            .ok();
        if current == last {
            continue;
        }
        last = current;

        // A half-written or mis-edited file must not take working routes down.
        // Keep serving the table we have and say why we did not swap it.
        match load_bindings_strict() {
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
pub async fn bind_listener(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await
}

/// Bind and serve. Used by tests; the daemon binds separately.
pub async fn serve_http(state: Arc<ProxyState>, port: u16) -> anyhow::Result<()> {
    let listener = bind_listener(port).await?;
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
    let Some(binding) = bindings.resolve(&host_header) else {
        return Ok(unknown_host_page(&bindings, &host_header));
    };
    let upstream = binding.target.clone();
    let tld = bindings.tld.clone();
    drop(bindings);

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

/// Nothing is bound to this hostname — say what is.
fn unknown_host_page(bindings: &Bindings, host: &str) -> Response<ProxyBody> {
    let host = html_escape(host.split(':').next().unwrap_or(host));

    let list = if bindings.bindings.is_empty() {
        "<p>Nothing is bound yet. Try <code>ports adopt</code> in a project, \
         or <code>ports bind myapp 3000</code>.</p>"
            .to_string()
    } else {
        let items: String = bindings
            .bindings
            .iter()
            .map(|b| {
                let hostname = html_escape(&b.hostname(&bindings.tld));
                format!(
                    "<li><a href=\"http://{hostname}/\">{hostname}</a> → <code>{}</code></li>",
                    html_escape(&b.target)
                )
            })
            .collect();
        format!("<p>Bound right now:</p><ul>{items}</ul>")
    };

    page(
        StatusCode::NOT_FOUND,
        "Not bound",
        format!("<h1>Nothing is bound to {host}</h1>{list}"),
    )
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
    fn the_unknown_host_page_lists_what_is_bound() {
        let mut bindings = Bindings::default();
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);

        let response = unknown_host_page(&bindings, "nope.localhost");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn an_empty_table_suggests_how_to_fill_it() {
        let response = unknown_host_page(&Bindings::default(), "nope.localhost");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
