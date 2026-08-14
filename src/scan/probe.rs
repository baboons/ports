//! Work out what a port is actually speaking, then describe it.
//!
//! Everything here is bounded. A scanner that hangs on one pathological
//! listener is worse than one that gives up on it, so every step has a budget
//! and the whole probe has a deadline over the top.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::scan::metadata::{detect_framework, extract_meta};
use crate::types::{HttpInfo, PageMeta, Protocol, TlsInfo};

/// Only the head matters, and unbounded reads on a log-streaming endpoint hurt.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Tuned against real silent listeners (Apple's rapportd accepts and then says
/// nothing). Anything that has not spoken by now is not going to.
const SNIFF_TIMEOUT: Duration = Duration::from_millis(800);
/// Generous for loopback, where a healthy server answers in single-digit ms.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_REDIRECTS: usize = 3;
/// Ceiling on a single port's entire probe, redirects included.
///
/// Every genuine HTTP server measured on a real machine replied inside 600ms,
/// so this leaves ample headroom. The ports that reach it are ones like a
/// non-HTTP service that accepts the socket and then stalls — they end up
/// classified `tcp` regardless, so waiting longer buys nothing.
const PROBE_DEADLINE: Duration = Duration::from_millis(3000);

#[derive(Debug, Default)]
pub struct ProbeResult {
    pub protocol: Protocol,
    pub http: Option<HttpInfo>,
    pub meta: Option<PageMeta>,
    pub tls: Option<TlsInfo>,
    pub probe_ms: u64,
    pub error: Option<String>,
}

/// What the first bytes off the socket suggest we are talking to.
#[derive(Debug, PartialEq, Eq)]
enum Hint {
    Http,
    MaybeTls,
    Other,
    Closed,
}

/// Decide what a port is speaking by sending a plaintext request and looking at
/// the first bytes of the reply.
///
///   "HTTP/"      -> plaintext HTTP
///   0x16 / 0x15  -> TLS handshake or alert; our cleartext GET was not a valid
///                   ClientHello, so a TLS server answers with an alert
///   reset, no data -> many TLS stacks just drop garbage; worth a TLS retry
///   anything else  -> some other protocol, or a banner server like SSH/SMTP
async fn sniff(port: u16, host: IpAddr) -> Hint {
    let Ok(Ok(mut socket)) =
        tokio::time::timeout(SNIFF_TIMEOUT, TcpStream::connect((host, port))).await
    else {
        return Hint::Closed;
    };

    let request = format!("GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    if socket.write_all(request.as_bytes()).await.is_err() {
        // Connected and then refused our bytes: a TLS server is the likeliest
        // explanation, so it is worth one handshake attempt.
        return Hint::MaybeTls;
    }

    let mut buffer = [0u8; 16];
    match tokio::time::timeout(SNIFF_TIMEOUT, socket.read(&mut buffer)).await {
        Ok(Ok(0)) | Err(_) => Hint::MaybeTls,
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
            // The classic "you spoke the wrong protocol at me" signal.
            Hint::MaybeTls
        }
        Ok(Err(_)) => Hint::MaybeTls,
        Ok(Ok(n)) => {
            let head = &buffer[..n];
            if head[0] == 0x16 || head[0] == 0x15 {
                Hint::MaybeTls
            } else if head.starts_with(b"HTTP/") {
                Hint::Http
            } else {
                Hint::Other
            }
        }
    }
}

/// Accepts any certificate.
///
/// Dev servers overwhelmingly use self-signed or mkcert certs; refusing them
/// would make this tool useless for exactly the case it exists for. We are
/// reading a certificate to describe it, not to trust anything it says.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Read what the peer's certificate claims about itself.
fn describe_cert(certs: &[CertificateDer<'_>], protocol: Option<String>) -> Option<TlsInfo> {
    use x509_parser::prelude::*;

    let leaf = certs.first()?;
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;

    let common_name = |name: &X509Name| -> Option<String> {
        name.iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .or_else(|| {
                name.iter_organization()
                    .next()
                    .and_then(|o| o.as_str().ok())
                    .map(str::to_string)
            })
    };

    let subject = common_name(cert.subject());
    let issuer = common_name(cert.issuer());

    let alt_names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => Some(
                            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                                .to_string(),
                        ),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Some(TlsInfo {
        // Nobody vouched for it if the issuer matches the subject, or there is
        // no issuer at all.
        self_signed: issuer.is_none() || issuer == subject,
        subject,
        issuer,
        valid_from: Some(cert.validity().not_before.to_string()),
        valid_to: Some(cert.validity().not_after.to_string()),
        protocol,
        alt_names: if alt_names.is_empty() {
            None
        } else {
            Some(alt_names)
        },
    })
}

struct FetchOutcome {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    tls: Option<TlsInfo>,
    final_url: String,
}

/// One request/response exchange, reading at most `MAX_BODY_BYTES` of body.
async fn fetch_once(url: &Uri, secure: bool) -> anyhow::Result<FetchOutcome> {
    let host = url.host().ok_or_else(|| anyhow::anyhow!("no host"))?;
    let port = url.port_u16().unwrap_or(if secure { 443 } else { 80 });

    // A bracketed IPv6 literal in the URI needs unwrapping before it can be
    // handed to the resolver.
    let connect_host = host.trim_start_matches('[').trim_end_matches(']');
    let stream = TcpStream::connect((connect_host, port)).await?;

    // Origin-form: just the path. Handing hyper the absolute URI makes it emit
    // proxy-form (`GET http://host/ HTTP/1.1`), which is legal but routes
    // differently on servers that match the raw target — Chrome's DevTools
    // endpoint answers 404 to it, so we would misreport a healthy service.
    let target = url.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let request = Request::builder()
        .method("GET")
        .uri(target)
        .header("host", format!("{host}:{port}"))
        // Some servers content-negotiate; ask for HTML so we get a <title>.
        .header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .header("user-agent", "ports-scanner/0.2 (+localhost inventory)")
        .header("connection", "close")
        .body(String::new())?;

    let (response, tls) = if secure {
        let server_name = match connect_host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(connect_host.to_string())?,
        };
        let stream = tls_connector().connect(server_name, stream).await?;

        let (_, connection) = stream.get_ref();
        let tls = describe_cert(
            connection.peer_certificates().unwrap_or(&[]),
            connection.protocol_version().map(|v| format!("{v:?}")),
        );

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        (sender.send_request(request).await?, tls)
    } else {
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        (sender.send_request(request).await?, None)
    };

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    // Stop reading once we have all the head we could need; a dev server
    // streaming logs from `/` would otherwise never finish.
    let mut body = response.into_body();
    let mut collected: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Some(chunk) = frame.data_ref() {
            let remaining = MAX_BODY_BYTES.saturating_sub(collected.len());
            if remaining == 0 {
                break;
            }
            let take = chunk.len().min(remaining);
            collected.extend_from_slice(&chunk[..take]);
            if collected.len() >= MAX_BODY_BYTES {
                break;
            }
        }
    }

    Ok(FetchOutcome {
        status,
        headers,
        body: String::from_utf8_lossy(&collected).into_owned(),
        tls,
        final_url: url.to_string(),
    })
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// GET a URL, following a few redirects so long as they stay on this machine.
///
/// An external redirect is left unfollowed and recorded as such: a localhost
/// port that bounces you to a public site is a finding, not something to chase.
async fn fetch_head(
    start: Uri,
    secure: bool,
) -> anyhow::Result<(FetchOutcome, u16, Option<String>)> {
    let mut url = start;
    let mut secure = secure;
    let mut first_status: Option<u16> = None;
    let mut first_redirect: Option<String> = None;

    for _ in 0..=MAX_REDIRECTS {
        let outcome = fetch_once(&url, secure).await?;
        let status = outcome.status;
        first_status.get_or_insert(status);

        let location = outcome.headers.get("location").cloned();
        let Some(location) = location.filter(|_| (300..400).contains(&status)) else {
            return Ok((outcome, first_status.unwrap_or(status), first_redirect));
        };

        // Resolve against the current URL so a relative Location works.
        let Ok(base) = url::Url::parse(&url.to_string()) else {
            return Ok((outcome, first_status.unwrap_or(status), first_redirect));
        };
        let Ok(next) = base.join(&location) else {
            return Ok((outcome, first_status.unwrap_or(status), first_redirect));
        };
        if !next.host_str().map(is_loopback_host).unwrap_or(false) {
            return Ok((outcome, first_status.unwrap_or(status), first_redirect));
        }

        first_redirect.get_or_insert(location);
        secure = next.scheme() == "https";
        let Ok(parsed) = next.as_str().parse::<Uri>() else {
            return Ok((outcome, first_status.unwrap_or(status), first_redirect));
        };
        url = parsed;
    }

    // Ran out of redirect budget; re-fetch is not worth it, report what we have.
    let outcome = fetch_once(&url, secure).await?;
    let status = first_status.unwrap_or(outcome.status);
    Ok((outcome, status, first_redirect))
}

/// Full probe of a single open port: classify it, then describe it.
pub async fn probe_port(port: u16, host: IpAddr) -> ProbeResult {
    let started = Instant::now();
    let elapsed = |start: Instant| start.elapsed().as_millis() as u64;

    match tokio::time::timeout(PROBE_DEADLINE, probe_inner(port, host)).await {
        Ok(mut result) => {
            result.probe_ms = elapsed(started);
            result
        }
        Err(_) => ProbeResult {
            protocol: Protocol::Tcp,
            probe_ms: elapsed(started),
            error: Some("probe deadline exceeded".into()),
            ..Default::default()
        },
    }
}

async fn probe_inner(port: u16, host: IpAddr) -> ProbeResult {
    let hint = sniff(port, host).await;

    if hint == Hint::Closed {
        return ProbeResult {
            protocol: Protocol::Tcp,
            error: Some("no response".into()),
            ..Default::default()
        };
    }

    // No plaintext fallback on the TLS path: the sniff already sent a cleartext
    // GET and it did not produce an HTTP reply, so repeating it can only burn
    // another request timeout before failing the same way.
    let secure = hint == Hint::MaybeTls;
    let scheme = if secure { "https" } else { "http" };
    let host_for_url = if host.is_ipv6() {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    let Ok(uri) = format!("{scheme}://{host_for_url}:{port}/").parse::<Uri>() else {
        return ProbeResult {
            protocol: Protocol::Tcp,
            error: Some("could not build url".into()),
            ..Default::default()
        };
    };

    match tokio::time::timeout(REQUEST_TIMEOUT, fetch_head(uri, secure)).await {
        Ok(Ok((outcome, first_status, redirect_to))) => {
            let mut http = HttpInfo {
                status: if first_status == 0 {
                    outcome.status
                } else {
                    first_status
                },
                redirect_to,
                server: outcome.headers.get("server").cloned(),
                powered_by: outcome.headers.get("x-powered-by").cloned(),
                content_type: outcome.headers.get("content-type").cloned(),
                framework: detect_framework(&outcome.headers),
                ..Default::default()
            };

            // Only recorded when we actually followed the chain, which
            // `fetch_head` does only within loopback.
            if outcome.status != http.status {
                http.final_status = Some(outcome.status);
                http.final_url = Some(outcome.final_url.clone());
            }

            let is_html = outcome
                .headers
                .get("content-type")
                .map(|ct| ct.contains("html"))
                .unwrap_or(false)
                || {
                    let head = &outcome.body[..outcome.body.len().min(512)].to_lowercase();
                    head.contains("<html") || head.contains("<!doctype html")
                };

            let meta = is_html.then(|| extract_meta(&outcome.body, &outcome.final_url));

            ProbeResult {
                protocol: if secure {
                    Protocol::Https
                } else {
                    Protocol::Http
                },
                http: Some(http),
                meta,
                tls: outcome.tls,
                ..Default::default()
            }
        }
        Ok(Err(err)) => ProbeResult {
            protocol: Protocol::Tcp,
            error: Some(err.to_string()),
            ..Default::default()
        },
        Err(_) => ProbeResult {
            protocol: Protocol::Tcp,
            error: Some("timeout".into()),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A server that answers every connection with a fixed payload.
    ///
    /// It must keep accepting: a probe makes two connections to a port, one to
    /// sniff the protocol and a second to actually fetch.
    async fn serve(payload: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = socket.read(&mut scratch).await;
                    let _ = socket.write_all(payload.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn describes_a_plain_http_server() {
        let body = "<html><head><title>Acme</title></head><body>hi</body></html>";
        let payload: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nserver: nginx\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );

        let port = serve(payload).await;
        let result = probe_port(port, IpAddr::from([127, 0, 0, 1])).await;

        assert_eq!(result.protocol, Protocol::Http);
        let http = result.http.expect("http info");
        assert_eq!(http.status, 200);
        assert_eq!(http.server.as_deref(), Some("nginx"));
        assert_eq!(http.framework.as_deref(), Some("nginx"));
        assert_eq!(result.meta.and_then(|m| m.title).as_deref(), Some("Acme"));
    }

    /// Capture the raw bytes of the second request a probe makes.
    ///
    /// The first connection is the sniff, which sends a hand-written request;
    /// the second is the real fetch, which is the one worth pinning down.
    #[tokio::test]
    async fn sends_an_origin_form_target_and_exactly_one_host_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    if let Ok(n) = socket.read(&mut buffer).await {
                        sink.lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&buffer[..n]).into_owned());
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        probe_port(port, IpAddr::from([127, 0, 0, 1])).await;

        let requests = captured.lock().unwrap();
        let fetch = requests.last().expect("a fetch request was made");

        // Origin-form. Absolute-form is for proxies, and servers that route on
        // the raw target — Chrome's DevTools endpoint among them — 404 on it.
        assert!(
            fetch.starts_with("GET / HTTP/1.1"),
            "expected origin-form request line, got: {:?}",
            fetch.lines().next()
        );

        let host_headers = fetch
            .lines()
            .filter(|line| line.to_lowercase().starts_with("host:"))
            .count();
        assert_eq!(host_headers, 1, "duplicate Host header in:\n{fetch}");
    }

    #[tokio::test]
    async fn classifies_a_silent_listener_as_tcp() {
        // Accepts the connection, then says nothing — Apple's rapportd, and a
        // good few IPC endpoints, behave exactly like this.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(socket);
            }
        });

        let result = probe_port(port, IpAddr::from([127, 0, 0, 1])).await;
        assert_eq!(result.protocol, Protocol::Tcp);
    }

    #[tokio::test]
    async fn a_closed_port_is_tcp_with_no_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let result = probe_port(port, IpAddr::from([127, 0, 0, 1])).await;
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.error.as_deref(), Some("no response"));
    }

    #[test]
    fn loopback_detection_covers_the_forms_a_redirect_can_use() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("myapp.localhost"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("10.0.0.1"));
    }
}
