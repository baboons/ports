//! End-to-end tests for the reverse proxy.
//!
//! These drive a real proxy against a real upstream over real sockets. The two
//! behaviours worth this much setup are the ones a naive proxy breaks without
//! any error surfacing: a WebSocket upgrade that never completes (Vite's HMR
//! socket, so the page just stops hot-reloading) and a streamed response that
//! gets buffered until the request ends (SSE, so events arrive in one clump at
//! the end or never).

use std::sync::Arc;
use std::time::Duration;

use ports::config::bindings::Bindings;
use ports::proxy::{serve_http, ProxyState};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A throwaway bindings file, unique per proxy.
///
/// Without this the write endpoints would edit the real configuration of
/// whoever runs the suite — these tests bind and unbind for real.
fn scratch_config() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    // One directory per test process, one file per proxy: a directory each
    // would leave dozens behind on every run.
    let dir = std::env::temp_dir().join(format!("ports-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join(format!(
        "bindings-{}.json",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Start the proxy on an ephemeral port with one binding pointing at `target`.
async fn start_proxy(name: &str, target: String) -> u16 {
    // Bind first to learn the port, then hand the number to the proxy: the
    // proxy owns its own listener so it can be started the way it really is.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let mut bindings = Bindings {
        http_port: port,
        https_port: None,
        ..Default::default()
    };
    bindings.upsert(name.to_string(), target, 0);
    let _ = &mut bindings;

    let state = Arc::new(ProxyState::with_path(bindings, scratch_config()));
    tokio::spawn(async move {
        let _ = serve_http(state, port).await;
    });

    // Wait for the listener to come up rather than racing it.
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    port
}

/// Send a raw request through the proxy and return the raw response.
async fn request(proxy_port: u16, host: &str, path: &str) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    socket
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn forwards_a_request_to_the_bound_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap_or(0);
                let received = String::from_utf8_lossy(&buffer[..n]).into_owned();

                // Echo back what the upstream saw, so the test can assert on it.
                let body = received.replace('\r', "");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    let proxy = start_proxy("myapp", format!("127.0.0.1:{upstream_port}")).await;
    let response = request(proxy, "myapp.localhost", "/some/path?q=1").await;

    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
    // The path survives the hop.
    assert!(response.contains("GET /some/path?q=1"));
    // The original Host is preserved, not rewritten to the upstream address:
    // frameworks build absolute URLs from it.
    assert!(
        response.contains("host: myapp.localhost"),
        "Host was not preserved:\n{response}"
    );
    assert!(response.contains("x-forwarded-host: myapp.localhost"));
    assert!(response.contains("x-forwarded-proto: http"));
    assert!(response.contains("x-forwarded-for: 127.0.0.1"));
}

#[tokio::test]
async fn an_unknown_hostname_gets_a_page_naming_what_is_bound() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let response = request(proxy, "nothing-here.localhost", "/").await;

    assert!(response.starts_with("HTTP/1.1 404"), "got: {response}");
    // It should tell you what *is* available rather than just failing.
    assert!(response.contains("myapp.localhost"));

    // The marker is how `ports bind` recognises the proxy and refuses to bind
    // it to itself. Checking the configured port is not enough, because
    // `ports serve --http-port` can move the running proxy off it.
    assert!(
        response.to_lowercase().contains("x-ports-proxy: 1"),
        "self-marker missing:\n{response}"
    );
}

#[tokio::test]
async fn a_bound_name_with_a_dead_upstream_explains_itself() {
    // Port 9 (discard) is reserved and refuses on loopback.
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let response = request(proxy, "myapp.localhost", "/").await;

    assert!(response.starts_with("HTTP/1.1 502"), "got: {response}");
    assert!(response.contains("nothing is listening"));
}

#[tokio::test]
async fn rewrites_a_redirect_that_points_at_the_raw_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            let location = format!("http://127.0.0.1:{upstream_port}/login");
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });

    let proxy = start_proxy("myapp", format!("127.0.0.1:{upstream_port}")).await;
    let response = request(proxy, "myapp.localhost", "/").await;

    assert!(response.starts_with("HTTP/1.1 302"), "got: {response}");
    // Following the upstream's own Location would walk the browser off the
    // proxy and onto the raw port, losing the hostname and its cookies.
    assert!(
        response
            .to_lowercase()
            .contains(&format!("location: http://myapp.localhost:{proxy}/login")),
        "redirect was not rewritten:\n{response}"
    );
}

#[tokio::test]
async fn streams_a_response_without_waiting_for_it_to_finish() {
    // An SSE endpoint: headers, then events spread over time, never ending.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                          transfer-encoding: chunked\r\n\r\n",
                    )
                    .await;
                let _ = socket.flush().await;

                for i in 0..5 {
                    let event = format!("data: tick-{i}\n\n");
                    let chunk = format!("{:x}\r\n{event}\r\n", event.len());
                    if socket.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = socket.flush().await;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            });
        }
    });

    let proxy = start_proxy("sse", format!("127.0.0.1:{upstream_port}")).await;

    let mut socket = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    socket
        .write_all(b"GET /events HTTP/1.1\r\nHost: sse.localhost\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(socket);
    let mut first_event = None;
    let started = std::time::Instant::now();

    // The first event is written ~0ms in and the last ~600ms in. If the proxy
    // buffered, nothing would arrive until the stream ended.
    for _ in 0..40 {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_millis(400), reader.read_line(&mut line)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(_)) => {
                if line.starts_with("data: tick-0") {
                    first_event = Some(started.elapsed());
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    let elapsed = first_event.expect("the first event should arrive");
    assert!(
        elapsed < Duration::from_millis(500),
        "first event took {elapsed:?} — the proxy is buffering the stream"
    );
}

#[tokio::test]
async fn completes_a_websocket_upgrade_and_pipes_both_directions() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();

    // A minimal upgrade handshake, then a byte-level echo. Enough to prove the
    // proxy stopped speaking HTTP and became a pipe, which is all HMR needs.
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).to_lowercase();

                if !request.contains("upgrade: websocket") {
                    let _ = socket
                        .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                }

                let _ = socket
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          upgrade: websocket\r\nconnection: Upgrade\r\n\
                          sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    )
                    .await;
                let _ = socket.flush().await;

                let mut frame = vec![0u8; 64];
                if let Ok(n) = socket.read(&mut frame).await {
                    let _ = socket.write_all(&frame[..n]).await;
                    let _ = socket.flush().await;
                }
            });
        }
    });

    let proxy = start_proxy("hmr", format!("127.0.0.1:{upstream_port}")).await;

    let mut socket = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    socket
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: hmr.localhost\r\n\
              Upgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 512 {
        match tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut byte)).await {
            Ok(Ok(_)) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }

    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "upgrade was not passed through:\n{head}"
    );
    assert!(head.to_lowercase().contains("upgrade: websocket"));

    // Now the tunnel: whatever we send must come back from the upstream.
    socket.write_all(b"ping-through-the-tunnel").await.unwrap();
    socket.flush().await.unwrap();

    let mut echoed = vec![0u8; 23];
    tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut echoed))
        .await
        .expect("tunnel should stay open")
        .expect("tunnel should carry bytes");

    assert_eq!(&echoed, b"ping-through-the-tunnel");
}

// --- The index page and its endpoints ---------------------------------------

/// Send a request with arbitrary headers and return the raw response.
async fn raw(proxy_port: u16, request: &str) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    socket.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn post(host: &str, path: &str, origin: Option<&str>, content_type: &str, body: &str) -> String {
    let origin_header = match origin {
        Some(origin) => format!("Origin: {origin}\r\n"),
        None => String::new(),
    };
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\n{origin_header}\
         Content-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn the_reserved_name_serves_the_index() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let response = request(proxy, "ports.localhost", "/").await;

    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
    assert!(response.contains("text/html"));
    // It should name what is bound.
    assert!(response.contains("myapp"));
}

#[tokio::test]
async fn the_index_page_fetches_nothing_from_the_internet() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let response = request(proxy, "ports.localhost", "/").await;
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();

    // Links to local servers are the whole point; what would break a dashboard
    // used offline is loading assets from elsewhere.
    assert!(
        !body.contains("<script src") && !body.contains("<script  src"),
        "index should inline its script"
    );
    assert!(
        !body.contains("rel=stylesheet") && !body.contains("rel=\"stylesheet\""),
        "index should inline its styles"
    );
    assert!(!body.contains("@import"), "index should not import styles");

    // Every absolute URL on the page must point at this machine.
    for (index, _) in body.match_indices("://") {
        let rest = &body[index + 3..];
        let host: String = rest
            .chars()
            .take_while(|c| !matches!(c, '/' | '"' | '\'' | ' ' | '<' | ')'))
            .collect();
        let bare = host.split(':').next().unwrap_or(&host);
        assert!(
            bare == "localhost" || bare.ends_with(".localhost") || bare == "127.0.0.1",
            "index references {bare:?}, which is not on this machine"
        );
    }
}

#[tokio::test]
async fn the_data_endpoint_returns_json() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let response = request(proxy, "ports.localhost", "/_ports/data").await;

    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
    assert!(response.contains("application/json"));
    assert!(response.contains("\"bound\""));
}

#[tokio::test]
async fn a_cross_origin_post_is_refused() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;

    // The attack this guards against: any page you visit can POST to
    // localhost. Without the check, evil.com could rebind your domains.
    let response = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/bind",
            Some("https://evil.example"),
            "application/json",
            r#"{"name":"pwned","target":"4000"}"#,
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
    assert!(response.contains("cross-origin"));
}

#[tokio::test]
async fn a_post_with_no_origin_at_all_is_refused() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;

    // A same-origin fetch always sends Origin, so its absence on a
    // state-changing request means something else sent it.
    let response = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/bind",
            None,
            "application/json",
            r#"{"name":"pwned","target":"4000"}"#,
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
}

#[tokio::test]
async fn a_form_encoded_post_is_refused_even_from_the_right_origin() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;

    // Form encoding is a "simple request" that skips the CORS preflight, so
    // requiring JSON is a second, independent barrier.
    let response = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/bind",
            Some(&format!("http://ports.localhost:{proxy}")),
            "application/x-www-form-urlencoded",
            "name=pwned&target=4000",
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 415"), "got: {response}");
}

#[tokio::test]
async fn a_same_origin_post_binds_and_unbinds() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let origin = format!("http://ports.localhost:{proxy}");

    let bound = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/bind",
            Some(&origin),
            "application/json",
            r#"{"name":"fromtheindex","target":"4321"}"#,
        ),
    )
    .await;
    assert!(bound.starts_with("HTTP/1.1 200"), "got: {bound}");
    assert!(bound.contains("fromtheindex.localhost"));

    // It should now be routable, which is the whole point.
    let listed = request(proxy, "ports.localhost", "/_ports/data").await;
    assert!(listed.contains("fromtheindex"));

    let unbound = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/unbind",
            Some(&origin),
            "application/json",
            r#"{"name":"fromtheindex"}"#,
        ),
    )
    .await;
    assert!(unbound.starts_with("HTTP/1.1 200"), "got: {unbound}");
}

#[tokio::test]
async fn binding_the_proxy_to_itself_is_refused_from_the_page_too() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let origin = format!("http://ports.localhost:{proxy}");

    let response = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/bind",
            Some(&origin),
            "application/json",
            &format!(r#"{{"name":"loop","target":"{proxy}"}}"#),
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 400"), "got: {response}");
    assert!(response.contains("loop"));
}

#[tokio::test]
async fn a_bound_hostname_still_proxies_rather_than_showing_the_index() {
    // The index must not shadow real traffic: /_ports/ paths only belong to it
    // on hostnames it actually serves.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
                          content-length: 8\r\n\r\nupstream",
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });

    let proxy = start_proxy("myapp", format!("127.0.0.1:{upstream_port}")).await;
    let response = request(proxy, "myapp.localhost", "/_ports/data").await;

    // The app's own /_ports/data, not ours.
    assert!(response.contains("upstream"), "got: {response}");
}

// --- Custom domains ---------------------------------------------------------

/// Start a proxy serving several domains at once.
async fn start_multi_domain(domains: &[&str], name: &str, target: String) -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let mut bindings = Bindings {
        domains: domains.iter().map(|d| d.to_string()).collect(),
        http_port: port,
        https_port: None,
        ..Default::default()
    };
    bindings.upsert(name.to_string(), target, 0);

    let state = Arc::new(ProxyState::with_path(bindings, scratch_config()));
    tokio::spawn(async move {
        let _ = serve_http(state, port).await;
    });

    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    port
}

/// An upstream that says which host it was asked for.
async fn echoing_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap_or(0);
                let body = String::from_utf8_lossy(&buffer[..n]).replace('\r', "");
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
                             content-length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn a_binding_answers_under_every_configured_domain() {
    let upstream = echoing_upstream().await;
    let proxy = start_multi_domain(
        &["localhost", "devbox.lan"],
        "myapp",
        format!("127.0.0.1:{upstream}"),
    )
    .await;

    // The same binding, reached by the name you use on the box and the name
    // your hosts file points at it from the rest of the network.
    for host in ["myapp.localhost", "myapp.devbox.lan"] {
        let response = request(proxy, host, "/").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{host} got: {response}"
        );
        // Host is preserved, so the app generates links for the name used.
        assert!(
            response.contains(&format!("host: {host}")),
            "{host} was not preserved:\n{response}"
        );
    }
}

#[tokio::test]
async fn a_domain_that_is_not_configured_does_not_route() {
    let upstream = echoing_upstream().await;
    let proxy = start_multi_domain(
        &["localhost", "devbox.lan"],
        "myapp",
        format!("127.0.0.1:{upstream}"),
    )
    .await;

    let response = request(proxy, "myapp.somewhere-else.lan", "/").await;
    assert!(response.starts_with("HTTP/1.1 404"), "got: {response}");
}

#[tokio::test]
async fn the_index_answers_under_every_configured_domain() {
    let proxy =
        start_multi_domain(&["localhost", "devbox.lan"], "myapp", "127.0.0.1:9".into()).await;

    for host in ["ports.localhost", "ports.devbox.lan"] {
        let response = request(proxy, host, "/").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{host} got: {response}"
        );
        assert!(response.contains("text/html"));
    }
}

#[tokio::test]
async fn the_bare_domain_shows_the_index_rather_than_an_error() {
    let proxy = start_multi_domain(&["devbox.lan"], "myapp", "127.0.0.1:9".into()).await;

    // Someone typing http://devbox.lan/ should see what is available.
    let response = request(proxy, "devbox.lan", "/").await;
    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
    assert!(response.contains("text/html"));
}

#[tokio::test]
async fn a_longer_domain_wins_over_a_shorter_one() {
    let upstream = echoing_upstream().await;
    // Both configured: myapp.devbox.lan must be `myapp`, not `myapp.devbox`.
    let proxy = start_multi_domain(
        &["lan", "devbox.lan"],
        "myapp",
        format!("127.0.0.1:{upstream}"),
    )
    .await;

    let response = request(proxy, "myapp.devbox.lan", "/").await;
    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
}

// --- Managing domains from the page -----------------------------------------

#[tokio::test]
async fn a_domain_can_be_added_and_removed_from_the_page() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let origin = format!("http://ports.localhost:{proxy}");

    let added = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/domain/add",
            Some(&origin),
            "application/json",
            r#"{"domain":"devbox.lan"}"#,
        ),
    )
    .await;
    assert!(added.starts_with("HTTP/1.1 200"), "got: {added}");

    // Adding it must actually change routing, not just the listing.
    let routed = request(proxy, "myapp.devbox.lan", "/").await;
    assert!(
        !routed.starts_with("HTTP/1.1 404"),
        "the new domain should route:\n{routed}"
    );

    let removed = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/domain/remove",
            Some(&origin),
            "application/json",
            r#"{"domain":"devbox.lan"}"#,
        ),
    )
    .await;
    assert!(removed.starts_with("HTTP/1.1 200"), "got: {removed}");

    let gone = request(proxy, "myapp.devbox.lan", "/").await;
    assert!(gone.starts_with("HTTP/1.1 404"), "got: {gone}");
}

#[tokio::test]
async fn the_page_cannot_remove_the_last_domain() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let origin = format!("http://ports.localhost:{proxy}");

    // It would leave the proxy answering for nothing, the page included.
    let response = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/domain/remove",
            Some(&origin),
            "application/json",
            r#"{"domain":"localhost"}"#,
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 400"), "got: {response}");
    assert!(response.contains("only domain"));

    // And the page is still there.
    assert!(request(proxy, "ports.localhost", "/")
        .await
        .starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn the_page_refuses_a_domain_the_cli_would_refuse() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;
    let origin = format!("http://ports.localhost:{proxy}");

    for bad in ["myapp.dev", "has space", "under_score"] {
        let response = raw(
            proxy,
            &post(
                "ports.localhost",
                "/_ports/domain/add",
                Some(&origin),
                "application/json",
                &format!(r#"{{"domain":"{bad}"}}"#),
            ),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "{bad} should have been refused, got: {response}"
        );
    }
}

#[tokio::test]
async fn domain_changes_carry_the_same_guards_as_binding() {
    let proxy = start_proxy("myapp", "127.0.0.1:9".to_string()).await;

    // Cross-origin.
    let hostile = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/domain/add",
            Some("https://evil.example"),
            "application/json",
            r#"{"domain":"evil.lan"}"#,
        ),
    )
    .await;
    assert!(hostile.starts_with("HTTP/1.1 403"), "got: {hostile}");

    // Form-encoded, which skips the CORS preflight.
    let simple = raw(
        proxy,
        &post(
            "ports.localhost",
            "/_ports/domain/add",
            Some(&format!("http://ports.localhost:{proxy}")),
            "application/x-www-form-urlencoded",
            "domain=evil.lan",
        ),
    )
    .await;
    assert!(simple.starts_with("HTTP/1.1 415"), "got: {simple}");

    // Neither should have taken effect.
    let listed = request(proxy, "ports.localhost", "/_ports/data").await;
    assert!(
        !listed.contains("evil.lan"),
        "a refused domain was added anyway"
    );
}

#[tokio::test]
async fn the_data_endpoint_reports_the_domains() {
    let proxy =
        start_multi_domain(&["localhost", "devbox.lan"], "myapp", "127.0.0.1:9".into()).await;
    let response = request(proxy, "ports.localhost", "/_ports/data").await;

    assert!(response.contains("\"domains\""));
    assert!(response.contains("devbox.lan"));
    // The page needs to know whether to draw its controls at all.
    assert!(response.contains("\"writable\":true"));
}
