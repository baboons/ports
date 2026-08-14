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

    let state = Arc::new(ProxyState::new(bindings));
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
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        socket.read_to_end(&mut response),
    )
    .await;
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
        response.to_lowercase().contains(&format!("location: http://myapp.localhost:{proxy}/login")),
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
                    let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n").await;
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
