//! A DNS server that only knows how to say "loopback".
//!
//! Needed only when the local TLD is not `.localhost`, which the OS already
//! resolves on its own. Everything under the configured TLD answers 127.0.0.1
//! (or ::1), everything else is NXDOMAIN.
//!
//! Hand-rolled rather than pulled from a DNS crate: the subset of the protocol
//! required here is a header, one question and one answer record, and a full
//! server library brings a zone model, recursion and a resolver we would never
//! use.

pub mod resolver;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// The unprivileged port the responder listens on.
///
/// `/etc/resolver/<tld>` supports a `port` keyword, so nothing here needs root
/// even when the TLD is custom.
pub const DNS_PORT: u16 = 15353;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// Long enough to spare the resolver, short enough that unbinding takes effect.
const TTL_SECONDS: u32 = 60;

#[derive(Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Whether the client asked us to recurse; echoed back so it does not warn.
    pub recursion_desired: bool,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The question section exactly as received, to copy into the reply.
    pub question: Vec<u8>,
}

/// Parse a query far enough to answer it.
///
/// Compression pointers are rejected rather than followed: they are not legal
/// in a question section, and following them is how a DNS parser gets an
/// infinite loop from a hostile packet.
pub fn parse_query(buffer: &[u8]) -> Option<Query> {
    if buffer.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([buffer[0], buffer[1]]);
    let flags = u16::from_be_bytes([buffer[2], buffer[3]]);
    let qdcount = u16::from_be_bytes([buffer[4], buffer[5]]);

    // A response, or anything other than exactly one question, is not ours.
    if flags & 0x8000 != 0 || qdcount != 1 {
        return None;
    }
    let recursion_desired = flags & 0x0100 != 0;

    let mut cursor = 12;
    let mut labels: Vec<String> = Vec::new();

    loop {
        let length = *buffer.get(cursor)? as usize;
        if length == 0 {
            cursor += 1;
            break;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        cursor += 1;
        let end = cursor + length;
        let label = buffer.get(cursor..end)?;
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        cursor = end;
        // A name cannot exceed 255 bytes; refuse to walk past that.
        if cursor > 255 + 12 {
            return None;
        }
    }

    let qtype = u16::from_be_bytes([*buffer.get(cursor)?, *buffer.get(cursor + 1)?]);
    let qclass = u16::from_be_bytes([*buffer.get(cursor + 2)?, *buffer.get(cursor + 3)?]);
    let question = buffer.get(12..cursor + 4)?.to_vec();

    Some(Query {
        id,
        recursion_desired,
        name: labels.join("."),
        qtype,
        qclass,
        question,
    })
}

/// What we decided to say.
pub enum Answer {
    Address(IpAddr),
    /// The name exists but has no record of the type asked for.
    NoData,
    NameError,
}

pub fn build_response(query: &Query, answer: &Answer) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);

    let rcode: u16 = match answer {
        Answer::NameError => 3,
        _ => 0,
    };
    let answer_count: u16 = match answer {
        Answer::Address(_) => 1,
        _ => 0,
    };

    // QR (response) + AA (authoritative), echoing RD so the client's own flag
    // comes back as the spec requires.
    let mut flags: u16 = 0x8000 | 0x0400 | rcode;
    if query.recursion_desired {
        flags |= 0x0100;
    }

    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&answer_count.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    out.extend_from_slice(&query.question);

    if let Answer::Address(address) = answer {
        // Point back at the question's name rather than repeating it.
        out.extend_from_slice(&[0xC0, 0x0C]);
        let (rtype, rdata): (u16, Vec<u8>) = match address {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL_SECONDS.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }

    out
}

/// Decide what to answer for a name.
pub fn answer_for(query: &Query, tld: &str) -> Answer {
    if query.qclass != CLASS_IN {
        return Answer::NameError;
    }

    let tld = tld.trim_matches('.').to_lowercase();
    let under_tld = query.name == tld || query.name.ends_with(&format!(".{tld}"));
    if !under_tld {
        return Answer::NameError;
    }

    match query.qtype {
        TYPE_A => Answer::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        TYPE_AAAA => Answer::Address(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        // The name exists, it just has no MX or HTTPS record. Saying NXDOMAIN
        // here would make some resolvers treat the whole name as missing.
        _ => Answer::NoData,
    }
}

/// Bind and serve. Used by tests; the daemon binds separately so it can give
/// up its privileges before answering anything.
pub async fn serve(tld: Arc<RwLock<String>>, port: u16) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    serve_on(socket, tld).await
}

/// Serve DNS over an already-bound socket.
pub async fn serve_on(socket: UdpSocket, tld: Arc<RwLock<String>>) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; 512];

    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let Some(query) = parse_query(&buffer[..size]) else {
            continue;
        };

        let answer = answer_for(&query, &tld.read().await);
        let response = build_response(&query, &answer);
        let _ = socket.send_to(&response, peer).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a question the way a resolver would.
    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    #[test]
    fn parses_a_question() {
        let query = parse_query(&query_bytes("myapp.test", TYPE_A)).expect("should parse");
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.name, "myapp.test");
        assert_eq!(query.qtype, TYPE_A);
        assert!(query.recursion_desired);
    }

    #[test]
    fn parses_a_multi_level_name() {
        let query = parse_query(&query_bytes("api.myapp.test", TYPE_A)).unwrap();
        assert_eq!(query.name, "api.myapp.test");
    }

    #[test]
    fn names_are_matched_case_insensitively() {
        let query = parse_query(&query_bytes("MyApp.TEST", TYPE_A)).unwrap();
        assert_eq!(query.name, "myapp.test");
        assert!(matches!(answer_for(&query, "test"), Answer::Address(_)));
    }

    #[test]
    fn rejects_malformed_and_hostile_packets() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0u8; 11]).is_none());

        // A compression pointer in the question: legal to encode, not legal
        // here, and following it is how a parser gets an infinite loop.
        let mut hostile = query_bytes("myapp.test", TYPE_A);
        hostile[12] = 0xC0;
        hostile[13] = 0x0C;
        assert!(parse_query(&hostile).is_none());

        // A response, not a query.
        let mut response = query_bytes("myapp.test", TYPE_A);
        response[2] = 0x81;
        assert!(parse_query(&response).is_none());
    }

    #[test]
    fn answers_a_under_the_tld_with_loopback() {
        let query = parse_query(&query_bytes("myapp.test", TYPE_A)).unwrap();
        match answer_for(&query, "test") {
            Answer::Address(IpAddr::V4(v4)) => assert_eq!(v4, Ipv4Addr::LOCALHOST),
            _ => panic!("expected a loopback A record"),
        }
    }

    #[test]
    fn answers_aaaa_with_the_v6_loopback() {
        let query = parse_query(&query_bytes("myapp.test", TYPE_AAAA)).unwrap();
        match answer_for(&query, "test") {
            Answer::Address(IpAddr::V6(v6)) => assert_eq!(v6, Ipv6Addr::LOCALHOST),
            _ => panic!("expected a loopback AAAA record"),
        }
    }

    #[test]
    fn the_bare_tld_resolves_too() {
        let query = parse_query(&query_bytes("test", TYPE_A)).unwrap();
        assert!(matches!(answer_for(&query, "test"), Answer::Address(_)));
    }

    #[test]
    fn anything_outside_the_tld_is_nxdomain() {
        for name in ["example.com", "myapp.localhost", "nottest"] {
            let query = parse_query(&query_bytes(name, TYPE_A)).unwrap();
            assert!(
                matches!(answer_for(&query, "test"), Answer::NameError),
                "{name} should not resolve"
            );
        }
    }

    #[test]
    fn an_unsupported_record_type_is_nodata_not_nxdomain() {
        // Chrome asks for HTTPS (type 65) alongside A. Answering NXDOMAIN
        // would tell it the whole name is missing.
        let query = parse_query(&query_bytes("myapp.test", 65)).unwrap();
        assert!(matches!(answer_for(&query, "test"), Answer::NoData));
    }

    #[test]
    fn a_response_echoes_the_id_and_carries_the_address() {
        let query = parse_query(&query_bytes("myapp.test", TYPE_A)).unwrap();
        let response = build_response(&query, &answer_for(&query, "test"));

        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x1234);
        // QR and AA set, RCODE 0.
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR should be set");
        assert_eq!(flags & 0x0400, 0x0400, "AA should be set");
        assert_eq!(flags & 0x000F, 0, "RCODE should be 0");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        // The A record's RDATA is the last four bytes.
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn an_nxdomain_response_sets_rcode_3_and_carries_no_answer() {
        let query = parse_query(&query_bytes("example.com", TYPE_A)).unwrap();
        let response = build_response(&query, &answer_for(&query, "test"));

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 3, "RCODE should be NXDOMAIN");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn resolves_over_a_real_socket() {
        let tld = Arc::new(RwLock::new("test".to_string()));
        // Port 0 lets the OS pick; bind first to learn which.
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        tokio::spawn(async move {
            let _ = serve(tld, port).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(("127.0.0.1", port)).await.unwrap();
        client.send(&query_bytes("myapp.test", TYPE_A)).await.unwrap();

        let mut buffer = vec![0u8; 512];
        let size = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv(&mut buffer),
        )
        .await
        .expect("responder should reply")
        .unwrap();

        assert_eq!(&buffer[size - 4..size], &[127, 0, 0, 1]);
    }
}
