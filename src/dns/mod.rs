//! A resolver that answers for the bound domains and forwards the rest.
//!
//! Names under a configured domain get 127.0.0.1 (or ::1); anything else is
//! relayed to an upstream resolver — Cloudflare by default — and its reply
//! returned untouched. That second half is what lets a whole network point at
//! this machine, rather than only this machine pointing at itself.
//!
//! Hand-rolled rather than pulled from a DNS crate. What we parse is a header
//! and one question, and what we generate is one A or AAAA record; everything
//! else is bytes in and bytes out. A server library would bring a zone model,
//! recursion and a cache we do not use.

pub mod resolver;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::config::bindings::Bindings;

/// How long to wait on one upstream before trying the next.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
/// DNS over TCP is length-prefixed; nothing legitimate approaches this.
const MAX_TCP_MESSAGE: usize = 8 * 1024;

/// Kept as the default; the configured value is what actually binds.
pub const DNS_PORT: u16 = crate::config::bindings::DEFAULT_DNS_PORT;

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
    /// We will not resolve this for you.
    Refused,
    /// We should have been able to answer and could not.
    ServerFailure,
}

pub fn build_response(query: &Query, answer: &Answer) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);

    let rcode: u16 = match answer {
        Answer::ServerFailure => 2,
        Answer::NameError => 3,
        Answer::Refused => 5,
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

/// Which of our addresses can this client actually reach us on?
///
/// Answering 127.0.0.1 to a machine across the network sends it to itself.
/// The kernel already knows which of our addresses it would use to talk to a
/// given peer, so ask it: connecting a UDP socket sends nothing, it just fixes
/// a route and a source address.
pub fn address_for_client(client: IpAddr, bindings: &Bindings, want_v6: bool) -> Option<IpAddr> {
    // Explicitly configured wins — auto-detection cannot know which of a
    // docker bridge and a LAN interface you meant. Only for the family asked
    // about, so a v4 override does not become a bogus AAAA.
    if let Some(advertise) = bindings
        .dns
        .advertise
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
    {
        return (advertise.is_ipv6() == want_v6).then_some(advertise);
    }

    // On the machine itself both families reach us, whichever it asked from.
    if client.is_loopback() {
        return Some(if want_v6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        });
    }

    // We can only route to a peer over the family it reached us on, so a v4
    // client has no v6 answer to be given.
    if client.is_ipv6() != want_v6 {
        return None;
    }

    let bind = if want_v6 { "[::]:0" } else { "0.0.0.0:0" };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    // Port 53 is arbitrary; connecting a UDP socket sends nothing, it only
    // asks the kernel which source address it would use.
    socket.connect((client, 53)).ok()?;
    let local = socket.local_addr().ok()?.ip();

    // A route resolving to a loopback or unspecified source tells the client
    // nothing it can use.
    if local.is_loopback() || local.is_unspecified() {
        return None;
    }
    Some(local)
}

/// Decide what to answer for a name, or None when it is not ours to answer.
///
/// None is the signal to forward: a name outside our domains is a question for
/// somebody else, not a name that does not exist.
pub fn answer_for_domains(query: &Query, bindings: &Bindings, client: IpAddr) -> Option<Answer> {
    if query.qclass != CLASS_IN {
        return None;
    }

    let ours = bindings.domains.iter().any(|domain| {
        let domain = domain.trim_matches('.').to_lowercase();
        query.name == domain || query.name.ends_with(&format!(".{domain}"))
    });
    if !ours {
        return None;
    }

    Some(match query.qtype {
        // No address this client could use means no answer. Handing back
        // 127.0.0.1 would point it at itself, which is worse than silence.
        TYPE_A => match address_for_client(client, bindings, false) {
            Some(address) => Answer::Address(address),
            None => Answer::NoData,
        },
        TYPE_AAAA => match address_for_client(client, bindings, true) {
            Some(address) => Answer::Address(address),
            None => Answer::NoData,
        },
        // The name exists, it just has no MX or HTTPS record. Saying NXDOMAIN
        // here would make some resolvers treat the whole name as missing.
        _ => Answer::NoData,
    })
}

/// Decide what to answer for a single domain. Kept for the tests that predate
/// the domain list, and for anyone reasoning about one domain at a time.
pub fn answer_for(query: &Query, tld: &str) -> Answer {
    let bindings = Bindings {
        domains: vec![tld.to_string()],
        ..Default::default()
    };
    answer_for_domains(query, &bindings, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap_or(Answer::NameError)
}

/// Everything the resolver needs to answer a query.
pub struct Resolver {
    /// Shared with the proxy, so a domain added from the page resolves at once.
    pub bindings: Arc<RwLock<Bindings>>,
}

impl Resolver {
    pub fn new(bindings: Arc<RwLock<Bindings>>) -> Self {
        Self { bindings }
    }

    /// Produce a reply for one query message.
    ///
    /// Returns None when the query is unparseable or the client has no
    /// business asking us, in which case nothing is sent back at all.
    pub async fn respond(&self, packet: &[u8], client: IpAddr) -> Option<Vec<u8>> {
        let query = parse_query(packet)?;

        let (answer, forwarders) = {
            let bindings = self.bindings.read().await;
            let answer = answer_for_domains(&query, &bindings, client);
            (answer, bindings.dns.forwarders())
        };

        // A name we own is answered here, whoever asked.
        if let Some(answer) = answer {
            return Some(build_response(&query, &answer));
        }

        // Everything else is someone else's to answer. Only for clients we are
        // willing to resolve on behalf of.
        if !may_forward_for(client) {
            return Some(build_response(&query, &Answer::Refused));
        }

        match forward(packet, &forwarders).await {
            Some(reply) => Some(reply),
            // Upstream unreachable is a server failure, not a missing name:
            // NXDOMAIN would tell the client the name does not exist and get
            // cached as such.
            None => Some(build_response(&query, &Answer::ServerFailure)),
        }
    }
}

/// Should we resolve arbitrary names for this client?
///
/// Loopback and private networks only. Binding :53 on a machine whose router
/// forwards port 53 would otherwise make it an open resolver, which is a
/// reflection-attack amplifier that gets you a call from your ISP.
pub fn may_forward_for(client: IpAddr) -> bool {
    match client {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // Loopback, link-local (fe80::/10) and unique-local (fc00::/7).
            v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Relay a query to the first upstream that answers.
async fn forward(packet: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for upstream in upstreams {
        // An ephemeral socket per query, bound to match the upstream family.
        let bind: SocketAddr = if upstream.is_ipv6() {
            "[::]:0".parse().ok()?
        } else {
            "0.0.0.0:0".parse().ok()?
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        if socket.send_to(packet, upstream).await.is_err() {
            continue;
        }

        let mut buffer = vec![0u8; 4096];
        match tokio::time::timeout(FORWARD_TIMEOUT, socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, from))) if from.ip() == upstream.ip() => {
                buffer.truncate(size);
                return Some(buffer);
            }
            // A reply from somewhere else is not an answer to this question.
            _ => continue,
        }
    }
    None
}

/// Serve DNS over UDP on an already-bound socket.
pub async fn serve_udp(socket: UdpSocket, resolver: Arc<Resolver>) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 4096];

    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let packet = buffer[..size].to_vec();
        let socket = Arc::clone(&socket);
        let resolver = Arc::clone(&resolver);

        // Spawned so a slow upstream cannot hold up every other query.
        tokio::spawn(async move {
            if let Some(reply) = resolver.respond(&packet, peer.ip()).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

/// Serve DNS over TCP.
///
/// Not optional in practice: when a reply does not fit in a UDP datagram the
/// server sets the truncated bit and the client retries over TCP, so a
/// UDP-only resolver fails on exactly the large answers it should handle.
pub async fn serve_tcp(listener: TcpListener, resolver: Arc<Resolver>) -> anyhow::Result<()> {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            let _ = handle_tcp(stream, peer.ip(), resolver).await;
        });
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    client: IpAddr,
    resolver: Arc<Resolver>,
) -> anyhow::Result<()> {
    // DNS over TCP frames every message with its length.
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_TCP_MESSAGE {
        return Ok(());
    }

    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await?;

    let Some(reply) = resolver.respond(&packet, client).await else {
        return Ok(());
    };

    stream
        .write_all(&(reply.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
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

    fn table(domains: &[&str]) -> Arc<RwLock<Bindings>> {
        Arc::new(RwLock::new(Bindings {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        }))
    }

    /// A stand-in upstream that answers everything with one fixed address.
    async fn fake_upstream(address: [u8; 4]) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                let Some(query) = parse_query(&buffer[..size]) else {
                    continue;
                };
                let reply = build_response(&query, &Answer::Address(IpAddr::V4(address.into())));
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        local
    }

    #[tokio::test]
    async fn a_remote_client_is_told_an_address_it_can_actually_reach() {
        // The bug this exists for: answering 127.0.0.1 to a machine across
        // the network sends it to itself.
        let bindings = Bindings {
            domains: vec!["nas.lan".into()],
            ..Default::default()
        };

        // Route lookup for a public address, which any machine with a default
        // route can do without sending anything.
        let answer = address_for_client("1.1.1.1".parse().unwrap(), &bindings, false);
        if let Some(address) = answer {
            assert!(
                !address.is_loopback(),
                "told a remote client to use {address}"
            );
        }

        // Loopback still gets loopback.
        assert_eq!(
            address_for_client("127.0.0.1".parse().unwrap(), &bindings, false),
            Some("127.0.0.1".parse().unwrap())
        );
        // And a loopback client still gets both families.
        assert_eq!(
            address_for_client("127.0.0.1".parse().unwrap(), &bindings, true),
            Some("::1".parse().unwrap())
        );
    }

    #[test]
    fn an_explicit_advertise_address_overrides_the_routing_table() {
        // A box with a docker bridge can route to the wrong interface.
        let bindings = Bindings {
            domains: vec!["nas.lan".into()],
            dns: crate::config::bindings::DnsConfig {
                advertise: Some("10.0.1.2".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        for client in ["127.0.0.1", "10.0.1.50", "1.1.1.1"] {
            assert_eq!(
                address_for_client(client.parse().unwrap(), &bindings, false),
                Some("10.0.1.2".parse().unwrap()),
                "{client}"
            );
            // A v4 override is not an AAAA answer.
            assert_eq!(
                address_for_client(client.parse().unwrap(), &bindings, true),
                None,
                "{client}"
            );
        }
    }

    #[tokio::test]
    async fn the_advertised_address_is_what_the_answer_carries() {
        let bindings = Arc::new(RwLock::new(Bindings {
            domains: vec!["nas.lan".into()],
            dns: crate::config::bindings::DnsConfig {
                advertise: Some("10.0.1.2".into()),
                ..Default::default()
            },
            ..Default::default()
        }));

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("tvarr.nas.lan", TYPE_A),
                "10.0.1.50".parse().unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(&reply[reply.len() - 4..], &[10, 0, 1, 2]);
    }

    #[tokio::test]
    async fn a_v4_client_asking_for_aaaa_gets_nodata_not_a_useless_answer() {
        let bindings = Arc::new(RwLock::new(Bindings {
            domains: vec!["nas.lan".into()],
            dns: crate::config::bindings::DnsConfig {
                advertise: Some("10.0.1.2".into()),
                ..Default::default()
            },
            ..Default::default()
        }));

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("tvarr.nas.lan", TYPE_AAAA),
                "10.0.1.50".parse().unwrap(),
            )
            .await
            .unwrap();

        // ::1 would send it to itself; NOERROR with no answer is the truth.
        assert_eq!(
            u16::from_be_bytes([reply[6], reply[7]]),
            0,
            "expected no answer"
        );
        assert_eq!(u16::from_be_bytes([reply[2], reply[3]]) & 0x000F, 0);
    }

    #[tokio::test]
    async fn a_name_we_own_is_answered_here_not_forwarded() {
        let bindings = table(&["nas.lan"]);
        // An upstream that would answer differently, to prove it was not asked.
        let upstream = fake_upstream([9, 9, 9, 9]).await;
        bindings.write().await.dns.forward = vec![upstream.to_string()];

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("myapp.nas.lan", TYPE_A),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .expect("should answer");

        assert_eq!(&reply[reply.len() - 4..], &[127, 0, 0, 1]);
    }

    #[tokio::test]
    async fn anything_else_is_forwarded_and_the_reply_returned() {
        let bindings = table(&["nas.lan"]);
        let upstream = fake_upstream([9, 9, 9, 9]).await;
        bindings.write().await.dns.forward = vec![upstream.to_string()];

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("example.com", TYPE_A),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .expect("should forward");

        // The upstream's answer, verbatim.
        assert_eq!(&reply[reply.len() - 4..], &[9, 9, 9, 9]);
        // And the client's transaction id survived the round trip.
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 0x1234);
    }

    #[tokio::test]
    async fn the_first_upstream_that_answers_wins() {
        let bindings = table(&["nas.lan"]);
        let working = fake_upstream([9, 9, 9, 9]).await;
        // A blackhole first: nothing listens on this port.
        let dead = "127.0.0.1:1".to_string();
        bindings.write().await.dns.forward = vec![dead, working.to_string()];

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("example.com", TYPE_A),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .expect("should fall through to the second");

        assert_eq!(&reply[reply.len() - 4..], &[9, 9, 9, 9]);
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_a_server_failure_not_a_missing_name() {
        let bindings = table(&["nas.lan"]);
        bindings.write().await.dns.forward = vec!["127.0.0.1:1".into()];

        let resolver = Resolver::new(bindings);
        let reply = resolver
            .respond(
                &query_bytes("example.com", TYPE_A),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .unwrap();

        // NXDOMAIN would tell the client the name does not exist, and be
        // cached as such long after the upstream came back.
        let rcode = u16::from_be_bytes([reply[2], reply[3]]) & 0x000F;
        assert_eq!(rcode, 2, "expected SERVFAIL");
    }

    #[test]
    fn only_private_clients_get_arbitrary_names_resolved() {
        // Binding :53 where a router forwards it would otherwise make this an
        // open resolver, which is a reflection amplifier.
        for allowed in ["127.0.0.1", "10.0.1.2", "192.168.1.5", "172.16.0.9", "::1"] {
            assert!(
                may_forward_for(allowed.parse().unwrap()),
                "{allowed} is on the local network"
            );
        }
        for refused in ["8.8.8.8", "1.1.1.1", "203.0.113.7", "2606:4700::1111"] {
            assert!(
                !may_forward_for(refused.parse().unwrap()),
                "{refused} is not ours to resolve for"
            );
        }
    }

    #[tokio::test]
    async fn a_public_client_is_refused_rather_than_served() {
        let bindings = table(&["nas.lan"]);
        let resolver = Resolver::new(bindings);

        let reply = resolver
            .respond(
                &query_bytes("example.com", TYPE_A),
                "8.8.8.8".parse().unwrap(),
            )
            .await
            .unwrap();
        let rcode = u16::from_be_bytes([reply[2], reply[3]]) & 0x000F;
        assert_eq!(rcode, 5, "expected REFUSED");

        // Our own domains are still answered, since that reveals nothing an
        // HTTP request to the same box would not. Whatever address comes back
        // must not be loopback, which would point the client at itself.
        let ours = resolver
            .respond(
                &query_bytes("myapp.nas.lan", TYPE_A),
                "8.8.8.8".parse().unwrap(),
            )
            .await
            .unwrap();
        let rcode = u16::from_be_bytes([ours[2], ours[3]]) & 0x000F;
        assert_eq!(rcode, 0, "our own domain should not be refused");
        if u16::from_be_bytes([ours[6], ours[7]]) > 0 {
            assert_ne!(&ours[ours.len() - 4..], &[127, 0, 0, 1]);
        }
    }

    #[tokio::test]
    async fn every_configured_domain_is_answered_locally() {
        let bindings = table(&["nas.lan", "localhost"]);
        let resolver = Resolver::new(bindings);

        for name in ["myapp.nas.lan", "myapp.localhost", "nas.lan"] {
            let reply = resolver
                .respond(&query_bytes(name, TYPE_A), "127.0.0.1".parse().unwrap())
                .await
                .unwrap();
            assert_eq!(&reply[reply.len() - 4..], &[127, 0, 0, 1], "{name}");
        }
    }

    #[tokio::test]
    async fn answers_over_tcp_with_its_length_framing() {
        let bindings = table(&["nas.lan"]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = serve_tcp(listener, Arc::new(Resolver::new(bindings))).await;
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let query = query_bytes("myapp.nas.lan", TYPE_A);
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();

        assert_eq!(&reply[reply.len() - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn forwarders_accept_a_bare_address_or_one_with_a_port() {
        use crate::config::bindings::parse_forwarder;
        assert_eq!(
            parse_forwarder("1.1.1.1").map(|a| a.to_string()).as_deref(),
            Some("1.1.1.1:53")
        );
        assert_eq!(
            parse_forwarder("9.9.9.9:5353")
                .map(|a| a.to_string())
                .as_deref(),
            Some("9.9.9.9:5353")
        );
        assert_eq!(
            parse_forwarder("[2606:4700:4700::1111]:53").map(|a| a.to_string()),
            Some("[2606:4700:4700::1111]:53".to_string())
        );
        assert!(parse_forwarder("not-an-address").is_none());
        assert!(parse_forwarder("").is_none());
    }

    #[tokio::test]
    async fn resolves_over_a_real_socket() {
        let bindings = Arc::new(RwLock::new(Bindings {
            domains: vec!["test".into()],
            ..Default::default()
        }));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();

        tokio::spawn(async move {
            let _ = serve_udp(socket, Arc::new(Resolver::new(bindings))).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(("127.0.0.1", port)).await.unwrap();
        client
            .send(&query_bytes("myapp.test", TYPE_A))
            .await
            .unwrap();

        let mut buffer = vec![0u8; 512];
        let size =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buffer))
                .await
                .expect("responder should reply")
                .unwrap();

        assert_eq!(&buffer[size - 4..size], &[127, 0, 0, 1]);
    }
}
