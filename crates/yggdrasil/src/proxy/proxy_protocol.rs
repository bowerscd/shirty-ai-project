//! PROXY-protocol header emission for upstream connections.
//!
//! Implements both [v1] (ASCII, human-readable, max 107 bytes) and [v2]
//! (binary, fixed 16-byte header + variable address block). The header is
//! emitted once on each new upstream TCP connection, **before** any
//! application-layer bytes flow.
//!
//! [v1]: https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt §2.1
//! [v2]: https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt §2.2

use std::net::{IpAddr, SocketAddr};

use tokio::io::AsyncWriteExt;

use yggdrasil_proto::branch::ProxyProto;

/// Encode + send a PROXY-protocol header describing the original client
/// `(client → server_listen)` connection on the freshly-opened `upstream`
/// stream. Caller must invoke this **before** copying any application data.
pub async fn write_header<W>(
    upstream: &mut W,
    version: ProxyProto,
    client: SocketAddr,
    server_listen: SocketAddr,
) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let buf = encode_header(version, client, server_listen);
    upstream.write_all(&buf).await
}

/// Encode a PROXY-protocol header to a freshly-allocated `Vec<u8>`. Split out
/// from [`write_header`] for unit-testing.
pub fn encode_header(
    version: ProxyProto,
    client: SocketAddr,
    server_listen: SocketAddr,
) -> Vec<u8> {
    match version {
        ProxyProto::V1 => encode_v1(client, server_listen),
        ProxyProto::V2 => encode_v2(client, server_listen),
    }
}

// ---- v1 ASCII -----------------------------------------------------------

fn encode_v1(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    // Spec: "PROXY <protocol> <client> <server> <client_port> <server_port>\r\n"
    // <protocol> ∈ {TCP4, TCP6, UNKNOWN}. We emit UNKNOWN if the family pair
    // mismatches (v1 doesn't support mixed-family).
    let s = match (client.ip(), server.ip()) {
        (IpAddr::V4(c), IpAddr::V4(srv)) => {
            format!(
                "PROXY TCP4 {} {} {} {}\r\n",
                c,
                srv,
                client.port(),
                server.port()
            )
        }
        (IpAddr::V6(c), IpAddr::V6(srv)) => {
            format!(
                "PROXY TCP6 {} {} {} {}\r\n",
                c,
                srv,
                client.port(),
                server.port()
            )
        }
        _ => "PROXY UNKNOWN\r\n".to_string(),
    };
    s.into_bytes()
}

// ---- v2 binary ----------------------------------------------------------

/// Magic v2 signature (12 bytes).
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

fn encode_v2(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    // Header layout (16 bytes fixed prefix):
    //   [0..12)  V2_SIG
    //   [12]     version (0x20) | command (0x01 = PROXY)        => 0x21
    //   [13]     family (high nibble) | protocol (low nibble)
    //                family: 0x1 = AF_INET, 0x2 = AF_INET6, 0x0 = AF_UNSPEC
    //                proto : 0x1 = STREAM (TCP), 0x0 = UNSPEC
    //   [14..16) address-block length in bytes, BE u16
    // Followed by the address block, format depending on family.
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&V2_SIG);
    out.push(0x21); // v2 + PROXY command

    match (client.ip(), server.ip()) {
        (IpAddr::V4(c), IpAddr::V4(s)) => {
            out.push(0x11); // AF_INET + STREAM
            let addr_len: u16 = 4 + 4 + 2 + 2;
            out.extend_from_slice(&addr_len.to_be_bytes());
            out.extend_from_slice(&c.octets());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&server.port().to_be_bytes());
        }
        (IpAddr::V6(c), IpAddr::V6(s)) => {
            out.push(0x21); // AF_INET6 + STREAM
            let addr_len: u16 = 16 + 16 + 2 + 2;
            out.extend_from_slice(&addr_len.to_be_bytes());
            out.extend_from_slice(&c.octets());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&server.port().to_be_bytes());
        }
        _ => {
            // Mixed family — emit LOCAL command (0x20) with AF_UNSPEC/UNSPEC
            // and empty address block. Per spec, LOCAL means "this connection
            // is from the proxy itself; ignore the addresses." Better than
            // lying about the family.
            out[12] = 0x20; // LOCAL command
            out.push(0x00); // AF_UNSPEC + UNSPEC
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: &str) -> SocketAddr {
        a.parse().unwrap()
    }
    fn v6(a: &str) -> SocketAddr {
        a.parse().unwrap()
    }

    #[test]
    fn v1_ipv4_header_matches_spec() {
        let h = encode_v1(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        let s = std::str::from_utf8(&h).unwrap();
        assert_eq!(s, "PROXY TCP4 203.0.113.7 198.51.100.4 54321 443\r\n");
        // Spec says v1 max is 107 bytes for IPv4. (For IPv6 it's 107 too.)
        assert!(h.len() <= 107);
    }

    #[test]
    fn v1_ipv6_header_matches_spec() {
        let h = encode_v1(v6("[2001:db8::1]:54321"), v6("[2001:db8::2]:443"));
        let s = std::str::from_utf8(&h).unwrap();
        assert_eq!(s, "PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n");
        assert!(h.len() <= 107);
    }

    #[test]
    fn v1_mixed_family_emits_unknown() {
        let h = encode_v1(v4("203.0.113.7:54321"), v6("[2001:db8::2]:443"));
        assert_eq!(h, b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn v2_ipv4_header_has_correct_layout() {
        let h = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        // Fixed prefix: 12 sig + 1 ver/cmd + 1 fam/proto + 2 addr_len + 12 addr
        // = 28 bytes total for v4.
        assert_eq!(h.len(), 28);
        assert_eq!(&h[..12], &V2_SIG);
        assert_eq!(h[12], 0x21); // v2 PROXY
        assert_eq!(h[13], 0x11); // AF_INET + STREAM
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 12);
        assert_eq!(&h[16..20], &[203, 0, 113, 7]);
        assert_eq!(&h[20..24], &[198, 51, 100, 4]);
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 54321);
        assert_eq!(u16::from_be_bytes([h[26], h[27]]), 443);
    }

    #[test]
    fn v2_ipv6_header_has_correct_layout() {
        let h = encode_v2(v6("[2001:db8::1]:54321"), v6("[2001:db8::2]:443"));
        // 12 sig + 1 ver/cmd + 1 fam/proto + 2 addr_len + 36 addr = 52.
        assert_eq!(h.len(), 52);
        assert_eq!(&h[..12], &V2_SIG);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x21); // AF_INET6 + STREAM
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 36);
    }

    #[test]
    fn v2_mixed_family_emits_local_command() {
        let h = encode_v2(v4("203.0.113.7:54321"), v6("[2001:db8::2]:443"));
        // 12 sig + 1 ver/cmd + 1 fam/proto + 2 addr_len = 16 (no address payload).
        assert_eq!(h.len(), 16);
        assert_eq!(h[12], 0x20); // v2 LOCAL
        assert_eq!(h[13], 0x00); // AF_UNSPEC + UNSPEC
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 0);
    }

    #[test]
    fn encode_dispatches_on_version() {
        let c = v4("203.0.113.7:1");
        let s = v4("198.51.100.4:1");
        let v1 = encode_header(ProxyProto::V1, c, s);
        let v2 = encode_header(ProxyProto::V2, c, s);
        assert!(v1.starts_with(b"PROXY TCP4"));
        assert_eq!(&v2[..12], &V2_SIG);
    }

    #[tokio::test]
    async fn write_header_emits_v1_bytes() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_header(
            &mut a,
            ProxyProto::V1,
            v4("203.0.113.7:1"),
            v4("198.51.100.4:443"),
        )
        .await
        .unwrap();
        drop(a);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut b, &mut buf).await.unwrap();
        assert_eq!(buf, b"PROXY TCP4 203.0.113.7 198.51.100.4 1 443\r\n");
    }
}
