//! PROXY-protocol header emission for upstream connections.
//!
//! Implements both [v1] (ASCII, human-readable, max 107 bytes) and [v2]
//! (binary, fixed 16-byte header + variable address block). For TCP, the
//! header is emitted once on each new upstream connection **before** any
//! application-layer bytes flow. For UDP HTTPS / HTTP/3 chain traffic,
//! the relay sends a PROXY v2 header as a standalone first datagram on
//! each new (relay→terminal) UDP flow; subsequent datagrams in the same
//! flow are forwarded raw. The terminal's h3 interpose socket calls
//! [`decode_v2_from_datagram`] on every received datagram and gates on
//! the v2 magic; valid QUIC datagrams cannot be mis-classified (see the
//! magic-byte non-collision tests in this module).
//!
//! [v1]: https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt §2.1
//! [v2]: https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt §2.2

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use ratatoskr::rule::ProxyProto;

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

// =============================================================================
// PROXY-protocol decoder (terminal-side ingest)
//
// Used by the L7 HTTPS frontend so that when a relay-mode peer emits PROXY-
// protocol in front of TLS, the terminal can recover the true client address
// and reflect it as X-Forwarded-For. We deliberately do NOT re-emit; the
// header is consumed before the rustls handshake.
//
// We support both v1 (text) and v2 (binary). Detection peeks the first bytes
// of the connection without consuming them on the "no header" path: if the
// first bytes match neither v1 ("PROXY ") nor v2 (V2_SIG), we return
// `Ok(None)` and the read buffer is rolled back into the returned prefix so
// the caller can splice it ahead of the rest of the stream.
//
// Failure modes:
// - v1 line longer than 107 bytes (spec max): error.
// - v1 unparseable family / addresses: error.
// - v2 declared address length larger than reasonable: error.
// - Short read (EOF mid-header): error.
// =============================================================================

/// Maximum allowed v1 line length per spec §2.1.
const V1_MAX_LINE: usize = 107;

/// Maximum v2 address payload we'll accept. The largest well-defined v2
/// payload is TCP6 (36 bytes) + TLVs; we cap at 536 to keep the read bounded
/// while still accommodating a reasonable TLV set.
const V2_MAX_ADDR: usize = 536;

/// Outcome of a successful PROXY-protocol parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyEndpoints {
    /// Original client (source) address asserted by the upstream proxy.
    pub client: SocketAddr,
    /// Local-facing (destination) address asserted by the upstream proxy.
    pub server: SocketAddr,
}

/// Detection + decode result.
///
/// `prefix` always contains every byte that was read from the wire while
/// detecting/parsing. On the `Some(...)` (header present) path, `prefix` is
/// empty after the header is fully consumed. On the `None` path, `prefix`
/// holds the bytes we peeked but did not interpret — callers must splice
/// these in front of subsequent reads.
#[derive(Debug)]
pub struct ProxyDecode {
    pub endpoints: Option<ProxyEndpoints>,
    pub leftover: Vec<u8>,
}

/// Read an optional PROXY-protocol header from `reader`.
///
/// Behavior:
/// - If the first byte hints at v1 (`'P'`) or v2 (`\r`), parse the full
///   header and return endpoints with empty leftover.
/// - Otherwise return `None` and hand back the bytes we read so they can be
///   prepended to the rest of the stream.
pub async fn read_optional_header<R>(reader: &mut R) -> std::io::Result<ProxyDecode>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Peek a single byte. If EOF here, propagate it — caller will see an
    // empty connection.
    let mut first = [0u8; 1];
    let n = reader.read(&mut first).await?;
    if n == 0 {
        return Ok(ProxyDecode {
            endpoints: None,
            leftover: Vec::new(),
        });
    }

    match first[0] {
        b'P' => decode_v1(reader, first[0]).await,
        0x0D => decode_v2(reader, first[0]).await,
        _ => Ok(ProxyDecode {
            endpoints: None,
            leftover: first.to_vec(),
        }),
    }
}

async fn decode_v1<R>(reader: &mut R, first: u8) -> std::io::Result<ProxyDecode>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Read the rest of the magic ("ROXY ") — 5 bytes.
    let mut tail = [0u8; 5];
    reader.read_exact(&mut tail).await?;
    if &tail != b"ROXY " {
        // Looked like v1 but wasn't. Hand the bytes back so the caller can
        // splice and continue without PROXY-protocol awareness.
        let mut leftover = vec![first];
        leftover.extend_from_slice(&tail);
        return Ok(ProxyDecode {
            endpoints: None,
            leftover,
        });
    }

    // Now consume until CRLF, capped at V1_MAX_LINE - 6 (already read 6
    // bytes: "PROXY ").
    let mut line = Vec::with_capacity(V1_MAX_LINE);
    line.extend_from_slice(b"PROXY ");
    let mut saw_cr = false;
    loop {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        line.push(b[0]);
        if b[0] == b'\n' && saw_cr {
            break;
        }
        saw_cr = b[0] == b'\r';
        if line.len() > V1_MAX_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 header exceeds 107 bytes",
            ));
        }
    }

    // Strip trailing CRLF.
    let body = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 not UTF-8"))?;

    // "PROXY UNKNOWN" / "PROXY UNKNOWN ..." → no usable endpoints, but
    // header is well-formed; treat as "header present, no addresses".
    let rest = body
        .strip_prefix("PROXY ")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 prefix"))?;

    if rest.starts_with("UNKNOWN") {
        return Ok(ProxyDecode {
            endpoints: None,
            leftover: Vec::new(),
        });
    }

    let mut parts = rest.split(' ');
    let fam = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 missing family"))?;
    let cli = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 missing client"))?;
    let srv = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 missing server"))?;
    let cp = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 missing cport"))?;
    let sp = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 missing sport"))?;

    let parse_v4 = |a: &str, p: &str| -> std::io::Result<SocketAddr> {
        let ip: Ipv4Addr = a
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 bad ipv4"))?;
        let port: u16 = p
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 bad port"))?;
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    };
    let parse_v6 = |a: &str, p: &str| -> std::io::Result<SocketAddr> {
        let ip: Ipv6Addr = a
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 bad ipv6"))?;
        let port: u16 = p
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "v1 bad port"))?;
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    };

    let endpoints = match fam {
        "TCP4" => ProxyEndpoints {
            client: parse_v4(cli, cp)?,
            server: parse_v4(srv, sp)?,
        },
        "TCP6" => ProxyEndpoints {
            client: parse_v6(cli, cp)?,
            server: parse_v6(srv, sp)?,
        },
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "v1 unknown family",
            ))
        }
    };

    Ok(ProxyDecode {
        endpoints: Some(endpoints),
        leftover: Vec::new(),
    })
}

async fn decode_v2<R>(reader: &mut R, first: u8) -> std::io::Result<ProxyDecode>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Confirm full 12-byte v2 signature.
    let mut rest_sig = [0u8; 11];
    reader.read_exact(&mut rest_sig).await?;
    let mut full_sig = [0u8; 12];
    full_sig[0] = first;
    full_sig[1..].copy_from_slice(&rest_sig);
    if full_sig != V2_SIG {
        // Looked like v2 but wasn't; return raw bytes.
        return Ok(ProxyDecode {
            endpoints: None,
            leftover: full_sig.to_vec(),
        });
    }

    // Next 4 bytes: ver/cmd | fam/proto | addr_len (u16 BE).
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await?;
    let ver_cmd = hdr[0];
    let fam_proto = hdr[1];
    let addr_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;

    if (ver_cmd & 0xF0) != 0x20 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "v2 wrong version",
        ));
    }
    if addr_len > V2_MAX_ADDR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "v2 addr_len too large",
        ));
    }

    let mut payload = vec![0u8; addr_len];
    reader.read_exact(&mut payload).await?;

    // LOCAL command: header present but addresses unusable.
    if (ver_cmd & 0x0F) == 0x00 {
        return Ok(ProxyDecode {
            endpoints: None,
            leftover: Vec::new(),
        });
    }

    // Only TCP over IPv4/IPv6 are recognized; UDP/UNIX yield "header present,
    // no usable endpoints".
    let endpoints = match fam_proto {
        0x11 => {
            // AF_INET + STREAM (TCP4): 4+4+2+2 = 12 bytes.
            if payload.len() < 12 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "v2 TCP4 short payload",
                ));
            }
            let c_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let s_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let c_port = u16::from_be_bytes([payload[8], payload[9]]);
            let s_port = u16::from_be_bytes([payload[10], payload[11]]);
            Some(ProxyEndpoints {
                client: SocketAddr::new(IpAddr::V4(c_ip), c_port),
                server: SocketAddr::new(IpAddr::V4(s_ip), s_port),
            })
        }
        0x21 => {
            // AF_INET6 + STREAM (TCP6): 16+16+2+2 = 36 bytes.
            if payload.len() < 36 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "v2 TCP6 short payload",
                ));
            }
            let mut c_oct = [0u8; 16];
            c_oct.copy_from_slice(&payload[0..16]);
            let mut s_oct = [0u8; 16];
            s_oct.copy_from_slice(&payload[16..32]);
            let c_ip = Ipv6Addr::from(c_oct);
            let s_ip = Ipv6Addr::from(s_oct);
            let c_port = u16::from_be_bytes([payload[32], payload[33]]);
            let s_port = u16::from_be_bytes([payload[34], payload[35]]);
            Some(ProxyEndpoints {
                client: SocketAddr::new(IpAddr::V6(c_ip), c_port),
                server: SocketAddr::new(IpAddr::V6(s_ip), s_port),
            })
        }
        _ => None,
    };

    Ok(ProxyDecode {
        endpoints,
        leftover: Vec::new(),
    })
}

/// Decode a PROXY v2 header from the start of a UDP datagram.
///
/// Returns `Some(endpoints)` if `buf` begins with the v2 magic and parses
/// as a valid TCP4 or TCP6 v2 PROXY header. Returns `None` for any
/// non-PROXY input — including any valid QUIC datagram, which the
/// magic-byte non-collision tests in this module prove cannot match.
///
/// Tolerant of malformed input: on truncation, oversized address length,
/// unknown family/proto, or LOCAL command, returns `None` rather than
/// erroring. The UDP caller (h3 interpose socket) treats `None` as
/// "this datagram is not a PROXY header — pass it to quinn"; malformed
/// PROXY-shaped datagrams are also surfaced as `None` and the call site
/// decides whether to drop or log.
///
/// Used by the terminal's HTTP/3 interpose socket to recover the real
/// client IP from the relay's first-datagram emission on the chain's
/// UDP/QUIC leg.
pub fn decode_v2_from_datagram(buf: &[u8]) -> Option<ProxyEndpoints> {
    if buf.len() < 16 || buf[..12] != V2_SIG {
        return None;
    }
    let ver_cmd = buf[12];
    let fam_proto = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;

    // Version (high nibble) must be 2.
    if (ver_cmd & 0xF0) != 0x20 {
        return None;
    }
    if addr_len > V2_MAX_ADDR {
        return None;
    }
    if buf.len() < 16 + addr_len {
        return None;
    }
    // LOCAL command (low nibble 0): header is well-formed but the
    // addresses are unusable. Surface as None so the caller falls back to
    // the quinn-observed peer addr.
    if (ver_cmd & 0x0F) == 0x00 {
        return None;
    }
    let payload = &buf[16..16 + addr_len];

    // The relay's encoder writes 0x11 / 0x21 (STREAM/TCP) even for UDP
    // chain traffic — this matches HAProxy's historical convention and
    // lets the encoder be shared between TCP and UDP forwarders.
    // Receivers that only need the address pair ignore the proto nibble.
    match fam_proto {
        0x11 if payload.len() >= 12 => {
            let c_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let s_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let c_port = u16::from_be_bytes([payload[8], payload[9]]);
            let s_port = u16::from_be_bytes([payload[10], payload[11]]);
            Some(ProxyEndpoints {
                client: SocketAddr::new(IpAddr::V4(c_ip), c_port),
                server: SocketAddr::new(IpAddr::V4(s_ip), s_port),
            })
        }
        0x21 if payload.len() >= 36 => {
            let mut c_oct = [0u8; 16];
            c_oct.copy_from_slice(&payload[0..16]);
            let mut s_oct = [0u8; 16];
            s_oct.copy_from_slice(&payload[16..32]);
            let c_ip = Ipv6Addr::from(c_oct);
            let s_ip = Ipv6Addr::from(s_oct);
            let c_port = u16::from_be_bytes([payload[32], payload[33]]);
            let s_port = u16::from_be_bytes([payload[34], payload[35]]);
            Some(ProxyEndpoints {
                client: SocketAddr::new(IpAddr::V6(c_ip), c_port),
                server: SocketAddr::new(IpAddr::V6(s_ip), s_port),
            })
        }
        _ => None,
    }
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
        tokio::io::AsyncReadExt::read_to_end(&mut b, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"PROXY TCP4 203.0.113.7 198.51.100.4 1 443\r\n");
    }

    // -------------------------------------------------------------------
    // Decoder tests.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn decode_v1_round_trips_through_encode() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let header = encode_v1(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        tokio::io::AsyncWriteExt::write_all(&mut a, &header)
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(
            out.endpoints,
            Some(ProxyEndpoints {
                client: v4("203.0.113.7:54321"),
                server: v4("198.51.100.4:443"),
            })
        );
        assert!(out.leftover.is_empty());
    }

    #[tokio::test]
    async fn decode_v1_v6_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let header = encode_v1(v6("[2001:db8::1]:54321"), v6("[2001:db8::2]:443"));
        tokio::io::AsyncWriteExt::write_all(&mut a, &header)
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(
            out.endpoints,
            Some(ProxyEndpoints {
                client: v6("[2001:db8::1]:54321"),
                server: v6("[2001:db8::2]:443"),
            })
        );
    }

    #[tokio::test]
    async fn decode_v1_unknown_is_header_present_but_no_endpoints() {
        let (mut a, mut b) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"PROXY UNKNOWN\r\n")
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(out.endpoints, None);
        assert!(out.leftover.is_empty());
    }

    #[tokio::test]
    async fn decode_v2_v4_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let header = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        tokio::io::AsyncWriteExt::write_all(&mut a, &header)
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(
            out.endpoints,
            Some(ProxyEndpoints {
                client: v4("203.0.113.7:54321"),
                server: v4("198.51.100.4:443"),
            })
        );
        assert!(out.leftover.is_empty());
    }

    #[tokio::test]
    async fn decode_v2_v6_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let header = encode_v2(v6("[2001:db8::1]:54321"), v6("[2001:db8::2]:443"));
        tokio::io::AsyncWriteExt::write_all(&mut a, &header)
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(
            out.endpoints,
            Some(ProxyEndpoints {
                client: v6("[2001:db8::1]:54321"),
                server: v6("[2001:db8::2]:443"),
            })
        );
    }

    #[tokio::test]
    async fn decode_v2_local_is_header_present_but_no_endpoints() {
        let (mut a, mut b) = tokio::io::duplex(256);
        // Mixed-family encode emits v2 LOCAL.
        let header = encode_v2(v4("203.0.113.7:1"), v6("[2001:db8::2]:1"));
        tokio::io::AsyncWriteExt::write_all(&mut a, &header)
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(out.endpoints, None);
        assert!(out.leftover.is_empty());
    }

    #[tokio::test]
    async fn decode_no_header_returns_peeked_bytes_as_leftover() {
        let (mut a, mut b) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"GET / HTTP/1.1\r\n")
            .await
            .unwrap();
        drop(a);
        let out = read_optional_header(&mut b).await.unwrap();
        assert_eq!(out.endpoints, None);
        // First byte 'G' was consumed; caller splices it back.
        assert_eq!(out.leftover, b"G");
    }

    #[tokio::test]
    async fn decode_v1_garbage_after_proxy_is_error() {
        let (mut a, mut b) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"PROXY ZZZZ 1 2 3 4\r\n")
            .await
            .unwrap();
        drop(a);
        let err = read_optional_header(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn decode_v1_too_long_is_error() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let mut bad = b"PROXY TCP4 ".to_vec();
        bad.extend(std::iter::repeat_n(b'X', 200));
        bad.extend_from_slice(b"\r\n");
        // Writer runs in the background so we don't deadlock on the duplex
        // pipe filling before the reader drains it.
        tokio::spawn(async move {
            let _ = tokio::io::AsyncWriteExt::write_all(&mut a, &bad).await;
        });
        let err = read_optional_header(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // ---- decode_v2_from_datagram (UDP path) ---------------------------------

    #[test]
    fn v2_datagram_round_trip_ipv4() {
        let client = v4("203.0.113.7:54321");
        let server = v4("198.51.100.4:443");
        let dgram = encode_v2(client, server);
        let decoded = decode_v2_from_datagram(&dgram).expect("v4 datagram decodes");
        assert_eq!(decoded.client, client);
        assert_eq!(decoded.server, server);
    }

    #[test]
    fn v2_datagram_round_trip_ipv6() {
        let client = v6("[2001:db8::1]:54321");
        let server = v6("[2001:db8::2]:443");
        let dgram = encode_v2(client, server);
        let decoded = decode_v2_from_datagram(&dgram).expect("v6 datagram decodes");
        assert_eq!(decoded.client, client);
        assert_eq!(decoded.server, server);
    }

    #[test]
    fn v2_datagram_with_trailing_bytes_decodes_using_addr_len() {
        // The relay sends PROXY v2 standalone in v1 of this feature, but the
        // decoder must be self-delimiting via `addr_len` per spec — so a
        // future change that coalesces the header with the first
        // application datagram does not silently break detection.
        let mut dgram = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        dgram.extend_from_slice(b"\xC0\xFF\xEE\xDE\xAD\xBE\xEF");
        let decoded = decode_v2_from_datagram(&dgram).expect("decodes despite trailer");
        assert_eq!(decoded.client, v4("203.0.113.7:54321"));
    }

    #[test]
    fn v2_datagram_rejects_short_input() {
        assert!(decode_v2_from_datagram(&[]).is_none());
        assert!(decode_v2_from_datagram(&[0x0D; 11]).is_none());
        // Full magic but no header trailer.
        assert!(decode_v2_from_datagram(&V2_SIG[..]).is_none());
    }

    #[test]
    fn v2_datagram_rejects_missing_magic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 0xAA;
        assert!(decode_v2_from_datagram(&buf).is_none());
    }

    #[test]
    fn v2_datagram_rejects_addr_len_larger_than_buffer() {
        let mut buf = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        let len_bytes = 1024u16.to_be_bytes();
        buf[14] = len_bytes[0];
        buf[15] = len_bytes[1];
        assert!(decode_v2_from_datagram(&buf).is_none());
    }

    #[test]
    fn v2_datagram_rejects_addr_len_above_v2_max_addr() {
        let mut buf = vec![0u8; 16 + 600];
        buf[..12].copy_from_slice(&V2_SIG);
        buf[12] = 0x21; // version 2 + PROXY
        buf[13] = 0x11; // AF_INET + STREAM
        let len_bytes = (V2_MAX_ADDR as u16 + 1).to_be_bytes();
        buf[14] = len_bytes[0];
        buf[15] = len_bytes[1];
        assert!(decode_v2_from_datagram(&buf).is_none());
    }

    #[test]
    fn v2_datagram_rejects_local_command() {
        // ver_cmd low nibble = 0 → LOCAL: header well-formed but addresses
        // unusable. The interpose socket falls back to the connection's
        // observed peer addr in this case.
        let mut buf = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        buf[12] = 0x20; // version 2 + LOCAL command
        assert!(decode_v2_from_datagram(&buf).is_none());
    }

    #[test]
    fn v2_datagram_rejects_wrong_version() {
        let mut buf = encode_v2(v4("203.0.113.7:54321"), v4("198.51.100.4:443"));
        buf[12] = 0x31; // version 3 + PROXY
        assert!(decode_v2_from_datagram(&buf).is_none());
    }

    #[test]
    fn v2_magic_byte_zero_clears_quic_long_header_form_bit() {
        // QUIC long-header packets (RFC 9000 §17.2) set the high bit (0x80,
        // the "header form" bit) in byte 0. PROXY v2 magic byte 0 is 0x0D.
        // Therefore no valid QUIC long-header packet can collide with our
        // gate condition `buf[..12] == V2_SIG` at the first byte.
        assert_eq!(
            V2_SIG[0] & 0x80,
            0,
            "v2 magic byte 0 must have QUIC form-bit clear"
        );
    }

    #[test]
    fn v2_magic_byte_zero_clears_quic_short_header_fixed_bit() {
        // QUIC short-header packets (RFC 9000 §17.3) have form bit (0x80)
        // clear AND fixed bit (0x40) set in byte 0. PROXY v2 magic byte 0
        // = 0x0D — both 0x80 and 0x40 clear. No valid QUIC short-header
        // packet can collide.
        assert_eq!(
            V2_SIG[0] & 0x40,
            0,
            "v2 magic byte 0 must have QUIC fixed-bit clear"
        );
    }

    #[test]
    fn synthetic_quic_initial_long_header_datagram_is_not_proxy() {
        // QUIC Initial: byte 0 = 0xC0..0xCF (form=1, fixed=1, type Initial).
        // Followed by 4-byte version, then connection IDs.
        let mut dgram = vec![0xC3, 0x00, 0x00, 0x00, 0x01];
        dgram.resize(1200, 0); // pad to a typical Initial size
        assert!(decode_v2_from_datagram(&dgram).is_none());
    }

    #[test]
    fn synthetic_quic_short_header_datagram_is_not_proxy() {
        // QUIC short header: form=0, fixed=1 → byte 0 in [0x40..0x80).
        let mut dgram = vec![0x40, 0xDE, 0xAD, 0xBE, 0xEF];
        dgram.resize(1024, 0);
        assert!(decode_v2_from_datagram(&dgram).is_none());
    }
}
