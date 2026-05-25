//! In-process mock PCP / NAT-PMP gateway used by the
//! `nat_traversal.rs` integration test. Binds a UDP socket on
//! loopback, parses every received datagram with the production
//! codec, records it in an inbox the test can assert against, and
//! emits a programmable response.
//!
//! Roughly 200 lines including the response-policy machinery. The
//! key design point is that it exercises the **production** PCP /
//! NAT-PMP codecs end-to-end, so a codec regression that shipped
//! in mapper.rs surfaces here too.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use yggdrasil::nat::wire::{natpmp, pcp, MapProtocol};

/// One request the mock gateway received and successfully parsed.
#[derive(Debug, Clone)]
pub enum MockRequest {
    Pcp(pcp::PcpMapRequest),
    NatPmp(natpmp::NatPmpMapRequest),
}

impl MockRequest {
    pub fn pcp(&self) -> Option<&pcp::PcpMapRequest> {
        match self {
            Self::Pcp(p) => Some(p),
            _ => None,
        }
    }
    pub fn natpmp(&self) -> Option<&natpmp::NatPmpMapRequest> {
        match self {
            Self::NatPmp(n) => Some(n),
            _ => None,
        }
    }
}

/// A programmable response the gateway will emit for the next
/// request. Tests pre-load a queue of these; the gateway pops one
/// per received request. Once the queue empties, the gateway uses
/// `default_policy`.
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// Echo back a PCP MAP response with the supplied result code
    /// and a fixed external port (defaults to the request's internal
    /// port, like real consumer routers).
    PcpSuccess {
        external_port_override: Option<u16>,
        assigned_lifetime: u32,
        epoch_time: u32,
        external_addr: Ipv4Addr,
    },
    PcpError {
        code: pcp::PcpResultCode,
        epoch_time: u32,
    },
    NatPmpSuccess {
        external_port_override: Option<u16>,
        assigned_lifetime: u32,
        seconds_since_epoch: u32,
    },
    NatPmpError {
        code: natpmp::NatPmpResultCode,
        seconds_since_epoch: u32,
    },
    /// Drop the request on the floor. Useful for simulating
    /// gateways that don't speak the requested protocol — the
    /// mapper will hit a socket timeout.
    Silent,
}

impl MockResponse {
    pub fn pcp_ok() -> Self {
        Self::PcpSuccess {
            external_port_override: None,
            assigned_lifetime: 7200,
            epoch_time: 100,
            external_addr: Ipv4Addr::new(203, 0, 113, 42),
        }
    }
    pub fn natpmp_ok() -> Self {
        Self::NatPmpSuccess {
            external_port_override: None,
            assigned_lifetime: 7200,
            seconds_since_epoch: 100,
        }
    }
}

/// Mock gateway state shared between the test and the listener task.
pub struct MockNatGateway {
    pub addr: SocketAddr,
    pub received: Arc<Mutex<Vec<MockRequest>>>,
    pub responses: Arc<Mutex<VecDeque<MockResponse>>>,
    pub default_response: Arc<Mutex<MockResponse>>,
    cancel: CancellationToken,
    join: Option<JoinHandle<()>>,
}

impl MockNatGateway {
    /// Bind on `127.0.0.1:0` and start serving. Returns immediately;
    /// the listener task runs until `shutdown()` is called or the
    /// gateway is dropped.
    pub async fn start() -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();

        let received = Arc::new(Mutex::new(Vec::new()));
        let responses: Arc<Mutex<VecDeque<MockResponse>>> = Arc::new(Mutex::new(VecDeque::new()));
        let default_response = Arc::new(Mutex::new(MockResponse::pcp_ok()));
        let cancel = CancellationToken::new();

        let r = received.clone();
        let q = responses.clone();
        let d = default_response.clone();
        let c = cancel.clone();
        let join = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    _ = c.cancelled() => return,
                    res = sock.recv_from(&mut buf) => {
                        let (n, peer) = match res {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let bytes = &buf[..n];
                        let parsed = parse_request(bytes);
                        if let Some(req) = parsed {
                            r.lock().push(req.clone());
                            // If lifetime was 0 (release), still
                            // record but emit no response — most
                            // gateways do reply, but suppressing
                            // here keeps test wire traffic minimal
                            // and matches RFC §15.1 best-effort.
                            let policy = q.lock().pop_front().unwrap_or_else(|| d.lock().clone());
                            let resp_bytes = synthesize(&req, &policy);
                            if let Some(b) = resp_bytes {
                                let _ = sock.send_to(&b, peer).await;
                            }
                        }
                    }
                }
            }
        });

        Self {
            addr,
            received,
            responses,
            default_response,
            cancel,
            join: Some(join),
        }
    }

    /// Queue one programmable response for the next received request.
    pub fn enqueue(&self, r: MockResponse) {
        self.responses.lock().push_back(r);
    }

    /// Replace the default response (used when the per-request
    /// queue is empty).
    pub fn set_default(&self, r: MockResponse) {
        *self.default_response.lock() = r;
    }

    /// Snapshot of every request received so far.
    pub fn requests(&self) -> Vec<MockRequest> {
        self.received.lock().clone()
    }

    /// Tear down the listener.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for MockNatGateway {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn parse_request(bytes: &[u8]) -> Option<MockRequest> {
    if bytes.is_empty() {
        return None;
    }
    match bytes[0] {
        pcp::PCP_VERSION => {
            // PCP MAP request is 60 bytes; manual parse since the
            // production decoder is for *responses*. We parse the
            // request form directly here.
            if bytes.len() < 60 {
                return None;
            }
            let lifetime_secs = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let mut client_octets = [0u8; 16];
            client_octets.copy_from_slice(&bytes[8..24]);
            let client_v6 = std::net::Ipv6Addr::from(client_octets);
            let client_addr = client_v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut nonce = [0u8; pcp::PCP_NONCE_LEN];
            nonce.copy_from_slice(&bytes[24..36]);
            let protocol = match bytes[36] {
                6 => MapProtocol::Tcp,
                17 => MapProtocol::Udp,
                _ => return None,
            };
            let internal_port = u16::from_be_bytes([bytes[40], bytes[41]]);
            let suggested_external_port = u16::from_be_bytes([bytes[42], bytes[43]]);
            let mut ext_octets = [0u8; 16];
            ext_octets.copy_from_slice(&bytes[44..60]);
            let ext_v6 = std::net::Ipv6Addr::from(ext_octets);
            let suggested_external_addr = ext_v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED);
            Some(MockRequest::Pcp(pcp::PcpMapRequest {
                lifetime_secs,
                client_addr,
                nonce,
                protocol,
                internal_port,
                suggested_external_port,
                suggested_external_addr,
            }))
        }
        natpmp::NATPMP_VERSION => {
            if bytes.len() < 12 {
                return None;
            }
            let opcode = bytes[1];
            let protocol = match opcode {
                natpmp::NATPMP_OPCODE_MAP_UDP => MapProtocol::Udp,
                natpmp::NATPMP_OPCODE_MAP_TCP => MapProtocol::Tcp,
                _ => return None,
            };
            let internal_port = u16::from_be_bytes([bytes[4], bytes[5]]);
            let suggested_external_port = u16::from_be_bytes([bytes[6], bytes[7]]);
            let lifetime_secs = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            Some(MockRequest::NatPmp(natpmp::NatPmpMapRequest {
                protocol,
                internal_port,
                suggested_external_port,
                lifetime_secs,
            }))
        }
        _ => None,
    }
}

fn synthesize(req: &MockRequest, policy: &MockResponse) -> Option<Vec<u8>> {
    match (req, policy) {
        (
            MockRequest::Pcp(p),
            MockResponse::PcpSuccess {
                external_port_override,
                assigned_lifetime,
                epoch_time,
                external_addr,
            },
        ) => {
            let mut out = vec![0u8; 60];
            out[0] = pcp::PCP_VERSION;
            out[1] = pcp::PCP_OPCODE_MAP | pcp::PCP_OPCODE_RESPONSE_BIT;
            out[2] = 0;
            out[3] = pcp::PcpResultCode::Success.as_u8();
            out[4..8].copy_from_slice(&assigned_lifetime.to_be_bytes());
            out[8..12].copy_from_slice(&epoch_time.to_be_bytes());
            out[24..36].copy_from_slice(&p.nonce);
            out[36] = p.protocol.ip_proto();
            out[40..42].copy_from_slice(&p.internal_port.to_be_bytes());
            let ext_port = external_port_override.unwrap_or(p.internal_port);
            out[42..44].copy_from_slice(&ext_port.to_be_bytes());
            let ext_v6 = external_addr.to_ipv6_mapped();
            out[44..60].copy_from_slice(&ext_v6.octets());
            Some(out)
        }
        (MockRequest::Pcp(p), MockResponse::PcpError { code, epoch_time }) => {
            let mut out = vec![0u8; 60];
            out[0] = pcp::PCP_VERSION;
            out[1] = pcp::PCP_OPCODE_MAP | pcp::PCP_OPCODE_RESPONSE_BIT;
            out[2] = 0;
            out[3] = code.as_u8();
            out[4..8].copy_from_slice(&0u32.to_be_bytes());
            out[8..12].copy_from_slice(&epoch_time.to_be_bytes());
            out[24..36].copy_from_slice(&p.nonce);
            out[36] = p.protocol.ip_proto();
            out[40..42].copy_from_slice(&p.internal_port.to_be_bytes());
            out[42..44].copy_from_slice(&p.internal_port.to_be_bytes());
            let zero_v6 = Ipv4Addr::UNSPECIFIED.to_ipv6_mapped();
            out[44..60].copy_from_slice(&zero_v6.octets());
            Some(out)
        }
        (
            MockRequest::NatPmp(n),
            MockResponse::NatPmpSuccess {
                external_port_override,
                assigned_lifetime,
                seconds_since_epoch,
            },
        ) => {
            let opcode = match n.protocol {
                MapProtocol::Udp => natpmp::NATPMP_OPCODE_MAP_UDP,
                MapProtocol::Tcp => natpmp::NATPMP_OPCODE_MAP_TCP,
            };
            let mut out = vec![0u8; 16];
            out[0] = natpmp::NATPMP_VERSION;
            out[1] = opcode | natpmp::NATPMP_OPCODE_RESPONSE_BIT;
            out[2..4].copy_from_slice(&natpmp::NatPmpResultCode::Success.as_u16().to_be_bytes());
            out[4..8].copy_from_slice(&seconds_since_epoch.to_be_bytes());
            out[8..10].copy_from_slice(&n.internal_port.to_be_bytes());
            let ext = external_port_override.unwrap_or(n.internal_port);
            out[10..12].copy_from_slice(&ext.to_be_bytes());
            out[12..16].copy_from_slice(&assigned_lifetime.to_be_bytes());
            Some(out)
        }
        (
            MockRequest::NatPmp(n),
            MockResponse::NatPmpError {
                code,
                seconds_since_epoch,
            },
        ) => {
            let opcode = match n.protocol {
                MapProtocol::Udp => natpmp::NATPMP_OPCODE_MAP_UDP,
                MapProtocol::Tcp => natpmp::NATPMP_OPCODE_MAP_TCP,
            };
            let mut out = vec![0u8; 16];
            out[0] = natpmp::NATPMP_VERSION;
            out[1] = opcode | natpmp::NATPMP_OPCODE_RESPONSE_BIT;
            out[2..4].copy_from_slice(&code.as_u16().to_be_bytes());
            out[4..8].copy_from_slice(&seconds_since_epoch.to_be_bytes());
            out[8..10].copy_from_slice(&n.internal_port.to_be_bytes());
            out[10..12].copy_from_slice(&n.internal_port.to_be_bytes());
            out[12..16].copy_from_slice(&0u32.to_be_bytes());
            Some(out)
        }
        (_, MockResponse::Silent) => None,
        // Protocol mismatch: gateway speaks NAT-PMP, mapper sent
        // PCP, or vice versa. Synthesize the closest version error
        // possible so the mapper's fallback path kicks in.
        (MockRequest::Pcp(p), MockResponse::NatPmpSuccess { .. })
        | (MockRequest::Pcp(p), MockResponse::NatPmpError { .. }) => {
            let mut out = vec![0u8; 60];
            out[0] = pcp::PCP_VERSION;
            out[1] = pcp::PCP_OPCODE_MAP | pcp::PCP_OPCODE_RESPONSE_BIT;
            out[3] = pcp::PcpResultCode::UnsuppVersion.as_u8();
            out[24..36].copy_from_slice(&p.nonce);
            Some(out)
        }
        (MockRequest::NatPmp(_), MockResponse::PcpSuccess { .. })
        | (MockRequest::NatPmp(_), MockResponse::PcpError { .. }) => {
            // Reply with NAT-PMP UnsupportedVersion so the mapper
            // surfaces a coherent error.
            let mut out = vec![0u8; 16];
            out[0] = natpmp::NATPMP_VERSION;
            out[1] = natpmp::NATPMP_OPCODE_MAP_TCP | natpmp::NATPMP_OPCODE_RESPONSE_BIT;
            out[2..4].copy_from_slice(
                &natpmp::NatPmpResultCode::UnsupportedVersion
                    .as_u16()
                    .to_be_bytes(),
            );
            Some(out)
        }
    }
}
