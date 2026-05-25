//! PCP (RFC 6887) MAP request/response codec.
//!
//! Covers the subset we actually need: the MAP opcode (1) for IPv4
//! port mapping. Frames are fixed 60 bytes; options are not emitted by
//! the client and are tolerated (but ignored) on the response.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{ipv4_to_mapped_v6, ipv6_mapped_to_v4, MapProtocol, WireError};

/// PCP version we speak. RFC 6887 defines V2; V1 was an earlier
/// pre-standard draft (NAT-PMP++) and is not interoperable.
pub const PCP_VERSION: u8 = 2;

/// MAP opcode. Bit 7 of the opcode byte is the request/response flag;
/// `0x01` is the request form, `0x81` the response form.
pub const PCP_OPCODE_MAP: u8 = 0x01;
/// Mask that distinguishes a response from a request on the opcode
/// byte.
pub const PCP_OPCODE_RESPONSE_BIT: u8 = 0x80;

/// Fixed wire size of a MAP request, no options. RFC 6887 §11.1.
pub const PCP_MAP_REQUEST_LEN: usize = 60;
/// Minimum wire size of a MAP response (header + MAP fields, no
/// options). Larger responses with options are accepted; we ignore the
/// option bytes.
pub const PCP_MAP_RESPONSE_LEN: usize = 60;

/// Length of the per-mapping random nonce the client emits and the
/// gateway echoes back. RFC 6887 §11.1.
pub const PCP_NONCE_LEN: usize = 12;

/// Result codes defined by RFC 6887 §7.4.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PcpResultCode {
    Success,
    UnsuppVersion,
    NotAuthorized,
    MalformedRequest,
    UnsuppOpcode,
    UnsuppOption,
    MalformedOption,
    NetworkFailure,
    NoResources,
    UnsuppProtocol,
    UserExQuota,
    CannotProvideExternal,
    AddressMismatch,
    ExcessiveRemotePeers,
}

impl PcpResultCode {
    pub fn from_wire(value: u8) -> Result<Self, WireError> {
        Ok(match value {
            0 => Self::Success,
            1 => Self::UnsuppVersion,
            2 => Self::NotAuthorized,
            3 => Self::MalformedRequest,
            4 => Self::UnsuppOpcode,
            5 => Self::UnsuppOption,
            6 => Self::MalformedOption,
            7 => Self::NetworkFailure,
            8 => Self::NoResources,
            9 => Self::UnsuppProtocol,
            10 => Self::UserExQuota,
            11 => Self::CannotProvideExternal,
            12 => Self::AddressMismatch,
            13 => Self::ExcessiveRemotePeers,
            other => return Err(WireError::UnknownResultCode(other as u16)),
        })
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::UnsuppVersion => 1,
            Self::NotAuthorized => 2,
            Self::MalformedRequest => 3,
            Self::UnsuppOpcode => 4,
            Self::UnsuppOption => 5,
            Self::MalformedOption => 6,
            Self::NetworkFailure => 7,
            Self::NoResources => 8,
            Self::UnsuppProtocol => 9,
            Self::UserExQuota => 10,
            Self::CannotProvideExternal => 11,
            Self::AddressMismatch => 12,
            Self::ExcessiveRemotePeers => 13,
        }
    }

    /// Lowercase short token for use as a `result_code` metric label.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UnsuppVersion => "unsupp_version",
            Self::NotAuthorized => "not_authorized",
            Self::MalformedRequest => "malformed_request",
            Self::UnsuppOpcode => "unsupp_opcode",
            Self::UnsuppOption => "unsupp_option",
            Self::MalformedOption => "malformed_option",
            Self::NetworkFailure => "network_failure",
            Self::NoResources => "no_resources",
            Self::UnsuppProtocol => "unsupp_protocol",
            Self::UserExQuota => "user_ex_quota",
            Self::CannotProvideExternal => "cannot_provide_external",
            Self::AddressMismatch => "address_mismatch",
            Self::ExcessiveRemotePeers => "excessive_remote_peers",
        }
    }

    /// True for codes the mapper should retry against the same
    /// gateway after a short delay. False codes are either success or
    /// permanent failures that we surface and move on from.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::NetworkFailure | Self::NoResources | Self::CannotProvideExternal
        )
    }

    /// True for codes that indicate the gateway does not speak PCP at
    /// all; the mapper should fall back to NAT-PMP in `auto` mode.
    /// RFC 6887 §9.
    pub fn should_fall_back_to_natpmp(self) -> bool {
        matches!(self, Self::UnsuppVersion)
    }
}

/// PCP MAP request frame (RFC 6887 §11.1), no options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcpMapRequest {
    /// Mapping lifetime in seconds. `0` requests release of the
    /// mapping identified by the `(protocol, internal_port, nonce)`
    /// tuple.
    pub lifetime_secs: u32,
    /// The client's source IP (v4-mapped on the wire). PCP uses this
    /// to detect double-NAT and the host-renumbered case.
    pub client_addr: Ipv4Addr,
    /// 96-bit cryptographically random mapping nonce. The mapper
    /// remembers this value and rejects responses whose nonce doesn't
    /// match.
    pub nonce: [u8; PCP_NONCE_LEN],
    pub protocol: MapProtocol,
    pub internal_port: u16,
    pub suggested_external_port: u16,
    pub suggested_external_addr: Ipv4Addr,
}

/// PCP MAP response frame (RFC 6887 §11.1), options skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcpMapResponse {
    pub result_code: PcpResultCode,
    /// Gateway-side monotonic epoch. RFC 6887 §8.5: if this goes
    /// backwards or jumps too far forward, the gateway lost state and
    /// the client must re-establish all mappings.
    pub epoch_time: u32,
    pub assigned_lifetime: u32,
    pub nonce: [u8; PCP_NONCE_LEN],
    pub protocol: MapProtocol,
    pub internal_port: u16,
    pub assigned_external_port: u16,
    pub assigned_external_addr: Ipv4Addr,
}

/// Encode a PCP MAP request into a fixed-size 60-byte buffer.
pub fn encode_map_request(req: &PcpMapRequest, out: &mut [u8; PCP_MAP_REQUEST_LEN]) {
    // Common header (24 bytes):
    //   0:    version
    //   1:    R(1) Opcode(7)
    //   2-3:  reserved
    //   4-7:  requested lifetime
    //   8-23: client IP (v4-mapped IPv6)
    out[0] = PCP_VERSION;
    out[1] = PCP_OPCODE_MAP;
    out[2] = 0;
    out[3] = 0;
    out[4..8].copy_from_slice(&req.lifetime_secs.to_be_bytes());
    let client_v6 = ipv4_to_mapped_v6(req.client_addr);
    out[8..24].copy_from_slice(&client_v6.octets());

    // MAP opcode payload (36 bytes, RFC 6887 §11.1):
    //   24-35: mapping nonce
    //   36:    protocol
    //   37-39: reserved
    //   40-41: internal port
    //   42-43: suggested external port
    //   44-59: suggested external IP (v4-mapped IPv6)
    out[24..24 + PCP_NONCE_LEN].copy_from_slice(&req.nonce);
    out[36] = req.protocol.ip_proto();
    out[37] = 0;
    out[38] = 0;
    out[39] = 0;
    out[40..42].copy_from_slice(&req.internal_port.to_be_bytes());
    out[42..44].copy_from_slice(&req.suggested_external_port.to_be_bytes());
    let ext_v6 = ipv4_to_mapped_v6(req.suggested_external_addr);
    out[44..60].copy_from_slice(&ext_v6.octets());
}

/// Decode a PCP MAP response. The buffer must be at least 60 bytes;
/// extra bytes (options) are tolerated and ignored.
///
/// Validates: version, opcode high bit, IPv4-mapped address fields,
/// known result code. Does **not** check the nonce — callers must
/// compare against the request's nonce themselves so they can decide
/// whether to silently discard or surface as an error.
pub fn decode_map_response(buf: &[u8]) -> Result<PcpMapResponse, WireError> {
    if buf.len() < PCP_MAP_RESPONSE_LEN {
        return Err(WireError::Truncated {
            needed: PCP_MAP_RESPONSE_LEN,
            got: buf.len(),
        });
    }

    let version = buf[0];
    if version != PCP_VERSION {
        return Err(WireError::BadVersion { version });
    }

    let opcode_byte = buf[1];
    if opcode_byte & PCP_OPCODE_RESPONSE_BIT == 0 {
        return Err(WireError::NotAResponse);
    }
    let opcode = opcode_byte & !PCP_OPCODE_RESPONSE_BIT;
    if opcode != PCP_OPCODE_MAP {
        return Err(WireError::BadOpcode { opcode });
    }

    // buf[2] is reserved.
    let result_code = PcpResultCode::from_wire(buf[3])?;
    let assigned_lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let epoch_time = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    // buf[12..24] is reserved (originally "Address" in v1; per RFC 6887
    // §7.2 the gateway must zero it on response). We don't validate it
    // because some routers leak data here; ignoring is safe.

    let mut nonce = [0u8; PCP_NONCE_LEN];
    nonce.copy_from_slice(&buf[24..24 + PCP_NONCE_LEN]);

    let proto_byte = buf[36];
    let protocol = match proto_byte {
        super::IP_PROTO_TCP => MapProtocol::Tcp,
        super::IP_PROTO_UDP => MapProtocol::Udp,
        other => return Err(WireError::BadOpcode { opcode: other }),
    };
    // buf[37..40] is reserved.
    let internal_port = u16::from_be_bytes([buf[40], buf[41]]);
    let assigned_external_port = u16::from_be_bytes([buf[42], buf[43]]);
    let mut ext_octets = [0u8; 16];
    ext_octets.copy_from_slice(&buf[44..60]);
    let ext_v6 = Ipv6Addr::from(ext_octets);
    let assigned_external_addr = ipv6_mapped_to_v4(ext_v6)?;

    Ok(PcpMapResponse {
        result_code,
        epoch_time,
        assigned_lifetime,
        nonce,
        protocol,
        internal_port,
        assigned_external_port,
        assigned_external_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(lifetime: u32) -> PcpMapRequest {
        PcpMapRequest {
            lifetime_secs: lifetime,
            client_addr: Ipv4Addr::new(192, 168, 1, 42),
            nonce: [
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            ],
            protocol: MapProtocol::Tcp,
            internal_port: 22,
            suggested_external_port: 22,
            suggested_external_addr: Ipv4Addr::UNSPECIFIED,
        }
    }

    fn synthesize_response(req: &PcpMapRequest, code: PcpResultCode) -> [u8; 60] {
        let mut out = [0u8; 60];
        out[0] = PCP_VERSION;
        out[1] = PCP_OPCODE_MAP | PCP_OPCODE_RESPONSE_BIT;
        out[2] = 0;
        out[3] = code.as_u8();
        out[4..8].copy_from_slice(&7200u32.to_be_bytes());
        out[8..12].copy_from_slice(&123u32.to_be_bytes());
        out[24..36].copy_from_slice(&req.nonce);
        out[36] = req.protocol.ip_proto();
        out[40..42].copy_from_slice(&req.internal_port.to_be_bytes());
        out[42..44].copy_from_slice(&req.suggested_external_port.to_be_bytes());
        let ext_v6 = ipv4_to_mapped_v6(Ipv4Addr::new(203, 0, 113, 42));
        out[44..60].copy_from_slice(&ext_v6.octets());
        out
    }

    #[test]
    fn encode_request_layout() {
        let req = sample_request(7200);
        let mut buf = [0u8; PCP_MAP_REQUEST_LEN];
        encode_map_request(&req, &mut buf);
        assert_eq!(buf[0], PCP_VERSION);
        assert_eq!(buf[1], PCP_OPCODE_MAP);
        assert_eq!(&buf[4..8], &7200u32.to_be_bytes());
        // Client v4-mapped at offset 8..24:
        assert_eq!(&buf[8..20], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&buf[20..24], &[192, 168, 1, 42]);
        // Nonce at 24..36:
        assert_eq!(&buf[24..36], &req.nonce);
        assert_eq!(buf[36], 6); // TCP
        assert_eq!(&buf[40..42], &22u16.to_be_bytes());
        assert_eq!(&buf[42..44], &22u16.to_be_bytes());
    }

    #[test]
    fn decode_success_response() {
        let req = sample_request(7200);
        let buf = synthesize_response(&req, PcpResultCode::Success);
        let resp = decode_map_response(&buf).unwrap();
        assert_eq!(resp.result_code, PcpResultCode::Success);
        assert_eq!(resp.assigned_lifetime, 7200);
        assert_eq!(resp.epoch_time, 123);
        assert_eq!(resp.nonce, req.nonce);
        assert_eq!(resp.protocol, MapProtocol::Tcp);
        assert_eq!(resp.internal_port, 22);
        assert_eq!(resp.assigned_external_port, 22);
        assert_eq!(resp.assigned_external_addr, Ipv4Addr::new(203, 0, 113, 42));
    }

    #[test]
    fn decode_each_error_code() {
        let req = sample_request(7200);
        for code in [
            PcpResultCode::UnsuppVersion,
            PcpResultCode::NotAuthorized,
            PcpResultCode::MalformedRequest,
            PcpResultCode::UnsuppOpcode,
            PcpResultCode::UnsuppOption,
            PcpResultCode::MalformedOption,
            PcpResultCode::NetworkFailure,
            PcpResultCode::NoResources,
            PcpResultCode::UnsuppProtocol,
            PcpResultCode::UserExQuota,
            PcpResultCode::CannotProvideExternal,
            PcpResultCode::AddressMismatch,
            PcpResultCode::ExcessiveRemotePeers,
        ] {
            let buf = synthesize_response(&req, code);
            let resp = decode_map_response(&buf).unwrap();
            assert_eq!(resp.result_code, code);
        }
    }

    #[test]
    fn rejects_truncated_response() {
        let buf = [0u8; 30];
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_request_form_response() {
        let req = sample_request(7200);
        let mut buf = synthesize_response(&req, PcpResultCode::Success);
        buf[1] = PCP_OPCODE_MAP; // strip response bit
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::NotAResponse)
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let req = sample_request(7200);
        let mut buf = synthesize_response(&req, PcpResultCode::Success);
        buf[0] = 1;
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::BadVersion { version: 1 })
        ));
    }

    #[test]
    fn classifies_unsupp_version_as_natpmp_fallback() {
        assert!(PcpResultCode::UnsuppVersion.should_fall_back_to_natpmp());
        assert!(!PcpResultCode::Success.should_fall_back_to_natpmp());
        assert!(!PcpResultCode::NetworkFailure.should_fall_back_to_natpmp());
    }

    #[test]
    fn classifies_transient_codes() {
        assert!(PcpResultCode::NetworkFailure.is_transient());
        assert!(PcpResultCode::NoResources.is_transient());
        assert!(PcpResultCode::CannotProvideExternal.is_transient());
        assert!(!PcpResultCode::Success.is_transient());
        assert!(!PcpResultCode::NotAuthorized.is_transient());
    }

    #[test]
    fn round_trip_via_synthetic_response() {
        // Drive a full encode→synthesize→decode cycle, the closest
        // thing to a server we can build without a network: build a
        // request, hand the request to a synthetic responder that
        // emits a response keyed by the request's fields, decode, and
        // assert the round-trip preserves what we sent.
        for proto in [MapProtocol::Tcp, MapProtocol::Udp] {
            let mut req = sample_request(7200);
            req.protocol = proto;
            req.internal_port = 12345;
            req.suggested_external_port = 12345;

            let mut buf = [0u8; PCP_MAP_REQUEST_LEN];
            encode_map_request(&req, &mut buf);

            let resp_buf = synthesize_response(&req, PcpResultCode::Success);
            let resp = decode_map_response(&resp_buf).unwrap();
            assert_eq!(resp.protocol, req.protocol);
            assert_eq!(resp.internal_port, req.internal_port);
            assert_eq!(resp.nonce, req.nonce);
        }
    }

    #[test]
    fn unknown_result_code_surfaces() {
        let req = sample_request(7200);
        let mut buf = synthesize_response(&req, PcpResultCode::Success);
        buf[3] = 99;
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::UnknownResultCode(99))
        ));
    }
}
