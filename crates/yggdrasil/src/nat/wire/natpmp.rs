//! NAT-PMP (RFC 6886) codec.
//!
//! NAT-PMP is PCP's predecessor: simpler, IPv4-only, no nonces, no
//! options. The wire format is three opcodes:
//!
//! - `0` — external-address request/response
//! - `1` — map UDP port
//! - `2` — map TCP port
//!
//! Responses are distinguished from requests by `opcode | 0x80`.
//! Requests are 2 bytes (external-address) or 12 bytes (map);
//! responses are 12 bytes (external-address) or 16 bytes (map).

use std::net::Ipv4Addr;

use super::{MapProtocol, WireError};

pub const NATPMP_VERSION: u8 = 0;

pub const NATPMP_OPCODE_EXTERNAL_ADDRESS: u8 = 0;
pub const NATPMP_OPCODE_MAP_UDP: u8 = 1;
pub const NATPMP_OPCODE_MAP_TCP: u8 = 2;
pub const NATPMP_OPCODE_RESPONSE_BIT: u8 = 0x80;

pub const NATPMP_EXTERNAL_ADDRESS_REQUEST_LEN: usize = 2;
pub const NATPMP_EXTERNAL_ADDRESS_RESPONSE_LEN: usize = 12;
pub const NATPMP_MAP_REQUEST_LEN: usize = 12;
pub const NATPMP_MAP_RESPONSE_LEN: usize = 16;

/// Result codes defined by RFC 6886 §3.5.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NatPmpResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
}

impl NatPmpResultCode {
    pub fn from_wire(value: u16) -> Result<Self, WireError> {
        Ok(match value {
            0 => Self::Success,
            1 => Self::UnsupportedVersion,
            2 => Self::NotAuthorized,
            3 => Self::NetworkFailure,
            4 => Self::OutOfResources,
            5 => Self::UnsupportedOpcode,
            other => return Err(WireError::UnknownResultCode(other)),
        })
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Success => 0,
            Self::UnsupportedVersion => 1,
            Self::NotAuthorized => 2,
            Self::NetworkFailure => 3,
            Self::OutOfResources => 4,
            Self::UnsupportedOpcode => 5,
        }
    }

    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UnsupportedVersion => "unsupp_version",
            Self::NotAuthorized => "not_authorized",
            Self::NetworkFailure => "network_failure",
            Self::OutOfResources => "out_of_resources",
            Self::UnsupportedOpcode => "unsupp_opcode",
        }
    }

    pub fn is_transient(self) -> bool {
        matches!(self, Self::NetworkFailure | Self::OutOfResources)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpMapRequest {
    pub protocol: MapProtocol,
    pub internal_port: u16,
    pub suggested_external_port: u16,
    pub lifetime_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpMapResponse {
    pub result_code: NatPmpResultCode,
    pub protocol: MapProtocol,
    pub seconds_since_epoch: u32,
    pub internal_port: u16,
    pub assigned_external_port: u16,
    pub assigned_lifetime: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpExternalAddressResponse {
    pub result_code: NatPmpResultCode,
    pub seconds_since_epoch: u32,
    pub external_address: Ipv4Addr,
}

pub fn encode_external_address_request(out: &mut [u8; NATPMP_EXTERNAL_ADDRESS_REQUEST_LEN]) {
    out[0] = NATPMP_VERSION;
    out[1] = NATPMP_OPCODE_EXTERNAL_ADDRESS;
}

pub fn encode_map_request(req: &NatPmpMapRequest, out: &mut [u8; NATPMP_MAP_REQUEST_LEN]) {
    let opcode = match req.protocol {
        MapProtocol::Udp => NATPMP_OPCODE_MAP_UDP,
        MapProtocol::Tcp => NATPMP_OPCODE_MAP_TCP,
    };
    out[0] = NATPMP_VERSION;
    out[1] = opcode;
    out[2] = 0; // reserved
    out[3] = 0; // reserved
    out[4..6].copy_from_slice(&req.internal_port.to_be_bytes());
    out[6..8].copy_from_slice(&req.suggested_external_port.to_be_bytes());
    out[8..12].copy_from_slice(&req.lifetime_secs.to_be_bytes());
}

fn validate_response_header(buf: &[u8], expected_opcode: u8) -> Result<u16, WireError> {
    if buf[0] != NATPMP_VERSION {
        return Err(WireError::BadVersion { version: buf[0] });
    }
    let op = buf[1];
    if op & NATPMP_OPCODE_RESPONSE_BIT == 0 {
        return Err(WireError::NotAResponse);
    }
    if op & !NATPMP_OPCODE_RESPONSE_BIT != expected_opcode {
        return Err(WireError::BadOpcode {
            opcode: op & !NATPMP_OPCODE_RESPONSE_BIT,
        });
    }
    Ok(u16::from_be_bytes([buf[2], buf[3]]))
}

pub fn decode_external_address_response(
    buf: &[u8],
) -> Result<NatPmpExternalAddressResponse, WireError> {
    if buf.len() < NATPMP_EXTERNAL_ADDRESS_RESPONSE_LEN {
        return Err(WireError::Truncated {
            needed: NATPMP_EXTERNAL_ADDRESS_RESPONSE_LEN,
            got: buf.len(),
        });
    }
    let raw_result = validate_response_header(buf, NATPMP_OPCODE_EXTERNAL_ADDRESS)?;
    let result_code = NatPmpResultCode::from_wire(raw_result)?;
    let seconds_since_epoch = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let external_address = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
    Ok(NatPmpExternalAddressResponse {
        result_code,
        seconds_since_epoch,
        external_address,
    })
}

pub fn decode_map_response(buf: &[u8]) -> Result<NatPmpMapResponse, WireError> {
    if buf.len() < NATPMP_MAP_RESPONSE_LEN {
        return Err(WireError::Truncated {
            needed: NATPMP_MAP_RESPONSE_LEN,
            got: buf.len(),
        });
    }
    if buf[0] != NATPMP_VERSION {
        return Err(WireError::BadVersion { version: buf[0] });
    }
    let op = buf[1];
    if op & NATPMP_OPCODE_RESPONSE_BIT == 0 {
        return Err(WireError::NotAResponse);
    }
    let bare_op = op & !NATPMP_OPCODE_RESPONSE_BIT;
    let protocol = match bare_op {
        NATPMP_OPCODE_MAP_UDP => MapProtocol::Udp,
        NATPMP_OPCODE_MAP_TCP => MapProtocol::Tcp,
        other => return Err(WireError::BadOpcode { opcode: other }),
    };
    let raw_result = u16::from_be_bytes([buf[2], buf[3]]);
    let result_code = NatPmpResultCode::from_wire(raw_result)?;
    let seconds_since_epoch = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let internal_port = u16::from_be_bytes([buf[8], buf[9]]);
    let assigned_external_port = u16::from_be_bytes([buf[10], buf[11]]);
    let assigned_lifetime = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Ok(NatPmpMapResponse {
        result_code,
        protocol,
        seconds_since_epoch,
        internal_port,
        assigned_external_port,
        assigned_lifetime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> NatPmpMapRequest {
        NatPmpMapRequest {
            protocol: MapProtocol::Tcp,
            internal_port: 8443,
            suggested_external_port: 8443,
            lifetime_secs: 3600,
        }
    }

    fn synthesize_map_response(req: &NatPmpMapRequest, code: NatPmpResultCode) -> [u8; 16] {
        let opcode = match req.protocol {
            MapProtocol::Udp => NATPMP_OPCODE_MAP_UDP,
            MapProtocol::Tcp => NATPMP_OPCODE_MAP_TCP,
        };
        let mut out = [0u8; 16];
        out[0] = NATPMP_VERSION;
        out[1] = opcode | NATPMP_OPCODE_RESPONSE_BIT;
        out[2..4].copy_from_slice(&code.as_u16().to_be_bytes());
        out[4..8].copy_from_slice(&55u32.to_be_bytes());
        out[8..10].copy_from_slice(&req.internal_port.to_be_bytes());
        out[10..12].copy_from_slice(&req.suggested_external_port.to_be_bytes());
        out[12..16].copy_from_slice(&3600u32.to_be_bytes());
        out
    }

    fn synthesize_ext_addr_response(code: NatPmpResultCode, ip: Ipv4Addr) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0] = NATPMP_VERSION;
        out[1] = NATPMP_OPCODE_EXTERNAL_ADDRESS | NATPMP_OPCODE_RESPONSE_BIT;
        out[2..4].copy_from_slice(&code.as_u16().to_be_bytes());
        out[4..8].copy_from_slice(&55u32.to_be_bytes());
        out[8..12].copy_from_slice(&ip.octets());
        out
    }

    #[test]
    fn encode_map_request_tcp_layout() {
        let req = sample_request();
        let mut buf = [0u8; NATPMP_MAP_REQUEST_LEN];
        encode_map_request(&req, &mut buf);
        assert_eq!(buf[0], NATPMP_VERSION);
        assert_eq!(buf[1], NATPMP_OPCODE_MAP_TCP);
        assert_eq!(&buf[2..4], &[0, 0]);
        assert_eq!(&buf[4..6], &8443u16.to_be_bytes());
        assert_eq!(&buf[6..8], &8443u16.to_be_bytes());
        assert_eq!(&buf[8..12], &3600u32.to_be_bytes());
    }

    #[test]
    fn encode_map_request_udp_opcode() {
        let req = NatPmpMapRequest {
            protocol: MapProtocol::Udp,
            internal_port: 51820,
            suggested_external_port: 51820,
            lifetime_secs: 3600,
        };
        let mut buf = [0u8; NATPMP_MAP_REQUEST_LEN];
        encode_map_request(&req, &mut buf);
        assert_eq!(buf[1], NATPMP_OPCODE_MAP_UDP);
    }

    #[test]
    fn decode_map_response_success_tcp() {
        let req = sample_request();
        let buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        let resp = decode_map_response(&buf).unwrap();
        assert_eq!(resp.result_code, NatPmpResultCode::Success);
        assert_eq!(resp.protocol, MapProtocol::Tcp);
        assert_eq!(resp.internal_port, 8443);
        assert_eq!(resp.assigned_external_port, 8443);
        assert_eq!(resp.assigned_lifetime, 3600);
        assert_eq!(resp.seconds_since_epoch, 55);
    }

    #[test]
    fn decode_map_response_success_udp() {
        let req = NatPmpMapRequest {
            protocol: MapProtocol::Udp,
            internal_port: 51820,
            suggested_external_port: 51820,
            lifetime_secs: 3600,
        };
        let buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        let resp = decode_map_response(&buf).unwrap();
        assert_eq!(resp.protocol, MapProtocol::Udp);
        assert_eq!(resp.internal_port, 51820);
    }

    #[test]
    fn decode_each_error_code() {
        let req = sample_request();
        for code in [
            NatPmpResultCode::UnsupportedVersion,
            NatPmpResultCode::NotAuthorized,
            NatPmpResultCode::NetworkFailure,
            NatPmpResultCode::OutOfResources,
            NatPmpResultCode::UnsupportedOpcode,
        ] {
            let buf = synthesize_map_response(&req, code);
            let resp = decode_map_response(&buf).unwrap();
            assert_eq!(resp.result_code, code);
        }
    }

    #[test]
    fn external_address_response_round_trip() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let buf = synthesize_ext_addr_response(NatPmpResultCode::Success, ip);
        let resp = decode_external_address_response(&buf).unwrap();
        assert_eq!(resp.result_code, NatPmpResultCode::Success);
        assert_eq!(resp.external_address, ip);
        assert_eq!(resp.seconds_since_epoch, 55);
    }

    #[test]
    fn external_address_request_encodes_two_bytes() {
        let mut buf = [0u8; NATPMP_EXTERNAL_ADDRESS_REQUEST_LEN];
        encode_external_address_request(&mut buf);
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn rejects_truncated_map_response() {
        let buf = [0u8; 10];
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_request_form_map_response() {
        let req = sample_request();
        let mut buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        buf[1] = NATPMP_OPCODE_MAP_TCP; // strip response bit
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::NotAResponse)
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let req = sample_request();
        let mut buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        buf[0] = 42;
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::BadVersion { version: 42 })
        ));
    }

    #[test]
    fn rejects_unknown_opcode() {
        let req = sample_request();
        let mut buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        buf[1] = 0x83; // response bit set, opcode 3 (unknown)
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::BadOpcode { opcode: 3 })
        ));
    }

    #[test]
    fn unknown_result_code_surfaces() {
        let req = sample_request();
        let mut buf = synthesize_map_response(&req, NatPmpResultCode::Success);
        buf[2..4].copy_from_slice(&42u16.to_be_bytes());
        assert!(matches!(
            decode_map_response(&buf),
            Err(WireError::UnknownResultCode(42))
        ));
    }

    #[test]
    fn classifies_transient_codes() {
        assert!(NatPmpResultCode::NetworkFailure.is_transient());
        assert!(NatPmpResultCode::OutOfResources.is_transient());
        assert!(!NatPmpResultCode::Success.is_transient());
        assert!(!NatPmpResultCode::NotAuthorized.is_transient());
        assert!(!NatPmpResultCode::UnsupportedVersion.is_transient());
    }
}
