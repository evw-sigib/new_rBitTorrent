//! Pure-Rust RFC 6886 NAT-PMP client for Proton VPN port forwarding.
//!
//! Wire format (all integers big-endian):
//!
//! ```text
//! external address request   : version(1)=0 opcode(1)=0
//! external address response  : version(1) opcode(1)=128 result(2) epoch(4) ipv4(4)        = 12 bytes
//! mapping request            : version(1)=0 opcode(1)=1|2 reserved(2) internal(2)
//!                              suggested_external(2) lifetime(4)                           = 12 bytes
//! mapping response           : version(1) opcode(1)=128+op result(2) epoch(4) internal(2)
//!                              mapped_external(2) lifetime(4)                              = 16 bytes
//! ```
//!
//! Proton's gateway (`10.2.0.1:5351`, reachable only inside the tunnel)
//! assigns the public port itself and forwards it to the *same* port on the
//! tunnel address, so the BitTorrent client must listen on the leased port.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, warn};

pub const NATPMP_PORT: u16 = 5351;
const VERSION: u8 = 0;
const OP_EXTERNAL_ADDRESS: u8 = 0;
const RESPONSE_BIT: u8 = 128;
const EXTERNAL_ADDRESS_RESPONSE_LEN: usize = 12;
const MAPPING_RESPONSE_LEN: usize = 16;

/// Lease lifetime requested from the gateway (Proton grants 60 s).
pub const LEASE_LIFETIME_SECS: u32 = 60;
/// Renewal period: comfortably inside the 60 s lifetime.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(45);

/// When to renew a lease the gateway granted for `lifetime` seconds: after
/// three quarters of it, at most [`RENEW_INTERVAL`] and at least 5 s (a
/// gateway granting less than asked must not see the lease lapse).
pub fn renew_after(lifetime: u32) -> Duration {
    Duration::from_secs(u64::from(lifetime) * 3 / 4).clamp(Duration::from_secs(5), RENEW_INTERVAL)
}
/// RFC 6886 §3.1 retransmission start; doubled on every retry.
pub const INITIAL_RETRY_TIMEOUT: Duration = Duration::from_millis(250);
/// Total transmissions per request (250 + 500 + 1000 + 2000 ms ≈ 3.75 s).
pub const MAX_ATTEMPTS: u32 = 4;
/// Proton's documented usage (`natpmpc -a 1 0 <proto> 60`): internal port 0,
/// the gateway picks the public port and forwards it to the same local port.
pub const PROTON_INTERNAL_PORT: u16 = 0;
/// Suggested external port for the very first request (Proton ignores it).
pub const INITIAL_SUGGESTED_PORT: u16 = 1;

pub const PMP_HINT: &str = "Proton VPN did not grant a forwarded port. Generate a new WireGuard \
configuration on account.protonvpn.com with the \"NAT-PMP (Port Forwarding)\" toggle enabled \
(the +pmp option), pick a P2P server, and paste the new .conf into the app options.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    pub fn opcode(self) -> u8 {
        match self {
            Protocol::Udp => 1,
            Protocol::Tcp => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Udp => "UDP",
            Protocol::Tcp => "TCP",
        }
    }
}

/// RFC 6886 §3.5 result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
    Other(u16),
}

impl ResultCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => ResultCode::Success,
            1 => ResultCode::UnsupportedVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::NetworkFailure,
            4 => ResultCode::OutOfResources,
            5 => ResultCode::UnsupportedOpcode,
            other => ResultCode::Other(other),
        }
    }

    /// Codes that mean "this gateway will not forward ports for you".
    pub fn means_port_forwarding_disabled(self) -> bool {
        matches!(
            self,
            ResultCode::NotAuthorized
                | ResultCode::UnsupportedOpcode
                | ResultCode::UnsupportedVersion
        )
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResultCode::Success => f.write_str("0 (success)"),
            ResultCode::UnsupportedVersion => f.write_str("1 (unsupported version)"),
            ResultCode::NotAuthorized => f.write_str("2 (not authorized / refused)"),
            ResultCode::NetworkFailure => f.write_str("3 (network failure)"),
            ResultCode::OutOfResources => f.write_str("4 (out of resources)"),
            ResultCode::UnsupportedOpcode => f.write_str("5 (unsupported opcode)"),
            ResultCode::Other(v) => write!(f, "{v} (unknown)"),
        }
    }
}

#[derive(Debug)]
pub enum NatPmpError {
    Truncated { expected: usize, got: usize },
    BadVersion(u8),
    UnexpectedOpcode { expected: u8, got: u8 },
    Rejected(ResultCode),
    InvalidMapping(&'static str),
    Timeout { attempts: u32 },
    Io(io::Error),
}

impl NatPmpError {
    /// True when the error means the user must change something on Proton's side.
    pub fn needs_pmp_hint(&self) -> bool {
        match self {
            NatPmpError::Rejected(code) => code.means_port_forwarding_disabled(),
            NatPmpError::Timeout { .. } => true,
            NatPmpError::Io(e) => e.kind() == io::ErrorKind::ConnectionRefused,
            _ => false,
        }
    }

    /// Malformed or unrelated packets are skipped while waiting for the real answer.
    fn is_ignorable_packet(&self) -> bool {
        matches!(
            self,
            NatPmpError::Truncated { .. }
                | NatPmpError::BadVersion(_)
                | NatPmpError::UnexpectedOpcode { .. }
        )
    }
}

impl fmt::Display for NatPmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatPmpError::Truncated { expected, got } => {
                write!(
                    f,
                    "truncated NAT-PMP response ({got} bytes, expected {expected})"
                )
            }
            NatPmpError::BadVersion(v) => write!(f, "unsupported NAT-PMP response version {v}"),
            NatPmpError::UnexpectedOpcode { expected, got } => {
                write!(f, "unexpected NAT-PMP opcode {got} (expected {expected})")
            }
            NatPmpError::Rejected(code) => write!(f, "NAT-PMP gateway answered result code {code}"),
            NatPmpError::InvalidMapping(why) => write!(f, "invalid NAT-PMP mapping: {why}"),
            NatPmpError::Timeout { attempts } => {
                write!(f, "no NAT-PMP answer after {attempts} attempts")
            }
            NatPmpError::Io(e) => write!(f, "NAT-PMP socket error: {e}"),
        }
    }
}

impl std::error::Error for NatPmpError {}

impl From<io::Error> for NatPmpError {
    fn from(e: io::Error) -> Self {
        NatPmpError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAddress {
    pub epoch: u32,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub protocol: Protocol,
    pub epoch: u32,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: u32,
}

// ---------------------------------------------------------------------------
// Encoding / decoding (pure)
// ---------------------------------------------------------------------------

pub fn encode_external_address_request() -> [u8; 2] {
    [VERSION, OP_EXTERNAL_ADDRESS]
}

pub fn encode_mapping_request(
    protocol: Protocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime: u32,
) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = VERSION;
    buf[1] = protocol.opcode();
    // buf[2..4] reserved, zero.
    buf[4..6].copy_from_slice(&internal_port.to_be_bytes());
    buf[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    buf[8..12].copy_from_slice(&lifetime.to_be_bytes());
    buf
}

fn be16(buf: &[u8], at: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = buf.get(at..at + 2) {
        b.copy_from_slice(s);
    }
    u16::from_be_bytes(b)
}

fn be32(buf: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = buf.get(at..at + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Validates the common header and returns the result code.
fn check_header(buf: &[u8], expected_len: usize, expected_op: u8) -> Result<(), NatPmpError> {
    // Opcode/version are checked first so stray packets of another kind are
    // recognised as such rather than as "truncated".
    let (Some(&version), Some(&opcode)) = (buf.first(), buf.get(1)) else {
        return Err(NatPmpError::Truncated {
            expected: expected_len,
            got: buf.len(),
        });
    };
    if version != VERSION {
        return Err(NatPmpError::BadVersion(version));
    }
    if opcode != expected_op {
        return Err(NatPmpError::UnexpectedOpcode {
            expected: expected_op,
            got: opcode,
        });
    }
    // A short error response still carries a meaningful result code (RFC 6886 §3.5).
    if buf.len() >= 4 {
        let code = ResultCode::from_u16(be16(buf, 2));
        if code != ResultCode::Success {
            return Err(NatPmpError::Rejected(code));
        }
    }
    if buf.len() < expected_len {
        return Err(NatPmpError::Truncated {
            expected: expected_len,
            got: buf.len(),
        });
    }
    Ok(())
}

pub fn decode_external_address_response(buf: &[u8]) -> Result<ExternalAddress, NatPmpError> {
    check_header(
        buf,
        EXTERNAL_ADDRESS_RESPONSE_LEN,
        RESPONSE_BIT | OP_EXTERNAL_ADDRESS,
    )?;
    Ok(ExternalAddress {
        epoch: be32(buf, 4),
        ip: Ipv4Addr::from(be32(buf, 8)),
    })
}

pub fn decode_mapping_response(buf: &[u8], protocol: Protocol) -> Result<Mapping, NatPmpError> {
    check_header(buf, MAPPING_RESPONSE_LEN, RESPONSE_BIT | protocol.opcode())?;
    let mapping = Mapping {
        protocol,
        epoch: be32(buf, 4),
        internal_port: be16(buf, 8),
        external_port: be16(buf, 10),
        lifetime: be32(buf, 12),
    };
    if mapping.external_port == 0 {
        return Err(NatPmpError::InvalidMapping(
            "gateway returned external port 0",
        ));
    }
    Ok(mapping)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A connected UDP NAT-PMP client with RFC 6886 retransmission.
#[derive(Debug)]
pub struct Client {
    socket: UdpSocket,
    gateway: SocketAddrV4,
    initial_timeout: Duration,
    attempts: u32,
}

impl Client {
    /// Binds to `local_ip` (the tunnel address, so the socket lives inside the
    /// VPN) and connects to the gateway so only its answers are received.
    pub async fn connect(local_ip: Ipv4Addr, gateway: SocketAddrV4) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(local_ip, 0))).await?;
        socket.connect(SocketAddr::V4(gateway)).await?;
        Ok(Self {
            socket,
            gateway,
            initial_timeout: INITIAL_RETRY_TIMEOUT,
            attempts: MAX_ATTEMPTS,
        })
    }

    #[cfg(test)]
    pub fn with_retry(mut self, initial_timeout: Duration, attempts: u32) -> Self {
        self.initial_timeout = initial_timeout;
        self.attempts = attempts.max(1);
        self
    }

    async fn transact<T>(
        &self,
        request: &[u8],
        decode: impl Fn(&[u8]) -> Result<T, NatPmpError>,
    ) -> Result<T, NatPmpError> {
        let mut buf = [0u8; 64];
        let mut wait = self.initial_timeout;
        for attempt in 1..=self.attempts {
            self.socket.send(request).await?;
            let deadline = Instant::now() + wait;
            loop {
                match timeout_at(deadline, self.socket.recv(&mut buf)).await {
                    Err(_elapsed) => break,
                    Ok(Err(e)) => return Err(NatPmpError::Io(e)),
                    Ok(Ok(n)) => {
                        let packet = buf.get(..n).unwrap_or(&[]);
                        match decode(packet) {
                            Ok(v) => return Ok(v),
                            Err(e) if e.is_ignorable_packet() => {
                                debug!("ignoring NAT-PMP packet: {e}");
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            debug!(
                attempt,
                timeout_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                "NAT-PMP request to {} timed out",
                self.gateway
            );
            wait = wait.saturating_mul(2);
        }
        Err(NatPmpError::Timeout {
            attempts: self.attempts,
        })
    }

    /// Opcode 0: the public IPv4 address of the tunnel.
    pub async fn external_address(&self) -> Result<ExternalAddress, NatPmpError> {
        self.transact(
            &encode_external_address_request(),
            decode_external_address_response,
        )
        .await
    }

    /// Opcodes 1/2: request or renew a mapping (lifetime 0 deletes it).
    pub async fn map(
        &self,
        protocol: Protocol,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: u32,
    ) -> Result<Mapping, NatPmpError> {
        let req =
            encode_mapping_request(protocol, internal_port, suggested_external_port, lifetime);
        self.transact(&req, |b| decode_mapping_response(b, protocol))
            .await
    }
}

/// Sends a single opcode-0 datagram without waiting: enough to make the kernel
/// WireGuard peer start its handshake.
pub async fn send_probe(local_ip: Ipv4Addr, target: SocketAddrV4) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(local_ip, 0))).await?;
    socket
        .send_to(&encode_external_address_request(), SocketAddr::V4(target))
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Port forwarding state machine
// ---------------------------------------------------------------------------

/// A successful UDP+TCP lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// The port rtbit must listen on (the TCP mapping's external port).
    pub port: u16,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub lifetime: u32,
    /// Set when the gateway's epoch went backwards (it lost its mappings).
    pub gateway_restarted: bool,
}

impl Lease {
    /// Ports that must be open in the firewall.
    pub fn firewall_ports(&self) -> Vec<u16> {
        let mut ports = vec![self.tcp_port];
        if self.udp_port != self.tcp_port {
            ports.push(self.udp_port);
        }
        ports
    }
}

/// What to do with rtbit after a lease attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortDecision {
    /// Same port as before: leave rtbit alone (zero-disruption renewal).
    Unchanged,
    /// First lease or a new port: update the firewall, then (re)start rtbit.
    Changed { old: Option<u16>, new: u16 },
}

pub fn decide(current: Option<u16>, leased: u16) -> PortDecision {
    if current == Some(leased) {
        PortDecision::Unchanged
    } else {
        PortDecision::Changed {
            old: current,
            new: leased,
        }
    }
}

/// Requests and renews the UDP + TCP mappings.
#[derive(Debug)]
pub struct PortForwarder {
    client: Client,
    current: Option<u16>,
    last_epoch: Option<(u32, Instant)>,
}

impl PortForwarder {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            current: None,
            last_epoch: None,
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    #[cfg(test)]
    pub fn current(&self) -> Option<u16> {
        self.current
    }

    /// RFC 6886 §3.6: the epoch should advance with wall time; a smaller value
    /// than expected means the gateway restarted and forgot its mappings.
    fn epoch_went_backwards(&mut self, epoch: u32) -> bool {
        let now = Instant::now();
        let backwards = match self.last_epoch {
            Some((prev, at)) => {
                let elapsed = u32::try_from(now.duration_since(at).as_secs()).unwrap_or(u32::MAX);
                // Allow the RFC's 7/8 tolerance plus 2 s of jitter.
                let expected = prev.saturating_add(elapsed - elapsed / 8);
                epoch.saturating_add(2) < expected
            }
            None => false,
        };
        self.last_epoch = Some((epoch, now));
        backwards
    }

    /// Requests (or renews) UDP and TCP mappings, suggesting the current port.
    pub async fn lease(&mut self) -> Result<Lease, NatPmpError> {
        let suggested = self.current.unwrap_or(INITIAL_SUGGESTED_PORT);
        let udp = self
            .client
            .map(
                Protocol::Udp,
                PROTON_INTERNAL_PORT,
                suggested,
                LEASE_LIFETIME_SECS,
            )
            .await?;
        let tcp = self
            .client
            .map(
                Protocol::Tcp,
                PROTON_INTERNAL_PORT,
                udp.external_port,
                LEASE_LIFETIME_SECS,
            )
            .await?;
        if udp.external_port != tcp.external_port {
            warn!(
                udp = udp.external_port,
                tcp = tcp.external_port,
                "NAT-PMP gave different UDP and TCP ports; rtbit will listen on the TCP port"
            );
        }
        let gateway_restarted = self.epoch_went_backwards(tcp.epoch);
        self.current = Some(tcp.external_port);
        Ok(Lease {
            port: tcp.external_port,
            udp_port: udp.external_port,
            tcp_port: tcp.external_port,
            lifetime: tcp.lifetime.min(udp.lifetime),
            gateway_restarted,
        })
    }

    /// Best-effort deletion of our mappings on shutdown (lifetime 0, single try).
    pub async fn release(&mut self) {
        if self.current.take().is_none() {
            return;
        }
        for proto in [Protocol::Udp, Protocol::Tcp] {
            let req = encode_mapping_request(proto, PROTON_INTERNAL_PORT, 0, 0);
            if let Err(e) = self.client.socket.send(&req).await {
                debug!("could not release NAT-PMP {} mapping: {e}", proto.as_str());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_follows_a_short_lifetime() {
        assert_eq!(renew_after(60), Duration::from_secs(45));
        assert_eq!(renew_after(7200), RENEW_INTERVAL);
        assert_eq!(renew_after(20), Duration::from_secs(15));
        assert_eq!(renew_after(2), Duration::from_secs(5));
        assert_eq!(renew_after(0), Duration::from_secs(5));
    }
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mapping_response(
        op: u8,
        result: u16,
        epoch: u32,
        internal: u16,
        ext: u16,
        life: u32,
    ) -> Vec<u8> {
        let mut v = vec![0, 128 + op];
        v.extend_from_slice(&result.to_be_bytes());
        v.extend_from_slice(&epoch.to_be_bytes());
        v.extend_from_slice(&internal.to_be_bytes());
        v.extend_from_slice(&ext.to_be_bytes());
        v.extend_from_slice(&life.to_be_bytes());
        v
    }

    fn external_response(result: u16, epoch: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0, 128];
        v.extend_from_slice(&result.to_be_bytes());
        v.extend_from_slice(&epoch.to_be_bytes());
        v.extend_from_slice(&ip);
        v
    }

    #[test]
    fn encodes_requests_exactly() {
        assert_eq!(encode_external_address_request(), [0, 0]);
        assert_eq!(
            encode_mapping_request(Protocol::Udp, 0, 1, 60),
            [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 60]
        );
        assert_eq!(
            encode_mapping_request(Protocol::Tcp, 0x1234, 51413, 3600),
            [0, 2, 0, 0, 0x12, 0x34, 0xc8, 0xd5, 0, 0, 0x0e, 0x10]
        );
    }

    #[test]
    fn decodes_external_address() {
        let ok = decode_external_address_response(&external_response(0, 1234, [185, 159, 157, 7]))
            .unwrap();
        assert_eq!(ok.ip, Ipv4Addr::new(185, 159, 157, 7));
        assert_eq!(ok.epoch, 1234);
    }

    #[test]
    fn decodes_valid_mappings() {
        let m = decode_mapping_response(&mapping_response(1, 0, 99, 0, 51234, 60), Protocol::Udp)
            .unwrap();
        assert_eq!(m.external_port, 51234);
        assert_eq!(m.lifetime, 60);
        assert_eq!(m.epoch, 99);
        let m = decode_mapping_response(&mapping_response(2, 0, 99, 0, 51234, 60), Protocol::Tcp)
            .unwrap();
        assert_eq!(m.protocol, Protocol::Tcp);
    }

    #[test]
    fn proton_pmp_disabled_codes_produce_the_hint() {
        for code in [2u16, 5, 1] {
            let err =
                decode_mapping_response(&mapping_response(1, code, 1, 0, 0, 0), Protocol::Udp)
                    .unwrap_err();
            assert!(matches!(err, NatPmpError::Rejected(_)), "{err}");
            assert!(err.needs_pmp_hint(), "code {code}");
        }
        // Network failure / out of resources are transient, no config hint.
        let err = decode_mapping_response(&mapping_response(1, 3, 1, 0, 0, 0), Protocol::Udp)
            .unwrap_err();
        assert!(!err.needs_pmp_hint());
        // RFC 6886 §3.5: an error reply may be only 4 bytes long; the code still counts.
        let err = decode_external_address_response(&[0, 128, 0, 2]).unwrap_err();
        assert!(matches!(
            err,
            NatPmpError::Rejected(ResultCode::NotAuthorized)
        ));
        assert!(NatPmpError::Timeout { attempts: 4 }.needs_pmp_hint());
        assert!(PMP_HINT.contains("NAT-PMP (Port Forwarding)"));
    }

    #[test]
    fn rejects_truncated_and_foreign_packets() {
        let full = mapping_response(2, 0, 1, 0, 40000, 60);
        for n in [0, 1, 3, 8, 15] {
            let err = decode_mapping_response(&full[..n], Protocol::Tcp).unwrap_err();
            assert!(
                matches!(err, NatPmpError::Truncated { .. }),
                "len {n}: {err}"
            );
        }
        let err = decode_external_address_response(&[0, 128, 0, 0, 0, 0]).unwrap_err();
        assert!(matches!(
            err,
            NatPmpError::Truncated {
                expected: 12,
                got: 6
            }
        ));
        // A UDP response while waiting for TCP is an opcode mismatch.
        let err = decode_mapping_response(&mapping_response(1, 0, 1, 0, 1, 60), Protocol::Tcp)
            .unwrap_err();
        assert!(matches!(
            err,
            NatPmpError::UnexpectedOpcode {
                expected: 130,
                got: 129
            }
        ));
        let mut bad_version = full.clone();
        bad_version[0] = 2;
        assert!(matches!(
            decode_mapping_response(&bad_version, Protocol::Tcp).unwrap_err(),
            NatPmpError::BadVersion(2)
        ));
        let zero_port = mapping_response(2, 0, 1, 0, 0, 60);
        assert!(matches!(
            decode_mapping_response(&zero_port, Protocol::Tcp).unwrap_err(),
            NatPmpError::InvalidMapping(_)
        ));
    }

    #[test]
    fn port_decision_only_changes_on_a_new_port() {
        assert_eq!(
            decide(None, 5000),
            PortDecision::Changed {
                old: None,
                new: 5000
            }
        );
        assert_eq!(decide(Some(5000), 5000), PortDecision::Unchanged);
        assert_eq!(
            decide(Some(5000), 6000),
            PortDecision::Changed {
                old: Some(5000),
                new: 6000
            }
        );
        let lease = Lease {
            port: 1,
            udp_port: 2,
            tcp_port: 1,
            lifetime: 60,
            gateway_restarted: false,
        };
        assert_eq!(lease.firewall_ports(), vec![1, 2]);
    }

    /// A scripted fake gateway on 127.0.0.1.
    struct FakeGateway {
        addr: SocketAddrV4,
        received: Arc<AtomicUsize>,
    }

    /// `script(n, request)` returns the reply for the n-th request (None = drop it).
    async fn fake_gateway(
        script: impl Fn(usize, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> FakeGateway {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = match sock.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => unreachable!(),
        };
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let idx = counter.fetch_add(1, Ordering::SeqCst);
                if let Some(reply) = script(idx, &buf[..n]) {
                    let _ = sock.send_to(&reply, peer).await;
                }
            }
        });
        FakeGateway { addr, received }
    }

    fn reply_for(req: &[u8], port: u16, epoch: u32) -> Vec<u8> {
        match req[1] {
            0 => external_response(0, epoch, [203, 0, 113, 9]),
            op => mapping_response(op, 0, epoch, 0, port, 60),
        }
    }

    #[tokio::test]
    async fn one_dropped_packet_is_retried_not_fatal() {
        // Drop the very first datagram; answer everything after that.
        let gw = fake_gateway(|n, req| (n > 0).then(|| reply_for(req, 41000, 10))).await;
        let client = Client::connect(Ipv4Addr::LOCALHOST, gw.addr)
            .await
            .unwrap()
            .with_retry(Duration::from_millis(30), 4);
        let mut pf = PortForwarder::new(client);
        let lease = pf.lease().await.unwrap();
        assert_eq!(lease.port, 41000);
        assert_eq!(pf.current(), Some(41000));
        // 1 dropped + UDP + TCP.
        assert_eq!(gw.received.load(Ordering::SeqCst), 3);
        let ext = pf.client().external_address().await.unwrap();
        assert_eq!(ext.ip, Ipv4Addr::new(203, 0, 113, 9));
    }

    #[tokio::test]
    async fn renewal_suggests_current_port_and_detects_changes() {
        let gw = fake_gateway(|n, req| {
            // First lease -> 41000, later -> 42000 (Proton reassigned).
            let port = if n < 2 { 41000 } else { 42000 };
            if n >= 2 && req[1] != 0 {
                // Renewal must suggest the previously leased port.
                assert_eq!(
                    u16::from_be_bytes([req[6], req[7]]),
                    if req[1] == 1 { 41000 } else { 42000 }
                );
            }
            Some(reply_for(req, port, 100 + n as u32))
        })
        .await;
        let client = Client::connect(Ipv4Addr::LOCALHOST, gw.addr)
            .await
            .unwrap()
            .with_retry(Duration::from_millis(50), 2);
        let mut pf = PortForwarder::new(client);
        let first = pf.lease().await.unwrap();
        assert_eq!(
            decide(None, first.port),
            PortDecision::Changed {
                old: None,
                new: 41000
            }
        );
        let second = pf.lease().await.unwrap();
        assert_eq!(
            decide(Some(first.port), second.port),
            PortDecision::Changed {
                old: Some(41000),
                new: 42000
            }
        );
    }

    #[tokio::test]
    async fn silent_gateway_times_out_with_hint() {
        let gw = fake_gateway(|_, _| None).await;
        let client = Client::connect(Ipv4Addr::LOCALHOST, gw.addr)
            .await
            .unwrap()
            .with_retry(Duration::from_millis(10), 4);
        let err = client.external_address().await.unwrap_err();
        assert!(matches!(err, NatPmpError::Timeout { attempts: 4 }));
        assert!(err.needs_pmp_hint());
        assert_eq!(gw.received.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn refused_and_garbage_packets() {
        // Garbage first (ignored), then a refusal.
        let gw = fake_gateway(|n, req| {
            if n == 0 {
                Some(vec![9, 9, 9])
            } else {
                Some(mapping_response(req[1], 2, 1, 0, 0, 0))
            }
        })
        .await;
        let client = Client::connect(Ipv4Addr::LOCALHOST, gw.addr)
            .await
            .unwrap()
            .with_retry(Duration::from_millis(40), 3);
        let err = client.map(Protocol::Udp, 0, 1, 60).await.unwrap_err();
        assert!(
            matches!(err, NatPmpError::Rejected(ResultCode::NotAuthorized)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn stale_reply_for_other_opcode_is_skipped() {
        // Reply to a mapping request with an opcode-0 answer first, then the real one.
        let gw = fake_gateway(|_, req| {
            if req[1] == 1 {
                let mut both = external_response(0, 5, [1, 2, 3, 4]);
                both.truncate(12);
                Some(both)
            } else {
                Some(reply_for(req, 1, 5))
            }
        })
        .await;
        let client = Client::connect(Ipv4Addr::LOCALHOST, gw.addr)
            .await
            .unwrap()
            .with_retry(Duration::from_millis(20), 2);
        let err = client.map(Protocol::Udp, 0, 1, 60).await.unwrap_err();
        // Only foreign packets arrived: that is a timeout, not a hard failure.
        assert!(matches!(err, NatPmpError::Timeout { attempts: 2 }));
    }

    #[test]
    fn epoch_reset_detection() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock_gw = fake_gateway(|_, _| None).await;
            let client = Client::connect(Ipv4Addr::LOCALHOST, sock_gw.addr)
                .await
                .unwrap();
            let mut pf = PortForwarder::new(client);
            assert!(!pf.epoch_went_backwards(1000));
            assert!(!pf.epoch_went_backwards(1001));
            assert!(pf.epoch_went_backwards(3));
        });
    }
}
