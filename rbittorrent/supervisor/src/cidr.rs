//! Minimal IPv4 CIDR type shared by the config, firewall and routing code.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 address with a prefix length, e.g. `10.2.0.2/32` or `192.168.0.0/16`.
///
/// The address keeps its host bits so the same type can describe an interface
/// address (`10.2.0.2/32`) and, after [`Ipv4Cidr::network`], a subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    /// Builds a CIDR, rejecting prefixes longer than 32 bits.
    pub const fn new(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix <= 32 {
            Some(Self { addr, prefix })
        } else {
            None
        }
    }

    /// Const constructor for compile-time constants; prefixes above 32 are clamped.
    pub const fn from_parts(addr: Ipv4Addr, prefix: u8) -> Self {
        Self {
            addr,
            prefix: if prefix > 32 { 32 } else { prefix },
        }
    }

    /// A single host (`/32`).
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    #[cfg(test)]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    fn mask(&self) -> u32 {
        match self.prefix {
            0 => 0,
            p => u32::MAX << (32 - u32::from(p)),
        }
    }

    /// The same prefix with all host bits cleared (`192.168.1.7/24` -> `192.168.1.0/24`).
    pub fn network(&self) -> Self {
        Self {
            addr: Ipv4Addr::from(u32::from(self.addr) & self.mask()),
            prefix: self.prefix,
        }
    }

    pub fn contains_addr(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask()) == (u32::from(self.addr) & self.mask())
    }

    /// True when `other` lies entirely inside `self`.
    pub fn contains(&self, other: &Ipv4Cidr) -> bool {
        other.prefix >= self.prefix && self.contains_addr(other.addr)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Error returned when a CIDR string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrParseError(pub String);

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not an IPv4 address or CIDR (expected e.g. 192.168.1.0/24)",
            self.0
        )
    }
}

impl std::error::Error for CidrParseError {}

impl FromStr for Ipv4Cidr {
    type Err = CidrParseError;

    /// Parses `a.b.c.d` (as `/32`) or `a.b.c.d/p`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let err = || CidrParseError(s.to_owned());
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), p.trim().parse::<u8>().map_err(|_| err())?),
            None => (s, 32),
        };
        let addr = addr.parse::<Ipv4Addr>().map_err(|_| err())?;
        Ipv4Cidr::new(addr, prefix).ok_or_else(err)
    }
}

/// Normalises every CIDR to its network address, removes duplicates and drops
/// any CIDR already covered by a wider one, so the result can be loaded into an
/// nftables `flags interval` set without "conflicting intervals" errors.
pub fn collapse(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let mut nets: Vec<Ipv4Cidr> = cidrs.iter().map(Ipv4Cidr::network).collect();
    // Widest prefixes first so that containment checks see the covering net.
    nets.sort_by(|a, b| a.prefix.cmp(&b.prefix).then(a.addr.cmp(&b.addr)));
    let mut out: Vec<Ipv4Cidr> = Vec::with_capacity(nets.len());
    for net in nets {
        if !out.iter().any(|kept| kept.contains(&net)) {
            out.push(net);
        }
    }
    out.sort_by(|a, b| a.addr.cmp(&b.addr).then(a.prefix.cmp(&b.prefix)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_hosts_and_prefixes() {
        assert_eq!(
            c("10.2.0.2"),
            Ipv4Cidr::from_parts(Ipv4Addr::new(10, 2, 0, 2), 32)
        );
        assert_eq!(c(" 192.168.1.0 / 24 ").prefix(), 24);
        assert!("10.0.0.0/33".parse::<Ipv4Cidr>().is_err());
        assert!("fd00::/8".parse::<Ipv4Cidr>().is_err());
        assert!("nonsense".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn network_and_containment() {
        assert_eq!(c("192.168.1.77/24").network(), c("192.168.1.0/24"));
        assert_eq!(c("1.2.3.4/0").network(), c("0.0.0.0/0"));
        assert!(c("172.16.0.0/12").contains(&c("172.30.32.0/23")));
        assert!(!c("172.30.32.0/23").contains(&c("172.16.0.0/12")));
        assert!(c("10.0.0.0/8").contains_addr(Ipv4Addr::new(10, 2, 0, 1)));
        assert!(!c("192.168.0.0/16").contains_addr(Ipv4Addr::new(10, 2, 0, 1)));
    }

    #[test]
    fn collapse_merges_overlaps_and_duplicates() {
        let got = collapse(&[
            c("172.30.32.0/23"),
            c("192.168.1.5/24"),
            c("172.16.0.0/12"),
            c("192.168.0.0/16"),
            c("192.168.0.0/16"),
            c("100.64.0.0/10"),
        ]);
        assert_eq!(
            got,
            vec![c("100.64.0.0/10"), c("172.16.0.0/12"), c("192.168.0.0/16")]
        );
    }
}
