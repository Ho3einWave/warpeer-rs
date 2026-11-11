//! Cloudflare WARP endpoint address space: the published anycast prefixes and the
//! set of UDP ports WARP listens on, plus helpers to pick a random endpoint or a
//! random IP from a prefix (used by the scanner and for the default endpoint).

use anyhow::{anyhow, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A CIDR prefix (network address + prefix length).
#[derive(Clone, Copy, Debug)]
pub struct Cidr {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Cidr {
    const fn v4(a: u8, b: u8, c: u8, d: u8, bits: u8) -> Self {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            bits,
        }
    }
    fn v6(s: &str, bits: u8) -> Self {
        Cidr {
            addr: IpAddr::V6(s.parse::<Ipv6Addr>().expect("static v6 literal")),
            bits,
        }
    }
}

/// The WARP anycast prefixes (mirrors warp-plus `warp/endpoint.go`).
pub fn warp_prefixes() -> Vec<Cidr> {
    vec![
        Cidr::v4(162, 159, 192, 0, 24),
        Cidr::v4(162, 159, 195, 0, 24),
        Cidr::v4(188, 114, 96, 0, 24),
        Cidr::v4(188, 114, 97, 0, 24),
        Cidr::v4(188, 114, 98, 0, 24),
        Cidr::v4(188, 114, 99, 0, 24),
        Cidr::v6("2606:4700:d0::", 64),
        Cidr::v6("2606:4700:d1::", 64),
    ]
}

/// The UDP ports WARP accepts handshakes on (mirrors warp-plus `warp/endpoint.go`).
pub fn warp_ports() -> &'static [u16] {
    &[
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
        955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
        2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
        7559, 8319, 8742, 8854, 8886,
    ]
}

/// Pick a random WARP port.
pub fn random_warp_port() -> u16 {
    let ports = warp_ports();
    *ports.choose(&mut rand::thread_rng()).unwrap()
}

/// Pick a random prefix matching the requested address family/families.
fn random_warp_prefix(v4: bool, v6: bool) -> Result<Cidr> {
    if !v4 && !v6 {
        return Err(anyhow!("must choose an IP version for random warp prefix"));
    }
    let cidrs = warp_prefixes();
    let mut rng = rand::thread_rng();
    loop {
        let c = *cidrs.choose(&mut rng).unwrap();
        match c.addr {
            IpAddr::V4(_) if v4 => return Ok(c),
            IpAddr::V6(_) if v6 => return Ok(c),
            _ => continue,
        }
    }
}

/// Return a random IP address within the given prefix.
pub fn random_ip_from_prefix(cidr: Cidr) -> Result<IpAddr> {
    let mut rng = rand::thread_rng();
    match cidr.addr {
        IpAddr::V4(base) => {
            let host_bits = 32 - cidr.bits as u32;
            let base = u32::from(base) & mask_u32(cidr.bits);
            let host: u32 = if host_bits >= 32 {
                rng.gen()
            } else {
                rng.gen_range(0..(1u32 << host_bits))
            };
            Ok(IpAddr::V4(Ipv4Addr::from(base | host)))
        }
        IpAddr::V6(base) => {
            let host_bits = 128 - cidr.bits as u32;
            let base = u128::from(base) & mask_u128(cidr.bits);
            let host: u128 = if host_bits >= 128 {
                rng.gen()
            } else {
                rng.gen_range(0..(1u128 << host_bits))
            };
            Ok(IpAddr::V6(Ipv6Addr::from(base | host)))
        }
    }
}

fn mask_u32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits as u32)
    }
}

fn mask_u128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits as u32)
    }
}

/// Pick a fully random WARP endpoint (random IP from a random prefix + random port).
pub fn random_warp_endpoint(v4: bool, v6: bool) -> Result<SocketAddr> {
    let prefix = random_warp_prefix(v4, v6)?;
    let ip = random_ip_from_prefix(prefix)?;
    Ok(SocketAddr::new(ip, random_warp_port()))
}
