//! Minimal parser for a standard, single-peer WireGuard configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::warp::key;

pub struct WgFileConfig {
    pub address: Ipv4Addr,
    pub private_key: StaticSecret,
    pub peer_public: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: SocketAddr,
    pub keepalive: u16,
}

pub async fn load(path: &Path) -> Result<WgFileConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading WireGuard config {}", path.display()))?;
    parse(&text).await
}

async fn parse(text: &str) -> Result<WgFileConfig> {
    let mut section = "";
    let mut address = None;
    let mut private_key = None;
    let mut peer_public = None;
    let mut preshared_key = None;
    let mut endpoint = None;
    let mut keepalive = 25;
    let mut peer_count = 0;

    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim();
            if section.eq_ignore_ascii_case("Peer") {
                peer_count += 1;
            }
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid WireGuard config line {}", index + 1))?;
        let name = name.trim();
        let value = value.trim();

        if section.eq_ignore_ascii_case("Interface") {
            if name.eq_ignore_ascii_case("Address") {
                address = value.split(',').find_map(|item| {
                    item.trim()
                        .split('/')
                        .next()
                        .and_then(|ip| ip.parse::<IpAddr>().ok())
                        .and_then(|ip| match ip {
                            IpAddr::V4(v4) => Some(v4),
                            IpAddr::V6(_) => None,
                        })
                });
            } else if name.eq_ignore_ascii_case("PrivateKey") {
                private_key = Some(value.to_string());
            }
        } else if section.eq_ignore_ascii_case("Peer") && peer_count == 1 {
            if name.eq_ignore_ascii_case("PublicKey") {
                peer_public = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("PresharedKey") {
                preshared_key = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("Endpoint") {
                endpoint = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("PersistentKeepalive") {
                // wg-quick accepts `off`, which means "no keepalive".
                keepalive = if value.eq_ignore_ascii_case("off") {
                    0
                } else {
                    value.parse().context("invalid PersistentKeepalive")?
                };
            }
        }
    }

    if peer_count != 1 {
        return Err(anyhow!(
            "WireGuard config must contain exactly one [Peer] section"
        ));
    }

    let endpoint_text = endpoint.ok_or_else(|| anyhow!("WireGuard config has no peer Endpoint"))?;
    let endpoint = tokio::net::lookup_host(&endpoint_text)
        .await
        .with_context(|| format!("resolving WireGuard endpoint {endpoint_text}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("WireGuard endpoint must resolve to IPv4"))?;

    Ok(WgFileConfig {
        address: address
            .ok_or_else(|| anyhow!("WireGuard config has no IPv4 Interface Address"))?,
        private_key: key::static_secret_from_b64(
            &private_key.ok_or_else(|| anyhow!("WireGuard config has no Interface PrivateKey"))?,
        )?,
        peer_public: key::public_from_b64(
            &peer_public.ok_or_else(|| anyhow!("WireGuard config has no Peer PublicKey"))?,
        )?,
        preshared_key: preshared_key
            .map(|value| key::decode_key_b64(&value))
            .transpose()?,
        endpoint,
        keepalive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_standard_config() {
        let config = parse(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32, fd00::2/128\n\
             [Peer]\n\
             PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Endpoint = 127.0.0.1:51820\n\
             PersistentKeepalive = 15\n",
        )
        .await
        .unwrap();

        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(config.endpoint, "127.0.0.1:51820".parse().unwrap());
        assert_eq!(config.keepalive, 15);
    }

    #[tokio::test]
    async fn parses_keepalive_off() {
        let config = parse(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32\n\
             [Peer]\n\
             PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Endpoint = 127.0.0.1:51820\n\
             PersistentKeepalive = off\n",
        )
        .await
        .unwrap();

        assert_eq!(config.keepalive, 0);
    }
}
