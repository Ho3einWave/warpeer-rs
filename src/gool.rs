//! warp-in-warp (gool), v2 — low-overhead design.
//!
//! ```text
//! SOCKS client → [inner WG + inner netstack] → localhost UDP → shim → [outer WG] → Cloudflare
//! ```
//!
//! The inner WireGuard packets must reach the WARP endpoint *through* the outer
//! tunnel. Rather than running a second smoltcp netstack for the outer hop (v1, which
//! was slow and lossy), we hand-wrap each inner WG datagram in a UDP/IPv4 frame
//! (src = outer interface IP, dst = the WARP endpoint) and feed it straight into the
//! outer engine's encapsulation channel. Responses are unwrapped the same way. Only
//! the inner tunnel keeps a netstack (to serve the SOCKS proxy).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

use crate::app::{self, Options, DOUBLE_MTU};
use crate::netstack::{EngineIo, NetStack};
use crate::obfs::JunkConfig;
use crate::proxy;
use crate::warp::Identity;
use crate::wg::{Tunnel, WgConfig};

pub async fn run(opts: &Options, primary: Identity, endpoints: Vec<SocketAddr>) -> Result<()> {
    // Bring up the outer tunnel + shim; keep `_outer` alive for the proxy's lifetime.
    let (shim_addr, _outer, _) = setup_outer_and_shim(opts, &primary, &endpoints).await?;

    if let Some(path) = &opts.inner_config {
        let config = crate::wgconfig::load(path).await?;
        info!(endpoint = %config.endpoint, "gool: bringing up custom inner tunnel");
        let (inner_ns, _inner_tunnel) =
            bring_up_custom_inner(config, shim_addr, opts.dns, opts.tcp_buf).await?;
        info!("gool: custom inner tunnel over WARP established");
        return proxy::serve(opts.bind, inner_ns).await;
    }

    // A custom outer leaves the primary WARP identity available for the inner layer.
    // WARP-over-WARP still needs a separate secondary identity for the inner layer.
    let inner = if opts.outer_config.is_some() {
        primary
    } else {
        crate::warp::load_or_create_identity(&opts.cache_dir.join("secondary"), &opts.license)
            .await
            .context("loading secondary identity")?
    };
    let reserved_inner = opts
        .reserved
        .unwrap_or_else(|| inner.reserved().unwrap_or([0, 0, 0]));

    info!("gool: bringing up inner tunnel");
    // No junk on the inner tunnel: it rides inside the outer tunnel's encryption,
    // and retrying with an identical (disabled) config would only add 12s per try.
    let inner_attempts = vec![JunkConfig::disabled()];
    let (inner_ns, _inner_tunnel) = app::bring_up(
        &inner,
        shim_addr,
        reserved_inner,
        &inner_attempts,
        opts.dns,
        app::Tuning {
            mtu: DOUBLE_MTU,
            keepalive: 20,
            tcp_buf: opts.tcp_buf,
        },
    )
    .await
    .context("inner tunnel")?;

    info!("gool: warp-in-warp established");
    proxy::serve(opts.bind, inner_ns).await
}

/// Bring up the gool OUTER tunnel (primary identity) and the UDP-wrapping shim.
/// Returns the local shim address, the outer tunnel guard, and the physical outer
/// endpoint address (used by TUN mode to keep that route outside the VPN).
pub(crate) async fn setup_outer_and_shim(
    opts: &Options,
    primary: &Identity,
    endpoints: &[SocketAddr],
) -> Result<(SocketAddr, Tunnel, Ipv4Addr)> {
    let inner_endpoint = if let Some(path) = &opts.inner_config {
        crate::wgconfig::load(path).await?.endpoint
    } else if opts.outer_config.is_some() {
        endpoints[0]
    } else {
        *endpoints.get(1).unwrap_or(&endpoints[0])
    };
    let (inner_endpoint_v4, inner_endpoint_port) = match inner_endpoint {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => {
            return Err(anyhow!(
            "the inner WARP tunnel requires an IPv4 endpoint; pass -e <ipv4:port> or scan with -4"
        ))
        }
    };

    let (outer_src_ip, physical_endpoint, outer_tunnel, outer_outbound_tx, outer_inbound_rx) =
        if let Some(path) = &opts.outer_config {
            let config = crate::wgconfig::load(path).await?;
            let outer_src_ip = config.address;
            let physical_endpoint = match config.endpoint {
                SocketAddr::V4(v4) => *v4.ip(),
                SocketAddr::V6(_) => unreachable!("custom config loader requires IPv4"),
            };
            info!(endpoint = %config.endpoint, "gool: bringing up custom outer tunnel");
            let (tunnel, outbound_tx, inbound_rx) =
                start_custom_engine(config, None, "outer").await?;
            (
                outer_src_ip,
                physical_endpoint,
                tunnel,
                outbound_tx,
                inbound_rx,
            )
        } else {
            let outer_endpoint = endpoints[0];
            let physical_endpoint = match outer_endpoint {
                SocketAddr::V4(v4) => *v4.ip(),
                SocketAddr::V6(_) => {
                    return Err(anyhow!(
                        "the outer WARP tunnel requires an IPv4 endpoint; scan with -4"
                    ))
                }
            };
            let outer_src_ip = app::interface_addresses(primary)?
                .into_iter()
                .find_map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .ok_or_else(|| anyhow!("primary identity has no IPv4 interface address"))?;
            let reserved_outer = opts.reserved_for(primary);
            info!("gool: bringing up outer WARP tunnel");
            let (tunnel, outbound_tx, inbound_rx) = app::start_engine(
                primary,
                outer_endpoint,
                reserved_outer,
                &opts.obfs_attempts,
                5,
            )
            .await?;
            (
                outer_src_ip,
                physical_endpoint,
                tunnel,
                outbound_tx,
                inbound_rx,
            )
        };

    // Shim: localhost UDP listener <-> outer engine channels, with UDP/IPv4 wrapping.
    let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let shim_addr = local.local_addr()?;
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let src_port: u16 = rand::thread_rng().gen_range(1024..=65535);

    // inner -> outer: read localhost datagram, wrap as UDP/IPv4, feed outer engine.
    {
        let local = local.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = local.recv_from(&mut buf).await {
                *client.lock().unwrap() = Some(from);
                let pkt = wrap_udp_ipv4(
                    outer_src_ip,
                    src_port,
                    inner_endpoint_v4,
                    inner_endpoint_port,
                    &buf[..n],
                );
                if outer_outbound_tx.send(pkt).is_err() {
                    break;
                }
            }
        });
    }
    // outer -> inner: read decapsulated IP packets, unwrap UDP payload, send to inner.
    {
        let local = local.clone();
        let client = client.clone();
        let mut outer_inbound_rx = outer_inbound_rx;
        tokio::spawn(async move {
            while let Some(ip_pkt) = outer_inbound_rx.recv().await {
                if let Some(payload) = unwrap_udp_ipv4(&ip_pkt) {
                    let addr = *client.lock().unwrap();
                    if let Some(addr) = addr {
                        let _ = local.send_to(payload, addr).await;
                    }
                }
            }
        });
    }
    info!(forwarder = %shim_addr, "gool: outer tunnel up, shim ready");

    Ok((shim_addr, outer_tunnel, physical_endpoint))
}

pub(crate) async fn start_custom_engine(
    config: crate::wgconfig::WgFileConfig,
    endpoint_override: Option<SocketAddr>,
    layer: &str,
) -> Result<(
    Tunnel,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
)> {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
    let io = EngineIo {
        inbound_tx,
        outbound_rx,
    };
    let endpoint = endpoint_override.unwrap_or(config.endpoint);
    let cfg = WgConfig {
        private_key: config.private_key,
        peer_public: config.peer_public,
        preshared_key: config.preshared_key,
        endpoint,
        keepalive: Some(config.keepalive),
        reserved: [0, 0, 0],
        junk: JunkConfig::disabled(),
        bind: None,
    };
    let mut tunnel = Tunnel::start(cfg, io);
    if !tunnel
        .wait_connected(std::time::Duration::from_secs(12))
        .await
    {
        return Err(anyhow!(
            "custom {layer} WireGuard handshake did not complete"
        ));
    }
    Ok((tunnel, outbound_tx, inbound_rx))
}

async fn bring_up_custom_inner(
    config: crate::wgconfig::WgFileConfig,
    endpoint: SocketAddr,
    dns: IpAddr,
    tcp_buf: usize,
) -> Result<(NetStack, Tunnel)> {
    let address = config.address;
    let (netstack, io) = NetStack::new(vec![IpAddr::V4(address)], vec![dns], DOUBLE_MTU, tcp_buf);
    let cfg = WgConfig {
        private_key: config.private_key,
        peer_public: config.peer_public,
        preshared_key: config.preshared_key,
        endpoint,
        keepalive: Some(config.keepalive),
        reserved: [0, 0, 0],
        junk: JunkConfig::disabled(),
        bind: None,
    };
    let mut tunnel = Tunnel::start(cfg, io);
    if !tunnel
        .wait_connected(std::time::Duration::from_secs(12))
        .await
    {
        return Err(anyhow!("custom inner WireGuard handshake did not complete"));
    }
    Ok((netstack, tunnel))
}

/// Wrap `payload` in a UDP/IPv4 datagram (IPv4 header checksum set; UDP checksum 0,
/// which is allowed over IPv4).
fn wrap_udp_ipv4(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];

    // IPv4 header (20 bytes, no options).
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol = UDP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    // UDP header (8 bytes) + payload.
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // pkt[26..28] = UDP checksum = 0 (disabled)
    pkt[28..].copy_from_slice(payload);

    pkt
}

/// Extract the UDP payload from a UDP/IPv4 packet, or None if it isn't UDP/IPv4.
fn unwrap_udp_ipv4(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 8 || pkt[9] != 17 {
        return None;
    }
    let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
    let start = ihl + 8;
    let end = (ihl + udp_len).min(pkt.len());
    if end < start {
        return None;
    }
    Some(&pkt[start..end])
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_unwraps_udp_payload() {
        let payload = b"wireguard datagram";
        let pkt = wrap_udp_ipv4(
            Ipv4Addr::new(172, 16, 0, 2),
            40_000,
            Ipv4Addr::new(188, 114, 97, 6),
            2408,
            payload,
        );

        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[0] >> 4, 4);
        assert_eq!(pkt[0] & 0x0f, 5);
        assert_eq!(pkt[9], 17);
        assert_eq!(
            u16::from_be_bytes([pkt[2], pkt[3]]) as usize,
            pkt.len(),
            "total length field"
        );
        assert_eq!(
            u16::from_be_bytes([pkt[24], pkt[25]]) as usize,
            8 + payload.len(),
            "udp length field"
        );
        // A header with its checksum filled in sums to zero.
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        assert_eq!(unwrap_udp_ipv4(&pkt), Some(&payload[..]));
    }

    #[test]
    fn rejects_non_ipv4_and_non_udp() {
        assert_eq!(unwrap_udp_ipv4(&[]), None);
        assert_eq!(unwrap_udp_ipv4(&[0x60; 40]), None); // IPv6
        let mut tcp = [0u8; 40];
        tcp[0] = 0x45;
        tcp[9] = 6;
        assert_eq!(unwrap_udp_ipv4(&tcp), None);
    }
}
