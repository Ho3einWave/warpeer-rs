//! The per-tunnel engine task: a UDP socket + a boringtun `Tunn`, bridged to the
//! netstack. It applies WARP reserved bytes to outgoing packets and fires junk
//! bursts before proactively-sent handshakes/keepalives.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info};

use super::WgConfig;
use crate::netstack::EngineIo;
use crate::obfs::JunkConfig;

const MAX_PKT: usize = 2048;

pub async fn run(cfg: WgConfig, io: EngineIo, connected: watch::Sender<bool>) {
    let EngineIo {
        inbound_tx,
        mut outbound_rx,
    } = io;

    let bind = cfg.bind.unwrap_or(match cfg.endpoint {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    });

    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            error!("udp bind {bind} failed: {e}");
            return;
        }
    };
    if let Err(e) = socket.connect(cfg.endpoint).await {
        error!("udp connect to {} failed: {e}", cfg.endpoint);
        return;
    }
    let peer_ip: IpAddr = cfg.endpoint.ip();
    let socket = Arc::new(socket);
    // Detached junk bursts observe this flag and stop once the engine task ends.
    let alive = Arc::new(AtomicBool::new(true));
    let _alive_guard = AliveGuard(alive.clone());

    let index: u32 = rand::thread_rng().gen();
    let mut tunn = match Tunn::new(
        cfg.private_key,
        cfg.peer_public,
        cfg.preshared_key,
        cfg.keepalive,
        index,
        None,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("tunn init failed: {e}");
            return;
        }
    };

    let reserved = cfg.reserved;
    let junk = cfg.junk;

    let mut recv_buf = vec![0u8; MAX_PKT];
    let mut tick = interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut handshake_seen = false;

    // Kick off the handshake immediately rather than waiting for the keepalive timer
    // (which, with a 20s interval on the inner gool tunnel, would otherwise stall).
    {
        let mut dst = vec![0u8; MAX_PKT];
        if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut dst, true) {
            send_net(&socket, p, reserved, &junk, junk.enabled, &alive).await;
        }
    }

    loop {
        tokio::select! {
            r = socket.recv(&mut recv_buf) => {
                match r {
                    Ok(n) => {
                        // WARP stamps the reserved bytes into replies too; boringtun reads
                        // bytes 0..4 as the message type, so clear 1..4 before parsing.
                        clear_reserved(&mut recv_buf[..n]);
                        let mut dst = vec![0u8; MAX_PKT];
                        let res = tunn.decapsulate(Some(peer_ip), &recv_buf[..n], &mut dst);
                        handle_decapsulate(&socket, &mut tunn, res, reserved, &inbound_tx, &alive).await;
                        signal_connected(&tunn, &mut handshake_seen, &connected);
                    }
                    Err(e) => debug!("udp recv error: {e}"),
                }
            }
            pkt = outbound_rx.recv() => {
                match pkt {
                    Some(ip_pkt) => {
                        let mut dst = vec![0u8; MAX_PKT];
                        match tunn.encapsulate(&ip_pkt, &mut dst) {
                            TunnResult::WriteToNetwork(p) => {
                                // Only the no-session handshake-initiation gets junk here;
                                // real data packets must go out untouched.
                                let allow = junk.enabled && is_handshake_init(p);
                                send_net(&socket, p, reserved, &junk, allow, &alive).await;
                            }
                            TunnResult::Done => {}
                            TunnResult::Err(e) => debug!("encapsulate error: {e:?}"),
                            _ => {}
                        }
                    }
                    None => return, // netstack dropped
                }
            }
            _ = tick.tick() => {
                let mut dst = vec![0u8; MAX_PKT];
                match tunn.update_timers(&mut dst) {
                    TunnResult::WriteToNetwork(p) => {
                        // Timer-driven sends are handshake inits or keepalives — both
                        // get the junk treatment (matches warp-plus' trick-on-keepalive).
                        send_net(&socket, p, reserved, &junk, junk.enabled, &alive).await;
                    }
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                        // boringtun stays in the expired state until someone starts a new
                        // handshake. An idle tunnel would otherwise never recover after an
                        // outage (no data packet would trigger one), so re-initiate here.
                        info!("wireguard session expired; re-initiating handshake");
                        handshake_seen = false;
                        let mut init = vec![0u8; MAX_PKT];
                        if let TunnResult::WriteToNetwork(p) =
                            tunn.format_handshake_initiation(&mut init, true)
                        {
                            send_net(&socket, p, reserved, &junk, junk.enabled, &alive).await;
                        }
                    }
                    TunnResult::Err(e) => debug!("update_timers: {e:?}"),
                    _ => {}
                }
                signal_connected(&tunn, &mut handshake_seen, &connected);
            }
        }
    }
}

/// Handle a `decapsulate` result: forward inner IP packets to the netstack, and
/// flush any WireGuard responses (handshake responses, queued data) back out.
async fn handle_decapsulate(
    socket: &Arc<UdpSocket>,
    tunn: &mut Tunn,
    res: TunnResult<'_>,
    reserved: [u8; 3],
    inbound_tx: &mpsc::UnboundedSender<Vec<u8>>,
    alive: &Arc<AtomicBool>,
) {
    match res {
        TunnResult::WriteToNetwork(p) => {
            send_net(socket, p, reserved, &JunkConfig::disabled(), false, alive).await;
            // Repeatedly poll with an empty datagram to drain queued packets.
            loop {
                let mut d = vec![0u8; MAX_PKT];
                match tunn.decapsulate(None, &[], &mut d) {
                    TunnResult::WriteToNetwork(p) => {
                        send_net(socket, p, reserved, &JunkConfig::disabled(), false, alive).await;
                    }
                    _ => break,
                }
            }
        }
        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
            let _ = inbound_tx.send(p.to_vec());
        }
        TunnResult::Done => {}
        TunnResult::Err(e) => debug!("decapsulate error: {e:?}"),
    }
}

/// Send a WireGuard packet: optionally precede it with a junk burst, stamp the WARP
/// reserved bytes, then transmit.
async fn send_net(
    socket: &Arc<UdpSocket>,
    pkt: &mut [u8],
    reserved: [u8; 3],
    junk: &JunkConfig,
    allow_junk: bool,
    alive: &Arc<AtomicBool>,
) {
    if allow_junk && junk.enabled {
        if is_handshake_init(pkt) {
            // The trick exists so the peer answers the handshake, so the burst must
            // be on the wire before it.
            send_junk(socket, junk, alive).await;
        } else {
            // A burst takes up to several seconds; sending it inline would stall the
            // whole engine (and every forwarded packet) for that long.
            let socket = socket.clone();
            let junk = junk.clone();
            let alive = alive.clone();
            tokio::spawn(async move { send_junk(&socket, &junk, &alive).await });
        }
    }
    apply_reserved(pkt, reserved);
    if let Err(e) = socket.send(pkt).await {
        debug!("udp send error: {e}");
    }
}

async fn send_junk(socket: &UdpSocket, junk: &JunkConfig, alive: &AtomicBool) {
    for pkt in junk.build_burst() {
        if !alive.load(Ordering::Relaxed) {
            return;
        }
        if socket.send(&pkt).await.is_err() {
            return;
        }
        tokio::time::sleep(junk.delay()).await;
    }
}

/// Clears the engine's alive flag when the task ends (including on abort), so
/// detached junk bursts stop instead of outliving the tunnel.
struct AliveGuard(Arc<AtomicBool>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Stamp the WARP 3-byte reserved value into the WireGuard header (bytes 1..4) of
/// message types 1–4, matching warp-plus.
fn apply_reserved(pkt: &mut [u8], reserved: [u8; 3]) {
    if pkt.len() > 3 && pkt[0] >= 1 && pkt[0] <= 4 {
        pkt[1..4].copy_from_slice(&reserved);
    }
}

fn is_handshake_init(pkt: &[u8]) -> bool {
    pkt.len() >= 4 && pkt[0] == 1
}

/// Zero the WARP reserved bytes (header bytes 1..4) on an incoming packet so the
/// WireGuard parser sees a valid message type.
fn clear_reserved(pkt: &mut [u8]) {
    if pkt.len() > 3 && pkt[0] >= 1 && pkt[0] <= 4 {
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 0;
    }
}

fn signal_connected(tunn: &Tunn, seen: &mut bool, connected: &watch::Sender<bool>) {
    if *seen {
        return;
    }
    let (time_since_handshake, ..) = tunn.stats();
    if time_since_handshake.is_some() {
        *seen = true;
        info!("wireguard handshake complete");
        let _ = connected.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_is_stamped_on_wg_messages_only() {
        let mut init = [1u8, 0, 0, 0, 0x11, 0x22];
        apply_reserved(&mut init, [0xab, 0xcd, 0xef]);
        assert_eq!(&init[..4], &[1, 0xab, 0xcd, 0xef]);

        // Non-WireGuard payloads (e.g. junk) are left untouched.
        let mut junk = [0xffu8, 0x00, 0x01, 0x02];
        apply_reserved(&mut junk, [0xab, 0xcd, 0xef]);
        assert_eq!(junk, [0xff, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn reserved_is_cleared_before_parsing() {
        let mut pkt = [4u8, 0xab, 0xcd, 0xef, 0x11];
        clear_reserved(&mut pkt);
        assert_eq!(&pkt[..4], &[4, 0, 0, 0]);
    }

    #[test]
    fn detects_handshake_initiation() {
        assert!(is_handshake_init(&[1, 0, 0, 0]));
        assert!(!is_handshake_init(&[4, 0, 0, 0]));
        assert!(!is_handshake_init(&[]));
    }
}
