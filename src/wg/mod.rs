//! WireGuard tunnel engine (boringtun) with WARP reserved bytes + junk obfuscation.

mod engine;

use std::net::SocketAddr;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::watch;

use crate::netstack::EngineIo;
use crate::obfs::JunkConfig;

/// Everything needed to bring up one WireGuard tunnel.
pub struct WgConfig {
    pub private_key: StaticSecret,
    pub peer_public: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    /// Peer UDP endpoint (the WARP edge, or a local forwarder for warp-in-warp).
    pub endpoint: SocketAddr,
    /// Persistent keepalive interval in seconds (None/0 = disabled).
    pub keepalive: Option<u16>,
    /// WARP 3-byte reserved value (the client_id), written into outgoing packets.
    pub reserved: [u8; 3],
    /// Junk-packet obfuscation config (trick / AmneziaWG).
    pub junk: JunkConfig,
    /// Optional explicit local bind address for the UDP socket.
    pub bind: Option<SocketAddr>,
}

/// A running tunnel. Dropping it aborts the engine task.
pub struct Tunnel {
    handle: tokio::task::JoinHandle<()>,
    connected: watch::Receiver<bool>,
}

impl Tunnel {
    /// Spawn the engine task for `cfg`, bridging IP packets through `io`.
    pub fn start(cfg: WgConfig, io: EngineIo) -> Tunnel {
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(engine::run(cfg, io, tx));
        Tunnel {
            handle,
            connected: rx,
        }
    }

    /// Wait up to `dur` for the first successful handshake.
    pub async fn wait_connected(&mut self, dur: Duration) -> bool {
        if *self.connected.borrow() {
            return true;
        }
        let fut = async {
            while self.connected.changed().await.is_ok() {
                if *self.connected.borrow() {
                    return true;
                }
            }
            false
        };
        tokio::time::timeout(dur, fut).await.unwrap_or(false)
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
