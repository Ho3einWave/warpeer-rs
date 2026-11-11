//! Junk-packet obfuscation.
//!
//! Before a real WireGuard handshake (and optionally keepalive) is sent, we emit a
//! burst of junk UDP datagrams toward the endpoint. This both defeats simple DPI
//! that fingerprints the WireGuard handshake and matches what warp-plus / AmneziaWG
//! do on the wire.
//!
//! This one config unifies two schemes:
//!   * warp-plus "trick"  — `t1` (raw random) and `t2` (random with a fake header),
//!     with hardcoded 20–50 packets of 40–120 bytes, 80–150 ms apart.
//!   * AmneziaWG          — configurable `Jc` (count), `Jmin`/`Jmax` (size bounds)
//!     and `Jdelay` (ms between packets).
//!
//! The trick presets are just particular settings of the Amnezia knobs.

use rand::Rng;
use std::time::Duration;

/// Optional fake header prepended to each junk packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderMode {
    /// Pure random bytes (warp-plus `t1`, AmneziaWG default).
    None,
    /// warp-plus `t2`: a fake "WireGuard-ish"/voice-looking 18-byte header.
    T2,
}

#[derive(Clone, Debug)]
pub struct JunkConfig {
    /// Inclusive range for the number of junk packets per burst.
    pub count: (u32, u32),
    /// Inclusive range for each packet's total size in bytes (header included).
    pub size: (usize, usize),
    /// Inclusive range for the delay between packets, in milliseconds.
    pub delay_ms: (u64, u64),
    /// Optional fake header.
    pub header: HeaderMode,
    /// When false, no junk is emitted.
    pub enabled: bool,
}

impl JunkConfig {
    /// No obfuscation (equivalent to warp-plus `t0`).
    pub fn disabled() -> Self {
        JunkConfig {
            count: (0, 0),
            size: (0, 0),
            delay_ms: (0, 0),
            header: HeaderMode::None,
            enabled: false,
        }
    }

    /// warp-plus trick `t1`: raw random junk.
    pub fn trick_t1() -> Self {
        JunkConfig {
            count: (20, 50),
            size: (10, 120),
            delay_ms: (80, 150),
            header: HeaderMode::None,
            enabled: true,
        }
    }

    /// warp-plus trick `t2`: junk prefixed with a fake header.
    pub fn trick_t2() -> Self {
        JunkConfig {
            count: (20, 50),
            size: (28, 138),
            delay_ms: (80, 150),
            header: HeaderMode::T2,
            enabled: true,
        }
    }

    /// AmneziaWG-style config from explicit knobs.
    pub fn amnezia(jc: u32, jmin: usize, jmax: usize, jdelay_ms: u64) -> Self {
        JunkConfig {
            count: (jc, jc),
            size: (jmin, jmax.max(jmin)),
            delay_ms: (jdelay_ms, jdelay_ms),
            header: HeaderMode::None,
            enabled: jc > 0,
        }
    }

    /// Build the burst of junk packets for one handshake attempt.
    pub fn build_burst(&self) -> Vec<Vec<u8>> {
        if !self.enabled {
            return Vec::new();
        }
        let mut rng = rand::thread_rng();
        let n = range_u32(&mut rng, self.count);
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let header = match self.header {
                HeaderMode::None => Vec::new(),
                HeaderMode::T2 => t2_header(&mut rng),
            };
            let lo = self.size.0.max(header.len() + 1);
            let hi = self.size.1.max(lo);
            let size = if lo == hi { lo } else { rng.gen_range(lo..=hi) };
            let mut pkt = vec![0u8; size];
            pkt[..header.len()].copy_from_slice(&header);
            rng.fill(&mut pkt[header.len()..]);
            out.push(pkt);
        }
        out
    }

    /// The delay to wait after sending each junk packet.
    pub fn delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let ms = if self.delay_ms.0 >= self.delay_ms.1 {
            self.delay_ms.0
        } else {
            rng.gen_range(self.delay_ms.0..=self.delay_ms.1)
        };
        Duration::from_millis(ms)
    }
}

fn range_u32(rng: &mut impl Rng, (lo, hi): (u32, u32)) -> u32 {
    if lo >= hi {
        lo
    } else {
        rng.gen_range(lo..=hi)
    }
}

/// The warp-plus `t2` fake header: 18 bytes, with bytes 6..14 randomized.
fn t2_header(rng: &mut impl Rng) -> Vec<u8> {
    const CLIST: [u8; 8] = [0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3];
    let mut h = vec![
        CLIST[rng.gen_range(0..CLIST.len())],
        0x00,
        0x00,
        0x00,
        0x01,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x44,
        0xD0,
    ];
    rng.fill(&mut h[6..14]);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_emits_nothing() {
        assert!(JunkConfig::disabled().build_burst().is_empty());
    }

    #[test]
    fn trick_bursts_stay_within_configured_bounds() {
        for cfg in [JunkConfig::trick_t1(), JunkConfig::trick_t2()] {
            let burst = cfg.build_burst();
            assert!(
                (cfg.count.0 as usize..=cfg.count.1 as usize).contains(&burst.len()),
                "unexpected burst size {}",
                burst.len()
            );
            for pkt in &burst {
                assert!(
                    pkt.len() >= cfg.size.0 && pkt.len() <= cfg.size.1,
                    "packet size {} outside {:?}",
                    pkt.len(),
                    cfg.size
                );
            }
        }
    }

    #[test]
    fn t2_packets_carry_the_fake_header() {
        const CLIST: [u8; 8] = [0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3];
        for pkt in JunkConfig::trick_t2().build_burst() {
            assert!(pkt.len() >= 18);
            assert!(CLIST.contains(&pkt[0]));
        }
    }

    #[test]
    fn amnezia_knobs_are_exact() {
        let cfg = JunkConfig::amnezia(4, 50, 200, 15);
        let burst = cfg.build_burst();
        assert_eq!(burst.len(), 4);
        assert!(burst.iter().all(|p| (50..=200).contains(&p.len())));
        assert_eq!(cfg.delay(), Duration::from_millis(15));
    }

    #[test]
    fn amnezia_clamps_inverted_size_bounds() {
        let cfg = JunkConfig::amnezia(3, 200, 50, 5);
        let burst = cfg.build_burst();
        assert_eq!(burst.len(), 3);
        assert!(burst.iter().all(|p| p.len() == 200));
    }
}
