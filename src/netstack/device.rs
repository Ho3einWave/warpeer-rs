//! A smoltcp `phy::Device` backed by channels instead of a real NIC.
//!
//! * Received (decapsulated) IP packets are pushed into an internal rx queue with
//!   [`ChannelDevice::push_rx`] and handed to smoltcp via `RxToken`.
//! * Packets smoltcp wants to transmit are emitted through a `TxToken` onto an
//!   unbounded channel, which the WireGuard engine drains and encapsulates.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

pub struct ChannelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new(tx: mpsc::UnboundedSender<Vec<u8>>, mtu: usize) -> Self {
        ChannelDevice {
            rx: VecDeque::new(),
            tx,
            mtu,
        }
    }

    /// Queue an inbound IP packet to be consumed by the next smoltcp poll.
    pub fn push_rx(&mut self, pkt: Vec<u8>) {
        self.rx.push_back(pkt);
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChannelRxToken;
    type TxToken<'a> = ChannelTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((ChannelRxToken { buf: pkt }, ChannelTxToken { tx: &self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken { tx: &self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct ChannelRxToken {
    buf: Vec<u8>,
}

impl RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

pub struct ChannelTxToken<'a> {
    tx: &'a mpsc::UnboundedSender<Vec<u8>>,
}

impl<'a> TxToken for ChannelTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.tx.send(buf);
        r
    }
}
