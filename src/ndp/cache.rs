use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};

use super::{NdpMonitor, NdpPacket};

pub struct NdpCache {
    entries: Arc<Mutex<HashMap<Ipv6Addr, MacAddr>>>,
    /// Pending IP Addresses (value: request has been sent)
    pending_requests: Arc<Mutex<HashMap<Ipv6Addr, bool>>>,
    /// Own the background thread so it is not dropped
    _background: std::thread::JoinHandle<Result<(), std::io::Error>>,
}

impl NdpCache {
    pub fn new(interface: &NetworkInterface) -> Self {
        let entries = Arc::new(Mutex::new(HashMap::new()));
        let requests = Arc::new(Mutex::new(HashMap::new()));

        let monitor = {
            let entries = entries.clone();
            let requests = requests.clone();
            let iface = interface.clone();
            std::thread::spawn(move || run_ndp_monitor(iface, entries, requests))
        };

        Self {
            entries,
            pending_requests: requests,
            _background: monitor,
        }
    }

    /// Get a copy of the current Ndp cache entries
    pub fn get_entries(&self) -> HashMap<Ipv6Addr, MacAddr> {
        self.entries.lock().unwrap().clone()
    }

    /// Check `NdpCache` for a `MacAddr` entry for a given `Ipv6Addr`
    /// If the entry does not exist, `None` is immediately returned and
    /// an NDP request is queued for a later `get()` attempt
    pub fn try_get(&self, addr: Ipv6Addr) -> Option<MacAddr> {
        if let Some(mac) = self.entries.lock().unwrap().get(&addr) {
            Some(*mac)
        } else {
            // If this IP isn't already in requests, add it
            self.pending_requests
                .lock()
                .unwrap()
                .entry(addr)
                .or_insert(false);
            None
        }
    }

    /// Check `NdpCache` for a `MacAddr` entry for a given `Ipv6Addr`
    /// If the entry does not exist, an NDP request is sent and this call blocks
    /// until either an NDP reply is received or the `timeout` duration passes.
    pub fn get(&self, addr: Ipv6Addr, timeout: Duration) -> Option<MacAddr> {
        let maybe_mac = {
            let entries = self.entries.lock().unwrap();
            entries.get(&addr).copied()
        };
        if let Some(mac) = maybe_mac {
            Some(mac)
        } else {
            {
                let mut pending = self.pending_requests.lock().unwrap();
                // If this IP isn't already in requests, add it
                pending.entry(addr).or_insert(false);
            }
            let start = std::time::Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(10));
                if let Some(mac) = self.try_get(addr) {
                    return Some(mac);
                }
                if start.elapsed() > timeout {
                    return None;
                }
            }
        }
    }
}

fn run_ndp_monitor(
    interface: NetworkInterface,
    entries: Arc<Mutex<HashMap<Ipv6Addr, MacAddr>>>,
    pending_requests: Arc<Mutex<HashMap<Ipv6Addr, bool>>>,
) -> std::io::Result<()> {
    let mut monitor = NdpMonitor::new(&interface)?;

    loop {
        for (pending, request_sent) in pending_requests.lock().unwrap().iter_mut() {
            if *request_sent {
                continue;
            }
            if monitor.send_solicitation(*pending).is_ok() {
                *request_sent = true;
            }
        }
        if let Some(NdpPacket::NeighborAdvertisement {
            src: _,
            src_mac,
            target,
        }) = monitor.next()
        {
            // Check to see if this is the reply to a pending request
            let mut requests = pending_requests.lock().unwrap();
            if let Some((ip, _)) = requests.remove_entry(&target) {
                entries.lock().unwrap().insert(ip, src_mac);
            }
        }
    }
}
