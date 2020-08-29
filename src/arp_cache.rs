use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::ArpOperations;

use super::arp::ArpMonitor;

pub struct ArpCache {
    entries: Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>>,
    /// Pending IP Addresses (value: request has been sent)
    pending_requests: Arc<Mutex<HashMap<Ipv4Addr, bool>>>,
    /// Own the background thread so it is not dropped
    _background: std::thread::JoinHandle<Result<(), std::io::Error>>,
}

impl ArpCache {
    pub fn new(interface: &NetworkInterface) -> Self {
        let entries = Arc::new(Mutex::new(HashMap::new()));
        let requests = Arc::new(Mutex::new(HashMap::new()));

        let monitor = {
            let entries = entries.clone();
            let requests = requests.clone();
            let iface = interface.clone();
            std::thread::spawn(move || run_arp_monitor(iface, entries, requests))
        };

        Self {
            entries: entries.clone(),
            pending_requests: requests.clone(),
            _background: monitor,
        }
    }

    /// Get a copy of the current Arp cache entries
    pub fn get_entries(&self) -> HashMap<Ipv4Addr, MacAddr> {
        self.entries.lock().unwrap().clone()
    }

    /// Check `ArpCache` for a `MacAddr` entry for a given `Ipv4Addr`
    /// If the entry does not exist, `None` is immediately returned and
    /// an ARP request is queued for a later `get()` attempt
    pub fn try_get(&self, addr: Ipv4Addr) -> Option<MacAddr> {
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

    /// Check `ArpCache` for a `MacAddr` entry for a given `Ipv4Addr`
    /// If the entry does not exist, an ARP request is sent and this call blocks
    /// until either an ARP reply is received or the `timeout` duration passes.
    pub fn get(&self, addr: Ipv4Addr, timeout: Duration) -> Option<MacAddr> {
        let maybe_mac = {
            let entries = self.entries.lock().unwrap();
            entries.get(&addr).map(|m| *m)
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

fn run_arp_monitor(
    interface: NetworkInterface,
    entries: Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>>,
    pending_requests: Arc<Mutex<HashMap<Ipv4Addr, bool>>>,
) -> std::io::Result<()> {
    let mut monitor = ArpMonitor::new(&interface)?;

    loop {
        for (pending, request_sent) in pending_requests.lock().unwrap().iter_mut() {
            if *request_sent {
                continue;
            }
            if let Ok(_) = monitor.send_request(*pending) {
                *request_sent = true;
            }
        }
        if let Some(packet) = monitor.next() {
            match packet.get_operation() {
                ArpOperations::Reply => {
                    // Check to see if this is the reply to a pending request
                    let mut requests = pending_requests.lock().unwrap();
                    if let Some((ip, _)) = requests.remove_entry(&packet.get_sender_proto_addr()) {
                        entries
                            .lock()
                            .unwrap()
                            .insert(ip, packet.get_sender_hw_addr());
                    }
                }
                _ => (),
            }
        }
    }
}
