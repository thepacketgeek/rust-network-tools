//! An assortment of network "tool" examples using libpnet
use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::datalink::{MacAddr, NetworkInterface};

/// ARP functions like monitoring & making requests, and an ArpCache
pub mod arp;

/// NDP functions like monitoring & making requests, and an NdpCache
pub mod ndp;

/// Routing/Forwarding Table Lookup
pub mod routes;

// Find the first Ipv4 Address on a NetworkInterface
pub fn find_ipv4_addr(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for network in &interface.ips {
        match network {
            pnet::ipnetwork::IpNetwork::V4(net) => return Some(net.ip()),
            _ => continue,
        }
    }
    None
}

// Find the first Ipv6 Address on a NetworkInterface
pub fn find_ipv6_addr(interface: &NetworkInterface) -> Option<Ipv6Addr> {
    for network in &interface.ips {
        match network {
            pnet::ipnetwork::IpNetwork::V6(net) => return Some(net.ip()),
            _ => continue,
        }
    }
    None
}

// Use ARP to resolve a given IPv4Addr on an interface
pub fn get_hw_addr(interface: &NetworkInterface, addr: Ipv4Addr) -> Option<MacAddr> {
    let request = arp::ArpRequest::new(interface, addr);
    request.request().ok()
}
