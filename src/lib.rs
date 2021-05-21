//! An assortment of network "tool" examples using libpnet
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use dns_lookup::lookup_host;
use pnet::datalink::{MacAddr, NetworkInterface};

/// ARP functions like monitoring & making requests, and an ArpCache
pub mod arp;

/// NDP functions like monitoring & making requests, and an NdpCache
pub mod ndp;

/// Routing/Forwarding Table Lookup
pub mod routes;

/// IP Addresses to find for Device DNS resolution
#[derive(Copy, Clone, Debug)]
pub enum IpType {
    /// Only Ipv4 Addresses
    V4,
    /// Only Ipv6 Addresses
    V6,
    /// Use whichever address exists (v6 preferred over v4)
    Either,
}

impl IpType {
    /// Test if this IpType matches the given address
    pub fn matches(&self, addr: IpAddr) -> bool {
        matches!(
            (addr, self),
            (IpAddr::V4(_), IpType::V4) | (IpAddr::V6(_), IpType::V6) | (_, IpType::Either)
        )
    }
}

/// Resolve a hostname (can be an Ip address) to the first matching IP of the given type
pub fn resolve_host(host: &str, version: IpType) -> Result<IpAddr> {
    let ips = lookup_host(&host)?;

    for ip in ips {
        if version.matches(ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("Unable to resolve {}", host))
}

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
