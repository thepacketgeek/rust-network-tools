use std::cell::RefCell;
use std::io;
use std::net::Ipv6Addr;

use ipnetwork::Ipv6Network;
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::icmpv6::{ndp as pnet_ndp, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
    MutablePacket, Packet, PacketSize,
};

use super::find_ipv6_addr;

mod cache;
pub use cache::NdpCache;

const NDP_MAC_PREFIX: [u8; 3] = [0x33, 0x33, 0xff];
const NDP_IP_ADDR: &str = "ff02::1:0:0";

pub enum NdpPacket {
    /// Link Layer Request
    NeighborSolicitation {
        src: Ipv6Addr,
        src_mac: MacAddr,
        target: Ipv6Addr,
    },
    /// Link Layer Node Response
    NeighborAdvertisement {
        src: Ipv6Addr,
        src_mac: MacAddr,
        target: Ipv6Addr,
    },
    /// L3 Router Prefix Discovery
    RouterSolicitation { src: Ipv6Addr, src_mac: MacAddr },
    /// L3 Router Response with available segment prefixes
    RouterAdvertisement {
        src: Ipv6Addr,
        src_mac: MacAddr,
        prefixes: Vec<Ipv6Network>,
    },
}

/// NdpMonitor is used to listen for IPv6 NDP Requests/Replies on a given interface
pub struct NdpMonitor {
    interface: NetworkInterface,
    /// Channel Receiver for packets
    tx: RefCell<Box<dyn datalink::DataLinkSender>>,
    /// Channel Receiver for packets
    rx: RefCell<Box<dyn datalink::DataLinkReceiver>>,
}

impl NdpMonitor {
    /// Create a new NdpMonitor for a given interface
    pub fn new(interface: &NetworkInterface) -> io::Result<Self> {
        let (tx, rx) = match datalink::channel(interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => {
                // Only Channel::Ethernet is supported currently
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid interface channel type",
                ));
            }
        };
        Ok(Self {
            interface: interface.clone(),
            tx: RefCell::new(tx),
            rx: RefCell::new(rx),
        })
    }

    pub fn send_solicitation(&self, addr: Ipv6Addr) -> io::Result<()> {
        let mut tx = self.tx.borrow_mut();
        let solicit = build_solicitation(&self.interface, addr)?;
        match tx.send_to(solicit.packet(), None) {
            Some(Ok(_)) => Ok(()),
            Some(Err(err)) => Err(err),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Channel is no longer available",
            )),
        }
    }
}

impl Iterator for NdpMonitor {
    type Item = NdpPacket;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rx.borrow_mut().next() {
            Ok(data) => {
                if let Some(packet) = EthernetPacket::new(data) {
                    match packet.get_ethertype() {
                        // We only want to operate on IPv6 packets
                        EtherType(0x86dd) => extract_ndp_packet(&packet),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// NdpRequest is used to send an NDP Requests and wait for the reply
pub struct NdpRequest<'a> {
    /// Interface to monitor
    interface: &'a NetworkInterface,
    /// IP Address that the request is targeting
    address: Ipv6Addr,
}

impl<'a> NdpRequest<'a> {
    /// Create a new NdpRequest for a given interface
    pub fn new(interface: &'a NetworkInterface, address: Ipv6Addr) -> Self {
        Self { interface, address }
    }

    /// Start the NDP Request/Reply process
    pub fn request(&self) -> io::Result<datalink::MacAddr> {
        let (mut tx, mut rx) = match datalink::channel(self.interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid interface channel type",
                ))
            }
        };

        // Build and Send an NDP Request
        let request = build_solicitation(self.interface, self.address)?;
        // Send the packet bytes via the `tx` Channel for our interface
        match tx.send_to(request.packet(), None) {
            Some(Ok(_)) => {
                println!("Sent NDP Request to {}", self.address);
            }
            Some(Err(err)) => return Err(err),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Channel is no longer available",
                ))
            }
        }

        // Now monitor NDP packets and listen for Reply
        while let Ok(data) = rx.next() {
            if let Some(packet) = EthernetPacket::new(data) {
                match packet.get_ethertype() {
                    // We only want to operate on IPv6 packets
                    EtherType(0x86dd) => match extract_ndp_packet(&packet) {
                        Some(NdpPacket::NeighborSolicitation { src_mac, .. }) => {
                            return Ok(src_mac)
                        }
                        _ => continue,
                    },
                    _ => continue,
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Stopped receiving packets",
        ))
    }
}

fn extract_ndp_packet(ethernet: &EthernetPacket<'_>) -> Option<NdpPacket> {
    Ipv6Packet::new(ethernet.payload()).and_then(|ipv6| match ipv6.get_next_header() {
        IpNextHeaderProtocols::Icmpv6 => {
            Icmpv6Packet::new(ipv6.payload()).and_then(|icmpv6| match icmpv6.get_icmpv6_type() {
                Icmpv6Types::NeighborAdvert => pnet_ndp::NeighborAdvertPacket::new(ipv6.payload())
                    .map(|na| NdpPacket::NeighborAdvertisement {
                        src: ipv6.get_source(),
                        src_mac: ethernet.get_source(),
                        target: na.get_target_addr(),
                    }),
                Icmpv6Types::NeighborSolicit => {
                    pnet_ndp::NeighborSolicitPacket::new(ipv6.payload()).and_then(|ns| {
                        extract_ndp_mac(&ns.get_options(), pnet_ndp::NdpOptionTypes::SourceLLAddr)
                            .map(|src_mac| NdpPacket::NeighborSolicitation {
                                src: ipv6.get_source(),
                                target: ns.get_target_addr(),
                                src_mac,
                            })
                    })
                }
                Icmpv6Types::RouterAdvert => pnet_ndp::RouterAdvertPacket::new(ipv6.payload())
                    .and_then(|ra| {
                        extract_ndp_mac(&ra.get_options(), pnet_ndp::NdpOptionTypes::SourceLLAddr)
                            .map(|src_mac| NdpPacket::RouterAdvertisement {
                                src: ipv6.get_source(),
                                src_mac,
                                prefixes: extract_ndp_prefixes(&ra.get_options()),
                            })
                    }),
                Icmpv6Types::RouterSolicit => pnet_ndp::RouterSolicitPacket::new(ipv6.payload())
                    .map(|_rs| NdpPacket::RouterSolicitation {
                        src: ipv6.get_source(),
                        src_mac: ethernet.get_source(),
                    }),
                _ => None,
            })
        }
        _ => None,
    })
}

fn extract_ndp_mac(
    options: &[pnet_ndp::NdpOption],
    option_type: pnet_ndp::NdpOptionType,
) -> Option<MacAddr> {
    for opt in options {
        if opt.option_type == option_type {
            let d = &opt.data;
            return Some(MacAddr::new(d[0], d[1], d[2], d[3], d[4], d[5]));
        }
    }
    None
}

fn extract_ndp_prefixes(options: &[pnet_ndp::NdpOption]) -> Vec<Ipv6Network> {
    let mut prefixes = Vec::with_capacity(2);
    for opt in options {
        if opt.option_type == pnet_ndp::NdpOptionTypes::PrefixInformation {
            let d = &opt.data;
            let mask = d[0];
            let addr_bytes: [u8; 16] = [
                d[14], d[15], d[16], d[17], d[18], d[19], d[20], d[21], d[22], d[23], d[24], d[25],
                d[26], d[27], d[28], d[29],
            ];
            if let Ok(network) = Ipv6Network::new(addr_bytes.into(), mask) {
                prefixes.push(network);
            }
        }
    }
    prefixes
}

pub fn build_solicitation(
    interface: &NetworkInterface,
    addr: Ipv6Addr,
) -> io::Result<MutableEthernetPacket> {
    let hw_addr = interface
        .mac
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "No MAC Address present"))?;

    let mut ns_packet = pnet_ndp::MutableNeighborSolicitPacket::owned(vec![0; 32]).unwrap();
    ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns_packet.set_icmpv6_code(pnet_ndp::Icmpv6Codes::NoCode);
    ns_packet.set_target_addr(addr);
    let hw_addr_bytes: [u8; 6] = hw_addr.into();
    ns_packet.set_options(&[pnet_ndp::NdpOption {
        option_type: pnet_ndp::NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: hw_addr_bytes.to_vec(),
    }]);

    let source_ip = find_ipv6_addr(interface).ok_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "No IPv4 Address present")
    })?;
    let mut ipv6_packet = MutableIpv6Packet::owned(vec![0; 72]).unwrap();
    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_hop_limit(1);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_source(source_ip);
    ipv6_packet.set_destination(get_ndp_dest_ip(&[0x00, 0x01, 0x0a, 0xbc]));
    ipv6_packet.set_payload_length(ns_packet.packet_size() as u16);
    ipv6_packet.set_payload(ns_packet.packet_mut());

    let hw_addr = interface
        .mac
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "No MAC Address present"))?;
    let mut ethernet_packet = MutableEthernetPacket::owned(vec![0u8; 88]).unwrap();
    ethernet_packet.set_source(hw_addr);
    ethernet_packet.set_destination(get_ndp_dest_mac(&[0x01, 0x0a, 0xbc]));
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);
    ethernet_packet.set_payload(ipv6_packet.packet_mut());
    Ok(ethernet_packet)
}

fn get_ndp_dest_mac(host_bytes: &[u8; 3]) -> MacAddr {
    let mut mac_bytes = [0u8; 6];
    for (i, b) in NDP_MAC_PREFIX.iter().enumerate() {
        mac_bytes[i] = *b;
    }
    for (i, b) in host_bytes.iter().enumerate() {
        mac_bytes[i + 3] = *b;
    }
    mac_bytes.into()
}

fn get_ndp_dest_ip(host_bytes: &[u8; 4]) -> Ipv6Addr {
    let ipv6: Ipv6Addr = NDP_IP_ADDR.parse().expect("Can parse const prefix");
    let mut ip_bytes: [u8; 16] = ipv6.octets();
    for (i, b) in host_bytes.iter().enumerate() {
        ip_bytes[i + 12] = *b;
    }
    ip_bytes.into()
}
