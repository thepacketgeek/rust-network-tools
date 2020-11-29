use std::cell::RefCell;
use std::io;
use std::net::Ipv6Addr;

use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::icmpv6::{ndp as pnet_ndp, Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
    MutablePacket, Packet,
};

pub enum NdpPacket {
    NeighborSolicitation {
        target: Ipv6Addr,
    },
    NeighborAdvertisement {
        target: Ipv6Addr, /*, mac: MacAddr */
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
        let (tx, rx) = match datalink::channel(&interface, Default::default())? {
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

    // pub fn send_request(&self, addr: Ipv4Addr) -> io::Result<()> {
    //     let mut tx = self.tx.borrow_mut();
    //     let request = build_request(&self.interface, addr)?;
    //     match tx.send_to(request.packet(), None) {
    //         Some(Ok(_)) => Ok(()),
    //         Some(Err(err)) => return Err(err),
    //         None => Err(io::Error::new(
    //             io::ErrorKind::BrokenPipe,
    //             "Channel is no longer available",
    //         )),
    //     }
    // }
}

impl<'a> Iterator for NdpMonitor {
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

fn extract_ndp_packet<'a>(ethernet: &EthernetPacket<'a>) -> Option<NdpPacket> {
    Ipv6Packet::new(ethernet.payload()).and_then(|ipv6| match ipv6.get_next_header() {
        IpNextHeaderProtocols::Icmpv6 => {
            Icmpv6Packet::new(ipv6.payload()).and_then(|icmpv6| match icmpv6.get_icmpv6_type() {
                Icmpv6Types::NeighborSolicit => {
                    pnet_ndp::NeighborSolicitPacket::new(icmpv6.payload()).and_then(|ns| {
                        Some(NdpPacket::NeighborSolicitation {
                            // src: ipv6.get_source(),
                            target: ns.get_target_addr(),
                        })
                    })
                }
                Icmpv6Types::NeighborAdvert => {
                    pnet_ndp::NeighborAdvertPacket::new(icmpv6.payload()).and_then(|na| {
                        for opt in na.get_options() {
                            if opt.option_type == pnet_ndp::NdpOptionTypes::TargetLLAddr {
                                dbg!(&opt);
                                return Some(NdpPacket::NeighborAdvertisement {
                                    // src: ipv6.get_source(),
                                    target: na.get_target_addr(),
                                    // mac: na.get_,
                                });
                            }
                        }
                        None
                    })
                }
                _ => None,
            })
        }
        _ => None,
    })
}
/*
/// NdpRequest is used to send an Ndp Requests and wait for the reply
pub struct NdpRequest<'a> {
    /// Interface to monitor
    interface: &'a NetworkInterface,
    /// IP Address that the request is targeting
    address: Ipv4Addr,
}

impl<'a> NdpRequest<'a> {
    /// Create a new NdpRequest for a given interface
    pub fn new(interface: &'a NetworkInterface, address: Ipv4Addr) -> Self {
        Self { interface, address }
    }

    /// Start the Ndp Request/Reply process
    pub fn request(&self) -> io::Result<datalink::MacAddr> {
        let (mut tx, mut rx) = match datalink::channel(&self.interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid interface channel type",
                ))
            }
        };

        // Build and Send an Ndp Request
        let request = build_request(&self.interface, self.address)?;
        // Send the packet bytes via the `tx` Channel for our interface
        match tx.send_to(request.packet(), None) {
            Some(Ok(_)) => {
                println!("Sent Ndp Request to {}", self.address);
            }
            Some(Err(err)) => return Err(err),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Channel is no longer available",
                ))
            }
        }

        // Now monitor Ndp packets and listen for Reply
        while let Ok(data) = rx.next() {
            if let Some(packet) = EthernetPacket::new(data) {
                match packet.get_ethertype() {
                    EtherType(0x0806) => {
                        if let Some(ndp) = NdpPacket::new(&packet.payload()) {
                            match ndp.get_operation() {
                                NdpOperations::Reply => {
                                    // Check to see if this is the reply to our request
                                    if ndp.get_sender_proto_addr() == self.address {
                                        return Ok(ndp.get_sender_hw_addr());
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Stopped receiving packets",
        ))
    }
}

pub fn build_request(
    interface: &NetworkInterface,
    addr: Ipv4Addr,
) -> io::Result<MutableEthernetPacket> {
    let mut ethernet_packet = MutableEthernetPacket::owned(vec![0u8; 42]).unwrap();

    let hw_addr = interface
        .mac
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "No MAC Address present"))?;
    let source_ip = find_ipv4_addr(&interface).ok_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "No IPv4 Address present")
    })?;

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(hw_addr);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut ndp_packet = MutableArpPacket::owned(vec![0; 28]).unwrap();

    ndp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    ndp_packet.set_protocol_type(EtherTypes::Ipv4);
    ndp_packet.set_hw_addr_len(6);
    ndp_packet.set_proto_addr_len(4);
    ndp_packet.set_operation(ArpOperations::Request);
    ndp_packet.set_sender_hw_addr(hw_addr);
    ndp_packet.set_sender_proto_addr(source_ip);
    ndp_packet.set_target_hw_addr(MacAddr::zero());
    ndp_packet.set_target_proto_addr(addr);

    ethernet_packet.set_payload(ndp_packet.packet_mut());

    Ok(ethernet_packet)
}
*/
