use std::cell::RefCell;
use std::io;
use std::net::Ipv4Addr;

use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
    MutablePacket, Packet,
};

use super::find_ipv4_addr;

pub mod cache;
pub use cache::ArpCache;

/// ArpMonitor is used to listen for ARP Requests/Replies on a given interface
pub struct ArpMonitor {
    interface: NetworkInterface,
    /// Channel Receiver for packets
    tx: RefCell<Box<dyn datalink::DataLinkSender>>,
    /// Channel Receiver for packets
    rx: RefCell<Box<dyn datalink::DataLinkReceiver>>,
}

impl ArpMonitor {
    /// Create a new ArpMonitor for a given interface
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

    pub fn send_request(&self, addr: Ipv4Addr) -> io::Result<()> {
        let mut tx = self.tx.borrow_mut();
        let request = build_request(&self.interface, addr)?;
        match tx.send_to(request.packet(), None) {
            Some(Ok(_)) => Ok(()),
            Some(Err(err)) => return Err(err),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Channel is no longer available",
            )),
        }
    }
}

impl<'a> Iterator for ArpMonitor {
    type Item = ArpPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rx.borrow_mut().next() {
            Ok(data) => {
                if let Some(packet) = EthernetPacket::new(data) {
                    match packet.get_ethertype() {
                        // We only want to operate on ARP packets
                        EtherType(0x0806) => {
                            if let Some(arp) = ArpPacket::owned(packet.payload().to_owned()) {
                                return Some(arp);
                            } else {
                                return None;
                            }
                        }
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

/// ArpRequest is used to send an ARP Requests and wait for the reply
pub struct ArpRequest<'a> {
    /// Interface to monitor
    interface: &'a NetworkInterface,
    /// IP Address that the request is targeting
    address: Ipv4Addr,
}

impl<'a> ArpRequest<'a> {
    /// Create a new ArpRequest for a given interface
    pub fn new(interface: &'a NetworkInterface, address: Ipv4Addr) -> Self {
        Self { interface, address }
    }

    /// Start the ARP Request/Reply process
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

        // Build and Send an ARP Request
        let request = build_request(&self.interface, self.address)?;
        // Send the packet bytes via the `tx` Channel for our interface
        match tx.send_to(request.packet(), None) {
            Some(Ok(_)) => {
                println!("Sent ARP Request to {}", self.address);
            }
            Some(Err(err)) => return Err(err),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Channel is no longer available",
                ))
            }
        }

        // Now monitor ARP packets and listen for Reply
        while let Ok(data) = rx.next() {
            if let Some(packet) = EthernetPacket::new(data) {
                match packet.get_ethertype() {
                    EtherType(0x0806) => {
                        if let Some(arp) = ArpPacket::new(&packet.payload()) {
                            match arp.get_operation() {
                                ArpOperations::Reply => {
                                    // Check to see if this is the reply to our request
                                    if arp.get_sender_proto_addr() == self.address {
                                        return Ok(arp.get_sender_hw_addr());
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
    // Adapted from https://github.com/libpnet/libpnet/blob/master/examples/arp_packet.rs
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

    let mut arp_packet = MutableArpPacket::owned(vec![0; 28]).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(hw_addr);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(addr);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    Ok(ethernet_packet)
}
