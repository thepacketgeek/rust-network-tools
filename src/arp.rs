use std::cell::RefCell;
use std::io;
use std::net::Ipv4Addr;

use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
    MutablePacket, Packet,
};

/// ArpMonitor is used to listen for ARP Requests/Replies on a given interface
pub struct ArpMonitor<'a> {
    /// Interface to monitor
    interface: &'a NetworkInterface,
    /// Count of how many ARP packets have been seen
    packet_count: RefCell<usize>,
}

impl<'a> ArpMonitor<'a> {
    /// Create a new ArpMonitor for a given interface
    pub fn new(interface: &'a NetworkInterface) -> Self {
        Self {
            interface,
            packet_count: RefCell::new(0),
        }
    }

    /// Start monitoring for ARP packets, up-to the given packet count
    pub fn monitor(&self, packet_count: usize) -> io::Result<()> {
        // Create an Ethernet channel on our interface
        let (_, mut rx) = match datalink::channel(&self.interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => {
                // Only Channel::Ethernet is supported currently
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid interface channel type",
                ));
            }
        };

        // Iterate through every packet received on the interface
        for data in rx.next() {
            if let Some(packet) = EthernetPacket::new(data) {
                match packet.get_ethertype() {
                    // We only want to operate on ARP packets
                    EtherType(0x0806) => {
                        ArpPacket::new(&packet.payload()).map(|arp| {
                            // Increment our packet count to signal when to stop monitoring
                            *self.packet_count.borrow_mut() += 1;
                            match arp.get_operation() {
                                ArpOperations::Request => eprintln!(
                                    "Request: {} is asking about {}",
                                    arp.get_sender_proto_addr(),
                                    arp.get_target_proto_addr()
                                ),
                                ArpOperations::Reply => eprintln!(
                                    "*Reply: {} has address {}",
                                    arp.get_sender_hw_addr(),
                                    arp.get_sender_proto_addr()
                                ),
                                _ => return,
                            }
                        });
                        // Since we're only counting ARP packets, only check this
                        // after ARP is received
                        if packet_count == *self.packet_count.borrow() {
                            // Return out of the function when the limit is hit
                            return Ok(());
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(())
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
        let request = self.build_request()?;
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

    fn build_request(&self) -> io::Result<MutableEthernetPacket> {
        // Adapted from https://github.com/libpnet/libpnet/blob/master/examples/arp_packet.rs
        let mut ethernet_packet = MutableEthernetPacket::owned(vec![0; 42]).unwrap();

        let hw_addr = self.interface.mac.ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "No MAC Address present")
        })?;
        let source_ip = get_ipv4_addr(&self.interface).ok_or_else(|| {
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
        arp_packet.set_target_proto_addr(self.address);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        Ok(ethernet_packet)
    }
}

fn get_ipv4_addr(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for network in &interface.ips {
        match network {
            pnet::ipnetwork::IpNetwork::V4(net) => return Some(net.ip()),
            _ => continue,
        }
    }
    None
}
