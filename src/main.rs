use anyhow::Result;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpOperations;
use structopt::StructOpt;

use network_tools::{arp, ndp, resolve_host, routes, IpType};

#[derive(Debug, StructOpt)]
struct Args {
    /// Network tool to run
    #[structopt(subcommand)]
    command: Command,
    /// Interface name to bind to
    #[structopt(short, long, global = true)]
    interface: Option<String>,
}

#[derive(Debug, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub enum Command {
    /// List available Interfaces
    Interfaces,
    /// List available Routes (or route for given destination host)
    Route {
        addr: Option<String>,
        /// Use IPv4 Only
        #[structopt(short = "4")]
        use_ipv4: bool,
        /// Use IPv6 Only
        #[structopt(short = "6")]
        use_ipv6: bool,
    },
    /// Monitor for ARP Request/Replies
    MonitorArp {
        #[structopt(short, long, default_value = "10")]
        /// Monitor until up to this many ARP packets seen
        count: usize,
    },
    /// Send an ARP request for a given IPv4 Address
    RequestArp { address: std::net::Ipv4Addr },
    /// Monitor for IPv6 NDP (Neighbor/Router Solicitations & Advertisements)
    MonitorNdp {
        #[structopt(short, long, default_value = "10")]
        /// Monitor until up to this many NDP packets seen
        count: usize,
    },
    /// Send an NDP request for a given IPv6 Address
    RequestNdp { address: std::net::Ipv6Addr },
}

fn main() -> Result<()> {
    let args = Args::from_args();
    let interfaces: Vec<NetworkInterface> = datalink::interfaces().into_iter().collect();

    match args.command {
        Command::Interfaces => {
            let mut width = 0usize;
            for iface in &interfaces {
                width = std::cmp::max(width, iface.name.len());
            }
            for iface in &interfaces {
                let addrs: Vec<_> = iface.ips.iter().map(|ip| format!("{}", ip.ip())).collect();
                println!("{:w$} [{}]", iface.name, addrs.join(", "), w = width + 2);
            }
        }
        Command::Route {
            addr,
            use_ipv4,
            use_ipv6,
        } => {
            let routes = if let Some(iface_name) = &args.interface {
                let interface = get_interface(interfaces, Some(iface_name));
                routes::Routes::with_interfaces(vec![interface])?
            } else {
                routes::Routes::new()?
            };
            let ip_type = match (use_ipv4, use_ipv6) {
                (true, false) => IpType::V4,
                (false, true) => IpType::V6,
                _ => IpType::Either,
            };
            if let Some(host) = addr {
                let destination = resolve_host(&host, ip_type)?;
                if let Some(next_hop) = routes.lookup_gateway(destination) {
                    println!(
                        "{} via {} [{}]",
                        destination,
                        next_hop.ip,
                        next_hop
                            .mac
                            .map(|mac| mac.to_string())
                            .unwrap_or_else(|| "--".to_owned())
                    );
                }
            } else {
                for route in routes
                    .routes()
                    .iter()
                    .filter(|r| ip_type.matches(r.next_hop.ip))
                {
                    println!(
                        "{}{} via {} [{}]",
                        if route.is_gateway { "*" } else { "" },
                        &route.prefix,
                        route.next_hop.ip,
                        route
                            .next_hop
                            .mac
                            .map(|mac| mac.to_string())
                            .unwrap_or_else(|| "--".to_owned())
                    );
                }
            }
        }
        Command::MonitorArp { count } => {
            let interface = get_interface(interfaces, args.interface.as_ref());
            let mut monitor = arp::ArpMonitor::new(&interface)?;
            let mut limit = count;
            loop {
                for arp in &mut monitor {
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
                        _ => return Ok(()),
                    }

                    if limit == 0 {
                        break;
                    }
                    limit -= 1;
                }
            }
        }
        Command::RequestArp { address } => {
            let interface = get_interface(interfaces, args.interface.as_ref());
            let requester = arp::ArpRequest::new(&interface, address);
            let hw_addr = requester.request()?;
            eprintln!("{} has MAC Address {}", address, hw_addr);
        }
        Command::MonitorNdp { count } => {
            let interface = get_interface(interfaces, args.interface.as_ref());
            let mut monitor = ndp::NdpMonitor::new(&interface)?;
            let mut limit = count;
            loop {
                for ndp in &mut monitor {
                    match ndp {
                        ndp::NdpPacket::NeighborAdvertisement {
                            src,
                            src_mac,
                            target,
                        } => {
                            eprintln!(
                                "Neighbor Advertisement*: {} has mac {} (responding to {})",
                                src, src_mac, target
                            );
                        }
                        ndp::NdpPacket::NeighborSolicitation {
                            src,
                            src_mac,
                            target,
                        } => {
                            eprintln!(
                                "Neighbor Solicitation: {} asking about {} (respond @ {})",
                                src, target, src_mac
                            );
                        }
                        ndp::NdpPacket::RouterSolicitation { src, src_mac } => {
                            eprintln!(
                                "Router Solicitation*: {} is asking (respond @ {})",
                                src, src_mac
                            );
                        }
                        ndp::NdpPacket::RouterAdvertisement {
                            src,
                            src_mac,
                            prefixes,
                        } => {
                            let networks = prefixes
                                .iter()
                                .map(|p| p.to_string())
                                .collect::<Vec<String>>()
                                .join(", ");
                            eprintln!(
                                "Router Advertisement*: {} is advertising the prefixes: {} (via {})",
                                src, networks, src_mac,
                            );
                        }
                    }
                    if limit == 0 {
                        break;
                    }
                    limit -= 1;
                }
            }
        }
        Command::RequestNdp { address } => {
            let interface = get_interface(interfaces, args.interface.as_ref());
            let requester = ndp::NdpRequest::new(&interface, address);
            let hw_addr = requester.request()?;
            eprintln!("{} has MAC Address {}", address, hw_addr);
        }
    }
    Ok(())
}

fn get_interface(
    interfaces: Vec<NetworkInterface>,
    iface_name: Option<&String>,
) -> NetworkInterface {
    if let Some(iface_name) = iface_name {
        interfaces
            .into_iter()
            .find(|iface| &iface.name == iface_name)
            .unwrap_or_else(|| {
                eprintln!("'{}' is not a valid interface", iface_name,);
                std::process::exit(1);
            })
    } else {
        interfaces
            .first()
            .map(|i| {
                eprintln!("Using interface: {}", i.name);
                i.clone()
            })
            .expect("No interfaces found")
    }
}
