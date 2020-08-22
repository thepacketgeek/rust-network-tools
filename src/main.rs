use pnet::datalink::{self, NetworkInterface};
use structopt::StructOpt;

use network_tools::arp;

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
    ListInterfaces,
    /// Monitor for ARP Request/Replies
    MonitorArp {
        #[structopt(short, long, default_value = "10")]
        /// Monitor until up to this many ARP packets seen
        count: usize,
    },
    /// Send an ARP request for a given IP Address
    RequestArp { address: std::net::Ipv4Addr },
}

fn main() {
    let args = Args::from_args();
    let interfaces: Vec<NetworkInterface> = datalink::interfaces().into_iter().collect();

    match args.command {
        Command::ListInterfaces => {
            let mut width = 0usize;
            for iface in &interfaces {
                width = std::cmp::max(width, iface.name.len());
            }
            for iface in &interfaces {
                let addrs: Vec<_> = iface.ips.iter().map(|ip| format!("{}", ip.ip())).collect();
                println!("{:w$} [{}]", iface.name, addrs.join(", "), w = width + 2);
            }
        }
        Command::MonitorArp { count } => {
            let interface = get_interface(&interfaces, args.interface.as_ref());
            let monitor = arp::ArpMonitor::new(interface);
            monitor.monitor(count).unwrap();
        }
        Command::RequestArp { address } => {
            let interface = get_interface(&interfaces, args.interface.as_ref());
            let requester = arp::ArpRequest::new(interface, address);
            let hw_addr = requester.request().unwrap();
            eprintln!("{} has MAC Address {}", address, hw_addr);
        }
    }
}

fn get_interface<'a>(
    interfaces: &'a Vec<NetworkInterface>,
    iface_name: Option<&String>,
) -> &'a NetworkInterface {
    if let Some(iface_name) = iface_name {
        interfaces
            .iter()
            .filter(|iface| &iface.name == iface_name)
            .next()
            .unwrap_or_else(|| {
                eprintln!(
                    "'{}' is not a valid interface, must be one of: {}",
                    iface_name,
                    interfaces
                        .iter()
                        .map(|iface| iface.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                std::process::exit(1);
            })
    } else {
        interfaces
            .first()
            .map(|i| {
                eprintln!("Using interface: {}", i.name);
                i
            })
            .expect("No interfaces found")
    }
}
