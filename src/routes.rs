use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Context};
use ipnetwork::ipv4_mask_to_prefix;
use pnet::datalink::{self, MacAddr, NetworkInterface};
use treebitmap::{address::Address, IpLookupTable};

use super::arp_cache::ArpCache;

#[derive(Debug)]
pub struct Entry<A>
where
    A: Address,
{
    gateway: A,
    interface: String,
}
#[derive(Debug)]
pub struct NextHop {
    pub gateway: IpAddr,
    pub mac: Option<MacAddr>,
}

pub struct Routes {
    // Learned routes (by prefix) with Gateway/Interface name
    v4rib: IpLookupTable<Ipv4Addr, Entry<Ipv4Addr>>,
    v6rib: IpLookupTable<Ipv6Addr, Entry<Ipv6Addr>>,
    interfaces: HashMap<String, NetworkInterface>,
    caches: HashMap<String, ArpCache>,
}

impl Routes {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_interfaces(datalink::interfaces())
    }

    pub fn with_interfaces(interfaces: Vec<NetworkInterface>) -> anyhow::Result<Self> {
        let ifaces: HashMap<String, NetworkInterface> = interfaces
            .into_iter()
            .map(|iface| (iface.name.clone(), iface))
            .collect();
        let v4rib = read_routes()?;
        let v6rib = IpLookupTable::new();

        let caches = ifaces
            .iter()
            .map(|(name, iface)| (name.clone(), ArpCache::new(&iface)))
            .collect();

        Ok(Self {
            v4rib,
            v6rib,
            interfaces: ifaces,
            caches,
        })
    }

    pub fn lookup_gateway(&self, destination: IpAddr) -> Option<NextHop> {
        match destination {
            IpAddr::V4(addr) => {
                if let Some((_prefix, _masklen, entry)) = self.v4rib.longest_match(addr) {
                    let mac = self.get_mac(&entry.interface, entry.gateway);
                    Some(NextHop {
                        gateway: IpAddr::V4(entry.gateway),
                        mac,
                    })
                } else {
                    None
                }
            }
            IpAddr::V6(addr) => {
                if let Some((_prefix, _masklen, entry)) = self.v6rib.longest_match(addr) {
                    let mac = self
                        .interfaces
                        .get(&entry.interface)
                        .and_then(|iface| iface.mac);
                    Some(NextHop {
                        gateway: IpAddr::V6(entry.gateway),
                        mac,
                    })
                } else {
                    None
                }
            }
        }
    }

    fn get_mac(&self, iface_name: &str, addr: Ipv4Addr) -> Option<MacAddr> {
        if let Some(cache) = self.caches.get(iface_name) {
            cache.get(addr, std::time::Duration::from_millis(100))
        } else {
            None
        }
    }

    pub fn routes(&self) -> Vec<(IpAddr, u32, IpAddr, Option<MacAddr>)> {
        let mut routes = Vec::with_capacity(self.v4rib.len() + self.v6rib.len());
        for (prefix, masklen, entry) in self.v4rib.iter() {
            routes.push((
                prefix.into(),
                masklen,
                entry.gateway.into(),
                self.get_mac(&entry.interface, entry.gateway),
            ))
        }
        for (prefix, masklen, entry) in self.v6rib.iter() {
            routes.push((prefix.into(), masklen, entry.gateway.into(), None));
        }
        routes
    }
}

#[cfg(target_os = "linux")]
fn read_routes<A>() -> anyhow::Result<IpLookupTable<A, Entry<A>>>
where
    A: Address + std::str::FromStr,
{
    let mut rib = IpLookupTable::new();
    let output = get_netstat_output()?;
    for line in output.lines() {
        if let Ok((dest, masklen, entry)) = parse_row(line) {
            rib.insert(dest, masklen, entry);
        }
    }

    Ok(rib)
}

#[cfg(not(test))]
#[cfg(target_os = "linux")]
fn get_netstat_output() -> io::Result<String> {
    let output = std::process::Command::new("netstat")
        .args(&["-rnf", "inet"])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "linux")]
fn parse_row<A: Address + std::str::FromStr>(line: &str) -> anyhow::Result<(A, u32, Entry<A>)> {
    let words: Vec<_> = line.split_ascii_whitespace().collect();
    if words.len() < 8 {
        return Err(anyhow!("Not a valid Route row"));
    }
    let dest: A = words[0]
        .parse()
        .map_err(|_| anyhow!("Couldn't parse Prefix"))?;
    let gw: A = words[1]
        .parse()
        .map_err(|_| anyhow!("Couldn't parse Gateway"))?;
    let mask = words[2]
        .parse()
        .map_err(|_| anyhow!("Couldn't parse Prefix mask"))
        .and_then(|m| ipv4_mask_to_prefix(m).context("Converting mask to masklen"))
        .map_err(|_| anyhow!("Couldn't parse Prefix mask"))?;
    let entry = Entry {
        gateway: gw,
        interface: words[7].to_owned(),
    };
    Ok((dest, u32::from(mask), entry))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
fn get_netstat_output() -> io::Result<String> {
    let output = r#"Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         172.16.0.1      0.0.0.0         UG        0 0          0 eth0
10.46.0.0       0.0.0.0         255.255.0.0     U         0 0          0 eth0
172.16.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U         0 0          0 docker0"#;
    Ok(output.to_string())
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let routes = Routes::new().unwrap();

        let next_hop = routes
            .lookup_gateway("172.16.0.4".parse().unwrap())
            .unwrap();

        assert_eq!(next_hop.gateway, "172.16.0.1".parse::<IpAddr>().unwrap());
    }
}
// #[cfg(target_os = "macos")]
// fn read_routes() -> io::Result<(Rib, Fib)> {
//     let mut rib: Rib = HashMap::new();
//     let mut fib: Fib = HashMap::new();
//     let output = Command::new("netstat").args(&["-rnf", "inet"]).output()?;
//     for line in String::from_utf8_lossy(&output.stdout).lines() {
//         let words: Vec<_> = line.split_ascii_whitespace().collect();
//         if words.len() < 4 {
//             continue;
//         }
//         let dest = if let Some(dest) = parse_destination(&words[0]) {
//             dest
//         } else {
//             continue;
//         };
//         eprintln!("Dest: {}", dest);
//         // let gw = words[1];
//         // let flags = words[2];
//         // let iface = words[3];
//     }

//     Ok((rib, fib))
// }

// #[cfg(target_os = "macos")]
// fn parse_destination(destination: &str) -> Option<IpNetwork> {
//     let mut new_dest = destination.to_owned();
//     if let Ok(dest) = destination.parse() {
//         Some(dest)
//     } else if destination == "default" {
//         Some(IpNetwork::V4(
//             Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
//         ))
//     } else {
//         eprintln!("Bad Dest: {}", destination);
//         None
//     }
// }
