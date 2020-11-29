use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Context};
use ip_network_table_deps_treebitmap::{address::Address, IpLookupTable};
use ipnetwork::{ipv4_mask_to_prefix, ipv6_mask_to_prefix, IpNetwork, Ipv4Network, Ipv6Network};
use pnet::datalink::{self, MacAddr, NetworkInterface};

use super::arp::ArpCache;

#[derive(Debug)]
pub struct Route {
    pub prefix: IpNetwork,
    pub next_hop: NextHop,
    pub interface: String,
    pub is_gateway: bool,
}

#[derive(Debug)]
pub struct NextHop {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub interface: Option<NetworkInterface>,
}

#[derive(Debug)]
struct Entry<A>
where
    A: Address,
{
    next_hop: A,
    interface: String,
    is_gateway: bool,
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
        let iface_names: HashSet<&String> = ifaces.keys().collect();
        let v4rib = RouteParser::<Ipv4Addr>::parse(&iface_names)?;
        let v6rib = RouteParser::<Ipv6Addr>::parse(&iface_names)?;

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
                if let Some((prefix, masklen, entry)) = self.v4rib.longest_match(addr) {
                    if entry.next_hop.is_unspecified() {
                        if let Ok(network) = Ipv4Network::new(prefix, masklen as u8) {
                            if network.contains(addr) {
                                return Some(NextHop {
                                    ip: IpAddr::V4(addr),
                                    mac: self.get_mac(&entry.interface, addr),
                                    interface: self
                                        .interfaces
                                        .get(&entry.interface)
                                        .map(|i| i.clone()),
                                });
                            }
                        }
                        // Next hop is not specified (uses the default gateway)
                        if let Some(default_gw) = self.v4rib.exact_match(entry.next_hop, 0) {
                            let mac = self.get_mac(&default_gw.interface, default_gw.next_hop);
                            return Some(NextHop {
                                ip: IpAddr::V4(default_gw.next_hop),
                                mac,
                                interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
                            });
                        }
                    }
                    let mac = self.get_mac(&entry.interface, entry.next_hop);
                    Some(NextHop {
                        ip: IpAddr::V4(entry.next_hop),
                        mac,
                        interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
                    })
                } else {
                    None
                }
            }
            IpAddr::V6(addr) => {
                if let Some((prefix, masklen, entry)) = self.v6rib.longest_match(addr) {
                    if entry.next_hop.is_unspecified() {
                        if let Ok(network) = Ipv6Network::new(prefix, masklen as u8) {
                            if network.contains(addr) {
                                return Some(NextHop {
                                    ip: IpAddr::V6(addr),
                                    mac: None,
                                    interface: self
                                        .interfaces
                                        .get(&entry.interface)
                                        .map(|i| i.clone()),
                                });
                            }
                        }
                        // Next hop is not specified (uses the default gateway)
                        if let Some(default_gw) = self.v6rib.exact_match("::".parse().unwrap(), 0) {
                            return Some(NextHop {
                                ip: IpAddr::V6(default_gw.next_hop),
                                mac: None,
                                interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
                            });
                        }
                    }
                    let mac = self
                        .interfaces
                        .get(&entry.interface)
                        .and_then(|iface| iface.mac);
                    Some(NextHop {
                        ip: IpAddr::V6(entry.next_hop),
                        mac,
                        interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
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

    pub fn routes(&self) -> Vec<Route> {
        let mut routes = Vec::with_capacity(self.v4rib.len() + self.v6rib.len());
        for (prefix, masklen, entry) in self.v4rib.iter() {
            routes.push(Route {
                prefix: IpNetwork::new(prefix.into(), masklen as u8).unwrap(),
                next_hop: NextHop {
                    ip: entry.next_hop.into(),
                    mac: self.get_mac(&entry.interface, entry.next_hop),
                    interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
                },
                interface: entry.interface.clone(),
                is_gateway: entry.is_gateway,
            });
        }
        for (prefix, masklen, entry) in self.v6rib.iter() {
            routes.push(Route {
                prefix: IpNetwork::new(prefix.into(), masklen as u8).unwrap(),
                next_hop: NextHop {
                    ip: entry.next_hop.into(),
                    mac: None,
                    interface: self.interfaces.get(&entry.interface).map(|i| i.clone()),
                },
                interface: entry.interface.clone(),
                is_gateway: entry.is_gateway,
            });
        }
        routes
    }
}

struct RouteParser<A>
where
    A: Address,
{
    _addr: std::marker::PhantomData<A>,
}

#[cfg(target_os = "linux")]
impl RouteParser<Ipv4Addr> {
    fn parse(
        interface_names: &HashSet<&String>,
    ) -> anyhow::Result<IpLookupTable<Ipv4Addr, Entry<Ipv4Addr>>> {
        let mut rib = IpLookupTable::new();
        let output = get_netstat_output(4)?;
        for line in output.lines() {
            if let Ok((dest, masklen, entry)) = Self::parse_row(line) {
                if interface_names.contains(&entry.interface) {
                    rib.insert(dest, masklen, entry);
                }
            }
        }

        Ok(rib)
    }

    fn parse_row(line: &str) -> anyhow::Result<(Ipv4Addr, u32, Entry<Ipv4Addr>)> {
        let words: Vec<_> = line.split_ascii_whitespace().collect();

        let dest = words[0]
            .parse()
            .map_err(|_| anyhow!("Couldn't parse Prefix"))?;
        let gw = words[1]
            .parse()
            .map_err(|_| anyhow!("Couldn't parse Gateway"))?;
        let mask = words[2]
            .parse()
            .map_err(|_| anyhow!("Couldn't parse Prefix mask"))
            .and_then(|m| ipv4_mask_to_prefix(m).context("Converting mask to masklen"))
            .map_err(|_| anyhow!("Couldn't parse Prefix mask"))?;
        let flags = words[3];
        let entry = Entry {
            next_hop: gw,
            interface: words[7].to_owned(),
            is_gateway: flags.contains('G'),
        };
        Ok((dest, mask.into(), entry))
    }
}

#[cfg(target_os = "linux")]
impl RouteParser<Ipv6Addr> {
    fn parse(
        interface_names: &HashSet<&String>,
    ) -> anyhow::Result<IpLookupTable<Ipv6Addr, Entry<Ipv6Addr>>> {
        let mut rib = IpLookupTable::new();
        let output = get_netstat_output(6)?;
        for line in output.lines() {
            if let Ok((dest, masklen, entry)) = Self::parse_row(line) {
                if interface_names.contains(&entry.interface) {
                    rib.insert(dest, masklen, entry);
                }
            }
        }
        Ok(rib)
    }

    fn parse_row(line: &str) -> anyhow::Result<(Ipv6Addr, u32, Entry<Ipv6Addr>)> {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        let dest: Ipv6Network = words[0]
            .parse()
            .map_err(|_| anyhow!("Couldn't parse Prefix"))?;
        let mask = ipv6_mask_to_prefix(dest.mask())?;
        let flags = words[2];
        let entry = Entry {
            next_hop: words[1]
                .parse()
                .map_err(|_| anyhow!("Couldn't parse Gateway"))?,
            interface: words[words.len() - 1].to_owned(),
            is_gateway: flags.contains('G'),
        };
        Ok((dest.ip(), mask.into(), entry))
    }
}

#[cfg(not(test))]
#[cfg(target_os = "linux")]
fn get_netstat_output(ip_version: u8) -> io::Result<String> {
    let output = std::process::Command::new("netstat")
        .args(&[&format!("-rn{}", ip_version)])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
fn get_netstat_output(ip_version: u8) -> io::Result<String> {
    let output = match ip_version {
        4 => {
            r#"Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         172.16.0.1      0.0.0.0         UG        0 0          0 eth0
10.46.0.0       0.0.0.0         255.255.0.0     U         0 0          0 eth0
172.16.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth0"#
        }
        6 => {
            r#"Kernel IPv6 routing table
Destination                    Next Hop                   Flag Met Ref Use If
::1/128                        ::                         U    256 1     0 lo
2604:a880:2:d1::/64            ::                         U    256 3     4 eth0
fe80::/64                      ::                         U    256 1     0 eth0
3001:10:ab::6/128              ::                         U    256 1     0 wg0
3001:10:ab::/64                ::                         U    1024 2     3 wg0
::/0                           2601:a10:2:dead::1         UG   1024 3384554 eth0
::1/128                        ::                         Un   0   4 46615 lo"#
        }
        _ => unimplemented!(),
    };
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

        assert_eq!(next_hop.ip, "172.16.0.4".parse::<IpAddr>().unwrap());

        let next_hop = routes.lookup_gateway("4.2.2.1".parse().unwrap()).unwrap();
        assert_eq!(next_hop.ip, "172.16.0.1".parse::<IpAddr>().unwrap());

        let next_hop = routes
            .lookup_gateway("3001:10:ab::abcd:10".parse().unwrap())
            .unwrap();
        assert_eq!(
            next_hop.ip,
            "3001:10:ab::abcd:10".parse::<IpAddr>().unwrap()
        );

        let next_hop = routes
            .lookup_gateway("2001::1:1:1:1".parse().unwrap())
            .unwrap();
        assert_eq!(next_hop.ip, "2601:a10:2:dead::1".parse::<IpAddr>().unwrap());
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
