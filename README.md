# Rust Network Tools

A small collection of example network tools based off of similar examples with [Scapy](https://scapy.net/) from this blog series: [Building Network Tools with Scapy](https://thepacketgeek.com/scapy/)

# Library Tools

- `ArpMonitor`
  - View sniffed ARP Requests & Replies on a network interface
- `ArpRequest`
  - Send an ARP request for a given IP and print out the replied MAC address
- `ArpCache`
  - Ipv4 ARP cache with ARP request capabilities
- `NdpMonitor`
  - View sniffed NDP Solicitations & Acknowledgements on a network interface
- `NdpRequest`
  - Send an NDP solicitation for a given IP and print out the replied MAC address
- `NdpCache`
  - Ipv6 NDP cache with NDP request capabilities
- `Routes`
  - Ipv4/v6 Route Table with destination lookup (parsed from netstat)


# Running the CLI

```sh
cargo run -- --help
network-tools 0.1.0

USAGE:
    network-tools [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --interface <interface>    Interface name to bind to

SUBCOMMANDS:
    help           Prints this message or the help of the given subcommand(s)
    interfaces     List available Interfaces
    monitor-arp    Monitor for ARP Request/Replies
    monitor-ndp
    request-arp    Send an ARP request for a given IPv4 Address
    request-ndp    Send an NDP request for a given IPv6 Address
    route          List available Routes (or route for given destination IpAddr)
```

## Permissions
In order to create a `Channel` for Tx/Rx on an interface, you'll need sudo permissions:

```rust
cargo build
sudo ./target/debug/build monitor-arp -i eth0
```