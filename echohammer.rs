/// Network Packet Testing Tool
/// A legitimate network diagnostics and packet generation utility
/// for testing network infrastructure and security monitoring.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::LazyLock;
use clap::{Arg, Command};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::packet::icmp::{MutableIcmpPacket, IcmpCode};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::sleep;
use tracing::{info, warn, error};
use anyhow::{Result, Context};
use colored::Colorize;
use std::io::Write;
use url;

/// ARP cache for efficient MAC address resolution
/// Reduces network overhead by caching resolved MAC addresses for 60 seconds
static ARP_CACHE: LazyLock<Mutex<HashMap<Ipv4Addr, (MacAddr, Instant)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Display professional banner with typewriter effect
async fn display_banner() {
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Title with typewriter effect
    let title = "    ███████╗ ██████╗██╗  ██╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ ";
    for ch in title.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_micros(500)).await;
    }
    println!();
    
    let title2 = "    ██╔════╝██╔════╝██║  ██║██╔═══██╗██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗";
    for ch in title2.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_micros(500)).await;
    }
    println!();
    
    println!("{}", "    █████╗  ██║     ███████║██║   ██║███████║███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝".bright_yellow());
    println!("{}", "    ██╔══╝  ██║     ██╔══██║██║   ██║██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗".bright_yellow());
    println!("{}", "    ███████╗╚██████╗██║  ██║╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║".bright_green());
    println!("{}", "    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝".bright_green());
    
    println!();
    println!("{}", "              NETWORK PACKET TESTING & DIAGNOSTICS FRAMEWORK              ".bright_magenta().bold());
    sleep(Duration::from_millis(100)).await;
    
    println!();
    println!("{}", "    ┌─────────────────────────────────────────────────────────────────────┐".bright_cyan());
    println!("{}", "    │                                                                     │".bright_cyan());
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Version: 9.20.2091vproAlpha | Author: khaninkali                 ".bright_white(),
        "│".bright_cyan()
    );
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Purpose: Network Infrastructure Testing & Security Analysis      ".bright_green(),
        "│".bright_cyan()
    );
    println!("{}", "    │                                                                     │".bright_cyan());
    println!("{}", "    └─────────────────────────────────────────────────────────────────────┘".bright_cyan());
    
    println!();
    println!("{}", "    ╔═══════════════════════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "    ║  WARNING: For authorized testing and diagnostics only             ║".bright_white());
    println!("{}", "    ║  Unauthorized use may violate laws and regulations                ║".bright_white());
    println!("{}", "    ╚═══════════════════════════════════════════════════════════════════╝".bright_red().bold());
    
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Typewriter initialization
    print!("{}", "    Initializing framework".bright_white());
    std::io::stdout().flush().unwrap();
    for _ in 0..3 {
        sleep(Duration::from_millis(400)).await;
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
    }
    println!(" {}", "READY".bright_green().bold());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Display banner first
    display_banner().await;
    let matches = Command::new("Network Packet Tester")
        .version("9.20.2091vproAlpha")
        .about("Network Packet Testing Tool - Infrastructure Diagnostics Utility")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("IP/URL")
                .help("Target IP address or URL for packet testing")
                .required(true),
        )
        .arg(
            Arg::new("threads")
                .short('T')
                .long("threads")
                .value_name("COUNT")
                .help("Number of concurrent worker threads")
                .default_value("4"),
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_name("SECONDS")
                .help("Test duration in seconds")
                .default_value("60"),
        )
        .arg(
            Arg::new("packet_size")
                .short('s')
                .long("packet-size")
                .value_name("BYTES")
                .help("ICMP packet size in bytes")
                .default_value("64"),
        )
        .arg(
            Arg::new("random_source")
                .short('r')
                .long("random-source")
                .help("Use random source IP addresses from local subnet")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats_interval")
                .long("stats-interval")
                .value_name("SECONDS")
                .help("Statistics reporting interval")
                .default_value("10"),
        )
        .arg(
            Arg::new("icmp_type")
                .short('i')
                .long("icmp-type")
                .value_name("TYPE")
                .help("ICMP message type")
                .default_value("8")
                .value_parser(["0", "3", "8", "11", "12"]),
        )
        .arg(
            Arg::new("interface")
                .short('I')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to use (e.g., wlan0, eth0)")
                .default_value("auto"),
        )
        .get_matches();

    // Initialize statistics tracking
    let stats = Arc::new(PacketStats::new());
    let stats_monitor = Arc::clone(&stats);
    
    // Parse and validate command line arguments
    let target_input = matches.get_one::<String>("target")
        .ok_or_else(|| anyhow::anyhow!("Target IP address or URL is required"))?
        .clone();
    
    // Resolve target to IP address (supports both IP and URL)
    let target_ip = resolve_target_to_ip(&target_input).await
        .context(format!("Failed to resolve target: {}", target_input))?;
    
    println!("{}", format!("[+] Resolved target '{}' to IP: {}", target_input, target_ip).bright_green());
    
    let threads: usize = matches.get_one::<String>("threads")
        .unwrap_or(&"4".to_string())
        .parse()
        .context("Invalid thread count - must be a positive integer")?;
    let duration: u64 = matches.get_one::<String>("duration")
        .unwrap_or(&"60".to_string())
        .parse()
        .context("Invalid duration - must be a positive integer")?;
    let packet_size: usize = matches.get_one::<String>("packet_size")
        .unwrap_or(&"64".to_string())
        .parse()
        .context("Invalid packet size - must be between 8 and 1500")?;
    let random_source: bool = matches.get_flag("random_source");
    let stats_interval: u64 = matches.get_one::<String>("stats_interval")
        .unwrap_or(&"10".to_string())
        .parse()
        .context("Invalid stats interval - must be a positive integer")?;
    let icmp_type: u8 = matches.get_one::<String>("icmp-type")
        .unwrap_or(&"8".to_string())
        .parse()
        .unwrap_or(8);
    let interface_name: String = matches.get_one::<String>("interface")
        .unwrap_or(&"auto".to_string())
        .to_string();
    
    println!("[+] Network Packet Tester v9.20.2091vproAlpha");
    println!("[+] Target: {} ({})", target_input, target_ip);
    println!("[+] Worker Threads: {}", threads);
    println!("[+] Test Duration: {}s", duration);
    println!("[+] Packet Size: {} bytes", packet_size);
    println!("[+] Random Source IPs: {}", random_source);
    println!("[+] Interface: {}", interface_name);
    println!("[+] ICMP Type: {}", icmp_type);
    println!();
    
    // Verify target is reachable before starting
    println!("{}", "[*] Verifying target reachability...".bright_yellow());
    match verify_target_reachable(&target_ip.to_string()).await {
        Ok(true) => println!("{}", "[+] Target is reachable - proceeding with test".bright_green()),
        Ok(false) => {
            println!("{}", "[!] Warning: Target may not be reachable, but continuing anyway".bright_yellow());
        }
        Err(e) => {
            println!("{}", format!("[!] Warning: Could not verify reachability: {}", e).bright_yellow());
        }
    }
    println!();
    
    // Start statistics monitoring
    let stats_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(stats_interval));
        loop {
            interval.tick().await;
            stats_monitor.print_stats();
        }
    });
    
    let attack_start = Instant::now();
    let mut handles = vec![];
    
    // Create worker threads for packet generation
    for i in 0..threads {
        let target_ip_clone = target_ip.to_string();
        let stats_clone = Arc::clone(&stats);
        let packet_size_clone = packet_size;
        let random_source_clone = random_source;
        let icmp_type_clone = icmp_type;
        let interface_name_clone = interface_name.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = packet_generation_worker(
                &target_ip_clone,
                i,
                packet_size_clone,
                random_source_clone,
                icmp_type_clone,
                &interface_name_clone,
                &stats_clone,
                duration
            ).await {
                error!("Packet worker {} failed: {}", i, e);
            }
        });
        
        handles.push(handle);
    }
    
    info!("[+] All {} packet workers initiated", threads);
    
    // Monitor test duration with real-time stats
    let mut last_stats_time = Instant::now();
    while attack_start.elapsed().as_secs() < duration {
        sleep(Duration::from_secs(1)).await;
        
        // Show real-time stats every 2 seconds
        if last_stats_time.elapsed().as_secs() >= 2 {
            let sent = stats.packets_sent.load(Ordering::Relaxed);
            let failed = stats.packets_failed.load(Ordering::Relaxed);
            let bytes = stats.bytes_sent.load(Ordering::Relaxed);
            let elapsed = attack_start.elapsed().as_secs();
            
            println!("[*] Stats: {} sent, {} failed, {} KB, {}s elapsed", 
                    sent, failed, bytes / 1024, elapsed);
            last_stats_time = Instant::now();
        }
    }
    
    info!("[+] Test duration completed");
    
    // Final statistics
    stats.print_stats();
    
    // Stop statistics monitoring
    stats_handle.abort();
    
    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("[+] Network Packet Tester completed successfully!");
    
    Ok(())
}

/// Statistics tracking for packet generation operations
/// Provides thread-safe counters for monitoring packet transmission performance
#[derive(Clone)]
struct PacketStats {
    packets_sent: Arc<AtomicUsize>,
    packets_failed: Arc<AtomicUsize>,
    bytes_sent: Arc<AtomicUsize>,
    start_time: Arc<Instant>,
}

/// Resolve target (IP or URL) to an IP address
/// Supports both direct IP addresses and domain names
async fn resolve_target_to_ip(target: &str) -> Result<Ipv4Addr> {
    // Try parsing as direct IP first
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    
    // Try parsing as URL and extract host
    let host = if target.starts_with("http://") || target.starts_with("https://") {
        url::Url::parse(target)
            .context("Invalid URL format")?
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in URL"))?
            .to_string()
    } else {
        target.to_string()
    };
    
    // Perform DNS resolution
    use tokio::net::lookup_host;
    let addresses: Vec<_> = lookup_host(format!("{}:80", host))
        .await
        .context(format!("DNS resolution failed for '{}'", host))?
        .collect();
    
    // Find first IPv4 address
    for addr in addresses {
        if let std::net::IpAddr::V4(ipv4) = addr.ip() {
            return Ok(ipv4);
        }
    }
    
    Err(anyhow::anyhow!("No IPv4 address found for target"))
}

/// Verify target is reachable using a simple ping test
/// Sends a single ICMP echo request and waits for response
async fn verify_target_reachable(target_ip: &str) -> Result<bool> {
    use std::process::Command;
    
    let target_clone = target_ip.to_string();
    
    // Use system ping command for quick reachability check
    let output = tokio::task::spawn_blocking(move || {
        Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg(&target_clone)
            .output()
    }).await??;
    
    Ok(output.status.success())
}

impl PacketStats {
    /// Create a new PacketStats instance with initialized counters
    fn new() -> Self {
        Self {
            packets_sent: Arc::new(AtomicUsize::new(0)),
            packets_failed: Arc::new(AtomicUsize::new(0)),
            bytes_sent: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
        }
    }
    
    /// Display current statistics including packet counts and transmission rate
    fn print_stats(&self) {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let failed = self.packets_failed.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        
        info!("[+] Packet Stats: Sent: {}, Failed: {}, Bytes: {:.2}MB, Rate: {:.2} pps",
              sent, failed, bytes as f64 / 1024.0 / 1024.0, sent as f64 / elapsed);
    }
}

/// Worker thread for generating and transmitting network packets
/// Handles packet construction, ARP resolution, and transmission with proper error handling
async fn packet_generation_worker(
    target: &str,
    worker_id: usize,
    packet_size: usize,
    random_source: bool,
    icmp_type: u8,
    interface_name: &str,
    stats: &PacketStats,
    global_duration: u64,
) -> Result<()> {
    println!("[*] Worker {} starting packet generation to {} for {}s", worker_id, target, global_duration);
    let target_ip: Ipv4Addr = target.parse()
        .context("Invalid target IP address format")?;
    
    // Find suitable network interface
    let interface = find_suitable_interface(&interface_name)
        .context("No suitable network interface found")?;
    
    let interface_mac = interface.mac
        .ok_or_else(|| anyhow::anyhow!("Interface MAC address not available"))?;
    
    // Create packet transmission channel
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => {
            println!("[+] Successfully created packet transmission channel on {}", interface.name);
            (tx, rx)
        },
        Ok(_) => return Err(anyhow::anyhow!("Unsupported channel type for interface")),
        Err(e) => return Err(anyhow::anyhow!("Failed to create network channel: {} - may need root privileges", e)),
    };
    
    // Resolve target MAC address using ARP
    println!("[*] Worker {} resolving MAC address for {} via ARP", worker_id, target_ip);
    let target_mac = match resolve_target_mac_cached(target_ip, &interface).await {
        Ok(mac) => {
            println!("[+] Worker {} resolved {} to MAC: {}", worker_id, target_ip, mac);
            mac
        }
        Err(e) => {
            println!("[!] Worker {} ARP resolution failed for {}: {}", worker_id, target_ip, e);
            // Use broadcast MAC as fallback for testing
            println!("[!] Worker {} using broadcast MAC as fallback", worker_id);
            MacAddr::broadcast()
        }
    };
    
    let mut packet_count = 0;
    let start_time = Instant::now();
    
    // Main packet generation loop
    while start_time.elapsed().as_secs() < global_duration {
        // Determine source IP address
        let source_ip = if random_source {
            generate_local_subnet_ip(&interface, worker_id)
        } else {
            get_primary_interface_ip(&interface)
        };
        
        // Construct ICMP packet
        println!("[*] Worker {} constructing packet: {} -> {} ({} bytes)", 
                worker_id, source_ip, target_ip, packet_size);
        let packet = match build_icmp_packet(
            source_ip, 
            target_ip, 
            interface_mac, 
            target_mac, 
            packet_size, 
            icmp_type
        ) {
            Ok(pkt) => {
                println!("[+] Worker {} packet constructed: {} bytes", worker_id, pkt.len());
                pkt
            }
            Err(e) => {
                println!("[!] Worker {} packet construction failed: {}", worker_id, e);
                continue;
            }
        };
        
        // Transmit packet with error handling
        match tx.send_to(&packet, None) {
            Some(Ok(_)) => {
                stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                stats.bytes_sent.fetch_add(packet.len(), Ordering::Relaxed);
                packet_count += 1;
                
                // Show every packet for debugging
                if packet_count % 10 == 0 {
                    println!("[+] Worker {}: Sent packet {} ({} bytes) to {}", 
                            worker_id, packet_count, packet.len(), target_ip);
                }
            }
            Some(Err(e)) => {
                stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                println!("[!] Worker {}: Packet {} failed: {}", worker_id, packet_count, e);
            }
            None => {
                stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                println!("[!] Worker {}: Network channel closed", worker_id);
                break;
            }
        }
        
        // Reduced rate limiting for more visible packets
        sleep(Duration::from_millis(100)).await;
    }
    
    info!("Packet worker {} completed: {} packets transmitted", worker_id, packet_count);
    Ok(())
}

/// Find a suitable network interface for packet transmission
/// Returns first non-loopback interface that is up and has a MAC address
fn find_suitable_interface(interface_name: &str) -> Result<pnet::datalink::NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    if interface_name != "auto" {
        if let Some(iface) = interfaces.iter().find(|iface| iface.name == interface_name) {
            println!("[+] Using specified interface: {} ({})", iface.name, iface.mac.unwrap_or_else(|| MacAddr::zero()));
            return Ok(iface.clone());
        }
        println!("[!] Interface {} not found, falling back to auto-detection", interface_name);
    }
    
    println!("[*] Available network interfaces:");
    for (i, iface) in interfaces.iter().enumerate() {
        println!("    {}: {} - UP: {}, MAC: {:?}", 
                 i, 
                 iface.name, 
                 iface.is_up(), 
                 iface.mac);
    }
    
    // Try to find the best interface
    if let Some(iface) = interfaces.iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.mac.is_some()) {
        println!("[+] Selected interface: {} - MAC: {:?}", iface.name, iface.mac);
        return Ok(iface.clone());
    }
    
    // Fallback to any interface with MAC
    for iface in interfaces {
        if iface.mac.is_some() {
            println!("[!] Using fallback interface: {} - MAC: {:?}", iface.name, iface.mac);
            return Ok(iface);
        }
    }
    
    Err(anyhow::anyhow!("No suitable network interface found - may need root privileges"))
}

/// Cached ARP resolution for efficient MAC address lookup
/// Reduces network overhead by caching resolved MAC addresses for 60 seconds
async fn resolve_target_mac_cached(target_ip: Ipv4Addr, interface: &pnet::datalink::NetworkInterface) -> Result<MacAddr> {
    // Check cache first
    {
        let cache = ARP_CACHE.lock().unwrap();
        if let Some((mac, timestamp)) = cache.get(&target_ip) {
            if timestamp.elapsed() < Duration::from_secs(60) {
                return Ok(*mac);
            }
        }
    }
    
    // Perform ARP resolution if not cached
    let mac = resolve_target_mac(target_ip, interface).await?;
    
    // Update cache
    {
        let mut cache = ARP_CACHE.lock().unwrap();
        cache.insert(target_ip, (mac, Instant::now()));
    }
    
    Ok(mac)
}

/// Perform ARP resolution to discover the MAC address of a target IP
/// Sends ARP requests and waits for responses with proper timeout handling
async fn resolve_target_mac(target_ip: Ipv4Addr, interface: &pnet::datalink::NetworkInterface) -> Result<MacAddr> {
    let source_mac = interface.mac
        .ok_or_else(|| anyhow::anyhow!("Interface MAC address not available"))?;
    let arp_packet = create_arp_request(target_ip, source_mac)?;
    
    // Create ARP communication channel
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => return Err(anyhow::anyhow!("Failed to create ARP communication channel")),
    };
    
    // Send ARP request
    if tx.send_to(&arp_packet, None).is_none() {
        return Err(anyhow::anyhow!("Failed to send ARP request"));
    }
    
    // Wait for ARP reply with timeout
    let timeout = Duration::from_secs(2);
    let start = Instant::now();
    
    while start.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if eth_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Arp {
                        if let Some(arp_packet) = pnet::packet::arp::ArpPacket::new(eth_packet.payload()) {
                            if arp_packet.get_sender_proto_addr() == target_ip {
                                return Ok(arp_packet.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
        sleep(Duration::from_millis(10)).await;
    }
    
    Err(anyhow::anyhow!("ARP resolution timeout - target may be unreachable"))
}

/// Create an ARP request packet for MAC address resolution
fn create_arp_request(target_ip: Ipv4Addr, source_mac: MacAddr) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; 42]; // Ethernet header (14) + ARP packet (28)
    
    // Ethernet header
    let mut eth_packet = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);
    
    // ARP header
    let mut arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut buffer[14..]).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet::packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(get_primary_interface_ip_raw());
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    
    Ok(buffer)
}

/// Get the primary IP address of the system
/// Returns the first non-loopback IPv4 address found
fn get_primary_interface_ip_raw() -> Ipv4Addr {
    for iface in datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback() {
            for ip in &iface.ips {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    return ipv4;
                }
            }
        }
    }
    // Fallback to localhost if no other interface found
    Ipv4Addr::new(127, 0, 0, 1)
}

/// Get the primary IP address of a specific interface
fn get_primary_interface_ip(interface: &pnet::datalink::NetworkInterface) -> Ipv4Addr {
    for ip in &interface.ips {
        if let std::net::IpAddr::V4(ipv4) = ip.ip() {
            return ipv4;
        }
    }
    // Fallback to localhost if no IP found
    Ipv4Addr::new(127, 0, 0, 1)
}

/// Generate a random IP address from the same subnet as the interface
/// Used for testing with varied source addresses within the local network
fn generate_local_subnet_ip(interface: &pnet::datalink::NetworkInterface, worker_id: usize) -> Ipv4Addr {
    if let Some(ip) = interface.ips.first() {
        if let std::net::IpAddr::V4(ipv4) = ip.ip() {
            let octets = ipv4.octets();
            // Generate IP in same subnet but different host portion
            let host_variation = (worker_id as u8 % 254) + 1; // Avoid 0 and 255
            return Ipv4Addr::new(octets[0], octets[1], octets[2], host_variation);
        }
    }
    
    // Fallback to private network range
    Ipv4Addr::new(192, 168, 1, 100 + (worker_id % 155) as u8)
}

/// Construct a complete ICMP packet with Ethernet, IPv4, and ICMP layers
/// Creates a properly formatted network packet for transmission
fn build_icmp_packet(
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_mac: MacAddr,
    packet_size: usize,
    icmp_type: u8,
) -> Result<Vec<u8>> {
    let icmp_header_size = 8;
    let ipv4_header_size = 20;
    let ethernet_header_size = 14;
    let payload_size = packet_size.saturating_sub(icmp_header_size);
    let total_size = ethernet_header_size + ipv4_header_size + icmp_header_size + payload_size;
    
    let mut buffer = vec![0u8; total_size];
    
    // Ethernet header (14 bytes)
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to create Ethernet packet"))?;
    eth_packet.set_destination(target_mac);
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    
    // IPv4 header (20 bytes) - use full remaining buffer
    let ipv4_offset = ethernet_header_size;
    let ipv4_packet_slice = &mut buffer[ipv4_offset..];
    let mut ipv4_packet = MutableIpv4Packet::new(ipv4_packet_slice)
        .ok_or_else(|| anyhow::anyhow!("Failed to create IPv4 packet"))?;
    
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((ipv4_header_size + icmp_header_size + payload_size) as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(target_ip);
    ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
    
    // ICMP header and payload - use remaining buffer after IPv4
    let icmp_offset = ipv4_offset + ipv4_header_size;
    let icmp_packet_slice = &mut buffer[icmp_offset..];
    let mut icmp_packet = MutableIcmpPacket::new(icmp_packet_slice)
        .ok_or_else(|| anyhow::anyhow!("Failed to create ICMP packet"))?;
    
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpType(icmp_type));
    icmp_packet.set_icmp_code(IcmpCode(0));
    
    // Add payload data if specified
    if payload_size > 0 {
        let payload: Vec<u8> = (0..payload_size)
            .map(|i| (i % 256) as u8)  // Simple pattern payload
            .collect();
        icmp_packet.set_payload(&payload);
    }
    
    // Calculate ICMP checksum
    icmp_packet.set_checksum(pnet::packet::icmp::checksum(&icmp_packet.to_immutable()));
    
    Ok(buffer)
} 
