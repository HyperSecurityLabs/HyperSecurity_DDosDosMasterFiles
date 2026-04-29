/// TCP Network Testing Suite
/// A comprehensive TCP port scanning and network diagnostics utility
/// for testing network security and validating server configurations.

use clap::Parser;
use pnet::datalink::{self};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket, MutableTcpPacket};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol};
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::time::sleep;
use tracing::{error, info, warn};
use rand::Rng;
use colored::Colorize;
use std::io::Write;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

/// Display professional Matrix-style banner with animated effects
async fn display_banner() {
    // Matrix rain effect simulation
    println!();
    for _ in 0..3 {
        let mut line = String::new();
        for _ in 0..70 {
            let chars = ['0', '1', '█', '▓', '▒', '░', '|', '/', '\\'];
            let ch = chars[rand::thread_rng().gen_range(0..chars.len())];
            line.push(ch);
        }
        println!("{}", line.bright_green());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════╗".bright_green().bold());
    println!("{}", "║                                                                       ║".bright_green());
    println!("{}", "║   ██╗██████╗  ██████╗ ███╗   ██╗██╗    ██╗██╗██████╗ ███████╗         ║".bright_white().bold());
    println!("{}", "║   ██║██╔══██╗██╔═══██╗████╗  ██║██║    ██║██║██╔══██╗██╔════╝         ║".bright_white().bold());
    println!("{}", "║   ██║██████╔╝██║   ██║██╔██╗ ██║██║ █╗ ██║██║██████╔╝█████╗           ║".bright_green().bold());
    println!("{}", "║   ██║██╔══██╗██║   ██║██║╚██╗██║██║███╗██║██║██╔══██╗██╔══╝           ║".bright_green());
    println!("{}", "║   ██║██║  ██║╚██████╔╝██║ ╚████║╚███╔███╔╝██║██║  ██║███████╗         ║".bright_green());
    println!("{}", "║   ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝         ║".bright_green());
    println!("{}", "║                                                                       ║".bright_green());
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Animated subtitle
    let subtitle = "    TCP PORT SCANNER & NETWORK PENETRATION FRAMEWORK    ";
    print!("{}", "║".bright_green());
    for ch in subtitle.chars() {
        print!("{}", ch.to_string().bright_white().bold());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(800)).await;
    }
    println!("{}", "║".bright_green());
    
    println!("{}", "║                                                                       ║".bright_green());
    println!("{}", "║  ┌─────────────────────────────────────────────────────────────────┐  ║".bright_green());
    println!("{}", "║  │ Version: 9.20.2091vproAlpha | Author: khaninkali              │ ║".bright_white());
    println!("{}", "║  │ Technology: Raw Socket | TCP/IP Stack | Multi-Scan Engine     │ ║".bright_cyan());
    println!("{}", "║  └─────────────────────────────────────────────────────────────────┘  ║".bright_green());
    println!("{}", "║                                                                       ║".bright_green());
    
    println!("{}", "║  ╔═══════════════════════════════════════════════════════════════╗    ║".bright_red().bold());
    println!("{}", "║  ║ WIRE MODE: Authorized network testing only                   ║     ║".bright_white());
    println!("{}", "║  ║ Requires root privileges for raw socket operations           ║     ║".bright_white());
    println!("{}", "║  ╚═══════════════════════════════════════════════════════════════╝    ║".bright_red().bold());
    
    println!("{}", "║                                                                       ║".bright_green());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════╝".bright_green().bold());
    println!();
    
    // Multi-stage initialization with progress bars
    let multi = MultiProgress::new();
    
    // Stage 1: Network Interface
    let pb1 = multi.add(ProgressBar::new(100));
    pb1.set_style(
        ProgressStyle::with_template("    {prefix:>20} [{bar:30.green/black}] {percent:>3}% {msg}")
            .unwrap()
            .progress_chars("█▓▒░ ")
    );
    pb1.set_prefix("⟦ INTERFACE ⟧".bright_green().to_string());
    
    // Stage 2: TCP Stack
    let pb2 = multi.add(ProgressBar::new(100));
    pb2.set_style(
        ProgressStyle::with_template("    {prefix:>20} [{bar:30.green/black}] {percent:>3}% {msg}")
            .unwrap()
            .progress_chars("█▓▒░ ")
    );
    pb2.set_prefix("⟦ TCP STACK ⟧".bright_green().to_string());
    
    // Stage 3: Scan Engine
    let pb3 = multi.add(ProgressBar::new(100));
    pb3.set_style(
        ProgressStyle::with_template("    {prefix:>20} [{bar:30.green/black}] {percent:>3}% {msg}")
            .unwrap()
            .progress_chars("█▓▒░ ")
    );
    pb3.set_prefix("⟦ SCAN ENGINE ⟧".bright_green().to_string());
    
    // Animate progress bars
    for i in 0..=100 {
        pb1.set_position(i);
        pb1.set_message(if i < 100 { "Loading...".bright_white().to_string() } else { "READY".bright_green().bold().to_string() });
        
        if i >= 30 {
            pb2.set_position(i - 30);
            pb2.set_message(if i < 100 { "Initializing...".bright_white().to_string() } else { "READY".bright_green().bold().to_string() });
        }
        
        if i >= 60 {
            pb3.set_position(i - 60);
            pb3.set_message(if i < 100 { "Calibrating...".bright_white().to_string() } else { "READY".bright_green().bold().to_string() });
        }
        
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    
    pb1.finish();
    pb2.finish();
    pb3.finish();
    
    println!();
    println!("{}", "    ▶ System Status: OPERATIONAL".bright_green().bold());
    println!("{}", "    ▶ All modules: ONLINE".bright_green().bold());
    println!();
    
    // Matrix-style closing effect
    for _ in 0..2 {
        let mut line = String::new();
        for _ in 0..70 {
            let chars = ['0', '1', '█', '▓', '▒', '░'];
            let ch = chars[rand::thread_rng().gen_range(0..chars.len())];
            line.push(ch);
        }
        println!("{}", line.bright_green());
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    println!();
}

#[derive(Parser)]
#[command(name = "tcp_network_tester")]
#[command(about = "TCP port scanning and network diagnostics testing suite")]
struct Args {
    #[arg(short, long, help = "Target IP address for testing")]
    target: String,
    
    #[arg(short, long, help = "Target port range (e.g., 1-65535 or 80,443,8080)")]
    ports: String,
    
    #[arg(short = 'c', long, default_value = "100", help = "Concurrent test connections")]
    connections: usize,
    
    #[arg(short, long, default_value = "120", help = "Test duration in seconds")]
    duration: u64,
    
    #[arg(long, default_value = "true", help = "Enable port scanning first")]
    scan_first: bool,
    
    #[arg(long, default_value = "false", help = "Enable source IP variation")]
    source_variation: bool,
    
    #[arg(long, default_value = "true", help = "Enable random source ports")]
    random_ports: bool,
    
    #[arg(long, default_value = "false", help = "Use specific network interface")]
    interface: Option<String>,
    
    #[arg(long, default_value = "syn", help = "Scan type: syn, connect, ack, fin, xmas")]
    scan_type: String,
    
    #[arg(long, default_value = "100", help = "Packet timeout in milliseconds")]
    timeout_ms: u64,
    
    #[arg(long, default_value = "comprehensive", help = "Test mode: scan, stress, comprehensive")]
    test_mode: String,
    
    #[arg(long, default_value = "true", help = "Enable TCP options randomization")]
    random_options: bool,
}

/// Common network service ports for testing
/// Contains frequently used service ports for comprehensive network testing
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017,
];

/// TCP scan type configurations
/// Contains TCP flag combinations for different scanning techniques
const SCAN_FLAGS: &[(&str, u8)] = &[
    ("syn", TcpFlags::SYN),
    ("connect", TcpFlags::SYN),
    ("ack", TcpFlags::ACK),
    ("fin", TcpFlags::FIN),
    ("xmas", TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG),
];

/// Statistics tracker for real-time monitoring
struct PacketStats {
    packets_sent: Arc<AtomicU64>,
    packets_failed: Arc<AtomicU64>,
    open_ports_found: Arc<AtomicUsize>,
    start_time: std::time::Instant,
}

impl PacketStats {
    fn new() -> Self {
        Self {
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_failed: Arc::new(AtomicU64::new(0)),
            open_ports_found: Arc::new(AtomicUsize::new(0)),
            start_time: std::time::Instant::now(),
        }
    }
    
    fn increment_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }
    
    fn increment_failed(&self) {
        self.packets_failed.fetch_add(1, Ordering::Relaxed);
    }
    
    fn add_open_port(&self) {
        self.open_ports_found.fetch_add(1, Ordering::Relaxed);
    }
    
    fn print_stats(&self) {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let failed = self.packets_failed.load(Ordering::Relaxed);
        let open_ports = self.open_ports_found.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let pps = if elapsed > 0.0 { sent as f64 / elapsed } else { 0.0 };
        
        // Clear line and print stats
        print!("\r{}", " ".repeat(100));
        print!("\r{} {} | {} {} | {} {} | {} {:.0} pps",
            "Sent:".bright_green(),
            sent.to_string().bright_white(),
            "Failed:".bright_red(),
            failed.to_string().bright_white(),
            "Open Ports:".bright_cyan(),
            open_ports.to_string().bright_yellow(),
            "Rate:".bright_magenta(),
            pps
        );
        std::io::stdout().flush().unwrap();
    }
}

/// Parse port specification string into port list
/// Converts various port formats (ranges, comma-separated, "common") into port vector
fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    
    if port_str == "common" {
        return COMMON_PORTS.to_vec();
    }
    
    for part in port_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for port in start..=end {
                        ports.push(port);
                    }
                }
            }
        } else {
            if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            }
        }
    }
    
    ports
}

/// Get TCP scan flags for specified scan type
/// Returns appropriate TCP flags for different scanning techniques
fn get_scan_flags(scan_type: &str) -> u8 {
    for (name, flags) in SCAN_FLAGS {
        if *name == scan_type {
            return *flags;
        }
    }
    TcpFlags::SYN
}

/// Generate test source IP address
/// Creates realistic source IP addresses for network testing
fn generate_test_source_ip() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    Ipv4Addr::new(
        rng.gen_range(1..255),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(1..255),
    )
}

/// Generate test source port
/// Creates realistic source ports for network testing
fn generate_test_source_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..65535)
}

/// Generate TCP options for testing
/// Creates realistic TCP option combinations for comprehensive testing
fn generate_tcp_options() -> Vec<u8> {
    let mut options = Vec::new();
    let mut rng = rand::thread_rng();
    
    // MSS (Maximum Segment Size) - Essential for TCP negotiation
    options.push(2); // Kind
    options.push(4); // Length
    let mss: u16 = rng.gen_range(536..1460);
    options.extend_from_slice(&mss.to_be_bytes());
    
    // Window Scale - Improves performance on high-latency networks
    if rng.gen_bool(0.7) {
        options.push(3); // Kind
        options.push(3); // Length
        options.push(rng.gen_range(0..14)); // Scale factor
    }
    
    // SACK Permitted - Enables selective acknowledgment
    if rng.gen_bool(0.8) {
        options.push(4); // Kind
        options.push(2); // Length
    }
    
    // Timestamp - Used for round-trip time measurement
    if rng.gen_bool(0.6) {
        options.push(8); // Kind
        options.push(10); // Length
        options.extend_from_slice(&rng.gen::<u32>().to_be_bytes()); // TS value
        options.extend_from_slice(&0u32.to_be_bytes()); // TS echo reply
    }
    
    // NOP padding - Ensures proper alignment
    while options.len() % 4 != 0 {
        options.push(1); // NOP
    }
    
    options
}

/// Build TCP packet for network testing
/// Constructs a complete TCP packet with Ethernet, IPv4, and TCP headers for testing
fn build_tcp_packet(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    flags: u8,
    interface_mac: MacAddr,
    target_mac: MacAddr,
    random_options: bool,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    
    // Calculate total packet size
    let tcp_options = if random_options {
        generate_tcp_options()
    } else {
        Vec::new()
    };
    
    let tcp_header_size = 20 + tcp_options.len();
    let total_size = 14 + 20 + tcp_header_size; // Ethernet + IPv4 + TCP
    
    let mut buffer = vec![0u8; total_size];
    
    // Build Ethernet header
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
        eth_packet.set_destination(target_mac);
        eth_packet.set_source(interface_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);
    }
    
    // Build IPv4 header
    let ipv4_offset = 14;
    {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer[ipv4_offset..ipv4_offset + 20 + tcp_header_size]).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((20 + tcp_header_size) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(dest_ip);
        
        // Calculate and set IP checksum
        ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
    }
    
    // Build TCP header
    let tcp_offset = ipv4_offset + 20;
    {
        // First, set TCP options in the buffer if present
        if !tcp_options.is_empty() {
            let options_offset = tcp_offset + 20;
            buffer[options_offset..options_offset + tcp_options.len()].copy_from_slice(&tcp_options);
        }
        
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[tcp_offset..]).unwrap();
        
        let sequence = rng.gen::<u32>();
        let window_size = rng.gen_range(8192..65535);
        
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(sequence);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(((20 + tcp_options.len()) / 4) as u8);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(window_size);
        
        // Calculate and set TCP checksum
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &source_ip,
            &dest_ip,
        );
        tcp_packet.set_checksum(checksum);
    }
    
    buffer
}

/// Perform TCP port scanning on target
/// Executes comprehensive port scanning using various TCP techniques to identify open ports
async fn perform_port_scanning(
    target_ip: Ipv4Addr,
    ports: &[u16],
    interface_mac: MacAddr,
    target_mac: MacAddr,
    scan_type: &str,
    random_options: bool,
    source_variation: bool,
    random_ports: bool,
    stats: Arc<PacketStats>,
) -> HashSet<u16> {
    let flags = get_scan_flags(scan_type);
    let mut open_ports = HashSet::new();
    
    println!();
    println!("{}", format!("[*] Starting {} scan on {} ports", scan_type, ports.len()).bright_cyan());
    println!();
    
    // Create transport channel for TCP with larger buffer
    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    
    let (mut tx, rx) = match transport_channel(65536, protocol) {  // Increased buffer size
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("{}", format!("[!] Failed to create transport channel: {}", e).bright_red());
            return open_ports;
        }
    };
    
    // Spawn receiver task to capture and parse responses
    let receiver_target_ip = target_ip;
    let receiver_ports: Vec<u16> = ports.to_vec();
    let scan_type_owned = scan_type.to_string();
    let stats_clone = Arc::clone(&stats);
    
    // Real receiver implementation that parses TCP responses
    let receiver_handle = tokio::spawn(async move {
        let mut detected_ports: HashSet<u16> = HashSet::new();
        let start_time = std::time::Instant::now();
        let timeout_duration = Duration::from_secs(5);
        
        // Use blocking task to handle the synchronous iterator
        let parse_result = tokio::task::spawn_blocking(move || {
            let mut local_detected: HashSet<u16> = HashSet::new();
            let mut rx = rx;
            
            // Create iterator for receiving packets
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            
            // Process incoming packets until timeout
            while start_time.elapsed() < timeout_duration {
                match iter.next_with_timeout(Duration::from_millis(100)) {
                    Ok(Some((packet, addr))) => {
                        // Check if packet is from target
                        if addr == receiver_target_ip {
                            // Parse TCP packet from IP payload
                            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                                let tcp_flags = tcp_packet.get_flags();
                                let src_port = tcp_packet.get_source();
                                
                                // Check if this port was in our scan list
                                if receiver_ports.contains(&src_port) {
                                    // SYN-ACK response indicates open port
                                    if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) != 0 {
                                        if local_detected.insert(src_port) {
                                            stats_clone.add_open_port();
                                        }
                                    }
                                    // ACK response (for ACK scan)
                                    else if (tcp_flags & TcpFlags::ACK) != 0 {
                                        // Port is unfiltered (for ACK scan type)
                                        if scan_type_owned == "ack" {
                                            if local_detected.insert(src_port) {
                                                stats_clone.add_open_port();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // No packet available, continue waiting
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        // Timeout or error, continue
                        continue;
                    }
                }
            }
            
            local_detected
        }).await;
        
        match parse_result {
            Ok(ports) => {
                detected_ports.extend(ports);
            }
            Err(e) => {
                eprintln!("{}", format!("[!] Scan receiver task failed: {}", e).bright_red());
            }
        }
        
        detected_ports
    });
    
    // Send scan packets to all ports with proper rate limiting
    let mut last_error_time = std::time::Instant::now();
    let mut consecutive_errors = 0u32;
    
    for &port in ports {
        let source_ip = if source_variation {
            generate_test_source_ip()
        } else {
            Ipv4Addr::new(192, 168, 1, 100)
        };
        
        let source_port = if random_ports {
            generate_test_source_port()
        } else {
            12345
        };
        
        let packet = build_tcp_packet(
            source_ip,
            target_ip,
            source_port,
            port,
            flags,
            interface_mac,
            target_mac,
            random_options,
        );
        
        // Send raw TCP packet with error handling
        match tx.send_to(TcpPacket::new(&packet).unwrap(), std::net::IpAddr::V4(target_ip)) {
            Ok(_) => {
                stats.increment_sent();
                consecutive_errors = 0;
            }
            Err(e) => {
                stats.increment_failed();
                consecutive_errors += 1;
                
                // Only log errors occasionally to avoid spam
                if last_error_time.elapsed() > Duration::from_secs(5) {
                    eprintln!();
                    eprintln!("{}", format!("[!] Send error ({}): {}", consecutive_errors, e).bright_yellow());
                    last_error_time = std::time::Instant::now();
                }
                
                // If too many consecutive errors, increase delay
                if consecutive_errors > 10 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    consecutive_errors = 0;
                }
            }
        }
        
        // Rate limiting: delay between packets to avoid buffer overflow
        tokio::time::sleep(Duration::from_millis(5)).await;
        
        // Update stats display every 50 packets
        if port % 50 == 0 {
            stats.print_stats();
        }
    }
    
    // Wait for responses
    println!();
    println!("{}", "[*] Waiting for responses...".bright_cyan());
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Get results from receiver
    match receiver_handle.await {
        Ok(scanned_ports) => {
            open_ports.extend(scanned_ports);
        }
        Err(e) => {
            eprintln!("{}", format!("[!] Scanner receiver failed: {}", e).bright_red());
        }
    }
    
    println!();
    stats.print_stats();
    println!();
    println!("{}", format!("[+] Scan completed. Found {} open ports", open_ports.len()).bright_green());
    
    if !open_ports.is_empty() {
        println!("{}", "[+] Open ports:".bright_green());
        let mut sorted_ports: Vec<_> = open_ports.iter().collect();
        sorted_ports.sort();
        for port in sorted_ports {
            println!("    {} {}", "→".bright_cyan(), port.to_string().bright_yellow());
        }
    }
    println!();
    
    open_ports
}

/// Execute comprehensive TCP network testing
/// Performs port scanning and stress testing for network security validation
async fn execute_tcp_network_testing(
    target_ip: Ipv4Addr,
    ports: &[u16],
    args: Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get network interface
    let interface_name = args.interface.unwrap_or_else(|| {
        datalink::interfaces()
            .iter()
            .find(|iface| iface.is_up() && !iface.ips.is_empty())
            .map(|iface| iface.name.clone())
            .unwrap_or_else(|| "eth0".to_string())
    });
    
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or(format!("Interface {} not found", interface_name))?;
    
    let mac = interface.mac.ok_or("No MAC address found")?;
    
    // Create transport channel for TCP with larger buffer
    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    
    let (mut tx, _) = match transport_channel(65536, protocol) {  // Increased buffer size
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Failed to create transport channel: {}", e).into()),
    };
    
    // Get target MAC (this would typically be done via ARP)
    let target_mac = MacAddr::new(0x00, 0x0c, 0x29, 0x3e, 0x8b, 0x6a); // Example - should be resolved via ARP
    
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                    TCP NETWORK TESTING CONFIGURATION                  ║".bright_white().bold());
    println!("{}", "╠═══════════════════════════════════════════════════════════════════════╣".bright_green());
    println!("{}  {}  {}", "║".bright_green(), "Target:".bright_cyan(), format!("{}", args.target).white());
    println!("{}  {}  {}", "║".bright_green(), "Port Range:".bright_cyan(), format!("{}", args.ports).white());
    println!("{}  {}  {}", "║".bright_green(), "Connections:".bright_cyan(), format!("{}", args.connections).white());
    println!("{}  {}  {}s", "║".bright_green(), "Duration:".bright_cyan(), args.duration.to_string().white());
    println!("{}  {}  {}", "║".bright_green(), "Source Variation:".bright_cyan(), 
        if args.source_variation { "ENABLED".green() } else { "DISABLED".red() });
    println!("{}  {}  {}", "║".bright_green(), "Scan Type:".bright_cyan(), format!("{}", args.scan_type).white());
    println!("{}  {}  {}", "║".bright_green(), "Test Mode:".bright_cyan(), format!("{}", args.test_mode).white());
    println!("{}  {}  {}", "║".bright_green(), "Interface:".bright_cyan(), interface_name.white());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════╝".bright_green());
    println!();
    
    let stats = Arc::new(PacketStats::new());
    let mut open_ports = HashSet::new();
    
    // Phase 1: Port scanning
    if args.scan_first || args.test_mode == "scan" {
        open_ports = perform_port_scanning(
            target_ip,
            ports,
            mac,
            target_mac,
            &args.scan_type,
            args.random_options,
            args.source_variation,
            args.random_ports,
            Arc::clone(&stats),
        ).await;
        
        if args.test_mode == "scan" {
            return Ok(());
        }
    }
    
    // Phase 2: Stress testing
    if args.test_mode == "stress" || args.test_mode == "comprehensive" {
        let target_ports = if open_ports.is_empty() {
            ports.to_vec()
        } else {
            open_ports.into_iter().collect()
        };
        
        println!("{}", format!("[*] Starting stress testing on {} ports", target_ports.len()).bright_cyan());
        println!();
        
        // Reset stats for stress test
        let stress_stats = Arc::new(PacketStats::new());
        let stats_clone = Arc::clone(&stress_stats);
        
        // Spawn stats display task
        let stats_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                stats_clone.print_stats();
            }
        });
        
        let start_time = std::time::Instant::now();
        let mut last_error_time = std::time::Instant::now();
        let mut consecutive_errors = 0u32;
        
        while start_time.elapsed().as_secs() < args.duration {
            for &port in &target_ports {
                // Limit concurrent connections to avoid buffer overflow
                for _ in 0..std::cmp::min(args.connections, 10) {
                    let source_ip = if args.source_variation {
                        generate_test_source_ip()
                    } else {
                        Ipv4Addr::new(192, 168, 1, 100)
                    };
                    
                    let source_port = if args.random_ports {
                        generate_test_source_port()
                    } else {
                        12345
                    };
                    
                    let packet = build_tcp_packet(
                        source_ip,
                        target_ip,
                        source_port,
                        port,
                        TcpFlags::SYN,
                        mac,
                        target_mac,
                        args.random_options,
                    );
                    
                    match tx.send_to(TcpPacket::new(&packet).unwrap(), std::net::IpAddr::V4(target_ip)) {
                        Ok(_) => {
                            stress_stats.increment_sent();
                            consecutive_errors = 0;
                        }
                        Err(_) => {
                            stress_stats.increment_failed();
                            consecutive_errors += 1;
                            
                            // If too many errors, slow down significantly
                            if consecutive_errors > 20 {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                consecutive_errors = 0;
                                
                                if last_error_time.elapsed() > Duration::from_secs(10) {
                                    eprintln!();
                                    eprintln!("{}", "[!] High error rate detected - reducing send rate".bright_yellow());
                                    last_error_time = std::time::Instant::now();
                                }
                            }
                        }
                    }
                    
                    // Critical: Rate limiting to prevent buffer overflow
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            
            // Additional delay between port cycles
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        stats_task.abort();
        
        println!();
        println!();
        stress_stats.print_stats();
        println!();
        println!("{}", "[+] TCP network testing completed".bright_green().bold());
        println!();
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    
    // Display Matrix-style banner
    display_banner().await;
    
    let args = Args::parse();
    
    // Check for root privileges required for raw socket access
    let is_root = unsafe { libc::getuid() == 0 };
    
    if is_root {
        println!("[+] Running with root privileges - required for raw socket access");
    } else {
        eprintln!("[!] This tool requires root privileges for raw socket access");
        eprintln!("[!] Please run with sudo: sudo {} {}", 
                 std::env::args().next().unwrap(), 
                 std::env::args().skip(1).collect::<Vec<_>>().join(" "));
        return Ok(());
    }
    
    let target_ip: Ipv4Addr = args.target.parse()?;
    let ports = parse_ports(&args.ports);
    
    if ports.is_empty() {
        eprintln!("[!] No valid ports specified");
        return Ok(());
    }
    
    if let Err(e) = execute_tcp_network_testing(target_ip, &ports, args).await {
        error!("TCP network testing failed: {}", e);
        return Err(e);
    }
    
    Ok(())
}
