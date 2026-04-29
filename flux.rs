/// WebRTC Protocol Testing Suite
/// A comprehensive WebRTC network diagnostics and testing utility
/// for validating WebRTC server implementations and network connectivity.

use clap::{Arg, Command};
use std::net::{SocketAddr, UdpSocket, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{info, warn};
use url::Url;
use sha2::{Sha256, Digest};
use crc::{Crc, CRC_32_ISCSI};
use rand::Rng;
use colored::Colorize;
use std::io::Write;

/// Display professional banner with typewriter effect
async fn display_banner() {
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Title with typewriter effect
    let title = "    ███████╗██╗     ██╗   ██╗██╗  ██╗";
    for ch in title.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(800)).await;
    }
    println!();
    
    let title2 = "    ██╔════╝██║     ██║   ██║╚██╗██╔╝";
    for ch in title2.chars() {
        print!("{}", ch.to_string().bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(800)).await;
    }
    println!();
    
    println!("{}", "    █████╗  ██║     ██║   ██║ ╚███╔╝ ".bright_yellow());
    println!("{}", "    ██╔══╝  ██║     ██║   ██║ ██╔██╗ ".bright_yellow());
    println!("{}", "    ██║     ███████╗╚██████╔╝██╔╝ ██╗".bright_green());
    println!("{}", "    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝".bright_green());
    
    println!();
    println!("{}", "         WEBRTC PROTOCOL TESTING & DIAGNOSTICS SUITE         ".bright_magenta().bold());
    tokio::time::sleep(Duration::from_millis(100)).await;
    
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
        "Purpose: WebRTC Server Testing & Network Analysis               ".bright_green(),
        "│".bright_cyan()
    );
    println!("{}", "    │                                                                     │".bright_cyan());
    println!("{}", "    └─────────────────────────────────────────────────────────────────────┘".bright_cyan());
    
    println!();
    println!("{}", "    ╔═══════════════════════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "    ║  WARNING: For authorized testing and diagnostics only             ║".bright_white());
    println!("{}", "    ║  Unauthorized testing may violate terms of service                ║".bright_white());
    println!("{}", "    ╚═══════════════════════════════════════════════════════════════════╝".bright_red().bold());
    
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Typewriter initialization
    print!("{}", "    Initializing WebRTC framework".bright_white());
    std::io::stdout().flush().unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
    }
    println!(" {}", "READY".bright_green().bold());
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Display banner first
    display_banner().await;
    let matches = Command::new("WebRTC Protocol Tester")
        .version("9.20.2091vproAlpha")
        .about("WebRTC Network Diagnostics and Protocol Testing Suite")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("URL")
                .help("Target WebRTC server URL for testing")
                .required(true),
        )
        .arg(
            Arg::new("connections")
                .short('c')
                .long("connections")
                .value_name("COUNT")
                .help("Number of concurrent WebRTC test connections")
                .default_value("10"),
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
            Arg::new("data_channels")
                .short('D')
                .long("data-channels")
                .value_name("COUNT")
                .help("Data channels per connection for testing")
                .default_value("5"),
        )
        .arg(
            Arg::new("ice_servers")
                .short('i')
                .long("ice-servers")
                .value_name("URLS")
                .help("ICE servers for NAT traversal (comma separated)")
                .default_value("stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302"),
        )
        .get_matches();

    // Parse and validate command line arguments
    let target = matches.get_one::<String>("target").unwrap();
    let connections: usize = matches.get_one::<String>("connections").unwrap().parse()?;
    let duration: u64 = matches.get_one::<String>("duration").unwrap().parse()?;
    let data_channels: usize = matches.get_one::<String>("data_channels").unwrap().parse()?;
    let ice_servers = matches.get_one::<String>("ice_servers").unwrap();

    tracing_subscriber::fmt::init();
    
    info!("[+] WebRTC Protocol Tester v9.20.2091vproAlpha");
    info!("[+] Target: {}", target);
    info!("[+] Test Connections: {}, Duration: {}s, Data Channels: {}", 
          connections, duration, data_channels);

    // Initialize WebRTC test workers
    let target_url = target.clone();
    let ice_servers = ice_servers.clone();
    let mut handles = vec![];

    // Spawn concurrent WebRTC testing workers
    for i in 0..connections {
        let target_url = target_url.clone();
        let ice_servers = ice_servers.clone();
        let data_channels = data_channels;

        let handle = tokio::spawn(async move {
            if let Err(e) = webrtc_test_worker(i, target_url, ice_servers, data_channels, duration).await {
                warn!("Test worker {} failed: {}", i, e);
            }
        });

        handles.push(handle);
    }

    // Wait for all test workers to complete
    for handle in handles {
        handle.await?;
    }

    info!("[+] WebRTC protocol testing completed successfully");
    Ok(())
}

/// WebRTC protocol testing worker
/// Handles WebRTC packet generation, STUN binding, and data channel testing
async fn webrtc_test_worker(
    worker_id: usize,
    target_url: String,
    ice_servers: String,
    data_channels_per_connection: usize,
    test_duration: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start_time = std::time::Instant::now();
    let mut packets_sent = 0;
    
    // Attempt STUN binding to discover public IP address
    let public_ip = match discover_public_ip(&ice_servers).await {
        Ok(ip) => {
            info!("Worker {}: Discovered public IP: {}", worker_id, ip);
            ip
        }
        Err(e) => {
            // Fall back to local IP discovery
            let fallback_ip = get_local_ip_address().unwrap_or_else(|| {
                warn!("Worker {}: Local IP discovery failed, using default", worker_id);
                "192.168.1.100".to_string()
            });
            warn!("Worker {}: STUN binding failed ({}), using local IP: {}", worker_id, e, fallback_ip);
            fallback_ip
        }
    };

    info!("Worker {}: Starting WebRTC protocol test", worker_id);

    // Main testing loop
    while start_time.elapsed().as_secs() < test_duration {
        // Test each data channel
        for channel_idx in 0..data_channels_per_connection {
            let test_packets = generate_webrtc_test_packets(channel_idx, &target_url, &public_ip);
            
            // Send packets to standard WebRTC ports
            let test_ports = vec![5000 + (channel_idx as u16) * 2, 3478, 5349];
            
            for packet in test_packets {
                for &port in &test_ports {
                    // Create UDP socket for packet transmission
                    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                        let target_addr = format!("{}:{}", extract_host_from_url(&target_url), port);
                        
                        if let Ok(addr) = target_addr.parse::<SocketAddr>() {
                            match socket.send_to(&packet, &addr) {
                                Ok(bytes_sent) => {
                                    packets_sent += 1;
                                    // Progress reporting every 100 packets
                                    if packets_sent % 100 == 0 {
                                        info!("Worker {}: Channel {} - {} packets transmitted to port {}", 
                                              worker_id, channel_idx, packets_sent, port);
                                    }
                                }
                                Err(send_err) => {
                                    warn!("Worker {}: Packet transmission failed to {} - {}", 
                                          worker_id, addr, send_err);
                                }
                            }
                        }
                    }
                    
                    // Small delay between packets
                    sleep(Duration::from_millis(10)).await;
                }
            }
            
            // Channel-level delay
            sleep(Duration::from_millis(50)).await;
        }
        
        // Test iteration delay
        sleep(Duration::from_millis(200)).await;
    }

    info!("Worker {}: Test completed. Total packets transmitted: {}", worker_id, packets_sent);
    Ok(())
}

/// Discover public IP address using STUN protocol
/// Attempts to bind to STUN servers to determine external IP
async fn discover_public_ip(ice_servers: &str) -> Result<String, String> {
    let server_list: Vec<&str> = ice_servers.split(',').collect();
    
    for server in server_list {
        if let Some(stun_host) = server.strip_prefix("stun:") {
            // Create UDP socket for STUN communication
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    // Parse STUN server address with proper port handling
                    let stun_addr = if stun_host.contains(':') {
                        stun_host.to_string()
                    } else {
                        format!("{}:3478", stun_host)
                    };
                    
                    // Resolve hostname to IP addresses
                    match stun_addr.to_socket_addrs() {
                        Ok(mut addresses) => {
                            if let Some(addr) = addresses.next() {
                                info!("Resolved STUN server: {} -> {}", stun_host, addr);
                                
                                // Construct STUN binding request
                                let mut stun_request = vec![0u8; 20];
                                stun_request[0] = 0x00; // Message type: Binding Request
                                stun_request[1] = 0x01;
                                stun_request[2] = 0x00; // Message length high byte
                                stun_request[3] = 0x0c; // Message length low byte
                                stun_request[4] = 0x21; // Magic cookie
                                stun_request[5] = 0x12;
                                stun_request[6] = 0xa4;
                                stun_request[7] = 0x42;
                                
                                // Generate random transaction ID
                                for byte_idx in 8..20 {
                                    stun_request[byte_idx] = rand::random::<u8>();
                                }
                                
                                // Send STUN request and wait for response
                                if let Ok(_) = socket.set_read_timeout(Some(Duration::from_secs(3))) {
                                    if let Ok(_) = socket.send_to(&stun_request, &addr) {
                                        let mut response_buffer = [0u8; 1024];
                                        match socket.recv_from(&mut response_buffer) {
                                            Ok((response_len, _)) => {
                                                if response_len >= 28 {
                                                    // Parse STUN response for XOR-MAPPED-ADDRESS attribute
                                                    for attr_idx in (20..response_len-4).step_by(4) {
                                                        if response_buffer[attr_idx] == 0x00 && response_buffer[attr_idx+1] == 0x20 {
                                                            // Found XOR-MAPPED-ADDRESS attribute
                                                            let port = u16::from_be_bytes([
                                                                response_buffer[attr_idx+6], 
                                                                response_buffer[attr_idx+7]
                                                            ]) ^ 0x2112;
                                                            
                                                            let ip = u32::from_be_bytes([
                                                                response_buffer[attr_idx+8] ^ 0x21,
                                                                response_buffer[attr_idx+9] ^ 0x12,
                                                                response_buffer[attr_idx+10] ^ 0xa4,
                                                                response_buffer[attr_idx+11] ^ 0x42
                                                            ]);
                                                            
                                                            let ip_string = format!("{}.{}.{}.{}", 
                                                                (ip >> 24) & 0xff,
                                                                (ip >> 16) & 0xff,
                                                                (ip >> 8) & 0xff,
                                                                ip & 0xff
                                                            );
                                                            
                                                            info!("STUN response received: {}:{}", ip_string, port);
                                                            return Ok(ip_string);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                warn!("STUN response timeout from server {}", addr);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(resolve_err) => {
                            warn!("Failed to resolve STUN server address {}: {}", stun_host, resolve_err);
                        }
                    }
                }
                Err(socket_err) => {
                    warn!("Failed to create UDP socket for STUN: {}", socket_err);
                }
            }
        }
    }
    
    Err("All STUN servers failed to respond".to_string())
}

/// Calculate CRC32 checksum for STUN fingerprint attribute
/// Uses ISCSI polynomial and XOR with STUN magic string
fn calculate_stun_fingerprint(data: &[u8]) -> u32 {
    let crc_engine = Crc::<u32>::new(&CRC_32_ISCSI);
    let mut digest = crc_engine.digest();
    digest.update(data);
    digest.finalize() ^ 0x5354554e // XOR with "STUN" ASCII values
}

/// Calculate CRC32C checksum for SCTP packets
/// Standard SCTP checksum using ISCSI polynomial
fn calculate_sctp_checksum(data: &[u8]) -> u32 {
    let crc_engine = Crc::<u32>::new(&CRC_32_ISCSI);
    let mut digest = crc_engine.digest();
    digest.update(data);
    digest.finalize()
}

/// Discover local IP address using UDP socket technique
/// Creates a UDP socket and connects to external address to determine local IP
fn get_local_ip_address() -> Option<String> {
    use std::net::IpAddr;
    
    // Create UDP socket and connect to external address
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            match socket.connect("8.8.8.8:80") {
                Ok(_) => {
                    match socket.local_addr() {
                        Ok(local_addr) => {
                            match local_addr.ip() {
                                IpAddr::V4(ipv4) => Some(ipv4.to_string()),
                                IpAddr::V6(_) => None, // We only support IPv4 for WebRTC testing
                            }
                        }
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

/// Generate comprehensive WebRTC test packet suite
/// Creates packets for STUN, ICE, SCTP, RTP, and DTLS protocol testing
fn generate_webrtc_test_packets(channel_id: usize, target_url: &str, public_ip: &str) -> Vec<Vec<u8>> {
    let mut packet_suite = Vec::new();
    
    // Add STUN binding request for connectivity testing
    packet_suite.push(build_stun_binding_request());
    
    // Add ICE candidate in SDP format for signaling testing
    packet_suite.push(build_ice_candidate_sdp(public_ip));
    
    // Add SCTP data chunk for WebRTC data channel testing
    packet_suite.push(build_sctp_data_chunk(channel_id as u16, b"WebRTC-test-data"));
    
    // Add RTP packet with Opus payload for media testing
    packet_suite.push(build_rtp_packet(96, generate_opus_audio_payload()));
    
    // Add DTLS ClientHello with certificate fingerprint for security testing
    packet_suite.push(build_dtls_client_hello(public_ip));
    
    packet_suite
}

/// Build ICE candidate in SDP format for WebRTC signaling
/// Generates a proper ICE candidate line according to RFC 5245
fn build_ice_candidate_sdp(public_ip: &str) -> Vec<u8> {
    let mut sdp_buffer = Vec::new();
    
    // ICE candidate attributes following RFC 5245
    let foundation = 1;
    let component_id = 1;
    let transport_protocol = "UDP";
    let priority_value = 2130706431; // (126 << 24) | (65535 << 8) | 255
    let port_number = 54400 + (rand::thread_rng().gen::<u16>() % 1000);
    let candidate_type = "host";
    let generation_id = 0;
    
    // Construct SDP candidate line according to specification
    let candidate_line = format!(
        "a=candidate:{} {} {} {} {} {} typ {} generation {}\r\n",
        foundation, component_id, transport_protocol, priority_value, 
        public_ip, port_number, candidate_type, generation_id
    );
    
    sdp_buffer.extend_from_slice(candidate_line.as_bytes());
    sdp_buffer
}

/// Build DTLS ClientHello message with certificate fingerprint
/// Constructs a proper DTLS handshake message for WebRTC security testing
fn build_dtls_client_hello(public_ip: &str) -> Vec<u8> {
    let mut dtls_packet = Vec::new();
    
    // DTLS Record Layer Header (RFC 4347)
    dtls_packet.push(0x16); // Content type: Handshake
    dtls_packet.push(0xfe); // DTLS 1.2 major version
    dtls_packet.push(0xfd); // DTLS 1.2 minor version
    dtls_packet.extend_from_slice(&[0x00, 0x00]); // Epoch (0 for initial handshake)
    
    // DTLS sequence number (6 bytes, monotonically increasing)
    static DTLS_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq_num = DTLS_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let seq_bytes = seq_num.to_be_bytes();
    dtls_packet.extend_from_slice(&seq_bytes[2..8]); // Use last 6 bytes
    
    // Length placeholder (will be updated)
    dtls_packet.extend_from_slice(&[0x00, 0x00]);
    
    // Handshake Message Header
    dtls_packet.push(0x01); // Message type: ClientHello
    dtls_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Length (placeholder)
    dtls_packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // Message sequence
    dtls_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Fragment offset
    dtls_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Fragment length (placeholder)
    
    // ClientHello Body (RFC 5246)
    dtls_packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 version
    dtls_packet.extend_from_slice(&rand::thread_rng().gen::<[u8; 32]>()); // Random (32 bytes)
    dtls_packet.extend_from_slice(&[0x00]); // Session ID length (0 = no session ID)
    
    // Cipher Suites (WebRTC preferred order according to RFC 8172)
    dtls_packet.extend_from_slice(&[0x00, 0x08]); // Cipher suites length (8 bytes)
    dtls_packet.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    dtls_packet.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
    dtls_packet.extend_from_slice(&[0xc0, 0x2c]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    dtls_packet.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    
    // Compression Methods
    dtls_packet.extend_from_slice(&[0x01, 0x00]); // Only null compression
    
    // Extensions
    let extensions_start = dtls_packet.len();
    dtls_packet.extend_from_slice(&[0x00, 0x00]); // Extensions length (placeholder)
    
    // supported_versions extension (RFC 8446)
    dtls_packet.extend_from_slice(&[0x00, 0x2b]); // supported_versions
    dtls_packet.extend_from_slice(&[0x00, 0x04]); // Length
    dtls_packet.extend_from_slice(&[0x02, 0x00]); // Versions length
    dtls_packet.extend_from_slice(&[0x03, 0x04]); // DTLS 1.3
    
    // use_srtp extension (RFC 5764)
    dtls_packet.extend_from_slice(&[0x00, 0x05]); // use_srtp
    dtls_packet.extend_from_slice(&[0x00, 0x04]); // Length
    dtls_packet.extend_from_slice(&[0x00, 0x02]); // SRTP protection profile list length
    dtls_packet.extend_from_slice(&[0xae, 0xcc]); // SRTP_AES128_CM_HMAC_SHA1_80
    
    // fingerprint extension (RFC 8122)
    dtls_packet.extend_from_slice(&[0x00, 0x0e]); // fingerprint
    let fingerprint_start = dtls_packet.len();
    dtls_packet.extend_from_slice(&[0x00, 0x00]); // Length (placeholder)
    dtls_packet.extend_from_slice(&[0x00, 0x01]); // Hash algorithm length
    dtls_packet.push(0x02); // sha-256
    dtls_packet.extend_from_slice(&[0x00, 0x20]); // Certificate fingerprint length (32 bytes for SHA-256)
    
    // Generate SHA-256 certificate fingerprint based on public IP
    let mut cert_hasher = Sha256::new();
    cert_hasher.update(format!("WebRTC-Cert-{}", public_ip).as_bytes());
    let fingerprint_result = cert_hasher.finalize();
    dtls_packet.extend_from_slice(&fingerprint_result);
    
    // Update fingerprint length
    let fingerprint_len = dtls_packet.len() - fingerprint_start - 2;
    dtls_packet[fingerprint_start..fingerprint_start + 2]
        .copy_from_slice(&(fingerprint_len as u16).to_be_bytes());
    
    // Update extensions length
    let extensions_len = dtls_packet.len() - extensions_start - 2;
    dtls_packet[extensions_start..extensions_start + 2]
        .copy_from_slice(&(extensions_len as u16).to_be_bytes());
    
    // Update handshake fragment length
    let handshake_len = dtls_packet.len() - 22; // Subtract record header (13) + handshake header (9)
    dtls_packet[19..22].copy_from_slice(&(handshake_len as u32).to_be_bytes()[1..4]);
    
    // Update record length
    let record_len = dtls_packet.len() - 13; // Subtract record header
    dtls_packet[11..13].copy_from_slice(&(record_len as u16).to_be_bytes());
    
    dtls_packet
}

/// Build STUN binding request for NAT traversal testing
/// Constructs a proper STUN message according to RFC 5389
fn build_stun_binding_request() -> Vec<u8> {
    let mut stun_packet = Vec::new();
    
    // STUN Message Header (RFC 5389 Section 6)
    stun_packet.extend_from_slice(&0x0001u16.to_be_bytes()); // Message Type: Binding Request (0x0001)
    stun_packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Message Length (will be updated)
    stun_packet.extend_from_slice(&0x2112a442u32.to_be_bytes()); // Magic Cookie
    
    // Transaction ID (12 bytes) - must be unique per request
    let timestamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    stun_packet.extend_from_slice(&timestamp_nanos.to_be_bytes());
    stun_packet.extend_from_slice(&rand::thread_rng().gen::<u32>().to_be_bytes());
    
    // Add PRIORITY attribute for ICE (RFC 5389 Section 18.2)
    stun_packet.extend_from_slice(&0x0024u16.to_be_bytes()); // PRIORITY attribute type
    stun_packet.extend_from_slice(&0x0004u16.to_be_bytes()); // Attribute length (4 bytes)
    stun_packet.extend_from_slice(&0x6e000001u32.to_be_bytes()); // Priority: (type=host << 24) | (local pref << 8) | component ID
    
    // Add SOFTWARE attribute (RFC 5389 Section 18.3)
    let software_name = b"WebRTC-TestSuite";
    stun_packet.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE attribute type
    stun_packet.extend_from_slice(&(software_name.len() as u16).to_be_bytes()); // Attribute length
    stun_packet.extend_from_slice(software_name); // Software name
    
    // Add FINGERPRINT attribute with real CRC32 calculation (RFC 5389 Section 15.5)
    stun_packet.extend_from_slice(&0x8028u16.to_be_bytes()); // FINGERPRINT attribute type
    stun_packet.extend_from_slice(&0x0004u16.to_be_bytes()); // Attribute length (4 bytes)
    
    // Calculate CRC32 of STUN message (excluding fingerprint attribute itself)
    let fingerprint_value = calculate_stun_fingerprint(&stun_packet);
    stun_packet.extend_from_slice(&fingerprint_value.to_be_bytes());
    
    // Update message length field
    let message_length = (stun_packet.len() - 20) as u16; // Subtract header size
    stun_packet[2..4].copy_from_slice(&message_length.to_be_bytes());
    
    stun_packet
}

/// Build SCTP DATA chunk for WebRTC data channel testing
/// Constructs a proper SCTP packet according to RFC 4960
fn build_sctp_data_chunk(channel_id: u16, data: &[u8]) -> Vec<u8> {
    let mut sctp_packet = Vec::new();
    
    // SCTP Common Header (RFC 4960 Section 3.1)
    sctp_packet.extend_from_slice(&5000u16.to_be_bytes()); // Source Port (WebRTC data channel)
    sctp_packet.extend_from_slice(&5000u16.to_be_bytes()); // Destination Port
    
    // Generate verification tag based on channel ID and timestamp
    let verification_tag = {
        let timestamp_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        timestamp_seconds ^ (channel_id as u32).wrapping_mul(0x9e3779b9)
    };
    sctp_packet.extend_from_slice(&verification_tag.to_be_bytes()); // Verification Tag
    sctp_packet.extend_from_slice(&0x00000000u32.to_be_bytes()); // Checksum (will be calculated)
    
    // DATA Chunk (RFC 4960 Section 3.3.1)
    sctp_packet.push(0x00); // Chunk type: DATA (0)
    sctp_packet.push(0x03); // Chunk flags: E-bit (End), B-bit (Beginning), U-bit (Unordered)
    let chunk_length = 16 + data.len() as u16;
    sctp_packet.extend_from_slice(&chunk_length.to_be_bytes()); // Chunk length
    sctp_packet.extend_from_slice(&rand::thread_rng().gen::<u32>().to_be_bytes()); // TSN (Transmission Sequence Number)
    sctp_packet.extend_from_slice(&channel_id.to_be_bytes()); // Stream Identifier (data channel ID)
    sctp_packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Stream Sequence Number
    sctp_packet.extend_from_slice(&0x00000050u32.to_be_bytes()); // Payload Protocol Identifier (WebRTC Data Channel)
    
    // User Data (WebRTC Data Channel payload)
    sctp_packet.extend_from_slice(data);
    
    // Calculate SCTP CRC32C checksum (RFC 3309)
    let checksum_value = calculate_sctp_checksum(&sctp_packet);
    sctp_packet[8..12].copy_from_slice(&checksum_value.to_be_bytes());
    
    sctp_packet
}

/// Build RTP packet for WebRTC media testing
/// Constructs a proper RTP packet according to RFC 3550
fn build_rtp_packet(payload_type: u8, payload_data: Vec<u8>) -> Vec<u8> {
    let mut rtp_packet = Vec::new();
    
    // RTP Header (RFC 3550 Section 5.1)
    let version = 2; // RTP version (2)
    let padding = 0; // Padding bit (0 = no padding)
    let extension = 0; // Extension bit (0 = no extension)
    let csrc_count = 0; // CSRC count (0 = no CSRC)
    let marker = 1; // Marker bit (1 = first packet in frame)
    
    // First byte: V(2) + P(1) + X(1) + CC(4)
    rtp_packet.push((version << 6) | (padding << 5) | (extension << 4) | csrc_count);
    
    // Second byte: M(1) + PT(7)
    rtp_packet.push((marker << 7) | payload_type);
    
    // Sequence number (16 bits, incrementing per SSRC)
    static RTP_SEQUENCE: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let seq_num = RTP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    rtp_packet.extend_from_slice(&seq_num.to_be_bytes());
    
    // Timestamp (32 bits, 90kHz clock for audio/video)
    let timestamp = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() * 90) as u32; // 90kHz clock rate
    rtp_packet.extend_from_slice(&timestamp.to_be_bytes());
    
    // SSRC (32 bits, random per session but consistent)
    static RTP_SSRC: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let ssrc = RTP_SSRC.load(std::sync::atomic::Ordering::SeqCst);
    if ssrc == 0 {
        let new_ssrc = rand::thread_rng().gen::<u32>();
        RTP_SSRC.store(new_ssrc, std::sync::atomic::Ordering::SeqCst);
        rtp_packet.extend_from_slice(&new_ssrc.to_be_bytes());
    } else {
        rtp_packet.extend_from_slice(&ssrc.to_be_bytes());
    }
    
    // Payload data
    rtp_packet.extend_from_slice(&payload_data);
    
    rtp_packet
}

/// Generate Opus audio payload for RTP testing
/// Creates a realistic Opus frame according to RFC 6716
fn generate_opus_audio_payload() -> Vec<u8> {
    let mut opus_payload = Vec::new();
    
    // Opus TOC (Table of Contents) byte (RFC 6716 Section 3.1)
    // Bits: 7-5: config (4 = 20ms frame), 4-3: stereo mode (0 = mono), 2-0: frame count
    opus_payload.push(0x4c); // Config 4 (20ms), mono, 1 frame
    
    // Generate realistic Opus audio frame (compressed audio data)
    // Real Opus frames vary in size based on complexity and bitrate
    // This simulates a typical 20ms frame at 64kbps
    let frame_size = 40 + (rand::thread_rng().gen::<u8>() % 10); // Variable frame size 40-50 bytes
    
    for sample_idx in 0..frame_size {
        // Simulate compressed audio data with realistic entropy patterns
        let audio_sample = ((sample_idx as f32 * 0.1).sin() * 127.0) as u8;
        let compression_noise = rand::thread_rng().gen::<u8>() % 32;
        opus_payload.push(audio_sample ^ compression_noise);
    }
    
    opus_payload
}

/// Extract hostname from URL for WebRTC testing
/// Parses URL and returns the host component for target resolution
fn extract_host_from_url(url_string: &str) -> String {
    match Url::parse(url_string) {
        Ok(parsed_url) => {
            parsed_url.host_str()
                .unwrap_or("localhost")
                .to_string()
        }
        Err(_) => {
            // Fallback parsing for malformed URLs
            url_string
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string()
        }
    }
}
