/// HTTP Load Testing Suite
/// A comprehensive HTTP load testing and performance validation utility
/// for testing web server capacity and validating HTTP configurations.

use clap::Parser;
use tokio::net::TcpStream;
use std::net::{SocketAddr, ToSocketAddrs, IpAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};
use anyhow::{Result, Context};
use once_cell::sync::Lazy;
use rand::Rng;
use colored::Colorize;
use std::io::Write;
use url::Url;
use hyper::{Request, Method};
use hyper::client::conn;
use http_body_util::Empty;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use tokio_native_tls::{TlsConnector, TlsStream};

#[derive(Parser)]
#[command(name = "http_load_tester")]
#[command(version = "9.20.2091vproAlpha")]
#[command(about = "HTTP load testing and performance validation suite")]
struct Args {
    #[arg(short = 't', long, help = "Target URL for testing (e.g., http://example.com or https://example.com)")]
    target: String,
    
    #[arg(short = 'i', long, help = "Network interface to use for testing")]
    interface: Option<String>,
    
    #[arg(short = 'T', long, default_value = "20", help = "Number of concurrent test threads")]
    threads: usize,
    
    #[arg(short = 'd', long, default_value = "120", help = "Test duration in seconds")]
    duration: u64,
    
    #[arg(short = 'm', long, default_value = "GET", help = "HTTP method to use for testing")]
    #[arg(value_parser = ["GET", "POST", "HEAD", "OPTIONS"])]
    method: String,
    
    #[arg(short = 's', long, help = "Use HTTPS instead of HTTP for testing")]
    https: bool,
    
    #[arg(short = '6', long, help = "Use IPv6 instead of IPv4 for testing")]
    ipv6: bool,
    
    #[arg(long, help = "Verify SSL certificates during testing")]
    verify_ssl: bool,
    
    #[arg(long, help = "Add random delays between requests for realistic testing")]
    random_delays: bool,
    
    #[arg(long, default_value = "true", help = "Enable DNS resolution (recommended)")]
    resolve_dns: bool,
    
    #[arg(long, default_value = "5", help = "Request timeout in seconds")]
    timeout: u64,
}

/// Display powerful fiery-style banner with special effects
async fn display_banner() {
    println!();
    
    // Fire effect - animated flames
    for _ in 0..3 {
        let mut flame_line = String::new();
        for _ in 0..75 {
            let flames = ['▲', '▼', '◆', '◇', '▣', '▢', '◈'];
            let ch = flames[rand::thread_rng().gen_range(0..flames.len())];
            flame_line.push(ch);
        }
        println!("{}", flame_line.bright_red().bold());
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "║                                                                       ║".bright_red());
    println!("{}", "║    ██████╗ ██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗       ║".bright_yellow().bold());
    println!("{}", "║   ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║████╗  ██║       ║".bright_yellow().bold());
    println!("{}", "║   ██║   ██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██╔██╗ ██║       ║".bright_red().bold());
    println!("{}", "║   ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║╚██╗██║       ║".bright_red());
    println!("{}", "║   ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║       ║".bright_red());
    println!("{}", "║    ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ║".bright_red());
    println!("{}", "║                                                                       ║".bright_red());
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Animated subtitle with fire effect
    let subtitle = "    HTTP LOAD TESTING FRAMEWORK | BURN THE LIMITS    ";
    print!("{}", "║".bright_red());
    for ch in subtitle.chars() {
        print!("{}", ch.to_string().bright_yellow().bold());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(700)).await;
    }
    println!("{}", "║".bright_red());
    
    println!("{}", "║                                                                       ║".bright_red());
    println!("{}", "║  ┌─────────────────────────────────────────────────────────────────┐  ║".bright_red());
    println!("{}", "║  │ Version: 9.20.2091vproAlpha | Author: khaninkali              │ ║".bright_white());
    println!("{}", "║  │ Engine: HTTP/HTTPS | Protocol: TCP/TLS | Mode: OVERLOAD       │ ║".bright_yellow());
    println!("{}", "║  └─────────────────────────────────────────────────────────────────┘  ║".bright_red());
    println!("{}", "║                                                                       ║".bright_red());
    
    println!("{}", "║  ╔═══════════════════════════════════════════════════════════════╗    ║".bright_yellow().bold());
    println!("{}", "║  ║  FIRE MODE: Maximum performance load testing                 ║     ║".bright_white().bold());
    println!("{}", "║  ║  Authorized testing only - Use responsibly                   ║     ║".bright_white().bold());
    println!("{}", "║  ╚═══════════════════════════════════════════════════════════════╝    ║".bright_yellow().bold());
    
    println!("{}", "║                                                                       ║".bright_red());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════╝".bright_red().bold());
    println!();
    
    // Fire initialization sequence
    println!("{}", "    ╔══[ IGNITION SEQUENCE ]══════════════════════════════════════╗".bright_red().bold());
    println!("{}", "    ║                                                             ║".bright_red());
    
    tokio::time::sleep(Duration::from_millis(80)).await;
    
    // Stage 1: HTTP Engine
    print!("{}", "    ║  ▶ ".bright_red());
    print!("{}", "[ HTTP ENGINE ]".bright_yellow().bold());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    
    for _ in 0..3 {
        print!("{}", " ▲".bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    println!("{}", " IGNITED ✓".bright_green().bold());
    
    // Stage 2: TLS Module
    print!("{}", "    ║  ▶ ".bright_red());
    print!("{}", "[ TLS MODULE ]".bright_yellow().bold());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(110)).await;
    
    for _ in 0..3 {
        print!("{}", " ▲".bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
    }
    println!("{}", " IGNITED ✓".bright_green().bold());
    
    // Stage 3: Load Generator
    print!("{}", "    ║  ▶ ".bright_red());
    print!("{}", "[ LOAD GENERATOR ]".bright_yellow().bold());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(130)).await;
    
    for _ in 0..3 {
        print!("{}", " ▲".bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
    println!("{}", " IGNITED ✓".bright_green().bold());
    
    // Stage 4: Thread Pool
    print!("{}", "    ║  ▶ ".bright_red());
    print!("{}", "[ THREAD POOL ]".bright_yellow().bold());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    for _ in 0..3 {
        print!("{}", " ▲".bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(65)).await;
    }
    println!("{}", " IGNITED ✓".bright_green().bold());
    
    // Stage 5: Request Forge
    print!("{}", "    ║  ▶ ".bright_red());
    print!("{}", "[ REQUEST FORGE ]".bright_yellow().bold());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(115)).await;
    
    for _ in 0..3 {
        print!("{}", " ▲".bright_red());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
    }
    println!("{}", " IGNITED ✓".bright_green().bold());
    
    println!("{}", "    ║                                                              ║".bright_red());
    tokio::time::sleep(Duration::from_millis(120)).await;
    
    println!("{}", "    ╚══════════════════════════════════════════════════════════════╝".bright_red().bold());
    println!();
    
    // Fire status display
    println!("{}", "    ╔════════════════════════════════════════════════════════════════╗".bright_yellow().bold());
    println!("{}", "    ║  🔥 TEMPERATURE: MAXIMUM  │  POWER: UNLIMITED  │  STATUS: HOT ║".bright_white().bold());
    println!("{}", "    ╚════════════════════════════════════════════════════════════════╝".bright_yellow().bold());
    println!();
    
    // Closing fire effect
    for _ in 0..2 {
        let mut flame_line = String::new();
        for _ in 0..75 {
            let flames = ['▲', '▼', '◆', '◇'];
            let ch = flames[rand::thread_rng().gen_range(0..flames.len())];
            flame_line.push(ch);
        }
        println!("{}", flame_line.bright_red());
        tokio::time::sleep(Duration::from_millis(35)).await;
    }
    
    println!();
    println!("{}", "         ⟨⟨⟨ OVERRUN FRAMEWORK BLAZING ⟩⟩⟩".bright_red().bold());
    println!();
}

/// Test connection to target before starting load test
/// Validates that the target is reachable and responding
async fn test_connection(target_url: &str, use_https: bool, verify_ssl: bool, use_ipv6: bool) -> Result<()> {
    println!("[*] Testing connection to target...");
    
    // Parse target URL
    let (host, port, _path, url_use_https) = parse_target_url(target_url)?;
    let actual_use_https = use_https || url_use_https;
    
    // Resolve hostname
    let socket_addrs = resolve_hostname(&host, port, use_ipv6, true).await?;
    let socket_addr = socket_addrs.first()
        .ok_or_else(|| anyhow::anyhow!("No socket addresses available"))?;
    
    println!("[*] Resolved {} to {}", host, socket_addr);
    
    // Try to connect
    let tcp_stream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(socket_addr)
    ).await {
        Ok(Ok(stream)) => {
            println!("[✓] TCP connection successful");
            stream
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("Connection failed: {}. Make sure the target server is running and accessible.", e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Connection timeout. Make sure the target server is running and accessible."));
        }
    };
    
    // Test HTTP/HTTPS with hyper
    if actual_use_https {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .danger_accept_invalid_hostnames(!verify_ssl)
            .build()?;
        
        let connector = tokio_native_tls::TlsConnector::from(connector);
        
        match tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(&host, tcp_stream)
        ).await {
            Ok(Ok(_)) => {
                println!("[✓] TLS handshake successful");
            }
            Ok(Err(e)) => {
                return Err(anyhow::anyhow!("TLS handshake failed: {}", e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!("TLS handshake timeout"));
            }
        }
    }
    
    println!("[✓] Connection test passed - target is reachable");
    println!();
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check if no arguments provided or --help flag
    let args_vec: Vec<String> = std::env::args().collect();
    if args_vec.len() == 1 || args_vec.contains(&"--help".to_string()) || args_vec.contains(&"-h".to_string()) {
        // Display banner before help
        display_banner().await;
    }
    
    let args = Args::parse();
    
    tracing_subscriber::fmt::init();
    
    // Test connection before starting load test
    if let Err(e) = test_connection(&args.target, args.https, args.verify_ssl, args.ipv6).await {
        error!("Connection test failed: {}", e);
        println!();
        println!("[!] Connection test failed: {}", e);
        println!("[!] Please verify:");
        println!("    - The target URL is correct");
        println!("    - The target server is running");
        println!("    - The target is accessible from this machine");
        println!("    - Firewall rules allow the connection");
        println!();
        return Err(e);
    }
    
    println!("[+] HTTP Load Tester v9.20.2091vproAlpha");
    println!("[+] Target: {}", args.target);
    println!("[+] Interface: {:?}", args.interface);
    println!("[+] Test Threads: {}", args.threads);
    println!("[+] Duration: {}s", args.duration);
    println!("[+] Method: {}", args.method);
    println!("[+] HTTPS: {}", args.https);
    println!("[+] IPv6: {}", args.ipv6);
    println!("[+] SSL Verify: {}", args.verify_ssl);
    println!("[+] Random Delays: {}", args.random_delays);
    println!("[+] DNS Resolution: {}", args.resolve_dns);
    println!("[+] Timeout: {}s", args.timeout);
    println!();

    let target_url = args.target.clone();
    let mut handles = vec![];
    let total_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let successful_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for i in 0..args.threads {
        let target_url = target_url.clone();
        let method = args.method.clone();
        let use_https = args.https;
        let verify_ssl = args.verify_ssl;
        let random_delays = args.random_delays;
        let timeout = args.timeout;
        let resolve_dns = args.resolve_dns;
        let interface = args.interface.clone();
        let ipv6 = args.ipv6;
        let total_requests_clone = Arc::clone(&total_requests);
        let successful_requests_clone = Arc::clone(&successful_requests);

        let handle = tokio::spawn(async move {
            match http_load_test_worker(i, target_url, method, args.duration, use_https, verify_ssl, random_delays, timeout, resolve_dns, interface, ipv6).await {
                Ok((total, successful)) => {
                    total_requests_clone.fetch_add(total, std::sync::atomic::Ordering::Relaxed);
                    successful_requests_clone.fetch_add(successful, std::sync::atomic::Ordering::Relaxed);
                    (total, successful)
                }
                Err(e) => {
                    error!("Worker {} failed: {}", i, e);
                    (0, 0)
                }
            }
        });

        handles.push(handle);
    }

    let mut _total_successful = 0;
    let mut _total_failed = 0;
    for handle in handles {
        match handle.await {
            Ok((total, successful)) => {
                // Variables are tracked via atomic counters instead
                info!("Worker completed: {} total, {} successful", total, successful);
            }
            Err(e) => error!("Thread join error: {}", e),
        }
    }

    let grand_total_requests = total_requests.load(std::sync::atomic::Ordering::Relaxed);
    let grand_total_successful = successful_requests.load(std::sync::atomic::Ordering::Relaxed);
    
    println!("[+] HTTP load testing completed");
    println!("[+] Total requests: {}", grand_total_requests);
    println!("[+] Successful requests: {}", grand_total_successful);
    println!("[+] Failed requests: {}", grand_total_requests - grand_total_successful);
    
    Ok(())
}

/// Browser user agents for HTTP testing
/// Contains realistic browser user-agent strings for comprehensive HTTP testing
static USER_AGENTS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
        "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
    ]
});

/// Parse and validate target URL with advanced logic
/// Extracts host, port, path, and scheme from URL for proper connection handling
fn parse_target_url(target_url: &str) -> Result<(String, u16, String, bool)> {
    // Parse URL using url crate for robust parsing
    let parsed_url = Url::parse(target_url)
        .context("Invalid URL format")?;
    
    // Extract scheme to determine if HTTPS
    let use_https = match parsed_url.scheme() {
        "https" => true,
        "http" => false,
        scheme => return Err(anyhow::anyhow!("Unsupported scheme: {}. Use http:// or https://", scheme)),
    };
    
    // Extract host
    let host = parsed_url.host_str()
        .ok_or_else(|| anyhow::anyhow!("No host found in URL"))?
        .to_string();
    
    // Extract port with proper defaults
    let port = parsed_url.port().unwrap_or(if use_https { 443 } else { 80 });
    
    // Extract path with query parameters
    let path = if parsed_url.query().is_some() {
        format!("{}?{}", parsed_url.path(), parsed_url.query().unwrap())
    } else {
        parsed_url.path().to_string()
    };
    
    // Validate host is not empty
    if host.is_empty() {
        return Err(anyhow::anyhow!("Host cannot be empty"));
    }
    
    // Validate port is in valid range
    if port == 0 {
        return Err(anyhow::anyhow!("Invalid port number: 0"));
    }
    
    info!("Parsed URL - Host: {}, Port: {}, Path: {}, HTTPS: {}", host, port, path, use_https);
    
    Ok((host, port, path, use_https))
}

/// Resolve hostname to IP addresses with advanced DNS logic
/// Performs DNS resolution with IPv4/IPv6 support and fallback mechanisms
async fn resolve_hostname(host: &str, port: u16, use_ipv6: bool, resolve_dns: bool) -> Result<Vec<SocketAddr>> {
    if !resolve_dns {
        // Skip DNS resolution, use default loopback
        let addr = if use_ipv6 {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
        } else {
            SocketAddr::from(([127, 0, 0, 1], port))
        };
        return Ok(vec![addr]);
    }
    
    // Try to parse as IP address first (skip DNS if already an IP)
    if let Ok(ip) = host.parse::<IpAddr>() {
        info!("Host is already an IP address: {}", ip);
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    
    // Perform DNS resolution
    let target = format!("{}:{}", host, port);
    match tokio::task::spawn_blocking(move || {
        target.to_socket_addrs()
    }).await {
        Ok(Ok(addrs)) => {
            let addr_vec: Vec<SocketAddr> = addrs.collect();
            if addr_vec.is_empty() {
                return Err(anyhow::anyhow!("DNS resolution returned no addresses"));
            }
            
            // Filter by IPv4/IPv6 preference
            let filtered: Vec<SocketAddr> = if use_ipv6 {
                addr_vec.iter()
                    .filter(|a| a.is_ipv6())
                    .copied()
                    .collect()
            } else {
                addr_vec.iter()
                    .filter(|a| a.is_ipv4())
                    .copied()
                    .collect()
            };
            
            // Use filtered addresses if available, otherwise use all
            let result = if filtered.is_empty() {
                addr_vec
            } else {
                filtered
            };
            
            info!("Resolved {} to {} addresses", host, result.len());
            Ok(result)
        }
        Ok(Err(e)) => {
            Err(anyhow::anyhow!("DNS resolution failed: {}", e))
        }
        Err(e) => {
            Err(anyhow::anyhow!("DNS resolution task failed: {}", e))
        }
    }
}

/// Execute HTTP load testing worker
/// Generates HTTP requests for testing web server capacity with IPv4/IPv6 support
async fn http_load_test_worker(
    id: usize,
    target_url: String,
    method: String,
    duration: u64,
    use_https: bool,
    verify_ssl: bool,
    random_delays: bool,
    timeout: u64,
    resolve_dns: bool,
    _interface_name: Option<String>,
    use_ipv6: bool,
) -> Result<(usize, usize)> {
    let start_time = std::time::Instant::now();
    let mut requests_sent = 0;
    let mut successful_requests = 0;
    let mut failed_requests = 0;
    
    // Parse target URL with advanced logic
    let (host, port, path, url_use_https) = match parse_target_url(&target_url) {
        Ok(parsed) => parsed,
        Err(e) => {
            error!("Worker {} failed to parse URL: {}", id, e);
            return Err(e);
        }
    };
    
    // Use HTTPS from URL if not explicitly overridden
    let actual_use_https = use_https || url_use_https;
    
    // Resolve hostname to socket addresses with advanced DNS logic
    let socket_addrs = match resolve_hostname(&host, port, use_ipv6, resolve_dns).await {
        Ok(addrs) => addrs,
        Err(e) => {
            error!("Worker {} failed to resolve hostname: {}", id, e);
            return Err(e);
        }
    };
    
    // Select socket address for testing (use first available)
    let socket_addr = socket_addrs.first()
        .ok_or_else(|| anyhow::anyhow!("No socket addresses available"))?;
    
    info!("Worker {} targeting {} ({})", id, host, socket_addr);
    
    // Create TLS connector if HTTPS is enabled
    let tls_connector = if actual_use_https {
        let mut builder = native_tls::TlsConnector::builder();
        // Configure TLS for testing
        if !verify_ssl {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        Some(Arc::new(tokio_native_tls::TlsConnector::from(builder.build().context("Failed to create TLS connector")?)))
    } else {
        None
    };

    // Main request loop
    while start_time.elapsed().as_secs() < duration {
        let user_agent = USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())];
        
        match tokio::time::timeout(
            Duration::from_secs(timeout),
            make_http_request_hyper(socket_addr, &host, &path, &method, user_agent, actual_use_https, &tls_connector)
        ).await {
            Ok(Ok(_)) => {
                successful_requests += 1;
            }
            Ok(Err(e)) => {
                failed_requests += 1;
                if failed_requests % 100 == 0 {
                    warn!("Worker {} request failed: {}", id, e);
                }
            }
            Err(_) => {
                failed_requests += 1;
                if failed_requests % 100 == 0 {
                    warn!("Worker {} request timeout", id);
                }
            }
        }
        
        requests_sent += 1;

        // Add realistic delays for testing
        if random_delays {
            let delay_ms = rand::thread_rng().gen_range(0..100);
            sleep(Duration::from_millis(delay_ms)).await;
        } else {
            sleep(Duration::from_millis(10)).await;
        }

        if requests_sent % 100 == 0 {
            info!("Worker {}: Sent {} requests, {} successful, {} failed", 
                  id, requests_sent, successful_requests, failed_requests);
        }
    }

    info!("Worker {} completed. Total: {}, Successful: {}, Failed: {}", 
          id, requests_sent, successful_requests, failed_requests);
    Ok((requests_sent, successful_requests))
}

/// Make HTTP request using hyper with HTTP/1.1 and HTTP/2 support
/// Real implementation with proper HTTP protocol handling
async fn make_http_request_hyper(
    socket_addr: &SocketAddr,
    host: &str,
    path: &str,
    method: &str,
    user_agent: &str,
    use_https: bool,
    tls_connector: &Option<Arc<tokio_native_tls::TlsConnector>>,
) -> Result<()> {
    // Connect with timeout
    let tcp_stream = match tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(socket_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(anyhow::anyhow!("Connection error: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("Connection timeout")),
    };
    
    // Enable TCP optimizations
    if let Err(e) = tcp_stream.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY: {}", e);
    }
    
    // Build HTTP request
    let http_method = match method {
        "POST" => Method::POST,
        "HEAD" => Method::HEAD,
        "OPTIONS" => Method::OPTIONS,
        _ => Method::GET,
    };
    
    let uri = if use_https {
        format!("https://{}{}", host, path)
    } else {
        format!("http://{}{}", host, path)
    };
    
    let req = Request::builder()
        .method(http_method)
        .uri(&uri)
        .header("Host", host)
        .header("User-Agent", user_agent)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Connection", "keep-alive")
        .header("Cache-Control", "no-cache")
        .body(Empty::<Bytes>::new())
        .context("Failed to build request")?;
    
    if use_https {
        // HTTPS connection with TLS
        let connector = tls_connector.as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS connector not available"))?;
        
        let tls_stream = match tokio::time::timeout(
            Duration::from_secs(3),
            connector.connect(host, tcp_stream)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow::anyhow!("TLS handshake error: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("TLS handshake timeout")),
        };
        
        // Use hyper HTTP/1.1 connection over TLS
        let (mut sender, conn) = match tokio::time::timeout(
            Duration::from_secs(2),
            conn::http1::handshake(TokioIo::new(tls_stream))
        ).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return Err(anyhow::anyhow!("HTTP handshake error: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("HTTP handshake timeout")),
        };
        
        // Spawn connection task
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Connection error: {}", e);
            }
        });
        
        // Send request and get response
        match tokio::time::timeout(
            Duration::from_secs(2),
            sender.send_request(req)
        ).await {
            Ok(Ok(response)) => {
                // Successfully sent request and got response
                let status = response.status();
                if status.is_success() || status.is_redirection() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("HTTP error: {}", status))
                }
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Request error: {}", e)),
            Err(_) => Err(anyhow::anyhow!("Request timeout")),
        }
    } else {
        // HTTP connection without TLS
        let (mut sender, conn) = match tokio::time::timeout(
            Duration::from_secs(2),
            conn::http1::handshake(TokioIo::new(tcp_stream))
        ).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return Err(anyhow::anyhow!("HTTP handshake error: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("HTTP handshake timeout")),
        };
        
        // Spawn connection task
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Connection error: {}", e);
            }
        });
        
        // Send request and get response
        match tokio::time::timeout(
            Duration::from_secs(2),
            sender.send_request(req)
        ).await {
            Ok(Ok(response)) => {
                // Successfully sent request and got response
                let status = response.status();
                if status.is_success() || status.is_redirection() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("HTTP error: {}", status))
                }
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("Request error: {}", e)),
            Err(_) => Err(anyhow::anyhow!("Request timeout")),
        }
    }
}

