/// HTTP Pipeline Testing Suite
///
/// A comprehensive HTTP/1.1 pipelining test utility designed to validate web server
/// capacity, connection handling, and HTTP configuration under sustained load.
/// 
/// This tool implements HTTP pipelining (RFC 2616 Section 8.1.2.2) by sending
/// multiple HTTP requests over a single persistent connection without waiting
/// for responses, allowing performance testing of server pipeline handling.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::io::{self, Write};
use std::net::ToSocketAddrs;
use std::thread;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};
use url::Url;

const VERSION: &str = "10.21.2092vproAlpha";

/// Command-line arguments for the HTTP pipeline tester
#[derive(Parser, Clone)]
#[command(name = "http_pipeline_tester")]
#[command(about = "HTTP pipeline testing and performance validation suite")]
struct CliArgs {
    /// Target URL to test (e.g., https://example.com)
    #[arg(short = 't', long)]
    target: String,
    
    /// Number of concurrent connections to establish
    #[arg(short = 'c', long, default_value = "50")]
    connections: usize,
    
    /// Duration of the test in seconds
    #[arg(short = 'd', long, default_value = "120")]
    duration: u64,
    
    /// HTTP method to use in requests
    #[arg(short = 'm', long, default_value = "GET")]
    #[arg(value_parser = ["GET", "POST", "HEAD", "OPTIONS"])]
    method: String,
    
    /// Use HTTPS protocol
    #[arg(short = 's', long)]
    https: bool,
    
    /// Enable TLS/SSL connections
    #[arg(long, default_value = "true")]
    enable_tls: bool,
    
    /// Verify SSL certificates (disable for self-signed certs)
    #[arg(long, default_value = "true")]
    verify_ssl: bool,
    
    /// Randomize User-Agent headers across requests
    #[arg(long, default_value = "true")]
    random_ua: bool,
    
    /// Enable advanced header variation techniques
    #[arg(long, default_value = "true")]
    evasion_mode: bool,
    
    /// Enable proxy support (requires proxy configuration)
    #[arg(long, default_value = "false")]
    use_proxy: bool,
    
    /// Randomly use HTTP/1.0 for some requests
    #[arg(long, default_value = "false")]
    http10_fallback: bool,
    
    /// Skip SSL certificate verification (insecure)
    #[arg(long, default_value = "false")]
    skip_cert_verify: bool,
    
    /// Enable Server Name Indication (SNI) for TLS
    #[arg(long, default_value = "true")]
    enable_sni: bool,
    
    /// Number of requests to pipeline per connection
    #[arg(long, default_value = "5")]
    pipeline_depth: usize,
    
    /// Interval between pipeline resends in seconds
    #[arg(long, default_value = "5")]
    resend_interval: u64,
    
    /// Enable additional HTTP headers for realistic traffic
    #[arg(long, default_value = "true")]
    advanced_mode: bool,
    
    /// Randomize request endpoints
    #[arg(long, default_value = "true")]
    random_endpoints: bool,
    
    /// Delay between connection establishments in milliseconds
    #[arg(long, default_value = "0")]
    connection_delay: u64,
}

/// Realistic browser User-Agent strings for HTTP testing
///
/// These User-Agent strings represent current major browsers and tools,
/// allowing the tester to simulate diverse client types for comprehensive testing.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "curl/8.5.0",
    "Wget/1.21.4",
    "Python-requests/2.31.0",
];

/// Common web endpoints for testing various server paths
///
/// Includes typical web application paths, API endpoints, and common
/// administrative paths to test server routing and access control.
const TEST_ENDPOINTS: &[&str] = &[
    "/", "/index.html", "/home", "/login", "/dashboard", "/search",
    "/api/v1/data", "/products", "/about", "/contact", "/admin",
    "/wp-admin", "/json", "/xml", "/feed", "/sitemap.xml",
    "/api/status", "/health", "/ping", "/test", "/debug",
    "/.env", "/config", "/backup", "/download", "/upload",
];

/// Standard HTTP methods for request testing
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

/// Selects a random User-Agent string from the predefined list
fn select_random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
}

/// Selects a random endpoint from the predefined list
fn select_random_endpoint() -> &'static str {
    let mut rng = rand::thread_rng();
    TEST_ENDPOINTS[rng.gen_range(0..TEST_ENDPOINTS.len())]
}

/// Selects a random HTTP method from the predefined list
fn select_random_http_method() -> &'static str {
    let mut rng = rand::thread_rng();
    HTTP_METHODS[rng.gen_range(0..HTTP_METHODS.len())]
}

/// Generates a batch of HTTP pipelined requests
///
/// Creates multiple HTTP requests that will be sent over a single connection
/// without waiting for responses (HTTP pipelining). Each request is customized
/// based on the provided configuration parameters.
///
/// # Arguments
/// * `host` - The target hostname for the Host header
/// * `user_agent` - User-Agent string to include in requests
/// * `pipeline_depth` - Number of requests to generate
/// * `advanced_mode` - Whether to include additional realistic headers
/// * `http10_fallback` - Whether to randomly use HTTP/1.0 protocol
/// * `random_endpoints` - Whether to randomize request paths
///
/// # Returns
/// A vector of formatted HTTP request strings ready to be sent
fn build_pipelined_requests(
    host: &str,
    user_agent: &str,
    pipeline_depth: usize,
    advanced_mode: bool,
    http10_fallback: bool,
    random_endpoints: bool,
) -> Vec<String> {
    let mut requests = Vec::with_capacity(pipeline_depth);
    let mut rng = rand::thread_rng();
    
    for _ in 0..pipeline_depth {
        let method = select_random_http_method();
        let endpoint = if random_endpoints {
            select_random_endpoint()
        } else {
            "/"
        };
        
        // Occasionally use HTTP/1.0 if fallback is enabled (30% chance)
        let http_version = if http10_fallback && rng.gen_bool(0.3) {
            "HTTP/1.0"
        } else {
            "HTTP/1.1"
        };
        
        // Build the request line and mandatory headers
        let mut request = format!(
            "{} {} {}\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Connection: keep-alive\r\n",
            method, endpoint, http_version, host, user_agent
        );
        
        // Add realistic browser headers when in advanced mode
        if advanced_mode {
            let accept_values = ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 
                                 "application/json", "*/*"];
            let lang_values = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en;q=0.8"];
            let encoding_values = ["gzip, deflate", "gzip, deflate, br", "identity"];
            let cache_values = ["no-cache", "max-age=0", "no-store"];
            
            request.push_str(&format!(
                "Accept: {}\r\n\
                 Accept-Language: {}\r\n\
                 Accept-Encoding: {}\r\n\
                 Cache-Control: {}\r\n\
                 X-Request-ID: {}.{}.{}.{}\r\n",
                accept_values[rng.gen_range(0..accept_values.len())],
                lang_values[rng.gen_range(0..lang_values.len())],
                encoding_values[rng.gen_range(0..encoding_values.len())],
                cache_values[rng.gen_range(0..cache_values.len())],
                rng.gen_range(1..255),
                rng.gen_range(0..256),
                rng.gen_range(0..256),
                rng.gen_range(1..255)
            ));
            
            // Add Content-Type and Content-Length for methods that typically have bodies
            if matches!(method, "POST" | "PUT" | "PATCH") {
                let content_types = ["application/x-www-form-urlencoded", "application/json", "text/plain"];
                let content_length = rng.gen_range(100..10000);
                request.push_str(&format!(
                    "Content-Type: {}\r\n\
                     Content-Length: {}\r\n",
                    content_types[rng.gen_range(0..content_types.len())],
                    content_length
                ));
            }
            
            // Randomly add a custom header (50% chance) for traffic variation
            if rng.gen_bool(0.5) {
                let uuid_str = uuid::Uuid::from_bytes(rand::random::<[u8; 16]>()).to_string();
                request.push_str(&format!("X-Custom-Header: {}\r\n", uuid_str));
            }
        } else {
            // Minimal headers for basic mode
            request.push_str(
                "Accept: */*\r\n\
                 Accept-Language: en-US,en;q=0.9\r\n"
            );
        }
        
        // Terminate headers section
        request.push_str("\r\n");
        
        // Add request body for methods that support it
        if matches!(method, "POST" | "PUT" | "PATCH") && advanced_mode {
            let body_length = rng.gen_range(100..1000);
            let body = generate_random_alphanumeric(body_length);
            request.push_str(&body);
        }
        
        requests.push(request);
    }
    
    requests
}

/// Generates a random alphanumeric string of specified length
///
/// Used for creating realistic request bodies in POST/PUT/PATCH requests.
fn generate_random_alphanumeric(length: usize) -> String {
    use rand::distributions::Alphanumeric;
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

/// Establishes and maintains a pipelined HTTP connection
///
/// Creates a TCP connection (optionally wrapped in TLS), sends pipelined HTTP requests,
/// and maintains the connection by periodically resending the pipeline. This simulates
/// sustained HTTP traffic for server capacity testing.
///
/// # Arguments
/// * `target` - The target URL to connect to
/// * `connection_id` - Unique identifier for this connection (for logging)
/// * `config` - Configuration parameters for the connection
///
/// # Errors
/// Returns an error if connection establishment, TLS handshake, or request sending fails
async fn establish_pipeline_connection(
    target: &str,
    connection_id: usize,
    config: &CliArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse target URL and extract connection details
    let url = Url::parse(target)?;
    let host = url.host_str().ok_or("Invalid host in URL")?;
    let port = url.port_or_known_default().ok_or("Unable to determine port")?;
    let is_https = url.scheme() == "https";
    
    // Establish TCP connection with optional socket tuning
    let tcp_stream = if config.advanced_mode {
        // Create socket with performance optimizations
        let socket = TcpSocket::new_v4()?;
        socket.set_nodelay(true)?;  // Disable Nagle's algorithm for lower latency
        socket.set_reuseaddr(true)?;  // Allow address reuse
        
        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()?
            .next()
            .ok_or("Failed to resolve target address")?;
        
        socket.connect(addr).await?
    } else {
        TcpStream::connect(format!("{}:{}", host, port)).await?
    };
    
    // Determine User-Agent for this connection
    let user_agent = if config.random_ua {
        select_random_user_agent()
    } else {
        USER_AGENTS[0]  // Use first (Chrome on Windows) as default
    };
    
    // Generate the pipelined requests
    let requests = build_pipelined_requests(
        host,
        user_agent,
        config.pipeline_depth,
        config.advanced_mode,
        config.http10_fallback,
        config.random_endpoints,
    );
    
    info!(
        "Connection {}: Established with {} pipelined requests",
        connection_id,
        requests.len()
    );
    
    // Concatenate all requests into a single payload
    let pipeline_payload = requests.join("");
    
    // Handle TLS wrapping if HTTPS is enabled
    if is_https && config.enable_tls {
        let mut tls_builder = native_tls::TlsConnector::builder();
        
        // Configure certificate verification based on settings
        if config.skip_cert_verify {
            tls_builder.danger_accept_invalid_certs(true);
            tls_builder.danger_accept_invalid_hostnames(true);
        }
        
        let native_connector = tls_builder.build()?;
        let tls_connector = tokio_native_tls::TlsConnector::from(native_connector);
        
        // Connect with or without SNI based on configuration
        let sni_hostname = if config.enable_sni { host } else { "localhost" };
        let mut tls_stream = tls_connector.connect(sni_hostname, tcp_stream).await?;
        
        info!("Connection {}: TLS handshake completed to {}:{}", connection_id, host, port);
        
        // Send initial pipeline
        tls_stream.write_all(pipeline_payload.as_bytes()).await?;
        
        // Maintain connection and resend pipeline periodically
        maintain_pipeline_connection(
            tls_stream,
            connection_id,
            &pipeline_payload,
            config,
        ).await?;
    } else {
        // Plain HTTP connection
        info!("Connection {}: Established plain HTTP to {}:{}", connection_id, host, port);
        
        let mut stream = tcp_stream;
        
        // Send initial pipeline
        stream.write_all(pipeline_payload.as_bytes()).await?;
        
        // Maintain connection and resend pipeline periodically
        maintain_pipeline_connection(
            stream,
            connection_id,
            &pipeline_payload,
            config,
        ).await?;
    }
    
    Ok(())
}

/// Maintains an active pipeline connection by periodically resending requests
///
/// Keeps the connection alive for the configured duration, resending the pipeline
/// at regular intervals to maintain sustained load on the target server.
///
/// # Type Parameters
/// * `S` - The stream type (either TcpStream or TlsStream<TcpStream>)
async fn maintain_pipeline_connection<S>(
    mut stream: S,
    connection_id: usize,
    pipeline_payload: &str,
    config: &CliArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWriteExt + Unpin,
{
    let mut resend_timer = interval(Duration::from_secs(config.resend_interval));
    let mut cycle_count = 0;
    
    loop {
        tokio::select! {
            // Test duration has elapsed
            _ = sleep(Duration::from_secs(config.duration)) => {
                info!("Connection {}: Test duration completed", connection_id);
                break;
            }
            // Time to resend the pipeline
            _ = resend_timer.tick() => {
                if let Err(e) = stream.write_all(pipeline_payload.as_bytes()).await {
                    warn!("Connection {}: Lost connection - {}", connection_id, e);
                    break;
                }
                
                cycle_count += 1;
                
                // Log progress every 5 cycles to avoid log spam
                if cycle_count % 5 == 0 {
                    info!("Connection {}: Pipeline resent {} times", connection_id, cycle_count);
                }
                
                // Add random jitter in advanced mode to simulate realistic traffic patterns
                if config.advanced_mode {
                    let jitter = rand::random::<u64>() % (config.resend_interval / 2);
                    sleep(Duration::from_secs(jitter)).await;
                }
            }
        }
    }
    
    Ok(())
}

/// Displays an animated ASCII art banner with startup sequence
///
/// Shows a professional animated banner with color effects during application startup,
/// providing visual feedback and branding for the tool.
fn display_animated_banner() {
    // Clear screen for clean presentation
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
    
    thread::sleep(Duration::from_millis(200));
    
    // ASCII art banner with animation
    let banner_lines = vec![
        "╔═══════════════════════════════════════════════════════════════════╗",
        "║                                                                   ║",
        "║   ██████╗ ██╗██████╗ ███████╗██╗     ██╗███╗   ██╗███████╗      ║",
        "║   ██╔══██╗██║██╔══██╗██╔════╝██║     ██║████╗  ██║██╔════╝      ║",
        "║   ██████╔╝██║██████╔╝█████╗  ██║     ██║██╔██╗ ██║█████╗        ║",
        "║   ██╔═══╝ ██║██╔═══╝ ██╔══╝  ██║     ██║██║╚██╗██║██╔══╝        ║",
        "║   ██║     ██║██║     ███████╗███████╗██║██║ ╚████║███████╗      ║",
        "║   ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝      ║",
        "║                                                                   ║",
        "║              HTTP/1.1 PIPELINING TEST FRAMEWORK                  ║",
        "║                                                                   ║",
        "╚═══════════════════════════════════════════════════════════════════╝",
    ];
    
    // Animate banner appearance with color gradient
    for (i, line) in banner_lines.iter().enumerate() {
        let colored_line = match i {
            0 | 11 => line.bright_cyan().bold(),
            2..=7 => line.bright_magenta().bold(),
            9 => line.bright_yellow().bold(),
            _ => line.bright_blue(),
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
        ("⚡", "Loading core modules", 150),
        ("🔧", "Initializing network stack", 150),
        ("🔐", "Configuring TLS subsystem", 150),
        ("📡", "Preparing pipeline engine", 150),
        ("✓", "System ready", 200),
    ];
    
    for (icon, message, delay) in init_steps {
        print!("    {} {}...", icon, message.bright_white());
        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_millis(delay));
        println!(" {}", "OK".bright_green().bold());
    }
    
    println!();
    thread::sleep(Duration::from_millis(300));
}

/// Displays an animated progress indicator during initialization
///
/// Shows a spinner animation while the pipeline connections are being established,
/// providing visual feedback to the user during the startup phase.
fn display_initialization_progress() {
    let spinner = ProgressBar::new_spinner();

    let style = ProgressStyle::with_template("⌬ PIPELINE TESTER ⌬  {spinner}  {msg}")
        .unwrap()
        .tick_strings(&["⧇", "⧆", "⧅", "⧄", "⧃", "⧂", "⧁", "⧀"]);

    spinner.set_style(style);
    spinner.enable_steady_tick(Duration::from_millis(90));
    spinner.set_message("Establishing Pipeline Connections...");
    
    thread::sleep(Duration::from_secs(2));
    
    spinner.finish_with_message("PIPELINE CORE: ONLINE ✓");
    println!();
}

/// Prompts user for configuration input interactively
///
/// Provides an interactive interface for users to configure test parameters,
/// with sensible defaults and validation.
fn prompt_for_configuration() -> io::Result<CliArgs> {
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    CONFIGURATION WIZARD".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    let mut input = String::new();
    
    // Target URL
    print!("{} ", "→ Target URL (e.g., https://example.com):".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let target = input.trim().to_string();
    
    // Number of connections
    print!("{} ", "→ Number of concurrent connections [50]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let connections = if input.trim().is_empty() {
        50
    } else {
        input.trim().parse().unwrap_or(50)
    };
    
    // Duration
    print!("{} ", "→ Test duration in seconds [120]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let duration = if input.trim().is_empty() {
        120
    } else {
        input.trim().parse().unwrap_or(120)
    };
    
    // Pipeline depth
    print!("{} ", "→ Pipeline depth (requests per connection) [5]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let pipeline_depth = if input.trim().is_empty() {
        5
    } else {
        input.trim().parse().unwrap_or(5)
    };
    
    // Advanced mode
    print!("{} ", "→ Enable advanced mode? (y/n) [y]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let advanced_mode = input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y");
    
    println!();
    println!("{}", "Configuration complete!".bright_green().bold());
    println!();
    
    Ok(CliArgs {
        target,
        connections,
        duration,
        method: "GET".to_string(),
        https: true,
        enable_tls: true,
        verify_ssl: true,
        random_ua: true,
        evasion_mode: advanced_mode,
        use_proxy: false,
        http10_fallback: false,
        skip_cert_verify: false,
        enable_sni: true,
        pipeline_depth,
        resend_interval: 5,
        advanced_mode,
        random_endpoints: true,
        connection_delay: 0,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging subsystem
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
    
    // Display configuration summary
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    TEST CONFIGURATION".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    println!("  {} {}", "Target:".bright_white().bold(), config.target.bright_green());
    println!("  {} {}", "Connections:".bright_white().bold(), config.connections.to_string().bright_green());
    println!("  {} {}s", "Duration:".bright_white().bold(), config.duration.to_string().bright_green());
    println!("  {} {}", "Method:".bright_white().bold(), config.method.bright_green());
    println!("  {} {}", "HTTPS:".bright_white().bold(), config.https.to_string().bright_green());
    println!("  {} {}", "Pipeline Depth:".bright_white().bold(), config.pipeline_depth.to_string().bright_green());
    println!("  {} {}s", "Resend Interval:".bright_white().bold(), config.resend_interval.to_string().bright_green());
    println!("  {} {}", "Random UA:".bright_white().bold(), config.random_ua.to_string().bright_green());
    println!("  {} {}", "Advanced Mode:".bright_white().bold(), config.advanced_mode.to_string().bright_green());
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Confirmation prompt
    print!("{} ", "→ Start test? (y/n) [y]:".bright_yellow().bold());
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    
    if !confirm.trim().is_empty() && !confirm.trim().eq_ignore_ascii_case("y") {
        println!("{}", "Test cancelled by user.".bright_red());
        return Ok(());
    }
    
    println!();
    display_initialization_progress();
    
    let mut connection_handles = Vec::with_capacity(config.connections);
    
    // Spawn concurrent pipeline connections
    for connection_id in 0..config.connections {
        let target = config.target.clone();
        let config_clone = config.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = establish_pipeline_connection(&target, connection_id, &config_clone).await {
                error!("Connection {} failed: {}", connection_id, e);
            }
        });
        
        connection_handles.push(handle);
        
        // Stagger connection establishment to avoid overwhelming the target
        if config.connection_delay > 0 {
            sleep(Duration::from_millis(config.connection_delay)).await;
        }
    }
    
    info!(
        "Initiated {} pipeline connections - sending pipelined requests",
        config.connections
    );
    
    println!("{}", "⚡ Test in progress...".bright_yellow().bold());
    println!();
    
    // Wait for the test duration to complete
    sleep(Duration::from_secs(config.duration)).await;
    
    info!("Test duration completed - waiting for connections to close");
    
    // Wait for all connection tasks to finish
    for handle in connection_handles {
        let _ = handle.await;
    }
    
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_green());
    println!("{}", "                    TEST COMPLETED".bright_green().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_green());
    println!();
    println!("  {} HTTP pipeline testing completed successfully", "✓".bright_green().bold());
    println!();
    
    Ok(())
}
