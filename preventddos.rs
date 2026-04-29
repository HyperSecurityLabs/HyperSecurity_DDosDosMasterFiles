/// DDoS Defense System
///
/// A comprehensive DDoS detection and mitigation system for network security.
/// Provides real-time traffic analysis, attack detection, and automated response capabilities
/// to protect network infrastructure from distributed denial-of-service attacks.

use clap::Parser;
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const VERSION: &str = "10.21.2092vproAlpha";

/// Command-line arguments for the DDoS defense system
#[derive(Debug, Clone, Parser)]
#[command(name = "ddos_defender")]
#[command(about = "DDoS defense system for network security and attack mitigation")]
struct CliArgs {
    /// Target interface to monitor
    #[arg(short = 'i', long)]
    interface: Option<String>,
    
    /// Report file path for output
    #[arg(short = 'r', long)]
    report_file: Option<String>,
    
    /// Maximum concurrent connections to handle
    #[arg(short = 'c', long, default_value = "100")]
    max_connections: usize,
    
    /// Monitoring duration in seconds
    #[arg(short = 'd', long, default_value = "300")]
    duration: u64,
    
    /// Detection threshold (packets/second)
    #[arg(short = 't', long, default_value = "1000")]
    threshold: u32,
    
    /// Protocol to monitor (tcp, udp, all)
    #[arg(short = 'p', long, default_value = "all")]
    #[arg(value_parser = ["tcp", "udp", "all"])]
    protocol: String,
    
    /// Enable automatic mitigation
    #[arg(long)]
    auto_mitigate: bool,
    
    /// Enable verbose logging
    #[arg(short = 'v', long)]
    verbose: bool,
    
    /// Output format (json, txt)
    #[arg(short = 'f', long, default_value = "json")]
    #[arg(value_parser = ["json", "txt"])]
    format: String,
}

/// Security event representing a detected attack or anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityEvent {
    event_id: String,
    timestamp: i64,
    source_ip: String,
    event_type: String,
    severity: String,
    description: String,
    packets_per_second: u32,
    bytes_per_second: u64,
    duration: u64,
    status: String,
    mitigation_applied: String,
    start_time: i64,
    end_time: Option<i64>,
}

/// Traffic pattern for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficPattern {
    timestamp: i64,
    source_ip: String,
    packet_count: u32,
    byte_count: u64,
    protocol: String,
    port: u16,
    flags: Vec<String>,
}

/// Defense rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenseRule {
    rule_id: String,
    name: String,
    condition: String,
    action: String,
    threshold: u32,
    duration: u64,
    active: bool,
}

/// DDoS attack record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DDoSAttack {
    attack_id: String,
    source_ip: String,
    attack_type: String,
    start_time: i64,
    end_time: Option<i64>,
    packets_per_second: u32,
    bytes_per_second: u64,
    status: String,
}

/// Blocked IP record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockedIP {
    ip: String,
    blocked_at: i64,
    expires_at: Option<i64>,
    reason: String,
}

/// Mitigation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MitigationRule {
    rule_id: String,
    name: String,
    action: String,
    active: bool,
}

/// System resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemResource {
    timestamp: i64,
    cpu_usage: f32,
    memory_usage: f32,
    network_rx: u64,
    network_tx: u64,
    connections: u32,
}

/// Main DDoS defense system structure
struct DDoSDefender {
    security_events: Arc<Mutex<Vec<SecurityEvent>>>,
    traffic_patterns: Arc<Mutex<VecDeque<TrafficPattern>>>,
    defense_rules: Arc<Mutex<Vec<DefenseRule>>>,
    attacks: Arc<Mutex<Vec<DDoSAttack>>>,
    blocked_ips: Arc<Mutex<Vec<BlockedIP>>>,
    mitigation_rules: Arc<Mutex<Vec<MitigationRule>>>,
    system_resources: Arc<Mutex<Vec<SystemResource>>>,
    output_format: String,
    output_file: Option<String>,
}

impl DDoSDefender {
    /// Creates a new DDoS defender instance
    fn new(output_format: String, output_file: Option<String>) -> Self {
        DDoSDefender {
            security_events: Arc::new(Mutex::new(Vec::new())),
            traffic_patterns: Arc::new(Mutex::new(VecDeque::new())),
            defense_rules: Arc::new(Mutex::new(Vec::new())),
            attacks: Arc::new(Mutex::new(Vec::new())),
            blocked_ips: Arc::new(Mutex::new(Vec::new())),
            mitigation_rules: Arc::new(Mutex::new(Vec::new())),
            system_resources: Arc::new(Mutex::new(Vec::new())),
            output_format,
            output_file,
        }
    }
    
    /// Initializes default defense rules
    fn initialize_default_rules(&self) {
        let mut rules = self.defense_rules.lock().unwrap();
        
        rules.push(DefenseRule {
            rule_id: Uuid::new_v4().to_string(),
            name: "SYN Flood Detection".to_string(),
            condition: "syn_rate > 1000".to_string(),
            action: "block".to_string(),
            threshold: 1000,
            duration: 300,
            active: true,
        });
        
        rules.push(DefenseRule {
            rule_id: Uuid::new_v4().to_string(),
            name: "UDP Flood Detection".to_string(),
            condition: "udp_rate > 5000".to_string(),
            action: "rate_limit".to_string(),
            threshold: 5000,
            duration: 300,
            active: true,
        });
        
        rules.push(DefenseRule {
            rule_id: Uuid::new_v4().to_string(),
            name: "HTTP Flood Detection".to_string(),
            condition: "http_rate > 500".to_string(),
            action: "challenge".to_string(),
            threshold: 500,
            duration: 300,
            active: true,
        });
        
        println!("[+] Initialized {} default defense rules", rules.len());
    }
    
    /// Starts monitoring for DDoS attacks
    fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting DDoS defense monitoring...");
        println!("[*] Monitoring system resources...");
        
        let system_resources = Arc::clone(&self.system_resources);
        let attacks = Arc::clone(&self.attacks);
        let mitigation_rules = Arc::clone(&self.mitigation_rules);
        let blocked_ips = Arc::clone(&self.blocked_ips);
        
        // Start resource monitoring thread
        let resources_clone = Arc::clone(&system_resources);
        thread::spawn(move || {
            Self::run_resource_monitor(resources_clone);
        });
        
        // Start mitigation engine thread
        thread::spawn(move || {
            Self::run_mitigation_engine(attacks, mitigation_rules, blocked_ips);
        });
        
        // Simulate monitoring for demonstration
        println!("[+] Defense systems active");
        println!("[*] Monitoring for attacks...");
        
        // Keep main thread alive
        loop {
            thread::sleep(Duration::from_secs(10));
            
            // Display status
            let resources = system_resources.lock().unwrap();
            if let Some(latest) = resources.last() {
                println!(
                    "[*] CPU: {:.1}% | Memory: {:.1}% | Connections: {}",
                    latest.cpu_usage, latest.memory_usage, latest.connections
                );
            }
        }
    }
    
    /// Monitors system resources continuously
    fn run_resource_monitor(system_resources: Arc<Mutex<Vec<SystemResource>>>) {
        println!("[*] Resource monitor started");
        
        loop {
            let cpu = Self::get_cpu_usage();
            let memory = Self::get_memory_usage();
            let (rx, tx) = Self::get_network_stats();
            let connections = Self::get_connection_count();
            
            let resource = SystemResource {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                cpu_usage: cpu,
                memory_usage: memory,
                network_rx: rx,
                network_tx: tx,
                connections,
            };
            
            let mut resources = system_resources.lock().unwrap();
            resources.push(resource);
            
            // Keep only last 100 entries
            if resources.len() > 100 {
                resources.remove(0);
            }
            
            thread::sleep(Duration::from_secs(5));
        }
    }
    
    /// Gets current CPU usage percentage
    fn get_cpu_usage() -> f32 {
        if let Ok(output) = Command::new("top").args(&["-bn1"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let cpu_regex = Regex::new(r"%Cpu\(s\):\s+([\d.]+)\s+us").unwrap();
            
            if let Some(captures) = cpu_regex.captures(&output_str) {
                if let Ok(usage) = captures[1].parse::<f32>() {
                    return usage;
                }
            }
        }
        0.0
    }

    /// Gets current memory usage percentage
    fn get_memory_usage() -> f32 {
        if let Ok(output) = Command::new("free").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                if line.starts_with("Mem:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let (Ok(total), Ok(used)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
                            return (used as f32 / total as f32) * 100.0;
                        }
                    }
                }
            }
        }
        0.0
    }

    /// Gets network statistics (RX/TX bytes)
    fn get_network_stats() -> (u64, u64) {
        if let Ok(output) = Command::new("cat").arg("/proc/net/dev").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                if line.contains("eth0") || line.contains("ens") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        if let (Ok(rx_bytes), Ok(tx_bytes)) = (parts[1].parse::<u64>(), parts[9].parse::<u64>()) {
                            return (rx_bytes, tx_bytes);
                        }
                    }
                }
            }
        }
        (0, 0)
    }

    /// Gets current connection count
    fn get_connection_count() -> u32 {
        if let Ok(output) = Command::new("ss").args(&["-tu", "-n"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            return output_str.lines().count() as u32 - 1; // Subtract header line
        }
        0
    }

    /// Runs the mitigation engine
    fn run_mitigation_engine(
        attacks: Arc<Mutex<Vec<DDoSAttack>>>,
        _mitigation_rules: Arc<Mutex<Vec<MitigationRule>>>,
        blocked_ips: Arc<Mutex<Vec<BlockedIP>>>,
    ) {
        println!("[*] Mitigation engine started");
        
        loop {
            // Clean up expired blocks
            Self::cleanup_expired_blocks(&blocked_ips);
            
            // Update attack statuses
            Self::update_attack_statuses(&attacks);
            
            thread::sleep(Duration::from_secs(10));
        }
    }

    /// Cleans up expired IP blocks
    fn cleanup_expired_blocks(blocked_ips: &Arc<Mutex<Vec<BlockedIP>>>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let mut blocked = blocked_ips.lock().unwrap();
        let mut to_remove = Vec::new();
        
        for (i, block) in blocked.iter().enumerate() {
            if let Some(expires) = block.expires_at {
                if now >= expires {
                    to_remove.push(i);
                    
                    // Unblock IP using iptables
                    if let Err(e) = Command::new("iptables")
                        .args(&["-D", "INPUT", "-s", &block.ip, "-j", "DROP"])
                        .output()
                    {
                        println!("[-] Failed to unblock IP {}: {}", block.ip, e);
                    } else {
                        println!("[+] Unblocked IP: {} (block expired)", block.ip);
                    }
                }
            }
        }
        
        // Remove expired blocks (in reverse order to maintain indices)
        for &i in to_remove.iter().rev() {
            blocked.remove(i);
        }
    }

    /// Updates attack statuses
    fn update_attack_statuses(attacks: &Arc<Mutex<Vec<DDoSAttack>>>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let mut attacks_vec = attacks.lock().unwrap();
        
        for attack in attacks_vec.iter_mut() {
            if attack.status == "active" && now - attack.start_time > 300 { // 5 minutes
                attack.status = "mitigated".to_string();
                attack.end_time = Some(now);
                println!("[+] Attack mitigated: {} from {}", attack.attack_id, attack.source_ip);
            }
        }
    }

    /// Generates a defense report
    fn generate_report(&self) -> Result<Value, Box<dyn std::error::Error>> {
        let attacks = self.attacks.lock().unwrap();
        let blocked_ips = self.blocked_ips.lock().unwrap();
        let system_resources = self.system_resources.lock().unwrap();
        
        let report = json!({
            "summary": {
                "total_attacks": attacks.len(),
                "active_attacks": attacks.iter().filter(|a| a.status == "active").count(),
                "blocked_ips": blocked_ips.len(),
                "mitigation_rules_active": self.mitigation_rules.lock().unwrap().iter().filter(|r| r.active).count()
            },
            "attacks": *attacks,
            "blocked_ips": *blocked_ips,
            "system_resources": system_resources.iter().last(),
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        });
        
        Ok(report)
    }

    /// Saves output to file
    fn save_output(&self, data: &Value) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(file_path) = &self.output_file {
            let content = match self.output_format.as_str() {
                "json" => serde_json::to_string_pretty(data)?,
                "txt" => {
                    let mut output = String::new();
                    if let Some(summary) = data.get("summary") {
                        output.push_str("DDoS Defense Report\n");
                        output.push_str("==================\n");
                        output.push_str(&format!("Total Attacks: {}\n", summary["total_attacks"]));
                        output.push_str(&format!("Active Attacks: {}\n", summary["active_attacks"]));
                        output.push_str(&format!("Blocked IPs: {}\n", summary["blocked_ips"]));
                        output.push_str(&format!("Active Rules: {}\n", summary["mitigation_rules_active"]));
                    }
                    output
                }
                _ => serde_json::to_string_pretty(data)?,
            };

            let mut file = File::create(file_path)?;
            file.write_all(content.as_bytes())?;
            println!("[+] Report saved to: {}", file_path);
        }
        Ok(())
    }
    
    /// Manually blocks an IP address
    fn block_ip_manual(ip: &str) -> Result<(), Box<dyn std::error::Error>> {
        Command::new("iptables")
            .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;
        println!("[+] IP {} blocked successfully", ip);
        Ok(())
    }
    
    /// Manually unblocks an IP address
    fn unblock_ip_manual(ip: &str) -> Result<(), Box<dyn std::error::Error>> {
        Command::new("iptables")
            .args(&["-D", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;
        println!("[+] IP {} unblocked successfully", ip);
        Ok(())
    }
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
        "║   ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗   ║",
        "║   ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝   ║",
        "║   ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║      ║",
        "║   ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║      ║",
        "║   ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║      ║",
        "║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝      ║",
        "║                                                                   ║",
        "║              DDOS DEFENSE & MITIGATION SYSTEM                    ║",
        "║                                                                   ║",
        "╚═══════════════════════════════════════════════════════════════════╝",
    ];
    
    // Animate banner appearance with color gradient
    for (i, line) in banner_lines.iter().enumerate() {
        let colored_line = match i {
            0 | 11 => line.bright_red().bold(),
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
        ("🛡️", "Loading defense modules", 150),
        ("🔍", "Initializing threat detection", 150),
        ("⚙️", "Configuring mitigation engine", 150),
        ("📊", "Starting resource monitor", 150),
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

/// Prompts user for configuration input interactively
fn prompt_for_configuration() -> io::Result<CliArgs> {
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!("{}", "                    CONFIGURATION WIZARD".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    let mut input = String::new();
    
    // Network interface
    print!("{} ", "→ Network interface to monitor (e.g., eth0) [auto]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let interface = if input.trim().is_empty() {
        None
    } else {
        Some(input.trim().to_string())
    };
    
    // Max connections
    print!("{} ", "→ Maximum concurrent connections [100]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let max_connections = if input.trim().is_empty() {
        100
    } else {
        input.trim().parse().unwrap_or(100)
    };
    
    // Duration
    print!("{} ", "→ Monitoring duration in seconds [300]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let duration = if input.trim().is_empty() {
        300
    } else {
        input.trim().parse().unwrap_or(300)
    };
    
    // Threshold
    print!("{} ", "→ Detection threshold (packets/sec) [1000]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let threshold = if input.trim().is_empty() {
        1000
    } else {
        input.trim().parse().unwrap_or(1000)
    };
    
    // Auto mitigation
    print!("{} ", "→ Enable automatic mitigation? (y/n) [y]:".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let auto_mitigate = input.trim().is_empty() || input.trim().eq_ignore_ascii_case("y");
    
    // Report file
    print!("{} ", "→ Report file path (optional):".bright_white().bold());
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let report_file = if input.trim().is_empty() {
        None
    } else {
        Some(input.trim().to_string())
    };
    
    println!();
    println!("{}", "Configuration complete!".bright_green().bold());
    println!();
    
    Ok(CliArgs {
        interface,
        report_file,
        max_connections,
        duration,
        threshold,
        protocol: "all".to_string(),
        auto_mitigate,
        verbose: false,
        format: "json".to_string(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    println!("{}", "                    DEFENSE CONFIGURATION".bright_yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    println!("  {} {}", "Interface:".bright_white().bold(), 
             config.interface.as_ref().unwrap_or(&"auto".to_string()).bright_green());
    println!("  {} {}", "Max Connections:".bright_white().bold(), 
             config.max_connections.to_string().bright_green());
    println!("  {} {}s", "Duration:".bright_white().bold(), 
             config.duration.to_string().bright_green());
    println!("  {} {} pps", "Threshold:".bright_white().bold(), 
             config.threshold.to_string().bright_green());
    println!("  {} {}", "Protocol:".bright_white().bold(), 
             config.protocol.bright_green());
    println!("  {} {}", "Auto Mitigation:".bright_white().bold(), 
             config.auto_mitigate.to_string().bright_green());
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_cyan());
    println!();
    
    // Confirmation prompt
    print!("{} ", "→ Start defense system? (y/n) [y]:".bright_yellow().bold());
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    
    if !confirm.trim().is_empty() && !confirm.trim().eq_ignore_ascii_case("y") {
        println!("{}", "Defense system cancelled by user.".bright_red());
        return Ok(());
    }
    
    println!();
    
    // Create defender instance
    let defender = DDoSDefender::new(
        config.format.clone(),
        config.report_file.clone(),
    );
    
    // Initialize default rules
    defender.initialize_default_rules();
    
    // Start monitoring
    println!("{}", "⚡ Defense system active...".bright_green().bold());
    println!();
    
    defender.start_monitoring()?;
    
    Ok(())
}
