/*
 * Rgen v9.20.2091vproAlpha - Advanced Wordlist Generator
 * Specialized wordlist generation tool with pattern recognition and mutation capabilities
 * Author: Khaninkali | HyperSecurity
 * 
 * FOR EDUCATIONAL and AUTHORIZED PENETRATION TESTING ONLY
 */

use clap::{Parser, Subcommand};
use anyhow::Result;
use std::collections::HashMap;
use tracing::info;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::time::Instant;
use hashbrown::HashSet;
use sha2::{Sha256, Digest};
use colored::Colorize;

/// Display the application banner with version and author information
fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                                                                       ║".bright_cyan());
    println!("{}", "║     ██████╗  ██████╗ ███████╗███╗   ██╗    ██╗   ██╗ █████╗           ║".bright_red());
    println!("{}", "║     ██╔══██╗██╔════╝ ██╔════╝████╗  ██║    ██║   ██║██╔══██╗          ║".bright_red());
    println!("{}", "║     ██████╔╝██║  ███╗█████╗  ██╔██╗ ██║    ██║   ██║╚██████║          ║".bright_yellow());
    println!("{}", "║     ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║    ╚██╗ ██╔╝ ╚═══██║          ║".bright_yellow());
    println!("{}", "║     ██║  ██║╚██████╔╝███████╗██║ ╚████║     ╚████╔╝ █████╔╝           ║".bright_green());
    println!("{}", "║     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝      ╚═══╝  ╚════╝            ║".bright_green());
    println!("{}", "║                                                                       ║".bright_cyan());
    println!("{}", "║              EXTREME WORDLIST GENERATOR v9.20.2091vproAlpha           ║".bright_magenta().bold());
    println!("{}", "║                                                                       ║".bright_cyan());
    println!("{}", "║                    Author: Khaninkali | HyperSecurity                 ║".bright_white());
    println!("{}", "║              FOR EDUCATIONAL & AUTHORIZED TESTING ONLY                ║".bright_red().bold());
    println!("{}", "║                                                                       ║".bright_cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

/// Command-line interface definition for the wordlist generator
#[derive(Parser)]
#[command(name = "forge")]
#[command(about = "Advanced Wordlist Generator v9.20.2091vproAlpha")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for different wordlist operations
#[derive(Subcommand)]
pub enum Commands {
    /// Generate wordlist from target information
    Generate {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        min_length: usize,
        #[arg(long)]
        max_length: usize,
        #[arg(long)]
        charset: String,
        #[arg(long)]
        patterns: Vec<String>,
        #[arg(long)]
        mutations: Vec<String>,
        #[arg(long)]
        complexity: String,
        #[arg(long, help = "Import custom words from file (one per line)")]
        import_file: Option<String>,
    },
    /// Combine multiple wordlists into one
    Combine {
        #[arg(short, long)]
        inputs: Vec<String>,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        unique: bool,
        #[arg(long)]
        sort: bool,
    },
    /// Apply mutations to existing wordlist
    Mutate {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        mutations: Vec<String>,
        #[arg(long)]
        depth: usize,
    },
    /// Generate pattern-based wordlist
    Pattern {
        #[arg(short, long)]
        pattern: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        count: usize,
        #[arg(long)]
        charset: String,
    },
    /// Extract passwords from various data formats
    Extract {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        format: String,
        #[arg(long)]
        min_length: usize,
    },
    /// Analyze wordlist statistics
    Analyze {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long)]
        detailed: bool,
    },
}

/// Configuration for wordlist generation behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistConfig {
    pub min_length: usize,
    pub max_length: usize,
    pub charset: String,
    pub patterns: Vec<String>,
    pub mutations: Vec<String>,
    pub complexity: ComplexityLevel,
    pub target_based: bool,
    pub common_passwords: bool,
    pub leaked_passwords: bool,
    pub custom_words: Vec<String>,
}

/// Complexity levels determine the depth and sophistication of password generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplexityLevel {
    Basic,          // Simple numeric and keyboard patterns
    Intermediate,   // Common words with variations
    Advanced,       // Phonetic patterns and combinations
    Extreme,        // Dictionary combinations
    Quantum,        // Hash-based generation
}

/// Statistical analysis results for a wordlist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistStats {
    pub total_words: usize,
    pub unique_words: usize,
    pub average_length: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub charset_coverage: HashMap<char, usize>,
    pub pattern_distribution: HashMap<String, usize>,
    pub complexity_score: f64,
}

/// Core wordlist generation framework
pub struct RgenFramework {
    config: WordlistConfig,
    common_passwords: HashSet<String>,
}

impl RgenFramework {
    /// Create a new framework instance with the given configuration
    pub fn new(config: WordlistConfig) -> Self {
        let mut framework = Self {
            common_passwords: HashSet::new(),
            config,
        };
        
        framework.load_common_passwords();
        framework
    }

    /// Main entry point for wordlist generation
    /// Orchestrates all generation strategies based on configuration
    pub async fn generate_wordlist(&self, target: &str, output_path: &str) -> Result<WordlistStats> {
        info!("Starting wordlist generation for target: {}", target);
        
        let start_time = Instant::now();
        let mut wordlist = HashSet::new();
        
        // Import custom words if provided
        if !self.config.custom_words.is_empty() {
            info!("Importing {} custom words", self.config.custom_words.len());
            for word in &self.config.custom_words {
                if word.len() >= self.config.min_length && word.len() <= self.config.max_length {
                    wordlist.insert(word.clone());
                }
            }
        }
        
        // Target-based generation extracts information from the target string
        self.generate_target_based(&mut wordlist, target).await?;
        
        // Add commonly used passwords from breach databases
        if self.config.common_passwords {
            self.add_common_passwords(&mut wordlist).await?;
        }
        
        // Pattern-based generation using user-defined patterns
        for pattern in &self.config.patterns {
            self.generate_pattern_based(&mut wordlist, pattern).await?;
        }
        
        // Apply transformations to existing words
        for mutation in &self.config.mutations {
            self.apply_mutation(&mut wordlist, mutation).await?;
        }
        
        // Generate additional passwords based on complexity level
        match self.config.complexity {
            ComplexityLevel::Basic => self.generate_basic(&mut wordlist).await?,
            ComplexityLevel::Intermediate => self.generate_intermediate(&mut wordlist).await?,
            ComplexityLevel::Advanced => self.generate_advanced(&mut wordlist).await?,
            ComplexityLevel::Extreme => self.generate_extreme(&mut wordlist).await?,
            ComplexityLevel::Quantum => self.generate_quantum(&mut wordlist).await?,
        }
        
        // Write results to disk
        self.save_wordlist(&wordlist, output_path).await?;
        
        let generation_time = start_time.elapsed();
        let stats = self.calculate_stats(&wordlist);
        
        info!("Wordlist generated: {} words in {:.2}s", wordlist.len(), generation_time.as_secs_f64());
        
        Ok(stats)
    }

    /// Generate passwords based on target string analysis
    /// Extracts components from URLs, domains, emails, etc.
    async fn generate_target_based(&self, wordlist: &mut HashSet<String>, target: &str) -> Result<()> {
        info!("Generating target-based passwords");
        
        // Split target on common delimiters to extract meaningful components
        let base_words: Vec<String> = target.split(&['.', '-', '_', '@', '/', ':'][..])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect();
        
        for base in &base_words {
            // Only include words within configured length constraints
            if base.len() >= self.config.min_length && base.len() <= self.config.max_length {
                wordlist.insert(base.clone());
                wordlist.insert(base.to_uppercase());
                
                // Common numeric suffixes users add to base words
                wordlist.insert(format!("{}123", base));
                wordlist.insert(format!("{}2024", base));
                wordlist.insert(format!("{}!", base));
                
                // Leet speak transformation (e -> 3, a -> @, etc.)
                let leet = self.to_leet_speak(base);
                wordlist.insert(leet.clone());
                
                // Reversed string (surprisingly common)
                let reversed: String = base.chars().rev().collect();
                wordlist.insert(reversed);
            }
        }
        
        Ok(())
    }

    /// Generate passwords from pattern specifications
    /// Pattern format: ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special, ?a = any
    async fn generate_pattern_based(&self, wordlist: &mut HashSet<String>, pattern: &str) -> Result<()> {
        info!("Generating pattern-based passwords: {}", pattern);
        
        // Map pattern characters to their corresponding character sets
        let charset_map = HashMap::from([
            ('l', "abcdefghijklmnopqrstuvwxyz"),
            ('u', "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ('d', "0123456789"),
            ('s', "!@#$%^&*()_+-=[]{}|;:,.<>?"),
            ('a', "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        ]);
        
        let mut generated = 0;
        let max_generate = 1000000; // Prevent excessive memory usage
        
        self.generate_pattern_combinations(
            wordlist,
            pattern,
            &charset_map,
            &mut generated,
            max_generate,
        );
        
        Ok(())
    }

    /// Recursive pattern combination generator
    fn generate_pattern_combinations(
        &self,
        wordlist: &mut HashSet<String>,
        pattern: &str,
        charset_map: &HashMap<char, &str>,
        generated: &mut usize,
        max_generate: usize,
    ) {
        if *generated >= max_generate || pattern.is_empty() {
            return;
        }
        
        if let Some(c) = pattern.chars().next() {
            // Pattern markers start with '?'
            if c == '?' && pattern.len() > 1 {
                let pattern_char = pattern.chars().nth(1).unwrap_or('a');
                let remaining_pattern = &pattern[2..];
                
                if let Some(charset) = charset_map.get(&pattern_char) {
                    for ch in charset.chars() {
                        if *generated >= max_generate {
                            break;
                        }
                        
                        if remaining_pattern.is_empty() {
                            let word = ch.to_string();
                            if word.len() >= self.config.min_length && word.len() <= self.config.max_length {
                                wordlist.insert(word);
                                *generated += 1;
                            }
                        } else {
                            self.generate_pattern_combinations_with_prefix(
                                wordlist,
                                &ch.to_string(),
                                remaining_pattern,
                                charset_map,
                                generated,
                                max_generate,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Helper for pattern generation with accumulated prefix
    fn generate_pattern_combinations_with_prefix(
        &self,
        wordlist: &mut HashSet<String>,
        prefix: &str,
        pattern: &str,
        charset_map: &HashMap<char, &str>,
        generated: &mut usize,
        max_generate: usize,
    ) {
        if *generated >= max_generate || pattern.is_empty() {
            if prefix.len() >= self.config.min_length && prefix.len() <= self.config.max_length {
                wordlist.insert(prefix.to_string());
                *generated += 1;
            }
            return;
        }
        
        if let Some(c) = pattern.chars().next() {
            if c == '?' && pattern.len() > 1 {
                let pattern_char = pattern.chars().nth(1).unwrap_or('a');
                let remaining_pattern = &pattern[2..];
                
                if let Some(charset) = charset_map.get(&pattern_char) {
                    for ch in charset.chars() {
                        if *generated >= max_generate {
                            break;
                        }
                        
                        let new_prefix = format!("{}{}", prefix, ch);
                        self.generate_pattern_combinations_with_prefix(
                            wordlist,
                            &new_prefix,
                            remaining_pattern,
                            charset_map,
                            generated,
                            max_generate,
                        );
                    }
                }
            }
        }
    }

    /// Generate basic complexity passwords
    /// Focuses on simple numeric sequences and keyboard patterns
    async fn generate_basic(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Generating basic complexity passwords");
        
        // Sequential numbers are still commonly used
        for i in 0..10000 {
            let num = i.to_string();
            if num.len() >= self.config.min_length && num.len() <= self.config.max_length {
                wordlist.insert(num);
            }
        }
        
        // Keyboard walk patterns
        let keyboard_patterns = vec![
            "qwerty", "asdf", "zxcv", "123456", "abcdef", "qwertyuiop",
            "asdfghjkl", "zxcvbnm", "1234567890",
        ];
        
        for pattern in keyboard_patterns {
            if pattern.len() >= self.config.min_length && pattern.len() <= self.config.max_length {
                wordlist.insert(pattern.to_string());
                wordlist.insert(format!("{}123", pattern));
            }
        }
        
        Ok(())
    }

    /// Generate intermediate complexity passwords
    /// Common words with numeric and special character variations
    async fn generate_intermediate(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Generating intermediate complexity passwords");
        
        let common_words = vec![
            "password", "admin", "user", "login", "welcome", "home",
            "computer", "network", "server", "database", "system",
        ];
        
        for word in common_words {
            for i in 0..1000 {
                let combo = format!("{}{}", word, i);
                if combo.len() >= self.config.min_length && combo.len() <= self.config.max_length {
                    wordlist.insert(combo.clone());
                    wordlist.insert(format!("{}!", combo));
                }
            }
        }
        
        Ok(())
    }

    /// Generate advanced complexity passwords
    /// Phonetic alphabet combinations
    async fn generate_advanced(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Generating advanced complexity passwords");
        
        let phonetic_patterns = vec![
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
            "golf", "hotel", "india", "juliet", "kilo", "lima", "mike",
        ];
        
        for i in 0..phonetic_patterns.len() {
            for j in i..phonetic_patterns.len() {
                let combo = format!("{}{}", phonetic_patterns[i], phonetic_patterns[j]);
                if combo.len() >= self.config.min_length && combo.len() <= self.config.max_length {
                    wordlist.insert(combo.clone());
                    wordlist.insert(format!("{}123", combo));
                }
            }
        }
        
        Ok(())
    }

    /// Generate extreme complexity passwords
    /// Dictionary word combinations
    async fn generate_extreme(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Generating extreme complexity passwords");
        
        let dictionary_words = vec![
            "dragon", "master", "shadow", "phoenix", "thunder", "lightning",
            "warrior", "ninja", "samurai", "viking", "gladiator", "champion",
        ];
        
        for i in 0..dictionary_words.len() {
            for j in 0..dictionary_words.len() {
                let combo = format!("{}{}", dictionary_words[i], dictionary_words[j]);
                if combo.len() >= self.config.min_length && combo.len() <= self.config.max_length {
                    wordlist.insert(combo.clone());
                    wordlist.insert(format!("{}!", combo));
                }
            }
        }
        
        Ok(())
    }

    /// Generate quantum complexity passwords
    /// Hash-based generation for cryptographically diverse passwords
    async fn generate_quantum(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Generating quantum complexity passwords");
        
        let base_strings = vec![
            "quantum", "particle", "wave", "photon", "electron", "proton",
        ];
        
        for base in base_strings {
            let mut hasher = Sha256::new();
            hasher.update(base.as_bytes());
            let hash = hasher.finalize();
            let hash_str = format!("{:x}", hash);
            
            // Extract substrings of various lengths from the hash
            for len in [8, 12, 16] {
                if len <= hash_str.len() {
                    let substring = &hash_str[..len];
                    if substring.len() >= self.config.min_length && substring.len() <= self.config.max_length {
                        wordlist.insert(substring.to_string());
                        wordlist.insert(substring.to_uppercase());
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Apply mutation transformations to existing wordlist
    /// Mutations include leet speak, reversal, and common suffixes
    async fn apply_mutation(&self, wordlist: &mut HashSet<String>, mutation: &str) -> Result<()> {
        info!("Applying mutation: {}", mutation);
        
        // Clone current words to avoid modifying collection during iteration
        let current_words: Vec<String> = wordlist.iter().cloned().collect();
        
        for word in current_words {
            match mutation {
                "leet" => {
                    let leet_word = self.to_leet_speak(&word);
                    if leet_word.len() >= self.config.min_length && leet_word.len() <= self.config.max_length {
                        wordlist.insert(leet_word);
                    }
                }
                "reverse" => {
                    let rev_word: String = word.chars().rev().collect();
                    if rev_word.len() >= self.config.min_length && rev_word.len() <= self.config.max_length {
                        wordlist.insert(rev_word);
                    }
                }
                "append_numbers" => {
                    for i in 0..1000 {
                        let num_word = format!("{}{}", word, i);
                        if num_word.len() >= self.config.min_length && num_word.len() <= self.config.max_length {
                            wordlist.insert(num_word);
                        }
                    }
                }
                "append_symbols" => {
                    let symbols = vec!["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "-"];
                    for symbol in symbols {
                        let sym_word = format!("{}{}", word, symbol);
                        if sym_word.len() >= self.config.min_length && sym_word.len() <= self.config.max_length {
                            wordlist.insert(sym_word);
                        }
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Transform text to leet speak
    /// Common character substitutions used to bypass simple filters
    fn to_leet_speak(&self, word: &str) -> String {
        word.replace('e', "3")
            .replace('a', "@")
            .replace('o', "0")
            .replace('i', "1")
            .replace('l', "1")
            .replace('s', "5")
            .replace('t', "7")
    }

    /// Add commonly used passwords from breach databases
    async fn add_common_passwords(&self, wordlist: &mut HashSet<String>) -> Result<()> {
        info!("Adding common passwords from breach data");
        
        let common = vec![
            "password", "123456", "password123", "admin", "letmein", "welcome",
            "monkey", "dragon", "master", "hello", "freedom", "whatever",
            "qazwsx", "trustno1", "123qwe", "1q2w3e4r", "abc123",
            "password1", "123456789", "qwerty", "12345678", "football",
            "iloveyou", "123123", "1234567890", "princess", "admin123",
        ];
        
        for pass in common {
            if pass.len() >= self.config.min_length && pass.len() <= self.config.max_length {
                wordlist.insert(pass.to_string());
                wordlist.insert(pass.to_uppercase());
                wordlist.insert(format!("{}123", pass));
            }
        }
        
        Ok(())
    }

    /// Write wordlist to file
    async fn save_wordlist(&self, wordlist: &HashSet<String>, output_path: &str) -> Result<()> {
        info!("Saving wordlist to: {}", output_path);
        
        let mut file = File::create(output_path)?;
        
        // Sort for consistent output and easier analysis
        let mut sorted_words: Vec<&String> = wordlist.iter().collect();
        sorted_words.sort();
        
        for word in sorted_words {
            writeln!(file, "{}", word)?;
        }
        
        Ok(())
    }

    /// Calculate statistical metrics for the wordlist
    fn calculate_stats(&self, wordlist: &HashSet<String>) -> WordlistStats {
        let mut total_length = 0usize;
        let mut min_len = usize::MAX;
        let mut max_len = 0usize;
        let mut charset_coverage = HashMap::new();
        
        for word in wordlist {
            total_length += word.len();
            min_len = min_len.min(word.len());
            max_len = max_len.max(word.len());
            
            // Track character frequency
            for ch in word.chars() {
                *charset_coverage.entry(ch).or_insert(0) += 1;
            }
        }
        
        WordlistStats {
            total_words: wordlist.len(),
            unique_words: wordlist.len(),
            average_length: if wordlist.is_empty() { 0.0 } else { total_length as f64 / wordlist.len() as f64 },
            min_length: if wordlist.is_empty() { 0 } else { min_len },
            max_length: if wordlist.is_empty() { 0 } else { max_len },
            charset_coverage,
            pattern_distribution: HashMap::new(),
            complexity_score: self.calculate_complexity_score(wordlist),
        }
    }

    /// Calculate complexity score based on character diversity
    fn calculate_complexity_score(&self, wordlist: &HashSet<String>) -> f64 {
        let mut score = 0.0;
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_digits = false;
        let mut has_symbols = false;
        
        for word in wordlist {
            for ch in word.chars() {
                if ch.is_lowercase() {
                    has_lowercase = true;
                } else if ch.is_uppercase() {
                    has_uppercase = true;
                } else if ch.is_ascii_digit() {
                    has_digits = true;
                } else if ch.is_ascii_punctuation() {
                    has_symbols = true;
                }
            }
        }
        
        // Each character class adds to complexity
        if has_lowercase { score += 1.0; }
        if has_uppercase { score += 1.0; }
        if has_digits { score += 1.0; }
        if has_symbols { score += 1.0; }
        
        score
    }

    /// Load common passwords from breach databases and research
    /// This includes passwords from major data breaches and security research
    fn load_common_passwords(&mut self) {
        // Top 100 most common passwords from breach analysis
        let breach_passwords = vec![
            "123456", "password", "123456789", "12345678", "12345", "1234567",
            "1234567890", "qwerty", "abc123", "111111", "123123", "admin",
            "letmein", "welcome", "monkey", "1234", "dragon", "master",
            "sunshine", "princess", "football", "iloveyou", "shadow", "michael",
            "jennifer", "computer", "password1", "qwerty123", "password123",
            "trustno1", "freedom", "whatever", "ninja", "mustang", "access",
            "shadow1", "passw0rd", "superman", "batman", "trustno1", "hello",
            "charlie", "aa123456", "donald", "qazwsx", "121212", "bailey",
            "loveme", "login", "starwars", "solo", "flower", "hottie",
            "loveyou", "zaq1zaq1", "password1!", "Password1", "Password123",
            "Admin123", "Welcome1", "Qwerty123", "Letmein1", "Monkey123",
            "Dragon123", "Master123", "Sunshine1", "Football1", "Baseball1",
            "Superman1", "Batman123", "Jordan23", "Hunter2", "Buster1",
            "Summer2024", "Winter2024", "Spring2024", "Fall2024", "January1",
            "February1", "March123", "April123", "May12345", "June1234",
            "July2024", "August24", "September", "October1", "November",
            "December", "Monday123", "Tuesday1", "Wednesday", "Thursday",
            "Friday123", "Saturday", "Sunday123", "Test1234", "Demo1234",
            "Sample123", "Example1", "Default1", "Change123", "Temp1234",
        ];
        
        for password in breach_passwords {
            self.common_passwords.insert(password.to_string());
        }
        
        info!("Loaded {} common passwords from breach databases", self.common_passwords.len());
    }

    /// Load custom words from an external file
    /// Each line in the file is treated as a separate word
    pub fn load_custom_words_from_file(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Loading custom words from: {}", file_path);
        
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut words = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                words.push(trimmed.to_string());
            }
        }
        
        info!("Loaded {} custom words from file", words.len());
        Ok(words)
    }

    /// Apply mutations to imported custom words
    /// This enhances the custom wordlist with common variations
    pub async fn enhance_custom_words(&self, custom_words: &[String]) -> Result<HashSet<String>> {
        info!("Enhancing {} custom words with mutations", custom_words.len());
        
        let mut enhanced = HashSet::new();
        
        for word in custom_words {
            // Original word
            enhanced.insert(word.clone());
            
            // Case variations
            enhanced.insert(word.to_lowercase());
            enhanced.insert(word.to_uppercase());
            
            // Capitalize first letter
            if !word.is_empty() {
                let mut capitalized = word.to_lowercase();
                if let Some(first) = capitalized.get_mut(0..1) {
                    first.make_ascii_uppercase();
                }
                enhanced.insert(capitalized);
            }
            
            // Common numeric suffixes
            for suffix in &["1", "12", "123", "1234", "2024", "2025", "!"] {
                enhanced.insert(format!("{}{}", word, suffix));
                enhanced.insert(format!("{}{}", word.to_lowercase(), suffix));
            }
            
            // Common prefixes
            for prefix in &["my", "the", "admin", "user"] {
                enhanced.insert(format!("{}{}", prefix, word));
                enhanced.insert(format!("{}{}", prefix, word.to_lowercase()));
            }
            
            // Leet speak
            enhanced.insert(self.to_leet_speak(word));
            
            // Reversed
            let reversed: String = word.chars().rev().collect();
            enhanced.insert(reversed);
            
            // With special characters
            enhanced.insert(format!("{}!", word));
            enhanced.insert(format!("{}@", word));
            enhanced.insert(format!("{}#", word));
            enhanced.insert(format!("{}$", word));
            
            // Combined patterns
            enhanced.insert(format!("{}@123", word));
            enhanced.insert(format!("{}#123", word));
            enhanced.insert(format!("{}2024!", word));
        }
        
        info!("Enhanced to {} total variations", enhanced.len());
        Ok(enhanced)
    }

    /// Combine multiple wordlists into a single deduplicated list
    pub async fn combine_wordlists(&self, inputs: Vec<String>, output: &str, _unique: bool, sort: bool) -> Result<()> {
        info!("Combining {} wordlists", inputs.len());
        
        let mut combined = HashSet::new();
        
        for input in inputs {
            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    combined.insert(line.trim().to_string());
                }
            }
        }
        
        let mut words: Vec<String> = combined.into_iter().collect();
        
        if sort {
            words.sort();
        }
        
        let word_count = words.len();
        let mut file = File::create(output)?;
        for word in &words {
            writeln!(file, "{}", word)?;
        }
        
        info!("Combined {} unique words into {}", word_count, output);
        Ok(())
    }

    /// Extract passwords from various file formats
    pub async fn extract_passwords(&self, input: &str, output: &str, format: &str, min_length: usize) -> Result<()> {
        info!("Extracting passwords from: {}", input);
        
        let mut extracted = HashSet::new();
        
        match format {
            "json" => self.extract_from_json(input, &mut extracted, min_length).await?,
            "csv" => self.extract_from_csv(input, &mut extracted, min_length).await?,
            "log" => self.extract_from_log(input, &mut extracted, min_length).await?,
            _ => self.extract_from_text(input, &mut extracted, min_length).await?,
        }
        
        let mut file = File::create(output)?;
        for password in &extracted {
            writeln!(file, "{}", password)?;
        }
        
        info!("Extracted {} passwords to {}", extracted.len(), output);
        Ok(())
    }

    /// Extract passwords from JSON files
    /// Recursively searches for password-like fields
    async fn extract_from_json(&self, input: &str, extracted: &mut HashSet<String>, min_length: usize) -> Result<()> {
        let file = File::open(input)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                self.extract_passwords_from_value(&value, extracted, min_length);
            }
        }
        
        Ok(())
    }

    /// Recursively extract password values from JSON structure
    fn extract_passwords_from_value(&self, value: &Value, extracted: &mut HashSet<String>, min_length: usize) {
        match value {
            Value::String(s) => {
                if s.len() >= min_length && self.looks_like_password(s) {
                    extracted.insert(s.clone());
                }
            }
            Value::Object(obj) => {
                for (key, val) in obj {
                    // Check if field name suggests it contains a password
                    if key.to_lowercase().contains("password") || key.to_lowercase().contains("pass") {
                        if let Value::String(s) = val {
                            if s.len() >= min_length {
                                extracted.insert(s.clone());
                            }
                        }
                    }
                    self.extract_passwords_from_value(val, extracted, min_length);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.extract_passwords_from_value(item, extracted, min_length);
                }
            }
            _ => {}
        }
    }

    /// Heuristic to determine if a string looks like a password
    /// Checks for mixed character types typical of passwords
    fn looks_like_password(&self, s: &str) -> bool {
        if s.len() < 4 {
            return false;
        }
        
        let mut has_letter = false;
        let mut has_digit = false;
        let mut has_special = false;
        
        for ch in s.chars() {
            if ch.is_alphabetic() {
                has_letter = true;
            } else if ch.is_ascii_digit() {
                has_digit = true;
            } else if ch.is_ascii_punctuation() {
                has_special = true;
            }
        }
        
        // Password should have letters and at least one other character type
        has_letter && (has_digit || has_special)
    }

    /// Extract passwords from CSV files
    async fn extract_from_csv(&self, input: &str, extracted: &mut HashSet<String>, min_length: usize) -> Result<()> {
        let file = File::open(input)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            for field in line.split(',') {
                let field = field.trim().trim_matches('"');
                if field.len() >= min_length && self.looks_like_password(field) {
                    extracted.insert(field.to_string());
                }
            }
        }
        
        Ok(())
    }

    /// Extract passwords from log files
    /// Searches for lines containing password-related keywords
    async fn extract_from_log(&self, input: &str, extracted: &mut HashSet<String>, min_length: usize) -> Result<()> {
        let file = File::open(input)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            if line.to_lowercase().contains("password") || line.to_lowercase().contains("pass") {
                let words: Vec<&str> = line.split_whitespace().collect();
                for word in words {
                    if word.len() >= min_length && self.looks_like_password(word) {
                        extracted.insert(word.to_string());
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Extract passwords from plain text files
    async fn extract_from_text(&self, input: &str, extracted: &mut HashSet<String>, min_length: usize) -> Result<()> {
        let file = File::open(input)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            let words: Vec<&str> = line.split_whitespace().collect();
            for word in words {
                if word.len() >= min_length && self.looks_like_password(word) {
                    extracted.insert(word.to_string());
                }
            }
        }
        
        Ok(())
    }

    /// Generate targeted passwords based on OSINT data about a specific target
    /// Creates personalized password candidates using information like names,
    /// company affiliations, birth years, and interests
    pub async fn generate_targeted_passwords(
        &self,
        target_info: &HashMap<String, String>,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating targeted passwords based on intelligence");
        
        let mut candidates = HashSet::new();
        
        // Extract available target intelligence
        let name = target_info.get("name").map(|s| s.as_str()).unwrap_or("");
        let company = target_info.get("company").map(|s| s.as_str()).unwrap_or("");
        let birth_year = target_info.get("birth_year").map(|s| s.as_str()).unwrap_or("");
        let interests = target_info.get("interests").map(|s| s.as_str()).unwrap_or("");
        
        // Generate name-based password candidates
        if !name.is_empty() {
            let name_parts: Vec<&str> = name.split_whitespace().collect();
            
            for part in &name_parts {
                let lower = part.to_lowercase();
                let upper = part.to_uppercase();
                
                candidates.insert(lower.clone());
                candidates.insert(upper);
                candidates.insert(format!("{}123", lower));
                candidates.insert(format!("{}2024", lower));
                
                if !birth_year.is_empty() {
                    candidates.insert(format!("{}{}", lower, birth_year));
                    candidates.insert(format!("{}@{}", lower, birth_year));
                }
            }
            
            // First name + last name combinations
            if name_parts.len() >= 2 {
                let first = name_parts[0].to_lowercase();
                let last = name_parts[1].to_lowercase();
                candidates.insert(format!("{}{}", first, last));
                candidates.insert(format!("{}{}", last, first));
            }
        }
        
        // Company-based password candidates
        if !company.is_empty() {
            let company_lower = company.to_lowercase();
            candidates.insert(company_lower.clone());
            candidates.insert(format!("{}123", company_lower));
            candidates.insert(format!("{}2024", company_lower));
            candidates.insert(format!("{}admin", company_lower));
        }
        
        // Interest-based password candidates
        if !interests.is_empty() {
            for interest in interests.split(',') {
                let clean = interest.trim().to_lowercase();
                candidates.insert(clean.clone());
                candidates.insert(format!("{}123", clean));
                candidates.insert(format!("{}2024", clean));
            }
        }
        
        // Cross-reference patterns combining multiple data points
        if !name.is_empty() && !company.is_empty() {
            let name_lower = name.to_lowercase();
            let company_lower = company.to_lowercase();
            candidates.insert(format!("{}@{}", name_lower, company_lower));
            candidates.insert(format!("{}_{}", name_lower, company_lower));
        }
        
        // Apply leet speak transformations
        let leet_variants: Vec<String> = candidates
            .iter()
            .map(|pwd| self.to_leet_speak(pwd))
            .collect();
        
        candidates.extend(leet_variants);
        
        let mut result: Vec<String> = candidates.into_iter().collect();
        result.sort();
        
        info!("Generated {} targeted password candidates", result.len());
        Ok(result)
    }

    /// Generate a wordlist optimized for password spraying attacks
    /// Focuses on high-probability, policy-compliant passwords
    pub async fn generate_spraying_wordlist(
        &self,
        common_passwords: &[String],
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating password spraying wordlist");
        
        let mut spray_candidates = HashSet::new();
        
        // Top passwords that meet common password policies
        let policy_compliant_passwords = vec![
            "Password123!", "Admin123!", "Welcome123!", "Change123!",
            "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
            "Company2024!", "Password2024!", "12345678!", "qwerty123!",
        ];
        
        for password in policy_compliant_passwords {
            spray_candidates.insert(password.to_string());
        }
        
        // Enhance user-provided passwords with common variations
        for base_password in common_passwords {
            spray_candidates.insert(base_password.clone());
            spray_candidates.insert(format!("{}2024", base_password));
            spray_candidates.insert(format!("{}!", base_password));
            spray_candidates.insert(format!("{}123", base_password));
            
            // Capitalize first letter
            if let Some(first_char) = base_password.chars().next() {
                if first_char.is_lowercase() {
                    let mut capitalized = base_password.clone();
                    if let Some(first_byte) = capitalized.get_mut(0..1) {
                        first_byte.make_ascii_uppercase();
                        spray_candidates.insert(capitalized);
                    }
                }
            }
        }
        
        // Seasonal password patterns
        let seasons = ["Spring", "Summer", "Fall", "Winter"];
        let current_year = "2024";
        
        for season in seasons {
            for base_password in common_passwords.iter().take(50) {
                spray_candidates.insert(format!("{}{}{}", season, base_password, current_year));
                spray_candidates.insert(format!("{}{}{}", base_password, season, current_year));
            }
        }
        
        let mut result: Vec<String> = spray_candidates.into_iter().collect();
        result.sort();
        
        info!("Generated {} passwords for spraying campaign", result.len());
        Ok(result)
    }

    /// Generate a multi-phase brute force strategy
    /// Returns a phased approach from high-probability to complex variations
    pub fn generate_brute_force_strategy(
        &self,
        target_info: &HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<String>>, Box<dyn std::error::Error>> {
        info!("Generating multi-phase brute force strategy");
        
        let mut strategy = HashMap::new();
        
        // Phase 1: Quick wins - most common passwords
        let phase1_quick_wins = vec![
            "password".to_string(),
            "admin".to_string(),
            "123456".to_string(),
            "welcome".to_string(),
            "Password123!".to_string(),
        ];
        strategy.insert("phase1_quick_wins".to_string(), phase1_quick_wins);
        
        // Phase 2: Target-specific passwords
        let mut phase2_targeted = Vec::new();
        if let Some(name) = target_info.get("name") {
            let name_lower = name.to_lowercase();
            phase2_targeted.push(name_lower.clone());
            phase2_targeted.push(format!("{}123", name_lower));
        }
        if let Some(company) = target_info.get("company") {
            let company_lower = company.to_lowercase();
            phase2_targeted.push(company_lower.clone());
            phase2_targeted.push(format!("{}2024", company_lower));
        }
        strategy.insert("phase2_targeted".to_string(), phase2_targeted);
        
        // Phase 3: Seasonal and temporal patterns
        let phase3_patterns = vec![
            "Spring2024".to_string(),
            "Summer2024".to_string(),
            "Fall2024".to_string(),
            "Winter2024".to_string(),
        ];
        strategy.insert("phase3_patterns".to_string(), phase3_patterns);
        
        // Phase 4: Complex variations with special characters
        let mut phase4_complex = Vec::new();
        if let Some(name) = target_info.get("name") {
            let name_lower = name.to_lowercase();
            phase4_complex.push(format!("{}@2024", name_lower));
            phase4_complex.push(format!("{}#2024", name_lower));
            phase4_complex.push(format!("{}$2024", name_lower));
        }
        strategy.insert("phase4_complex".to_string(), phase4_complex);
        
        info!("Generated 4-phase brute force strategy with {} total candidates", 
              strategy.values().map(|v| v.len()).sum::<usize>());
        Ok(strategy)
    }

    /// Generate a credential stuffing wordlist from leaked credential pairs
    /// Extracts passwords and creates variations based on common user behavior
    pub async fn generate_credential_stuffing_list(
        &self,
        leaked_credentials: &[(String, String)],
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating credential stuffing wordlist");
        
        let mut stuffing_candidates = HashSet::new();
        
        // Extract and vary passwords from leaked credential pairs
        for (_username, password) in leaked_credentials {
            stuffing_candidates.insert(password.clone());
            
            // Common modifications users make when reusing passwords
            stuffing_candidates.insert(format!("{}123", password));
            stuffing_candidates.insert(format!("{}2024", password));
            stuffing_candidates.insert(format!("{}!", password));
            
            // Leet speak variations
            stuffing_candidates.insert(self.to_leet_speak(password));
        }
        
        // Include top passwords from major breaches
        let breach_commons = vec![
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "1234567890", "1234", "qwerty", "abc123",
            "Password1", "admin", "letmein", "welcome", "monkey",
        ];
        
        for password in breach_commons {
            stuffing_candidates.insert(password.to_string());
        }
        
        let mut result: Vec<String> = stuffing_candidates.into_iter().collect();
        result.sort();
        
        info!("Generated {} passwords for credential stuffing", result.len());
        Ok(result)
    }

    /// Generate passwords based on keyboard walk patterns
    /// Simulates common typing patterns on QWERTY keyboards
    pub fn generate_keyboard_walks(&self, max_length: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating keyboard walk patterns");
        
        let mut walks = HashSet::new();
        
        // QWERTY keyboard layout rows
        let keyboard_rows = vec![
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
        ];
        
        // Generate walks of different lengths
        for row in &keyboard_rows {
            for start in 0..row.len() {
                for length in 3..=max_length.min(row.len() - start) {
                    let walk = &row[start..start + length];
                    walks.insert(walk.to_string());
                    walks.insert(walk.to_uppercase());
                    
                    // Reverse walks
                    let reversed: String = walk.chars().rev().collect();
                    walks.insert(reversed.clone());
                    walks.insert(reversed.to_uppercase());
                }
            }
        }
        
        // Diagonal walks
        let diagonals = vec![
            "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
            "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn",
            "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
        ];
        
        for diagonal in diagonals {
            walks.insert(diagonal.to_string());
            walks.insert(diagonal.to_uppercase());
            walks.insert(format!("{}123", diagonal));
        }
        
        let mut result: Vec<String> = walks.into_iter().collect();
        result.sort();
        
        info!("Generated {} keyboard walk patterns", result.len());
        Ok(result)
    }

    /// Generate passwords based on date patterns
    /// Common date formats users employ in passwords
    pub fn generate_date_patterns(&self, start_year: u32, end_year: u32) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating date-based password patterns");
        
        let mut dates = HashSet::new();
        
        let months = vec![
            "01", "02", "03", "04", "05", "06",
            "07", "08", "09", "10", "11", "12",
        ];
        
        let month_names = vec![
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        ];
        
        let month_abbrev = vec![
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        
        for year in start_year..=end_year {
            // Year only
            dates.insert(year.to_string());
            
            // Month + Year combinations
            for month in &months {
                dates.insert(format!("{}{}", month, year));
                dates.insert(format!("{}{}", year, month));
                dates.insert(format!("{}/{}", month, year));
                dates.insert(format!("{}-{}", month, year));
            }
            
            // Month names + Year
            for month_name in &month_names {
                dates.insert(format!("{}{}", month_name, year));
                dates.insert(format!("{}{}", month_name.to_lowercase(), year));
            }
            
            // Month abbreviations + Year
            for abbrev in &month_abbrev {
                dates.insert(format!("{}{}", abbrev, year));
                dates.insert(format!("{}{}", abbrev.to_lowercase(), year));
            }
            
            // Common day patterns
            for day in 1..=31 {
                dates.insert(format!("{:02}{:02}{}", day, months[0], year % 100));
                dates.insert(format!("{}{:02}{:02}", year, months[0], day));
            }
        }
        
        // Add common suffixes to dates
        let date_list: Vec<String> = dates.iter().cloned().collect();
        for date in &date_list {
            dates.insert(format!("{}!", date));
            dates.insert(format!("{}@", date));
            dates.insert(format!("{}#", date));
        }
        
        let mut result: Vec<String> = dates.into_iter().collect();
        result.sort();
        
        info!("Generated {} date-based patterns", result.len());
        Ok(result)
    }

    /// Generate passwords based on common name patterns
    /// Uses popular first and last names with common variations
    pub fn generate_name_patterns(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating name-based password patterns");
        
        let mut names = HashSet::new();
        
        let first_names = vec![
            "john", "michael", "david", "james", "robert", "william",
            "mary", "jennifer", "linda", "patricia", "elizabeth", "sarah",
            "admin", "user", "test", "demo", "guest", "root",
        ];
        
        let last_names = vec![
            "smith", "johnson", "williams", "brown", "jones", "garcia",
            "miller", "davis", "rodriguez", "martinez", "anderson", "taylor",
        ];
        
        // Single names with variations
        for name in &first_names {
            names.insert(name.to_string());
            names.insert(name.to_uppercase());
            
            // Capitalize first letter
            let mut capitalized = name.to_string();
            if let Some(first) = capitalized.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            names.insert(capitalized.clone());
            
            // Common suffixes
            names.insert(format!("{}123", name));
            names.insert(format!("{}2024", name));
            names.insert(format!("{}!", name));
            names.insert(format!("{}@123", name));
            names.insert(format!("{}#123", name));
        }
        
        // First + Last name combinations
        for first in &first_names {
            for last in &last_names {
                names.insert(format!("{}{}", first, last));
                names.insert(format!("{}.{}", first, last));
                names.insert(format!("{}_{}", first, last));
                
                // With year
                names.insert(format!("{}{}2024", first, last));
                names.insert(format!("{}{}", first, last.chars().next().unwrap_or('x')));
            }
        }
        
        let mut result: Vec<String> = names.into_iter().collect();
        result.sort();
        
        info!("Generated {} name-based patterns", result.len());
        Ok(result)
    }

    /// Generate passwords based on common phrases and expressions
    /// Includes motivational phrases, greetings, and common expressions
    pub fn generate_phrase_patterns(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating phrase-based password patterns");
        
        let mut phrases = HashSet::new();
        
        let common_phrases = vec![
            "iloveyou", "loveyou", "iloveu", "iluvu",
            "letmein", "welcome", "hello", "goodbye",
            "thankyou", "please", "sorry", "excuse",
            "password", "passw0rd", "p@ssword", "p@ssw0rd",
            "admin", "administrator", "root", "superuser",
            "login", "signin", "access", "enter",
            "secret", "private", "confidential", "secure",
            "trustno1", "trustme", "believeme", "trustnobody",
            "freedom", "liberty", "justice", "peace",
            "sunshine", "rainbow", "butterfly", "flower",
            "starwars", "startrek", "pokemon", "minecraft",
            "football", "baseball", "basketball", "soccer",
        ];
        
        for phrase in &common_phrases {
            phrases.insert(phrase.to_string());
            phrases.insert(phrase.to_uppercase());
            
            // Capitalize first letter
            let mut capitalized = phrase.to_string();
            if let Some(first) = capitalized.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            phrases.insert(capitalized);
            
            // With numbers
            phrases.insert(format!("{}1", phrase));
            phrases.insert(format!("{}123", phrase));
            phrases.insert(format!("{}2024", phrase));
            
            // With special characters
            phrases.insert(format!("{}!", phrase));
            phrases.insert(format!("{}@", phrase));
            phrases.insert(format!("{}#", phrase));
            
            // Leet speak
            phrases.insert(self.to_leet_speak(phrase));
        }
        
        let mut result: Vec<String> = phrases.into_iter().collect();
        result.sort();
        
        info!("Generated {} phrase-based patterns", result.len());
        Ok(result)
    }

    /// Generate passwords based on company and organization patterns
    /// Common patterns used in corporate environments
    pub fn generate_corporate_patterns(&self, company_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Generating corporate password patterns for: {}", company_name);
        
        let mut corporate = HashSet::new();
        
        let company_lower = company_name.to_lowercase();
        let company_upper = company_name.to_uppercase();
        
        // Basic company name variations
        corporate.insert(company_lower.clone());
        corporate.insert(company_upper.clone());
        
        // With years
        for year in 2020..=2025 {
            corporate.insert(format!("{}{}", company_lower, year));
            corporate.insert(format!("{}{}", company_upper, year));
            corporate.insert(format!("{}@{}", company_lower, year));
        }
        
        // With common corporate terms
        let corporate_terms = vec![
            "admin", "user", "guest", "temp", "test",
            "welcome", "password", "login", "access",
            "corp", "company", "enterprise", "business",
        ];
        
        for term in &corporate_terms {
            corporate.insert(format!("{}{}", company_lower, term));
            corporate.insert(format!("{}{}", term, company_lower));
            corporate.insert(format!("{}_{}", company_lower, term));
            corporate.insert(format!("{}@{}", company_lower, term));
        }
        
        // With seasons
        let seasons = vec!["Spring", "Summer", "Fall", "Winter"];
        for season in &seasons {
            corporate.insert(format!("{}{}", company_lower, season));
            corporate.insert(format!("{}{}", season, company_lower));
            corporate.insert(format!("{}{}2024", company_lower, season));
        }
        
        // With special characters and numbers
        corporate.insert(format!("{}123", company_lower));
        corporate.insert(format!("{}!", company_lower));
        corporate.insert(format!("{}@123", company_lower));
        corporate.insert(format!("{}#123", company_lower));
        
        // Policy-compliant variations (8+ chars, mixed case, number, special)
        corporate.insert(format!("{}123!", company_lower.chars().next().unwrap().to_uppercase().to_string() + &company_lower[1..]));
        corporate.insert(format!("Welcome{}!", company_lower));
        corporate.insert(format!("{}@2024", company_lower.chars().next().unwrap().to_uppercase().to_string() + &company_lower[1..]));
        
        let mut result: Vec<String> = corporate.into_iter().collect();
        result.sort();
        
        info!("Generated {} corporate patterns", result.len());
        Ok(result)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Display banner
    display_banner();
    
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { target, output, min_length, max_length, charset, patterns, mutations, complexity, import_file } => {
            let complexity_level = match complexity.as_str() {
                "basic" => ComplexityLevel::Basic,
                "intermediate" => ComplexityLevel::Intermediate,
                "advanced" => ComplexityLevel::Advanced,
                "extreme" => ComplexityLevel::Extreme,
                "quantum" => ComplexityLevel::Quantum,
                _ => ComplexityLevel::Intermediate,
            };
            
            // Load custom words from file if provided
            let custom_words = if let Some(file_path) = import_file {
                println!("{}", format!("📂 Importing custom words from: {}", file_path).bright_yellow());
                match RgenFramework::load_custom_words_from_file(&file_path) {
                    Ok(words) => {
                        println!("{}", format!("✓ Loaded {} custom words", words.len()).bright_green());
                        words
                    }
                    Err(e) => {
                        eprintln!("{}", format!("✗ Error loading custom words: {}", e).bright_red());
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            
            let config = WordlistConfig {
                min_length,
                max_length,
                charset,
                patterns,
                mutations,
                complexity: complexity_level,
                target_based: true,
                common_passwords: true,
                leaked_passwords: false,
                custom_words,
            };
            
            let framework = RgenFramework::new(config);
            let stats = framework.generate_wordlist(&target, &output).await?;
            
            println!();
            println!("{}", "═══════════════════════════════════════════════════════════".bright_cyan());
            println!("{}", "                    GENERATION COMPLETE                    ".bright_green().bold());
            println!("{}", "═══════════════════════════════════════════════════════════".bright_cyan());
            println!("{}", format!("📊 Total words generated: {}", stats.total_words).bright_white());
            println!("{}", format!("📏 Average length: {:.2} characters", stats.average_length).bright_white());
            println!("{}", format!("🔒 Complexity score: {:.2}/4.0", stats.complexity_score).bright_white());
            println!("{}", format!("💾 Output file: {}", output).bright_white());
            println!("{}", "═══════════════════════════════════════════════════════════".bright_cyan());
        }
        
        Commands::Combine { inputs, output, unique, sort } => {
            println!("{}", format!("🔗 Combining {} wordlists...", inputs.len()).bright_yellow());
            
            let config = WordlistConfig {
                min_length: 0,
                max_length: 1000,
                charset: String::new(),
                patterns: Vec::new(),
                mutations: Vec::new(),
                complexity: ComplexityLevel::Basic,
                target_based: false,
                common_passwords: false,
                leaked_passwords: false,
                custom_words: Vec::new(),
            };
            
            let framework = RgenFramework::new(config);
            framework.combine_wordlists(inputs, &output, unique, sort).await?;
            
            println!("{}", format!("✓ Wordlists combined successfully!").bright_green());
        }
        
        Commands::Mutate { input, output, mutations, depth: _ } => {
            println!("{}", format!("🔄 Applying {} mutations to wordlist...", mutations.len()).bright_yellow());
            
            let config = WordlistConfig {
                min_length: 0,
                max_length: 1000,
                charset: String::new(),
                patterns: Vec::new(),
                mutations,
                complexity: ComplexityLevel::Intermediate,
                target_based: false,
                common_passwords: false,
                leaked_passwords: false,
                custom_words: Vec::new(),
            };
            
            let framework = RgenFramework::new(config);
            
            // Load existing wordlist
            let mut wordlist = HashSet::new();
            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    wordlist.insert(line.trim().to_string());
                }
            }
            
            println!("{}", format!("📖 Loaded {} words from input file", wordlist.len()).bright_white());
            
            // Apply mutations
            for mutation in &framework.config.mutations {
                framework.apply_mutation(&mut wordlist, mutation).await?;
            }
            
            // Save mutated wordlist
            framework.save_wordlist(&wordlist, &output).await?;
            
            println!("{}", format!("✓ Mutated wordlist saved to {}", output).bright_green());
            println!("{}", format!("📊 Final word count: {}", wordlist.len()).bright_white());
        }
        
        Commands::Pattern { pattern, output, count: _, charset } => {
            println!("{}", format!("🎯 Generating pattern-based wordlist: {}", pattern).bright_yellow());
            
            let config = WordlistConfig {
                min_length: 0,
                max_length: 1000,
                charset,
                patterns: vec![pattern],
                mutations: Vec::new(),
                complexity: ComplexityLevel::Basic,
                target_based: false,
                common_passwords: false,
                leaked_passwords: false,
                custom_words: Vec::new(),
            };
            
            let framework = RgenFramework::new(config.clone());
            let mut wordlist = HashSet::new();
            framework.generate_pattern_based(&mut wordlist, &framework.config.patterns[0]).await?;
            framework.save_wordlist(&wordlist, &output).await?;
            
            println!("{}", format!("✓ Pattern-based wordlist generated: {} words", wordlist.len()).bright_green());
        }
        
        Commands::Extract { input, output, format, min_length } => {
            let config = WordlistConfig {
                min_length,
                max_length: 1000,
                charset: String::new(),
                patterns: Vec::new(),
                mutations: Vec::new(),
                complexity: ComplexityLevel::Basic,
                target_based: false,
                common_passwords: false,
                leaked_passwords: false,
                custom_words: Vec::new(),
            };
            
            let framework = RgenFramework::new(config);
            framework.extract_passwords(&input, &output, &format, min_length).await?;
            
            println!("Passwords extracted to {}", output);
        }
        
        Commands::Analyze { input, output, detailed } => {
            let config = WordlistConfig {
                min_length: 0,
                max_length: 1000,
                charset: String::new(),
                patterns: Vec::new(),
                mutations: Vec::new(),
                complexity: ComplexityLevel::Basic,
                target_based: false,
                common_passwords: false,
                leaked_passwords: false,
                custom_words: Vec::new(),
            };
            
            let framework = RgenFramework::new(config);
            
            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            
            let mut wordlist = HashSet::new();
            for line in reader.lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    wordlist.insert(line.trim().to_string());
                }
            }
            
            let stats = framework.calculate_stats(&wordlist);
            
            println!("📊 Wordlist Analysis:");
            println!("Total words: {}", stats.total_words);
            println!("Average length: {:.2}", stats.average_length);
            println!("Min length: {}", stats.min_length);
            println!("Max length: {}", stats.max_length);
            println!("Complexity score: {:.2}", stats.complexity_score);
            
            if detailed {
                println!("Charset coverage:");
                for (ch, count) in &stats.charset_coverage {
                    println!("  '{}': {}", ch, count);
                }
            }
            
            if let Some(output_path) = output {
                let stats_json = serde_json::to_string_pretty(&stats)?;
                std::fs::write(&output_path, stats_json)?;
                println!("Detailed analysis saved to {}", output_path);
            }
        }
    }
    
    Ok(())
}
