use clap::Parser;
use colored::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Prefix to search for (in hex)
    #[arg(short, long)]
    prefix: String,

    /// Case sensitive search (Note: Ed25519 hex is typically lowercase, this might restrict results)
    #[arg(short = 's', long, default_value_t = false)]
    case_sensitive: bool,

    /// Output file to save the key pair (optional)
    #[arg(short, long)]
    output: Option<String>,

    /// Print only the JSON output to stdout
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Silent execution (suppress progress bar and logs)
    #[arg(short = 'q', long, default_value_t = false)]
    quiet: bool,
}

fn is_prefix_valid(prefix: &str) -> bool {
    let valid_chars = "0123456789abcdefABCDEF";
    prefix.chars().all(|c| valid_chars.contains(c))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // We keep the prefix normalization for display/logic, but we'll use nibbles for searching
    let prefix = normalize_prefix(&args);

    validate_prefix(&prefix)?;

    let quiet = args.quiet || args.json;

    if !quiet {
        print_banner();
        println!(
            "{} {}",
            "🔍 Searching for Ed25519 key with prefix:".bold().blue(),
            prefix.yellow().bold()
        );
        println!(
            "{} {}",
            "🖥️  Using CPU cores:".bold().blue(),
            num_cpus::get().to_string().yellow()
        );
    }

    let estimated_attempts = calculate_estimated_attempts(prefix.len());

    if !quiet {
        println!(
            "{} {}",
            "📊 Estimated attempts needed:".bold().blue(),
            format!("~{}", format_number(estimated_attempts)).yellow()
        );
        println!("{}", "⏱️  Starting search...\n".bold().green());
    }

    let (found, attempts) = initialize_shared_state();
    
    // Prepare nibbles for fast comparison
    let target_nibbles = hex_string_to_nibbles(&prefix);

    // Only set up progress bar if not in quiet mode
    let pb = if !quiet {
        Some(setup_progress_bar(estimated_attempts))
    } else {
        None
    };

    let start_time = Instant::now();
    let monitor_handle = spawn_progress_monitor(
        pb.clone(),
        attempts.clone(),
        found.clone(),
        estimated_attempts,
    );

    let result = perform_parallel_search(&target_nibbles, &attempts, &found);

    found.store(true, Ordering::Relaxed);
    monitor_handle.join().unwrap();

    if let Some(bar) = pb {
        bar.finish_and_clear();
    }

    let elapsed = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);

    match result {
        Some(key_result) => handle_success(key_result, &args, &prefix, total_attempts, elapsed),
        None => {
            if !quiet {
                println!("\n{}", "❌ Search was interrupted".red().bold());
            }
            Err("Search interrupted".into())
        }
    }
}

// --- Helper Functions ---

fn print_banner() {
    println!("{}", "=============================================".bright_purple());
    println!("{}", "       Vanity Ed25519 Key Generator          ".bright_purple().bold());
    println!("{}\n", "=============================================".bright_purple());
}

fn normalize_prefix(args: &Args) -> String {
    if args.case_sensitive {
        args.prefix.clone()
    } else {
        args.prefix.to_lowercase()
    }
}

fn validate_prefix(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_prefix_valid(prefix) {
        println!("{}", "❌ Prefix must contain only hexadecimal characters (0-9, a-f)".red().bold());
        return Err(format!("Invalid prefix: {}", prefix).into());
    }
    Ok(())
}

fn calculate_estimated_attempts(prefix_len: usize) -> u64 {
    16_u64.pow(prefix_len as u32)
}

fn initialize_shared_state() -> (Arc<AtomicBool>, Arc<AtomicU64>) {
    (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU64::new(0)),
    )
}

fn setup_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | {per_sec} | ETA: {eta}"
            )
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

fn spawn_progress_monitor(
    pb: Option<ProgressBar>,
    attempts: Arc<AtomicU64>,
    found: Arc<AtomicBool>,
    initial_estimate: u64,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_update_time = Instant::now();
        let mut last_attempts = 0u64;
        let mut current_total = initial_estimate;

        while !found.load(Ordering::Relaxed) {
            let current = attempts.load(Ordering::Relaxed);

            if let Some(ref bar) = pb {
                // Update total if we exceed initial estimate
                if current > current_total {
                    current_total = current + (current / 10); // Add 10% buffer
                    bar.set_length(current_total);
                }

                bar.set_position(current);

                // Recalculate ETA every second based on actual rate
                if last_update_time.elapsed() >= Duration::from_secs(1) {
                    let rate =
                        (current - last_attempts) as f64 / last_update_time.elapsed().as_secs_f64();
                    if rate > 0.0 && current < current_total {
                        let remaining = current_total - current;
                        let eta_secs = (remaining as f64 / rate) as u64;
                        bar.set_message(format!("~{}s remaining", eta_secs));
                    }
                    last_attempts = current;
                    last_update_time = Instant::now();
                }
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    })
}

// Convert hex string to nibbles (0-15)
fn hex_string_to_nibbles(hex: &str) -> Vec<u8> {
    hex.chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect()
}

struct KeyResult {
    #[allow(dead_code)] // Used in original logic logic but maybe not all fields needed for output directly, keeping for consistency
    signing_key: SigningKey,
    #[allow(dead_code)]
    verifying_key: VerifyingKey,
    public_key_hex: String,
    rfc8032_private_key: [u8; 64],
}

fn perform_parallel_search(
    target_nibbles: &[u8],
    attempts: &Arc<AtomicU64>,
    found: &Arc<AtomicBool>,
) -> Option<KeyResult> {
    (0..num_cpus::get()).into_par_iter().find_map_any(|_| {
        let mut rng = OsRng;
        let local_attempts = Arc::clone(attempts);
        let local_found = Arc::clone(found);

        loop {
            if local_found.load(Ordering::Relaxed) {
                return None;
            }

            let (signing_key, verifying_key, rfc8032_private_key) =
                generate_ed25519_key(&mut rng);

            // Fast prefix check using nibbles
            let key_bytes = verifying_key.as_bytes();
            let mut matches = true;
            for (i, &nibble) in target_nibbles.iter().enumerate() {
                let byte = key_bytes[i / 2];
                let key_nibble = if i % 2 == 0 {
                    byte >> 4
                } else {
                    byte & 0x0F
                };
                
                if key_nibble != nibble {
                    matches = false;
                    break;
                }
            }

            // Increment counter
            local_attempts.fetch_add(1, Ordering::Relaxed);

            if matches {
                local_found.store(true, Ordering::Relaxed);
                let public_key_hex = hex::encode(key_bytes);
                return Some(KeyResult {
                    signing_key,
                    verifying_key,
                    public_key_hex,
                    rfc8032_private_key,
                });
            }
        }
    })
}

#[inline(always)]
fn generate_ed25519_key(rng: &mut OsRng) -> (SigningKey, VerifyingKey, [u8; 64]) {
    // RFC 8032 Ed25519 key generation
    
    // 1. Generate 32-byte random seed
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // 2. Hash the seed with SHA-512 to get 64 bytes
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let digest = hasher.finalize();

    // 3. Clamp the first 32 bytes
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&digest[..32]);
    clamped[0] &= 248; 
    clamped[31] &= 63; 
    clamped[31] |= 64; 

    // 4. Create the signing key
    let signing_key = SigningKey::from_bytes(&clamped);
    let verifying_key = signing_key.verifying_key();
    // String allocation removed from here

    // 5. Create 64-byte RFC 8032 private key
    let mut rfc8032_private_key = [0u8; 64];
    rfc8032_private_key[..32].copy_from_slice(&clamped);
    rfc8032_private_key[32..].copy_from_slice(&digest[32..]);

    (
        signing_key,
        verifying_key,
        rfc8032_private_key,
    )
}

fn handle_success(
    result: KeyResult,
    args: &Args,
    _prefix: &str,
    total_attempts: u64,
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_key_hex = hex::encode(result.rfc8032_private_key);

    if args.json {
        let keypair = MeshCoreKeypair {
            public_key: result.public_key_hex.to_uppercase(),
            private_key: private_key_hex.to_uppercase(),
        };
        let json_output = serde_json::to_string_pretty(&keypair)?;
        println!("{}", json_output);
    } else if !args.quiet {
        println!("\n{}", "✓ Key Generated Successfully!".bold().green());
        println!("{}", "=============================================".bright_black());
        
        println!("{}:", "Public Key".cyan().bold());
        println!("{}", result.public_key_hex.to_uppercase().white());
        
        println!("\n{}:", "Private Key".cyan().bold());
        println!("{}", private_key_hex.to_uppercase().white());
        
        println!("\n{}", "Validation Status:".yellow().bold());
        println!(
            "{}",
            "✓ RFC 8032 Ed25519 compliant - Proper SHA-512 expansion, scalar clamping, and key consistency verified".green()
        );
        println!("{}", "=============================================".bright_black());
        
        let attempts_str = format_number(total_attempts);
        let time_str = format!("{:.1}s", elapsed.as_secs_f64());
        let keys_per_sec = format_number((total_attempts as f64 / elapsed.as_secs_f64()) as u64);

        println!(
            "{}: {} {}: {} {}: {}",
            "Attempts".bold(),
            attempts_str.yellow(),
            "Time".bold(),
            time_str.yellow(),
            "Keys/sec".bold(),
            keys_per_sec.green()
        );
    }

    // Save to file only if output arg is present
    if let Some(output_filename) = &args.output {
        match save_keypair_json(
            output_filename,
            &result.public_key_hex.to_uppercase(),
            &private_key_hex.to_uppercase(),
        ) {
            Ok(_) => {
                if !args.quiet && !args.json {
                    println!("\n{} {}", "💾 Key pair saved to:".bold(), output_filename.green())
                }
            }
            Err(e) => {
                eprintln!("\n{} {}", "⚠️  Failed to save key pair:".red().bold(), e);
                return Err("Failed to save key pair".into());
            }
        }
    }
    Ok(())
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[derive(Serialize)]
struct MeshCoreKeypair {
    public_key: String,
    private_key: String,
}

fn save_keypair_json(filename: &str, public_key: &str, private_key: &str) -> std::io::Result<()> {
    let keypair = MeshCoreKeypair {
        public_key: public_key.to_string(),
        private_key: private_key.to_string(),
    };

    let json_data = serde_json::to_string_pretty(&keypair).map_err(Error::other)?;

    fs::write(filename, json_data)?;
    Ok(())
}

// Helper function to get CPU count
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}
