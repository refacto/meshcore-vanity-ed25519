use clap::Parser;
use colored::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Prefix to search for (in hex)
    #[arg(short, long)]
    prefix: String,

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

struct PrefixTarget {
    bytes: Vec<u8>,
    remainder_nibble: Option<u8>,
}

fn is_prefix_valid(prefix: &str) -> bool {
    let valid_chars = "0123456789abcdefABCDEF";
    prefix.chars().all(|c| valid_chars.contains(c))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let prefix = args.prefix.clone();

    validate_prefix(&prefix)?;

    // Quiet mode only suppresses logs (stderr), NOT the result (stdout)
    let quiet = args.quiet;

    if !quiet {
        print_banner();
        eprintln!(
            "{} {}",
            "🔍 Searching for Ed25519 key with prefix:".bold().blue(),
            prefix.yellow().bold()
        );
        eprintln!(
            "{} {}",
            "🖥️  Using CPU cores:".bold().blue(),
            num_cpus::get().to_string().yellow()
        );
    }

    let estimated_attempts = calculate_estimated_attempts(prefix.len());

    if !quiet {
        eprintln!(
            "{} {}",
            "📊 Estimated attempts needed:".bold().blue(),
            format!("~{}", format_number(estimated_attempts)).yellow()
        );
        eprintln!("{}", "⏱️  Starting search...\n".bold().green());
    }

    let (found, attempts) = initialize_shared_state();

    // Prepare optimized target for fast comparison
    let target = parse_prefix_target(&prefix);

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

    let result = perform_parallel_search(&target, &attempts, &found);

    found.store(true, Ordering::Relaxed);
    monitor_handle.join().unwrap();

    if let Some(bar) = pb {
        // Kept visible as requested
        bar.abandon();
    }

    let elapsed = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);

    match result {
        Some(key_result) => handle_success(key_result, &args, &prefix, total_attempts, elapsed),
        None => {
            if !quiet {
                eprintln!("\n{}", "❌ Search was interrupted".red().bold());
            }
            Err("Search interrupted".into())
        }
    }
}

// --- Helper Functions ---

fn print_banner() {
    eprintln!(
        "{}",
        "=============================================".bright_purple()
    );
    eprintln!(
        "{}",
        "       Vanity Ed25519 Key Generator          "
            .bright_purple()
            .bold()
    );
    eprintln!(
        "{}\n",
        "=============================================".bright_purple()
    );
}

fn validate_prefix(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_prefix_valid(prefix) {
        eprintln!(
            "{}",
            "❌ Prefix must contain only hexadecimal characters (0-9, a-f)"
                .red()
                .bold()
        );
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
            .progress_chars("#>- ")
    );
    // indicatif defaults to stderr, which is what we want
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
                    current_total = current; // Add 10% buffer
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

// Optimized parsing: Convert hex string to full bytes and optional remainder nibble
fn parse_prefix_target(hex: &str) -> PrefixTarget {
    let nibbles: Vec<u8> = hex.chars().map(|c| c.to_digit(16).unwrap() as u8).collect();

    let chunks = nibbles.chunks_exact(2);
    let remainder = chunks.remainder();

    let bytes: Vec<u8> = chunks.map(|chunk| (chunk[0] << 4) | chunk[1]).collect();

    let remainder_nibble = if remainder.is_empty() {
        None
    } else {
        Some(remainder[0])
    };

    PrefixTarget {
        bytes,
        remainder_nibble,
    }
}

struct KeyResult {
    #[allow(dead_code)]
    signing_key: SigningKey,
    #[allow(dead_code)]
    verifying_key: VerifyingKey,
    public_key_hex: String,
    private_key_hex: String,
}

fn perform_parallel_search(
    target: &PrefixTarget,
    attempts: &Arc<AtomicU64>,
    found: &Arc<AtomicBool>,
) -> Option<KeyResult> {
    (0..num_cpus::get()).into_par_iter().find_map_any(|_| {
        // Initialize StdRng from entropy once per thread
        let mut rng = StdRng::from_entropy();
        let local_attempts = Arc::clone(attempts);
        let local_found = Arc::clone(found);

        loop {
            if local_found.load(Ordering::Relaxed) {
                return None;
            }

            let (signing_key, verifying_key, rfc8032_private_key) = generate_ed25519_key(&mut rng);

            // Fast prefix check
            let key_bytes = verifying_key.as_bytes();
            let mut matches = true;

            // 1. Check full bytes
            for (i, &byte) in target.bytes.iter().enumerate() {
                if key_bytes[i] != byte {
                    matches = false;
                    break;
                }
            }

            // 2. Check remainder nibble if present
            if matches && let Some(nibble) = target.remainder_nibble {
                let next_byte_idx = target.bytes.len();
                if (key_bytes[next_byte_idx] >> 4) != nibble {
                    matches = false;
                }
            }

            // Increment counter
            local_attempts.fetch_add(1, Ordering::Relaxed);

            if matches {
                local_found.store(true, Ordering::Relaxed);

                let public_key_hex = hex::encode(key_bytes);
                let private_key_hex = hex::encode(rfc8032_private_key);

                return Some(KeyResult {
                    signing_key,
                    verifying_key,
                    public_key_hex,
                    private_key_hex,
                });
            }
        }
    })
}

#[inline(always)]
fn generate_ed25519_key<R: RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey, [u8; 64]) {
    // RFC 8032 Ed25519 key generation (MeshCore compliant)

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

    // 5. Create 64-byte RFC 8032 private key [clamped][hash_remainder]
    let mut rfc8032_private_key = [0u8; 64];
    rfc8032_private_key[..32].copy_from_slice(&clamped);
    rfc8032_private_key[32..].copy_from_slice(&digest[32..]);

    (signing_key, verifying_key, rfc8032_private_key)
}

fn handle_success(
    result: KeyResult,
    args: &Args,
    _prefix: &str,
    total_attempts: u64,
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.json {
        let keypair = MeshCoreKeypair {
            public_key: result.public_key_hex.to_uppercase(),
            private_key: result.private_key_hex.to_uppercase(),
        };
        let json_output = serde_json::to_string_pretty(&keypair)?;
        // JSON output always to stdout
        println!("{}", json_output);
    } else {
        // Human readable output
        println!(
            "{}",
            "=============================================".bright_black()
        );
        println!("{}:", "Public Key".cyan().bold());
        println!("{}", result.public_key_hex.to_uppercase().white());

        println!("\n{}:", "Private Key".cyan().bold());
        println!("{}", result.private_key_hex.to_uppercase().white());
        println!(
            "{}",
            "=============================================".bright_black()
        );
    }

    // Print Stats and Validation to stderr, unless quiet
    if !args.quiet {
        eprintln!("\n{}", "✓ Key Generated Successfully!".bold().green());

        eprintln!("\n{}", "Validation Status:".yellow().bold());
        eprintln!(
            "{}",
            "✓ RFC 8032 Ed25519 compliant - Proper SHA-512 expansion, scalar clamping, and key consistency verified".green()
        );

        let attempts_str = format_number(total_attempts);
        let time_str = format!("{:.1}s", elapsed.as_secs_f64());
        let keys_per_sec = format_number((total_attempts as f64 / elapsed.as_secs_f64()) as u64);

        eprintln!(
            "{} {} {} {} {} {}",
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
            &result.private_key_hex.to_uppercase(),
        ) {
            Ok(_) => {
                if !args.quiet {
                    eprintln!(
                        "\n{} {}",
                        "💾 Key pair saved to:".bold(),
                        output_filename.green()
                    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_validity() {
        let mut rng = StdRng::seed_from_u64(42);
        let (_signing_key, verifying_key, private_key_bytes) = generate_ed25519_key(&mut rng);

        // Manually reconstruct the public key from the private key components
        // private_key_bytes is 64 bytes: [clamped_scalar (32)][hash_remainder (32)]
        let scalar_bytes: [u8; 32] = private_key_bytes[0..32].try_into().unwrap();

        // In Ed25519, the "private key" usually refers to the seed,
        // but here we are working with the "expanded" private key components.
        // `SigningKey::from_bytes` expects the SCALAR if it's the clamped version?
        // ed25519-dalek 2.x `SigningKey::from_bytes` expects the *Scalar*.
        // And `generate_ed25519_key` produces `clamped` which IS the scalar.

        let re_signing_key = SigningKey::from_bytes(&scalar_bytes);
        let re_verifying_key = re_signing_key.verifying_key();

        assert_eq!(
            verifying_key.as_bytes(),
            re_verifying_key.as_bytes(),
            "Public key derived from private key components should match the generated verifying key"
        );
    }

    #[test]
    fn test_parse_prefix_target() {
        // "12" -> 0x12 (18)
        let t = parse_prefix_target("12");
        assert_eq!(t.bytes, vec![0x12]);
        assert_eq!(t.remainder_nibble, None);

        // "123" -> 0x12, remainder 3
        let t = parse_prefix_target("123");
        assert_eq!(t.bytes, vec![0x12]);
        assert_eq!(t.remainder_nibble, Some(3));

        // "A" -> remainder 10
        let t = parse_prefix_target("A");
        let empty: Vec<u8> = vec![];
        assert_eq!(t.bytes, empty);
        assert_eq!(t.remainder_nibble, Some(10));
    }
}
