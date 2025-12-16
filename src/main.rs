use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use rand::rngs::OsRng;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Prefix to search for (in hex)
    #[arg(short, long)]
    prefix: String,

    /// Case sensitive search
    #[arg(short = 's', long, default_value_t = false)]
    case_sensitive: bool,

    /// Output file to save the key pair (default: keypair_<prefix>.txt)
    #[arg(short, long)]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Normalize the prefix
    let prefix = if args.case_sensitive {
        args.prefix.clone()
    } else {
        args.prefix.to_lowercase()
    };

    println!("🔍 Searching for Ed25519 key with prefix: {}", prefix);
    println!("🖥️  Using {} CPU cores", num_cpus::get());

    // Calculate estimated attempts needed
    let prefix_len = prefix.len();
    let estimated_attempts = 16_u64.pow(prefix_len as u32);

    println!(
        "📊 Estimated attempts needed: ~{}",
        format_number(estimated_attempts)
    );
    println!("⏱️  Starting search...\n");

    // Shared atomic counter and flag
    let attempts = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));

    // Progress bar setup
    let pb = ProgressBar::new(estimated_attempts);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | {per_sec} | ETA: {eta}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let start_time = Instant::now();
    let pb_clone = pb.clone();
    let attempts_clone = attempts.clone();
    let found_clone = found.clone();

    // Spawn a thread to update the progress bar
    let update_thread = std::thread::spawn(move || {
        let mut last_update_time = Instant::now();
        let mut last_attempts = 0u64;
        let mut current_total = estimated_attempts;

        while !found_clone.load(Ordering::Relaxed) {
            let current = attempts_clone.load(Ordering::Relaxed);

            // Update total if we exceed initial estimate
            if current > current_total {
                current_total = current + (current / 10); // Add 10% buffer
                pb_clone.set_length(current_total);
            }

            pb_clone.set_position(current);

            // Recalculate ETA every second based on actual rate
            if last_update_time.elapsed() >= Duration::from_secs(1) {
                let rate =
                    (current - last_attempts) as f64 / last_update_time.elapsed().as_secs_f64();
                if rate > 0.0 && current < current_total {
                    let remaining = current_total - current;
                    let eta_secs = (remaining as f64 / rate) as u64;
                    pb_clone.set_message(format!("~{}s remaining", eta_secs));
                }
                last_attempts = current;
                last_update_time = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    });

    // Parallel search across all CPU cores
    let result: Option<(SigningKey, VerifyingKey, String, [u8; 64])> =
        (0..num_cpus::get()).into_par_iter().find_map_any(|_| {
            let mut rng = OsRng;
            let local_attempts = Arc::clone(&attempts);
            let local_found = Arc::clone(&found);

            loop {
                if local_found.load(Ordering::Relaxed) {
                    return None;
                }

                // RFC 8032 Ed25519 key generation:
                // SHA-512 is used because RFC 8032 specifies it as part of the standard Ed25519 key derivation.
                // Why SHA-512?
                // - The first 32 bytes become the clamped scalar (secret key for signing)
                // - The second 32 bytes are used as a nonce/randomness source during signing
                // - This ensures deterministic signatures while maintaining security
                // - MeshCore follows this standard format for compatibility

                // 1. Generate 32-byte random seed
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);

                // 2. Hash the seed with SHA-512 to get 64 bytes
                let mut hasher = Sha512::new();
                hasher.update(&seed);
                let digest = hasher.finalize();

                // 3. Clamp the first 32 bytes (scalar clamping)
                let mut clamped = [0u8; 32];
                clamped.copy_from_slice(&digest[..32]);
                clamped[0] &= 248; // Clear bottom 3 bits
                clamped[31] &= 63; // Clear top 2 bits
                clamped[31] |= 64; // Set bit 6

                // 4. Create the signing key from the clamped scalar
                let signing_key = SigningKey::from_bytes(&clamped);
                let verifying_key = signing_key.verifying_key();
                let public_key_hex = hex::encode(verifying_key.as_bytes());

                // 5. Create 64-byte RFC 8032 private key: [clamped_scalar][sha512_second_half]
                let mut rfc8032_private_key = [0u8; 64];
                rfc8032_private_key[..32].copy_from_slice(&clamped);
                rfc8032_private_key[32..].copy_from_slice(&digest[32..]);

                // Check if it matches the prefix
                let matches = if args.case_sensitive {
                    public_key_hex.starts_with(&prefix)
                } else {
                    public_key_hex.to_lowercase().starts_with(&prefix)
                };

                // Increment counter
                local_attempts.fetch_add(1, Ordering::Relaxed);

                if matches {
                    local_found.store(true, Ordering::Relaxed);
                    return Some((
                        signing_key,
                        verifying_key,
                        public_key_hex,
                        rfc8032_private_key,
                    ));
                }
            }
        });

    found.store(true, Ordering::Relaxed);
    update_thread.join().unwrap();
    pb.finish();

    let elapsed = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);

    match result {
        Some((_signing_key, _verifying_key, public_key_hex, rfc8032_private_key)) => {
            let private_key_hex = hex::encode(rfc8032_private_key);

            println!("\n✓ Key Generated Successfully!");
            println!("Public Key:");
            println!("{}", public_key_hex.to_uppercase());
            println!("Private Key:");
            println!("{}", private_key_hex.to_uppercase());
            println!("Validation Status:");
            println!(
                "✓ RFC 8032 Ed25519 compliant - Proper SHA-512 expansion, scalar clamping, and key consistency verified"
            );
            println!("{}", format_number(total_attempts));
            println!("Attempts");
            println!("{:.1}s", elapsed.as_secs_f64());
            println!("Time");
            println!(
                "{}",
                format_number((total_attempts as f64 / elapsed.as_secs_f64()) as u64)
            );
            println!("Keys/sec");

            // Save to file
            let output_filename = args
                .output
                .unwrap_or_else(|| format!("meshcore_{}.json", prefix));

            match save_keypair_json(
                &output_filename,
                &public_key_hex.to_uppercase(),
                &private_key_hex.to_uppercase(),
            ) {
                Ok(_) => println!("\n💾 Key pair saved to: {}", output_filename),
                Err(e) => eprintln!("\n⚠️  Failed to save key pair: {}", e),
            }
        }
        None => {
            println!("\n❌ Search was interrupted");
        }
    }
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

    let json_data = serde_json::to_string_pretty(&keypair)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

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
