# Vanity Ed25519 Key Generator for MeshCore

A high-performance CLI tool written in Rust for generating vanity Ed25519 key pairs. Optimized specifically for modern CPUs, achieving orders of magnitude faster search speeds than web-based alternatives.

Designed to produce keys compatible with **MeshCore** requirements (64-byte private keys).

## 🚀 Performance

| Tool | Speed (approx.) | System |
|------|-----------------|--------|
| [Web Generator](https://gessaman.com/mc-keygen/) | ~8,000 keys/sec | Microsoft Edge 143.0.3650.66, 13th Gen Intel(R) Core(TM) i9-13950HX, 32 CPU threads, 30GiB RAM, Linux |
| **vanity_ed25519** | **~650,000+ keys/sec** | 13th Gen Intel(R) Core(TM) i9-13950HX, 32 CPU threads, 30GiB RAM, Linux, rustc 1.92.0 |
| **vanity_ed25519** | **~1,500,000+ keys/sec** | AMD Ryzen 9 7950X 16-Core Processor, 32 CPU threads, 30GiB RAM, Arch Linux, rustc 1.92.0 |


This tool utilizes:
- **Native CPU Instructions:** Auto-detects and uses AVX2/SIMD via `.cargo/config.toml`.
- **Parallelism:** Saturates all available CPU threads using `rayon`.
- **ASM Acceleration:** Uses assembly-optimized SHA-512 implementations.
- **Zero Allocation Loop:** Optimized hot-loop with no heap allocations.

## 📦 Installation

Ensure you have [Rust installed](https://rustup.rs/).

```bash
git clone https://github.com/Nachtalb/meshcore-vanity-ed25519.git
cd vanity_ed25519

# Build and install locally
cargo install --path .
```

*Note: The build configuration is set to automatically enable native CPU optimizations (AVX2, etc.) for maximum speed.*

## 🛠️ Usage

### Basic Search
Search for a public key starting with `DEAD`:
```bash
vanity_ed25519 --prefix DEAD
```

### Save to File
Save the resulting JSON keypair to a file:
```bash
vanity_ed25519 --prefix CAFE --output my_key.json
```

### Quiet / JSON Mode
Useful for piping into other tools:
```bash
vanity_ed25519 --prefix 1234 --json --quiet > key.json
```

### Full Options
```text
Usage: vanity_ed25519 [OPTIONS] --prefix <PREFIX>

Options:
  -p, --prefix <PREFIX>  Prefix to search for (in hex)
  -o, --output <OUTPUT>  Output file to save the key pair (optional)
      --json             Print only the JSON output to stdout
  -q, --quiet            Silent execution (suppress progress bar and logs)
  -h, --help             Print help
  -V, --version          Print version
```

## 🔐 MeshCore Compatibility

This tool generates keys strictly adhering to the MeshCore format requirements:

- **Public Key:** 32 bytes (64 hex characters)
- **Private Key:** 64 bytes (128 hex characters)
    - Composed of `[clamped_scalar (32 bytes)] || [hash_extension (32 bytes)]`.
- **Validation:** Internal tests verify RFC 8032 compliance and key pair mathematical validity.

## 📄 License

LGPL-3.0
