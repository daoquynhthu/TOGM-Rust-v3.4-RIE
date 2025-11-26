# Threshold OTP Group Messaging (TOGM) v3.4 Reinforced Initialization & Entropy Integrity Edition (RIE)

**Core Security Properties: Reinforced Initialization and Entropy Integrity**

*Anonymous Geek Collective*  
*November 23, 2025*

## Overview

TOGM v3.4 RIE enhances the initialization process through Multi-Source Entropy Aggregation (MSEA), Universal Hash extraction, and full NIST SP 800-90B validation. The protocol is implemented in Rust with a modular, no_std core, ensuring no external cryptographic dependencies and portability across anonymity networks like Tor and I2P.

The Master Pad is constructed via BGW MPC over GF(2^8), providing information-theoretic security: under the assumption of at least one honest hardware entropy source, the gigabyte-scale pad maintains statistical uniformity (SD ≤ 2^{-80}) even if drand is compromised and up to t-1 devices are backdoored. The design adapts entropy sourcing based on group size—continuous drand for small groups (n ≤ 50) and aggregated hardware noise for large groups (n > 50)—while DBAP enforces device integrity across local, pairwise, and threshold layers.

Key features include SIMD-optimized XOR in core/xor.rs, asynchronous bootstrap in protocol/bootstrap/orchestrator.rs, and watchdog anomaly detection. Post-bootstrap, the system operates fully offline, with pure OTP per 4096-byte block and SIP for integrity.
**Repository**: https://github.com/daoquynhthu/TOGM-Rust-v3.4-RIE 

## Security Properties

| Property                  | Status          | Notes |
|---------------------------|-----------------|-------|
| Perfect Secrecy           | Yes (unconditional) | Pure OTP; total plaintext ≤ Master Pad size (`pad/usage_stats.rs` tracks) |
| Entropy integrity vs global drand compromise | Yes | Requires ≥1 honest hardware entropy source via MSEA (`sp800_90b.rs`) |
| Entropy integrity vs t-1 backdoored devices | Yes | Leftover Hash Lemma + universal hash (`core/universal_hash.rs`) |
| Entropy health validation | Yes | NIST SP 800-90B compliant estimators (10 tests in `sp800_90b.rs`) |
| Share integrity           | Yes | 64B information-theoretic SIP tags (`core/sip64.rs` over GF(2^8)) |
| MPC channel replay/resistance | Yes | Randomized sequencing + one-time tags (`net/sequencer.rs`) |
| False-positive resistance (Sixth Iron Law) | Yes | Double human confirmation (`messaging/queue.rs` scanner) |
| 48h auto-burn             | Yes (graceful) | +12h reminder window (`watchdog.rs`) |
| Threshold permanent deadlock | Yes (irreversible) | ≤ t-1 members ⇒ entropy loss (`mpc/reconstruct.rs` aborts) |
| Fully decentralized post-bootstrap | Yes | Offline-capable; Rust no_std core (`lib.rs`) for portability |
| Dynamic membership PFS/BFS | Yes | Full re-bootstrap on ratchet (`protocol/bootstrap/member_extend.rs`) |
| Realtime performance      | Extreme | SIMD XOR + Lagrange (∼5 ms for t=7, n=10, `core/xor.rs`) |
| Anonymity network compatibility | Yes | Tor (`net/tor/arti_impl.rs`) + I2P (`net/i2p/i2pd_impl.rs`); batched traffic |
| Device attestation        | Yes | DBAP: local HMAC + pairwise SIP + threshold consensus (`binary_attestation.rs`) |

For full details, refer to the [whitepaper](docs/WHITEPAPER_COMPLIANCE.md) and [DBAP documentation](docs/DBAP.md).

## Version Evolution

| Version | Defining Achievement | Core Mechanism |
|---------|----------------------|----------------|
| v3.0    | Pure ITS core        | Runtime drand every 30s (`net/drand/client.rs`) |
| v3.1    | Remove runtime drand | One-time BLAKE3 chain (computational, deprecated) |
| v3.2    | Gigabyte Master Pad  | Pure OTP + Sixth Iron Law (`pad/lifecycle.rs`) |
| v3.2 APE| Absolute Purity      | Physical entropy + continuous drand (`entropy/sources.rs`) |
| v3.3 RIE| Initialization unconquerable | MSEA + Universal Hash + NIST 90B + SIP + DBAP + Rust no_std core |
| v3.4 RIE| Code documentation and compliance | Strict Rustdoc comments + audit plan integration (docs/RUST_AUDIT_PLAN.md) |

## Prerequisites

- Rust 1.75+ (stable channel; install via rustup: rustup toolchain install stable --force)
- Cargo with LTO=thin and codegen-units=1 enabled (see .cargo/config.toml)
- Hardware entropy sources: CPU jitter, RdRand (Intel), audio/video capture (locked-mode enforced)
- Anonymity networks: Tor (via arti-client) and/or I2P (via i2pd-client)
- No external crypto dependencies (enforced via `Cargo.lock`)

## Building

1. Clone the repository:
git clone https://github.com/daoquynhthu/TOGM-Rust-v3.4-RIE.git
cd TOGM-Rust-v3.3-RIE
text2. Enable features as needed (e.g., for small groups n ≤ 50):
cargo build --release --features "drand i2p dbap watchdog"
text- `drand`: Enables drand integration for small groups.
- `i2p`: Enables I2P support.
- `dbap`: Enables Device Binary Attestation Protocol.
- `watchdog`: Enables anomaly detection and auto-burn.
- `paranoid`: Adds dummy operations for timing resistance.

3. The build script (`build.rs`) generates constants like `genesis_hash.rs` for binary verification.

Build produces a staticlib (`libtigm.a`) and rlib for FFI integration. Coverage >98% via `cargo test --all-features`.

## Usage

### Bootstrap (3–8 minutes, hardened)

Run the bootstrap orchestrator for group initialization:

```rust
// Example in Rust (see examples/rust/main.rs)
use togm::protocol::bootstrap::orchestrator::BootstrapOrchestrator;
use togm::platform::pc::LockedMode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
 LockedMode::enforce()?;  // Disable USB/Bluetooth, memguard alloc

 let n = 10;  // Group size
 let t = (2 * n / 3) + 1;  // Threshold

 let mut orch = BootstrapOrchestrator::new(n, t, true)?;  // Scale-adaptive entropy
 orch.run_async()?;  // Asynchronous stages with rollback/timeout

 // Post-bootstrap: Master Pad distributed, DBAP attested
 Ok(())
}

```

For small groups (n ≤ 50): Drand interleaves automatically.
Locked-mode enforced; entropy validated via NIST SP 800-90B.
Distribution: Batched over Noise XX (30s) via Tor/I2P.

### Messaging (Offline-Capable OTP)
Encrypt and send 4096B blocks:
Rustuse togm::core::otp_engine::{encrypt, sip_mac};
use togm::pad::masterpad::MasterPad;

let pad = MasterPad::load(current_block_id)?;
let keystream = &pad.block[0..plaintext.len()];
let mac_key = &pad.block[plaintext.len()..plaintext.len() + 64];

let ciphertext = encrypt(&plaintext, keystream);
let mac = sip_mac(&ciphertext, &metadata, mac_key);

queue.broadcast(block_id || sender_idx || ciphertext || mac)?;  // 7-day offline backoff

Reconstruction: On-demand Lagrange interpolation from ≥t shares.
Ratchet: Triggers MSEA re-bootstrap on membership changes.
Integrity: SIP MAC over GF(2^8); DBAP consensus.

### Iron Laws Enforcement
Enforced via iron_laws.rs and state machine:

48h absence → auto-burn (+12h grace).
Single BURN → immediate zeroize.
3 co-signs for expulsion.
Pre-shared offline keys for contingency.
30 days offline + 3 signatures → inheritance.
Computational ciphertext → double confirmation before burn.

Watchdog (watchdog.rs) monitors pad locks, DBAP, Tor, entropy; anomalies trigger burn.
Multi-Device and Permissions

Linking: QR temporary + roster fingerprinting (multi_device/linking.rs).
Limits: Per-grade caps + threshold signatures (multi_device/limiter.rs).
Roles: Threshold-signed changes (group_permissions/role_management.rs).

### FFI Examples
See examples/ for Swift, C++, and Python bindings via include/togm.h (cbindgen-generated).
Testing and Auditing

### Unit tests: cargo test (all modules, >98% coverage).
Integration: cargo test --test dbap_full_cycle (three-layer DBAP + network splits).
Audit docs: RUST_AUDIT_FIXES.md; invites for Trail of Bits/Cure53.


### Threat Model
Adversary: Computationally unbounded, active, controls public channels. Capabilities: drand compromise, <t backdoors, traffic analysis on Tor/I2P, entropy poisoning. Honest majority t=⌈2n/3⌉. Addressed via MSEA linearity, DBAP proofs, and Iron Laws, under the honest majority assumption.

## Contributing
Contributions must adhere to WHITEPAPER_COMPLIANCE.md: no PRNG/PRF/XOF; NIST-compliant entropy; full DBAP/SIP. Fork, branch, PR with tests.

## License
This project is licensed under the AGPL-3.0 (see LICENSE). For production use, ensure compliance with anonymity and export controls.
For questions, open an issue or contact the Anonymous Geek Collective.