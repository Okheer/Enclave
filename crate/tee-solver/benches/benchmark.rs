use alloy_primitives::{Address, U256};
use chrono::Utc;
/// Criterion benchmarks for PRISM TEE Solver Engine cryptographic operations.
/// Run with:  cargo bench
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tee_solver::{
    attestation::AttestationSigner,
    types::{Intent, QuoteData},
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_intent() -> Intent {
    Intent {
        user: Address::ZERO,
        token_in: Address::ZERO,
        token_out: Address::ZERO,
        amount_in: U256::from(1000u64),
        min_amount_out: U256::from(900u64),
        deadline: 9_999_999_999,
        nonce: 1,
    }
}

fn make_quote(output: u64) -> QuoteData {
    QuoteData {
        output_amount: U256::from(output),
        fill_route: Address::ZERO,
        gas_estimate: U256::from(100_000u64),
        timestamp: Utc::now(),
        solver_id: "solver_bench".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/// Bench: compact 65-byte ECDSA signature generation (prehash)
fn bench_sign(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let hash = [42u8; 32];

    c.bench_function("sign_hash (compact 65-byte)", |b| {
        b.iter(|| signer.sign_hash(black_box(&hash)).unwrap())
    });
}

/// Bench: compact 65-byte ECDSA signature verification (prehash)
fn bench_verify(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let hash = [42u8; 32];
    let signature = signer.sign_hash(&hash).unwrap();

    c.bench_function("verify_signature (compact 65-byte)", |b| {
        b.iter(|| {
            signer
                .verify_signature(black_box(&hash), black_box(&signature))
                .unwrap()
        })
    });
}

/// Bench: batch verification of 50 signatures
fn bench_batch_verify(c: &mut Criterion) {
    let signers: Vec<_> = (0u8..50)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i + 1;
            AttestationSigner::from_seed(&seed).unwrap()
        })
        .collect();
    let hash = [42u8; 32];
    let sigs: Vec<_> = signers
        .iter()
        .map(|s| s.sign_hash(&hash).unwrap())
        .collect();

    c.bench_function("batch_verify x50", |b| {
        b.iter(|| {
            for (s, sig) in signers.iter().zip(sigs.iter()) {
                black_box(s.verify_signature(&hash, sig).unwrap());
            }
        })
    });
}

/// Bench: full attestation creation (ABI encode + prehash sign)
fn bench_attestation_create(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let intent = make_intent();
    let quote = make_quote(950);

    c.bench_function("create_attestation (ABI-encoded)", |b| {
        b.iter(|| {
            signer
                .create_attestation(
                    black_box(&intent),
                    black_box(&quote),
                    black_box(100u64),
                    black_box([0u8; 32]),
                )
                .unwrap()
        })
    });
}

/// Bench: ABI encoding of attestation (192 bytes, 6 × 32-byte slots)
fn bench_abi_encode(c: &mut Criterion) {
    let signer = AttestationSigner::new().unwrap();
    let att = signer
        .create_attestation(&make_intent(), &make_quote(950), 100, [0u8; 32])
        .unwrap();

    c.bench_function("attestation.to_abi_bytes (192 B)", |b| {
        b.iter(|| black_box(att.to_abi_bytes()))
    });
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_batch_verify,
    bench_attestation_create,
    bench_abi_encode,
);
criterion_main!(benches);
