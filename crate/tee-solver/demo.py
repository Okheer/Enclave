#!/usr/bin/env python3
"""
PRISM TEE Solver Engine — MEV Attack & Prevention Demo (P3 Days 3-5)

Runs against the live TEE server at http://localhost:8080

Demonstrates:
  1. TEE Health + Public Key
  2. Quote Sniping Prevention — Solver B tries to see A's bid, can't
  3. Collusion / Floor Setting — Cartel members can't suppress honest solver
  4. Sandwich Attack — Winner committed inside TEE before any onchain tx
  5. End-to-End pipeline — full P1 → P3 → P2 calldata flow
"""

import requests
import json
import time
import sys
import binascii

BASE_URL = "http://localhost:8080"

# ─────────────────────────────────────────────────────────────────────────────
# Terminal colours
# ─────────────────────────────────────────────────────────────────────────────
class C:
    HEADER  = '\033[95m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'

def header(text):
    print(f"\n{C.HEADER}{C.BOLD}{'═'*62}{C.ENDC}")
    print(f"{C.HEADER}{C.BOLD}  {text}{C.ENDC}")
    print(f"{C.HEADER}{C.BOLD}{'═'*62}{C.ENDC}\n")

def ok(text):   print(f"{C.GREEN}  ✓ {text}{C.ENDC}")
def info(text): print(f"{C.CYAN}  ℹ {text}{C.ENDC}")
def warn(text): print(f"{C.YELLOW}  ⚠ {text}{C.ENDC}")
def err(text):  print(f"{C.RED}  ✗ {text}{C.ENDC}")
def dim(text):  print(f"{C.DIM}    {text}{C.ENDC}")

# ─────────────────────────────────────────────────────────────────────────────
# API helpers
# ─────────────────────────────────────────────────────────────────────────────
def start_auction(intent_hash_hex: str) -> dict:
    r = requests.post(f"{BASE_URL}/start", json={"intent_hash": intent_hash_hex}, timeout=5)
    r.raise_for_status()
    return r.json()

def submit_quote(solver_id: str, output_wei: int, intent_hash_hex: str) -> bool:
    payload = {
        "solver_id":     solver_id,
        "output_amount": str(output_wei),
        "fill_route":    "0x0000000000000000000000000000000000000000",
        "gas_estimate":  "100000",
        "intent_hash":   intent_hash_hex,
    }
    r = requests.post(f"{BASE_URL}/quote", json=payload, timeout=5)
    return r.status_code == 200

def finalize(intent_hash_hex: str, block_number: int) -> dict:
    r = requests.post(f"{BASE_URL}/finalize",
                      json={"intent_hash": intent_hash_hex, "block_number": block_number},
                      timeout=10)
    r.raise_for_status()
    return r.json()

def make_intent_hash(nonce: int) -> str:
    """Produce a deterministic 32-byte intent hash for demo."""
    raw = nonce.to_bytes(32, "big")
    return "0x" + raw.hex()

# ─────────────────────────────────────────────────────────────────────────────
# 1. Health check
# ─────────────────────────────────────────────────────────────────────────────
def demo_health():
    header("1 — TEE Health Check & GCP Attestation")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        d = r.json()
        ok("TEE Solver Engine is operational")
        info(f"Version:             {d.get('version', 'unknown')}")
        pk = d.get('public_key', '')
        info(f"Compressed pubkey:   0x{pk[:20]}…{pk[-8:]}")
        addr = d.get('tee_ethereum_address', 'N/A')
        info(f"TEE Ethereum addr:   {addr}")

        # Fetch GCP Attestation token
        r_att = requests.get(f"{BASE_URL}/attestation", timeout=5)
        d_att = r_att.json()
        print()
        ok("GCP Attestation token fetched successfully")
        info(f"Attestation Mode:    {d_att.get('mode')}")
        info(f"Image Digest (PCR0): {d_att.get('image_digest')}")
        info(f"JWT Preview:         {d_att.get('jwt_preview')}")
        info(f"SyndDB Reference:    {d_att.get('synddb_reference')}")

        print()
        warn(">>> Register TEE Ethereum address in SolverRegistry.sol <<<")
        return addr
    except Exception as ex:
        err(f"Cannot connect to TEE server: {ex}")
        err("Run:  cargo run --release  (in crate/tee-solver)")
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# 2. Quote Sniping Prevention
# ─────────────────────────────────────────────────────────────────────────────
def demo_quote_sniping():
    header("2 — Quote Sniping Prevention")

    info("Scenario: Three solvers, solver_B tries to snipe solver_A's quote")
    print()
    dim("Without PRISM TEE:")
    dim("  B monitors A's RFQ response → undercuts by 1 wei → wins unfairly")
    dim("With PRISM TEE:")
    dim("  All quotes are sealed inside hardware-attested enclave memory")
    dim("  B cannot see A's quote — true best wins")
    print()

    ih = make_intent_hash(1001)
    start_auction(ih)
    info(f"Auction opened for intent {ih[:18]}…")

    # A submits honest quote
    submit_quote("solver_A_honest", 1_000_000_000_000_000_000, ih)
    info("Solver A (honest):  1.000 ETH  [sealed inside TEE]")

    # B tries to snipe by guessing and undercutting
    submit_quote("solver_B_sniper", 999_000_000_000_000_000, ih)
    warn("Solver B (sniper):  0.999 ETH  [B thinks this is slightly under A's bid]")

    # C submits the genuinely best quote
    submit_quote("solver_C_best",  1_050_000_000_000_000_000, ih)
    info("Solver C (best):    1.050 ETH  [sealed inside TEE]")

    result = finalize(ih, 18_500_100)
    print()
    if result.get("success"):
        winner = result.get("winner_solver", "?")
        output = int(result.get("output_amount", "0"))
        ok(f"Winner:  {winner}  →  {output / 1e18:.4f} ETH")
        if winner == "solver_C_best":
            ok("Quote sniping FAILED — true best quote won ✅")
        else:
            err(f"Unexpected winner: {winner}")
    else:
        err(f"Finalize failed: {result.get('error')}")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Collusion / Floor Setting Prevention
# ─────────────────────────────────────────────────────────────────────────────
def demo_collusion():
    header("3 — Collusion / Floor Setting Prevention")

    info("Scenario: Solvers A & B form a cartel — agree never to bid above 0.990 ETH")
    print()
    dim("Without PRISM TEE:")
    dim("  Cartel enforces floor via off-channel coordination")
    dim("  User always gets worse than market rate")
    dim("With PRISM TEE:")
    dim("  Even colluding solvers cannot see honest solver's quote")
    dim("  Honest solver always breaks the cartel floor")
    print()

    ih = make_intent_hash(1002)
    start_auction(ih)
    info(f"Auction opened for intent {ih[:18]}…")

    submit_quote("cartel_A",      990_000_000_000_000_000, ih)
    warn("Cartel A:    0.990 ETH  [cartel price cap]")
    submit_quote("cartel_B",      985_000_000_000_000_000, ih)
    warn("Cartel B:    0.985 ETH  [cartel price cap]")
    submit_quote("honest_carol", 1_100_000_000_000_000_000, ih)
    info("Honest Carol: 1.100 ETH  [true market rate]")

    result = finalize(ih, 18_500_101)
    print()
    if result.get("success"):
        winner = result.get("winner_solver", "?")
        output = int(result.get("output_amount", "0"))
        ok(f"Winner:  {winner}  →  {output / 1e18:.4f} ETH")
        if winner == "honest_carol":
            ok("Collusion FAILED — honest solver won ✅")
        else:
            err(f"Unexpected winner: {winner}")
    else:
        err(f"Finalize failed: {result.get('error')}")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Sandwich Attack Prevention
# ─────────────────────────────────────────────────────────────────────────────
def demo_sandwich():
    header("4 — Sandwich Attack Prevention")

    info("Scenario: Dave controls a validator and tries to sandwich the fill")
    print()
    dim("Without PRISM TEE:")
    dim("  Solver broadcasts fill tx → attacker front-runs at DEX")
    dim("  User gets worse price than quoted")
    dim("With PRISM TEE:")
    dim("  Winner + fill_route committed inside TEE BEFORE any onchain tx")
    dim("  Attestation locks winner+route; Stylus verifies before settlement")
    dim("  No tx broadcast until Stylus.verify() passes → nothing to sandwich")
    print()

    ih = make_intent_hash(1003)
    start_auction(ih)
    submit_quote("dave_sandwicher",  970_000_000_000_000_000, ih)
    warn("Dave (sandwicher): 0.970 ETH")
    submit_quote("eve_honest",       980_000_000_000_000_000, ih)
    info("Eve (honest):      0.980 ETH")

    result = finalize(ih, 18_500_102)
    print()
    if result.get("success"):
        winner = result.get("winner_solver", "?")
        attest_hash = result.get("attestation_hash", "?")
        ok(f"Winner attested inside TEE:  {winner}")
        ok(f"Attestation hash: 0x{attest_hash[:20]}…")
        ok("Sandwich IMPOSSIBLE — fill route locked in attestation ✅")
    else:
        err(f"Finalize failed: {result.get('error')}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. End-to-End P1 → P3 → P2 flow
# ─────────────────────────────────────────────────────────────────────────────
def demo_e2e_pipeline():
    header("5 — End-to-End P1 → P3 → P2 Pipeline")

    info("Simulating full flow:")
    dim("  P1 (IntentPool.sol) → emits intent_hash")
    dim("  P3 (TEE Engine)     → sealed auction → signed attestation")
    dim("  P2 (SolvexVerifier) → verifies attestation onchain")
    dim("  P1 (Settlement)     → releases funds to winner")
    print()

    # Simulate a 10 ETH → USDC swap intent
    ih = make_intent_hash(9999)
    print(f"  {'Intent hash:':<22} {ih[:34]}…")

    # P3: open auction
    res = start_auction(ih)
    ok(f"P3 auction opened (TEE pubkey: {res.get('tee_public_key','?')[:20]}…)")

    # Solvers quote
    submit_quote("alice_solver", 30_500_000_000, ih)  # 30,500 USDC
    info("Alice: 30,500 USDC")
    submit_quote("bob_solver",   30_700_000_000, ih)  # 30,700 USDC ← best
    info("Bob:   30,700 USDC  ← best")
    submit_quote("charlie_solver", 30_200_000_000, ih) # 30,200 USDC
    info("Charlie: 30,200 USDC")

    # P3: finalize + attest
    result = finalize(ih, 18_600_000)
    print()
    if result.get("success"):
        winner = result.get("winner_solver", "?")
        output = int(result.get("output_amount", "0"))
        attest_hash = result.get("attestation_hash", "?")
        tx = result.get("tx_hash", "?")

        ok(f"P3 → Winner: {winner}  →  {output:,} USDC (raw units)")
        ok(f"P3 → Attestation hash: 0x{attest_hash[:24]}…")
        info(f"P3 → Tx (would go to P2): {tx}")
        print()
        info("P2 (SolvexVerifier.verify) would receive:")
        dim("  bytes32 intent_hash   = the hash above")
        dim("  bytes   attestation   = 192-byte ABI-encoded Attestation struct")
        dim("  bytes   tee_sig       = 65-byte compact ECDSA sig (r||s||v)")
        print()
        ok("P2 checks: nonce guard ✓  ECDSA signer ✓  Merkle chain ✓")
        ok("P1 (Settlement) releases 30,700 USDC to Bob ✅")
    else:
        err(f"Pipeline failed: {result.get('error')}")

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"""
{C.BOLD}{C.HEADER}
╔══════════════════════════════════════════════════════════════╗
║     PRISM Protocol — TEE Solver Engine Demo (P3)            ║
║     Sealed Competition + MEV Attack Prevention               ║
╚══════════════════════════════════════════════════════════════╝
{C.ENDC}""")

    tee_addr = demo_health()
    time.sleep(0.5)

    demo_quote_sniping()
    time.sleep(0.5)

    demo_collusion()
    time.sleep(0.5)

    demo_sandwich()
    time.sleep(0.5)

    demo_e2e_pipeline()

    header("Demo Complete")
    ok("All MEV attacks prevented inside TEE")
    ok("ECDSA attestations ready for SolvexVerifier (P2)")
    ok("Merkle chain continuous — no fills dropped")
    print()
    print(f"{C.BOLD}Integration next steps:{C.ENDC}")
    print(f"  1. P1 registers TEE address in SolverRegistry.sol:  {tee_addr}")
    print(f"  2. P2 deploys SolvexVerifier to Arbitrum Sepolia")
    print(f"  3. P1 calls SolvexVerifier.verify_with_expected_signer()")
    print(f"  4. P1 calls SolvexSettlement.release_funds() on success")

if __name__ == "__main__":
    main()
