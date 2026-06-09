# Enclave Protocol Contracts

This directory contains the smart contracts that power the PRISM sealed-auction settlement protocol. The contracts implement a 4-layer stack where users submit swap intents, solvers compete in a sealed auction (orchestrated by TEE enclave), and settlements are verified via cryptographic attestations.

## Architecture Overview

```
┌─────────────────┐
│  IntentPool     │  ← Users submit signed intents + escrowed input tokens
└────────┬────────┘
         │
┌────────▼────────┐
│  SolverRegistry │  ← Manages solver registration, TEE keys, reputation, slashing
└────────┬────────┘
         │
┌────────▼──────────────┐
│ SolvexSettlement      │  ← Orchestrates settlement after TEE attestation
│ (Solidity)            │
└────────┬──────────────┘
         │
┌────────▼──────────────────┐
│ SolvexVerifier (Stylus)   │  ← Verifies TEE-signed attestations in Rust/WASM
│ Gas: ~310 gas            │
└──────────────────────────┘
```

---

## Contract Details

### 1. **IntentPool.sol** (`src/IntentPool.sol`)

**Purpose**: Entry point for user swap intents. Manages EIP-712 signed intent validation and token escrow.

**Key Responsibilities**:
- **Intent Submission**: Accept signed user intents via EIP-712, validate fields
  - `tokenIn` ≠ `tokenOut` (prevents no-op swaps)
  - `amountIn` > 0 and `amountOutMin` > 0
  - Deadline validation (not in the past)
  - Nonce replay protection
- **Escrow Management**: Pull input tokens from user and hold in escrow until settlement
- **State Lifecycle**: Track intent states: `PENDING` → `FILLED` (settled) or `PENDING` → `EXPIRED` (refunded after deadline)
- **Token Custody**: Use SafeERC20 to handle non-standard ERC20 implementations

**Struct: EscrowRecord**
```solidity
struct EscrowRecord {
    address     user;               // Original intent sender
    address     token_in;           // Input token (escrowed here)
    uint256     amount_in;          // Amount of token_in locked
    uint256     min_amount_out;     // Minimum output required (floor set by user)
    uint256     deadline;           // Unix timestamp deadline for settlement/refund
    IntentState state;              // PENDING, FILLED, EXPIRED, or CANCELLED
}
```

**Key Functions**:
- `submitIntent(Intent, signature)` — Submit and escrow a swap intent
- `markFilled(intent_hash, winner_solver)` — Called by SolvexSettlement to mark FILLED and release tokens
- `refundIntent(intent_hash)` — Allow users to recover escrowed tokens after deadline
- `getEscrowRecord(intent_hash)` — Retrieve escrow details for verification

**Events**:
- `IntentSubmitted` — Emitted when a new intent is escrowed
- `IntentFilled` — Emitted when SolvexSettlement marks intent as FILLED

---

### 2. **SolverRegistry.sol** (`src/SolverRegistry.sol`)

**Purpose**: Registry and reputation system for competing solvers. Manages solver onboarding, TEE public key lifecycle, stake accounting, and performance-based slashing.

**Key Responsibilities**:
- **Solver Onboarding**: Register solvers with:
  - Minimum stake (collateral for penalties)
  - TEE public key (secp256k1, 65 bytes uncompressed)
  - Activation flag (only active solvers can win auctions)
- **Key Rotation**: Allow solvers to rotate TEE public keys with TTL enforcement (7 days)
- **Reputation Tracking**: EMA-based reputation score (0–1000, where 1000 = perfect)
  - Updated after each successful fill via `updateReputation()`
  - Thresholds:
    - R < 300: Suspended (ineligible for auctions)
    - R > 850: Premium tier (Phase 2 feature: reduced fees)
- **Slashing**: Permanent removal of misbehaving solvers
  - Called by SolvexSettlement if attestation fails
  - Slashed funds → protocol fee recipient

**Struct: SolverRecord**
```solidity
struct SolverRecord {
    bytes   teePubkey;       // secp256k1 public key from TEE enclave
    uint256 keyRegisteredAt; // Block timestamp of key registration
    uint256 stake;           // ETH collateral held in registry
    uint256 reputation;      // EMA score in [0, 1000]
    bool    slashed;         // Permanent ban flag
    bool    active;          // Can participate in auctions
}
```

**Key Functions**:
- `registerSolver(teePubkey)` — Onboard a new solver with stake
- `rotateKey(newTeePubkey)` — Update TEE public key (must rotate before TTL expires)
- `updateReputation(solver, accuracy)` — Update EMA reputation after fill (SETTLER_ROLE only)
- `slashSolver(solver, amount, reason)` — Penalize solver for misconduct (SETTLER_ROLE only)
- `isValidSolver(solver)` — Check if solver is active and not slashed
- `getTeePubkey(solver)` — Retrieve solver's current TEE public key

**Events**:
- `SolverRegistered` — Solver joins protocol
- `SolverKeyRotated` — TEE key updated
- `ReputationUpdated` — Accuracy score adjusted
- `SolverSlashed` — Solver permanently removed

---

### 3. **SolvexSettlement.sol** (`src/SolvexSettlement.sol`)

**Purpose**: Core settlement orchestration. Verifies TEE attestations, releases escrowed tokens, and distributes rewards.

**Key Responsibilities**:
- **Attestation Verification**: Call SolvexVerifier (Stylus) to verify TEE-signed attestations
  - Perform 3 checks: nonce guard, ECDSA signature, Merkle chain continuity
  - Revert on failure
- **Settlement Flow**:
  1. Guard: Prevent double-settlement (check `settled[intent_hash]`)
  2. Validate: Ensure solver is active and not slashed
  3. Cross-check: Attestation intent_hash matches submitted intent_hash
  4. Zero-output guard: Reject degenerate fills
  5. Merkle chain check: Verify chain continuity (belt-and-suspenders with Stylus)
  6. **Call SolvexVerifier** (Stylus/Rust, ~310 gas)
  7. Min-output check: Verify output_amount ≥ user's `min_amount_out`
  8. State writes (CEI pattern)
  9. Token release from IntentPool
  10. Fee distribution (solver gets 99.9%, treasury gets 0.1%)
  11. Reputation update based on accuracy
- **Fee Distribution**: Split amount_in:
  - `(amount_in - protocol_fee) → winner_solver`
  - `protocol_fee (0.1% BPS) → feeRecipient`

**Struct: Attestation**
```solidity
struct Attestation {
    bytes32 intent_hash;      // Canonical intent ID from user submission
    address winner_solver;    // Address that won the sealed auction
    address fill_route;       // Path taken for the swap (e.g., DEX router)
    uint256 output_amount;    // Actual output received (attested by TEE)
    uint64  block_number;     // Block number when attestation was generated
    bytes32 prev_attest_hash; // Previous attestation hash (Merkle chain linkage)
}
```

**Key Functions**:
- `settleIntent(intent_hash, attestation, tee_sig)` — Submit attestation and settle intent
  - Calls `solvexVerifier.verify()` with ABI-encoded attestation
  - Releases tokens and distributes rewards
  - **Requires** attestation to be ABI-encoded: `abi.encode(attestation)`
- `isSettled(intent_hash)` — Check if intent already settled (replay guard)
- `getLastAttestationHash()` — Retrieve Merkle chain head

**Events**:
- `AttestationVerified` — Attestation signature check passed
- `IntentSettled` — Tokens released and rewards distributed
- `RewardDistributed` — Solver received payout

**Phase 2 Features** (stubbed):
- `slashSolverForNonFill()` — Slash solver if it won auction but failed to fill by deadline

---

### 4. **SolvexVerifier.sol** (Stylus/Rust, `stylus/solver-verifier/src/lib.rs`)

**Purpose**: Cryptographic attestation verifier compiled to WASM. Performs three critical security checks with 10x gas efficiency vs. Solidity.

**Gas Efficiency**:
- Stylus (WASM): ~310 gas per verification
- Equivalent Solidity: ~3,000 gas
- **10x savings** due to optimized ECDSA recovery in Rust

**Key Responsibilities**:
- **Nonce Guard**: Check if intent_hash already settled (replay prevention)
  - Maintains `settled_intents` mapping in Stylus contract storage
  - Rejects if intent already marked settled
- **ECDSA Signature Verification**:
  - Compute `keccak256(abi.encode(attestation))`
  - Recover signer from signature using EVM `ecrecover` precompile
  - Compare recovered signer against solver's TEE public key (from attestation)
  - Reject if signature invalid or signer mismatch
- **Merkle Chain Continuity**:
  - Verify `attestation.prev_attest_hash` matches stored `last_attest_hash`
  - Ensure no attestations silently dropped
  - Advance chain head: `last_attest_hash = keccak256(abi.encode(attestation))`

**Struct: Attestation** (Rust mirror of Solidity version)
```rust
pub struct Attestation {
    pub intentHash: FixedBytes<32>,
    pub winnerSolver: Address,
    pub fillRoute: Address,
    pub outputAmount: U256,
    pub blockNumber: u64,
    pub prevAttestHash: FixedBytes<32>,
}
```

**Key Functions**:
- `verify(intent_hash, attestation_data, tee_sig)` → `Result<bool, Vec<u8>>`
  - **Input**: Attestation as ABI-encoded bytes (not struct)
  - **Output**: `Ok(true)` on success; `Err(error_encoding)` on failure
  - Internally decodes attestation, verifies signature, checks chain
- `verify_with_expected_signer(intent_hash, attestation_data, tee_sig, expected_signer)` → `Result<bool, Vec<u8>>`
  - Same as `verify()` + additional check: recovered signer == `expected_signer`

**Events**:
- `AttestationVerified` — Signature and chain checks passed
- `MerkleChainAdvanced` — Chain head updated

**Errors**:
- `IntentAlreadySettled` — Intent replay detected
- `InvalidSignature` — Signature length or recovery failed
- `MerkleChainBroken` — prev_attest_hash mismatch
- `InvalidAttestation` — ABI decode or intent_hash mismatch

---

## Contract Interactions

### Happy Path: Intent Settlement

```
1. User submits signed intent
   IntentPool.submitIntent(intent, signature)
   → IntentPool escrows token_in
   → Event: IntentSubmitted

2. TEE enclave runs sealed auction (off-chain)
   → Selects winning solver
   → Generates attestation (with signature)

3. Solver calls settlement
   SolvexSettlement.settleIntent(intent_hash, attestation, tee_sig)
   
   3a. Check: Not already settled ✓
   3b. Check: Solver is active ✓
   3c. Check: Attestation intent_hash matches ✓
   3d. Check: Output_amount > 0 ✓
   3e. Check: Merkle chain pre-check ✓
   3f. Call: SolvexVerifier.verify() (Stylus/Rust)
       - Nonce guard ✓
       - ECDSA signature ✓
       - Merkle chain continuity ✓
   3g. Check: output_amount ≥ min_amount_out ✓
   3h. Mark settled + advance Merkle chain
   3i. Release escrowed tokens from IntentPool
   3j. Distribute: solver gets 99.9%, treasury gets 0.1%
   3k. Update solver reputation
   
   → Event: AttestationVerified
   → Event: IntentSettled
   → Event: RewardDistributed
```

### Failure Cases:

**Invalid Attestation**:
- SolvexVerifier rejects due to bad signature or replay
- SolvexSettlement reverts: `AttestationVerificationFailed`
- Intent remains PENDING, user can refund after deadline

**Output Below Minimum**:
- SolvexSettlement reverts: `OutputBelowMinimum`
- Tokens stay escrowed, can be refunded after deadline
- Solver's reputation not updated

**Solver Slashed**:
- If solver misbehaves, SolvexSettlement calls `SolverRegistry.slashSolver()`
- Solver marked inactive and removed from eligible list
- Slashed stake → protocol treasury

---

## File Structure

```
contracts/
├── CONTRACTS.md                   # This file
├── src/
│   ├── IntentPool.sol            # Intent escrow and lifecycle
│   ├── SolvexSettlement.sol       # Settlement orchestration
│   ├── SolverRegistry.sol         # Solver registry + reputation
│   └── interfaces/
│       ├── IIntentPool.sol        # IntentPool interface
│       ├── ISolverRegistry.sol    # SolverRegistry interface
│       └── ISolvexVerifier.sol    # SolvexVerifier interface (Stylus)
├── stylus/
│   └── solver-verifier/
│       ├── Cargo.toml             # Rust dependencies
│       ├── src/
│       │   └── lib.rs             # Stylus verifier implementation
│       └── Stylus.toml            # Stylus build config
└── lib/
    └── [OpenZeppelin contracts]
```

---

## Key Design Patterns

### 1. **CEI (Checks-Effects-Interactions)**
SolvexSettlement follows CEI strictly:
- Checks: Validate all conditions
- Effects: Update state (`settled`, `lastAttestationHash`)
- Interactions: Call IntentPool, distribute tokens

### 2. **Reentrancy Protection**
- SolvexSettlement uses `ReentrancyGuard` from OpenZeppelin
- SolverRegistry uses `ReentrancyGuard` to protect stake withdrawals

### 3. **Access Control**
- SolverRegistry uses OpenZeppelin `AccessControl`
- SolvexSettlement granted `SETTLER_ROLE` to call `updateReputation()` and `slashSolver()`

### 4. **EIP-712 Signature**
- IntentPool uses EIP-712 for domain-separated signatures
- Prevents signature replay across chains/contracts

### 5. **Merkle Chain Linkage**
- Each attestation hash links to previous attestation
- Ensures no silent drops in the attestation stream
- Checked by both Solidity (pre-check) and Stylus (enforcement)

---

## Deployment Checklist

- [ ] Deploy `SolverRegistry` with `feeRecipient` address
- [ ] Deploy `IntentPool` with `SolvexSettlement` address
- [ ] Deploy `SolvexSettlement` with addresses of:
  - `SolvexVerifier` (Stylus contract on Arbitrum)
  - `SolverRegistry`
  - `IntentPool`
  - `feeRecipient` (protocol treasury)
- [ ] Grant `SolvexSettlement` the `SETTLER_ROLE` in `SolverRegistry`
- [ ] Verify all contracts compile: `forge build`
- [ ] Run tests: `forge test`

---

## Phase 2 Extensions

Currently stubbed for Phase 2 implementation:

1. **Non-Fill Slashing**: `SolvexSettlement.slashSolverForNonFill()`
   - Slash solver if it won auction but failed to fill by deadline
   - Requires on-chain AuctionResult storage (from TEE relay)

2. **Fee Tier System**: In `SolverRegistry`
   - Premium solvers (R > 0.85) get reduced fee caps
   - Suspended solvers (R < 0.3) cannot participate

3. **Quoted Amount Storage**: In `IntentPool.EscrowRecord`
   - Store solver's sealed quote (from TEE AuctionResult)
   - Use for more accurate accuracy scoring vs. min_amount_out floor

---

## Testing

Run all tests:
```bash
forge test
```

Build with IR optimization (required for SolvexSettlement due to stack depth):
```bash
forge build --via-ir
```

Generate Stylus ABI:
```bash
cd contracts/stylus/solver-verifier
cargo stylus export-abi
```

---

## Security Notes

⚠️ **This code has not been audited.**

Key security considerations:
- Attestation verification relies on correct TEE enclave implementation
- Solver slashing requires monitoring and swift response
- ECDSA signature recovery uses EVM precompile (trusted)
- Merkle chain guard against attestation drops is redundant (both Solidity + Stylus check)

For production deployment, engage professional security audit.

---

## References

- [Arbitrum Stylus Documentation](https://docs.arbitrum.io/stylus/stylus-gentle-introduction)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
- [EIP-712: Typed structured data hashing](https://eips.ethereum.org/EIPS/eip-712)
- [PRISM Protocol Specification](../README.md)
