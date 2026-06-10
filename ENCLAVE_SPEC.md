# ENCLAVE Protocol Specification

## Private Routing & Intent Settlement Mechanism
### A TEE-Sealed Solver Competition with Stylus-Verified Onchain Attestation on Arbitrum

**Date:** 2026-06-06  
**Status:** MVP Specification (Phase 1 Core + Phase 2 Extended Vision)  
**Platform:** Arbitrum One (L2) + GCP Confidential Space (TEE)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Phase 1: Core MVP](#phase-1-core-mvp)
5. [Phase 2: Extended Vision](#phase-2-extended-vision)
6. [Component Specifications](#component-specifications)
7. [Data Flow & Protocol](#data-flow--protocol)
8. [Security Model](#security-model)
9. [Gas Cost Analysis](#gas-cost-analysis)
10. [Development Architecture](#development-architecture)
11. [Key Dependencies](#key-dependencies)

---

## Executive Summary

ENCLAVE eliminates solver-level MEV from intent-based DEX routing by sealing the entire solver competition inside a Trusted Execution Environment (TEE), then proving the correct solver won using a Rust smart contract on Arbitrum Stylus.

### The 14-Word Pitch
> **"Prove your solver won fairly — without trusting anyone, including us."**

### Key Differentiator
Instead of expensive zkVM proofs ($0.018–$0.13 per proof, 30 seconds to 3 minutes), ENCLAVE uses **Stylus ECDSA batch verification** at roughly **10× lower gas cost** (~310 gas per fill vs. ~3,000 gas in Solidity) and **sub-second completion**.

### Core Innovation Stack
- **TEE Solver Pool**: GCP Confidential Space runs sealed auction where no solver sees competitors' quotes
- **SolvexVerifier (Stylus/Rust)**: Verifies ECDSA attestations onchain with batch optimization
- **IntentPool + Settlement (Solidity)**: Non-custodial escrow and fund release gating

---

## Problem Statement

### The Solver MEV Problem

In traditional intent protocols (CoW Protocol, 1inch Fusion, UniswapX), solver competition is observable—enabling three attack vectors:

1. **Quote Sniping**: Solver sees competing quote and undercuts by 1 wei, claiming reward with no real improvement
2. **Collusive Floor Setting**: Colluding solvers agree to never bid above minimum threshold, suppressing genuine competition
3. **Sandwich at Settlement**: Solver controlling settlement transaction front-runs fill at DEX level

### Current Protocol Gaps

| Protocol | Transparency | Latency | Solver Trust |
|----------|--------------|---------|--------------|
| CoW Protocol | Batch opaque to solvers | High (~minutes) | Single trusted coordinator |
| 1inch Fusion | Solver competition observable | Medium | Partially trusted solver pool |
| UniswapX | Solver competition observable | Medium | Partially trusted filler pool |
| **ENCLAVE** | **TEE-sealed competition** | **<1 second** | **Hardware-attested enclave** |

---

## Solution Overview

### Architecture Stack (4 Layers)

```
┌──────────────────────────────────────────────────────────┐
│ Layer 1: User Intent Submission                          │
│ └─ User signs EIP-712 intent, sends to IntentPool        │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 2: Sealed TEE Solver Competition                   │
│ └─ GCP Confidential Space: collect quotes → argmax       │
│    └─ No solver sees peers' bids                         │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 3: Stylus Attestation Verification                 │
│ └─ SolvexVerifier (Rust/WASM): verify ECDSA signature    │
│    └─ Nonce guard, Merkle chain check                    │
└────────────────────┬─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│ Layer 4: Solidity Settlement                             │
│ └─ Release escrowed funds, distribute solver fees        │
└──────────────────────────────────────────────────────────┘
```

### Why TEE + Stylus Solves the Problem

1. **TEE Seals Competition**: Hardware-attested enclave prevents all three attack vectors
   - No solver sees peer quotes (eliminates quote sniping and collusion)
   - Deterministic argmax selection (prevents manipulation)
   - Isolated memory space prevents operator observation

2. **Stylus Proves Correctness Onchain**: Cryptographic proof of TEE execution at 10× lower cost
   - ECDSA batch verification vs. zkVM proofs
   - Sub-second completion vs. 30-minute wait
   - Compounding gas savings at scale

3. **Non-Custodial Settlement**: Funds only released after Stylus verifies attestation
   - Solver cannot sandwich at settlement (funds locked until verified)
   - User retains control until winning fill confirmed
   - Timeout refund mechanism prevents fund lock

---

## Phase 1: Core MVP

### What is Being Built

Three tightly integrated primitives form the complete intent-execution pipeline:

#### 1. Sealed TEE Solver Pool
- **Platform**: GCP Confidential Space (hardware-attested enclave)
- **Functionality**:
  - Solvers register stake + TEE public key onchain
  - Sealed auction logic: collect quotes from registered solvers
  - Deterministic winner selection via argmax(output_amount)
  - Emit ECDSA-signed attestation of winner
- **Security Property**: No solver—including TEE operator—can observe peer quotes

#### 2. SolvexVerifier (Stylus/Rust Contract)
- **Language**: Rust compiled to WASM via Arbitrum Stylus
- **Purpose**: Verify ECDSA attestations emitted by TEE
- **Operations** (in sequence):
  1. **Nonce Guard**: Bloom filter prevents replay attacks
  2. **ECDSA Signature Check**: Recover signer from attestation hash, verify against TEE pubkey in SolverRegistry
  3. **Merkle Chain Continuity**: Ensure no fills silently dropped from history
- **Gas Cost**: ~310 gas per verification vs. ~3,000 in Solidity (89.7% reduction)

#### 3. IntentPool + Settlement (Solidity Layer)
- **IntentPool.sol**:
  - Receive EIP-712 signed user intents
  - Validate intent schema (token_in, token_out, amount_in, min_amount_out, deadline)
  - Escrow user funds in contract
  - Store intent hash registry
  - Handle timeout refunds

- **SolvexSettlement.sol**:
  - Gate fund release on successful SolvexVerifier attestation
  - Distribute solver fees to winning solver
  - Emit settlement events for indexing
  - Handle cross-chain message passing (Phase 2)

- **SolverRegistry.sol**:
  - Solver registration with staking requirement
  - TEE public key management with expiration
  - Reputation score tracking (Phase 2)
  - Slashing mechanism for protocol violations

### Intent Schema (EIP-712)

```solidity
struct Intent {
    address user;           // Intent originator
    address token_in;       // Token being sold
    address token_out;      // Token being bought
    uint256 amount_in;      // Exact amount to sell
    uint256 min_amount_out; // Minimum acceptable output
    uint64 deadline;        // Intent expiration timestamp
    uint64 nonce;           // Replay protection per-user
}

// intent_hash = keccak256(abi.encode(Intent))
```

### Attestation Schema (TEE-Signed)

```solidity
struct Attestation {
    bytes32 intent_hash;      // Hash of original user intent
    address winner_solver;    // Winning solver address
    address fill_route;       // DEX router used for fill
    uint256 output_amount;    // Actual output amount achieved
    uint64 block_number;      // Arbitrum block number
    bytes32 prev_attest_hash; // Previous attestation hash (Merkle chain)
}

// tee_sig = ECDSA.sign(tee_private_key, keccak256(abi.encode(Attestation)))
```

### SolvexVerifier Implementation (Pseudocode)

```rust
#[external]
pub fn verify(
    &self,
    intent_hash: FixedBytes<32>,
    attestation: Attestation,
    tee_sig: Bytes,
) -> Result<bool, Vec<u8>> {
    // 1. Check nonce replay guard
    self.check_nonce(intent_hash)?;
    
    // 2. Recover ECDSA signer and verify against TEE pubkey
    let signer = ecrecover(keccak256(encode(&attestation)), &tee_sig)?;
    let tee_key = self.solver_registry.get_pubkey(attestation.winner_solver)?;
    ensure!(signer == tee_key, SolvexError::InvalidAttestation);
    
    // 3. Verify Merkle chain continuity
    self.verify_chain(attestation.prev_attest_hash)?;
    
    Ok(true)
}
```

### Phase 1 Deliverables

- [ ] SolvexVerifier (Rust/Stylus) fully functional with ECDSA batch ops
- [ ] SolverRegistry.sol with staking and key management
- [ ] IntentPool.sol with EIP-712 intent escrow
- [ ] SolvexSettlement.sol with attestation-gated fund release
- [ ] End-to-end integration tests on Anvil + Arbitrum Sepolia
- [ ] Demo UI showing MEV attack comparison and gas benchmarks

---

## Phase 2: Extended Vision

### What is Being Built

Reputation system and cross-chain routing for competitive solver market.

#### 1. Solver Reputation System

**Reputation Score**: $R(s) \in [0, 1]$ based on:
- Fill accuracy: $\frac{\text{actual\_output}}{\text{quoted\_output}}$
- Latency performance
- Slash-free history

**Update Mechanism** (Exponential Moving Average):

$$R_{\text{new}}(s) = \alpha \cdot \text{accuracy} + (1 - \alpha) \cdot R_{\text{prev}}(s)$$

Where $\alpha = 0.05$ (responds over ~20 fills, preventing single-event manipulation).

**Fee-Tier Gating**:
- $R(s) > 0.85$: Lower fee cap (incentivizes quality)
- $0.3 \leq R(s) \leq 0.85$: Standard fee cap
- $R(s) < 0.3$: Temporary suspension from auctions

**Benefits**:
- Meritocratic solver market mirrors prime brokerage quality-based pricing
- High-quality solvers get preferential access → better margins
- Users benefit from competitive pressure among high-rep solvers

#### 2. Cross-Chain Intent Routing

**Multi-Chain Solver Pool**:
- Solvers query liquidity across Arbitrum One, Base, and Optimism simultaneously
- TEE selects best cross-chain fill based on output amount
- Atomic bridge execution via shared settlement contract on each chain

**Data Flow**:
1. User submits intent without specifying destination chain
2. TEE queries liquidity aggregator for all chains
3. TEE selects best fill (highest output)
4. TEE submits atomic cross-chain settlement

**Benefits**:
- Solves liquidity fragmentation problem
- Users automatically get best cross-chain fill
- No user knowledge of chain distribution required

### Phase 2 Deliverables

- [ ] Reputation score storage and update mechanism in SolverRegistry
- [ ] ReputationGateModule.sol for fee-tier gating
- [ ] Cross-chain settlement contract clones on Base, Optimism
- [ ] Bridge contract supporting atomic cross-chain fills
- [ ] Reputation dashboard backed by The Graph / Subgraph
- [ ] Solver performance analytics

---

## Component Specifications

### Smart Contracts (Solidity + Stylus)

#### SolvexVerifier (Stylus/Rust)

| Property | Value |
|----------|-------|
| **Language** | Rust (WASM via Arbitrum Stylus) |
| **File** | `contracts/stylus/solvex-verifier/src/lib.rs` |
| **Dependencies** | `alloy-primitives`, `alloy-sol-types` |
| **External Calls** | ecrecover (0x01), keccak256 |
| **Gas Cost** | ~310 gas per ECDSA verification |
| **Deployment** | `cargo stylus deploy --release` |

**Interface**:
```rust
#[external]
pub fn verify(
    intent_hash: FixedBytes<32>,
    attestation: Attestation,
    tee_sig: Bytes,
) -> Result<bool, Vec<u8>>;
```

#### SolverRegistry.sol (Solidity)

| Property | Value |
|----------|-------|
| **Purpose** | Solver onboarding, staking, reputation |
| **File** | `contracts/src/SolverRegistry.sol` |
| **Base** | Adapted from SyndDB's TeeKeyManager.sol |
| **State** | Solver → (staked, pubkey, reputation, slashed) |
| **Key Functions** | `registerSolver()`, `slashSolver()`, `updateReputation()` |

**Key Functions**:
```solidity
function registerSolver(
    address _solver,
    bytes calldata _pubkey,
    bytes calldata _attestation
) external payable;

function slashSolver(address _solver, uint256 _amount) external;

function isValidSolver(address _solver) external view returns (bool);

function getReputation(address _solver) external view returns (uint256);
```

#### IntentPool.sol (Solidity)

| Property | Value |
|----------|-------|
| **Purpose** | Receive intents, validate, escrow funds |
| **File** | `contracts/src/IntentPool.sol` |
| **EIP-712** | Domain separator for intent signature verification |
| **State** | Intent hash → (user, amount_in, escrow status, deadline) |
| **Key Functions** | `submitIntent()`, `getIntentState()`, `refundIntent()` |

**Key Functions**:
```solidity
function submitIntent(
    Intent calldata _intent,
    bytes calldata _signature
) external returns (bytes32 intent_hash);

function getIntentState(bytes32 _intent_hash)
    external
    view
    returns (IntentState);

function refundIntent(bytes32 _intent_hash) external;
```

#### SolvexSettlement.sol (Solidity)

| Property | Value |
|----------|-------|
| **Purpose** | Attestation-gated fund release, fee distribution |
| **File** | `contracts/src/SolvexSettlement.sol` |
| **Key Functions** | `settleIntent()`, `distributeRewards()` |

**Settlement Flow**:
```solidity
function settleIntent(
    bytes32 _intent_hash,
    Attestation calldata _attestation,
    bytes calldata _tee_sig,
    address _solver
) external {
    require(solvexVerifier.verify(_intent_hash, _attestation, _tee_sig));
    
    // Release escrowed funds to solver
    // Update solver reputation
    // Emit settlement event
}
```

### Off-Chain Services (Rust)

#### enclave-solver-engine

| Property | Value |
|----------|-------|
| **Purpose** | Sealed TEE solver competition logic |
| **Platform** | GCP Confidential Space |
| **Language** | Rust |
| **Key Modules** | config, competition, attestation, http_api, registry |

**Entry Point** (`main.rs`):
1. Generate ephemeral secp256k1 signing key
2. Request GCP Confidential Space OIDC token
3. Register TEE public key in SolverRegistry via bootstrap
4. Start HTTP API server to receive quote submissions
5. Run sealed auction loop

**HTTP API Endpoints**:
- `POST /quote`: Solver submits quote for intent
- `GET /status`: Health check + TEE attestation
- `GET /result/{intent_hash}`: Get winning fill details

**Competition Logic** (`competition.rs`):
```rust
pub fn run_auction(intent: Intent, quotes: Vec<Quote>) -> Result<Quote> {
    // quotes is sealed - no individual quote observable
    
    // Select winner deterministically
    let winner = quotes
        .iter()
        .max_by_key(|q| q.output_amount)
        .ok_or(AuctionError::NoQuotes)?;
    
    Ok(winner.clone())
}
```

**Attestation Signing** (`attestation.rs`):
```rust
pub fn sign_attestation(
    attestation: &Attestation,
    signing_key: &SigningKey,
) -> Result<Bytes> {
    let digest = keccak256(encode(attestation));
    let signature = signing_key.sign_digest_recoverable(digest)?;
    Ok(signature.to_bytes())
}
```

#### enclave-bootstrap

| Property | Value |
|----------|-------|
| **Purpose** | TEE key generation and registration |
| **Depends On** | enclave-shared, gcp-attestation |
| **Key Function** | Submit TEE public key to SolverRegistry |

**Bootstrap Flow**:
1. Generate secp256k1 keypair
2. Request GCP OIDC token (proves TEE execution)
3. Call `SolverRegistry.registerSolver()` with pubkey + attestation
4. Wait for confirmation
5. Return registered solver address

#### enclave-shared

| Property | Value |
|----------|-------|
| **Purpose** | Shared types and utilities |
| **Key Modules** | types/intent, types/attestation, cbor, config |

**Core Types** (`types/intent.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Intent {
    pub user: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub min_amount_out: U256,
    pub deadline: u64,
    pub nonce: u64,
}

impl Intent {
    pub fn eip712_hash(&self) -> FixedBytes<32> {
        keccak256(encode(self))
    }
}
```

**Core Types** (`types/attestation.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Attestation {
    pub intent_hash: FixedBytes<32>,
    pub winner_solver: Address,
    pub fill_route: Address,
    pub output_amount: U256,
    pub block_number: u64,
    pub prev_attest_hash: FixedBytes<32>,
}
```

#### enclave-intent-indexer

| Property | Value |
|----------|-------|
| **Purpose** | Event indexing and state machine tracking |
| **Backend** | The Graph / Subgraph |
| **Entities** | Intent, Solver, Fill, Settlement |

**Event Tracking**:
- `IntentSubmitted`: user, intent_hash, amount_in, deadline
- `SolverQuoted`: intent_hash, solver, output_amount, timestamp
- `IntentFilled`: intent_hash, winner_solver, output_amount, fill_route
- `IntentSettled`: intent_hash, winner_solver, fee_paid, block_number

---

## Data Flow & Protocol

### Complete User Journey (Happy Path)

**Step 1: User Intent Submission**
```
User signs intent (EIP-712) → IntentPool.submitIntent()
├─ Verify user signature
├─ Validate intent schema (min_out, deadline)
├─ Escrow token_in amount in contract
├─ Store intent_hash in registry
└─ Emit IntentSubmitted event → Indexer notifies solvers
```

**Step 2: Sealed TEE Solver Competition**
```
enclave-solver-engine receives intent → Run auction
├─ Accept quotes from registered solvers (timeout: T seconds)
│  ├─ Validator: solver has valid registration + stake
│  ├─ Validator: min_out ≤ quoted output ≤ historical best
│  └─ Sealed memory: no quote observable to other solvers
├─ Select winner: argmax(output_amount)
├─ Sign Attestation with TEE key
└─ Submit to SolvexSettlement.settleIntent()
```

**Step 3: Stylus Attestation Verification**
```
SolvexSettlement calls SolvexVerifier.verify() → Rust/WASM
├─ Check nonce: intent_hash not previously settled
├─ ECDSA verify: recover(tee_sig, attestation_hash) == TEE pubkey
├─ Merkle chain: prev_attest_hash matches history
└─ Return true → Settlement proceeds
```

**Step 4: Fund Release & Settlement**
```
SolvexSettlement.settleIntent() continues
├─ Release escrowed token_in to solver
├─ Solver executes fill (DEX interaction)
├─ Distribute fee from solver to protocol
├─ Update solver reputation: accuracy = output_achieved / output_quoted
├─ Emit IntentSettled event → Indexer confirms
└─ User receives token_out directly from solver (or DEX)
```

### Timeout & Refund Path

If no attestation received within `SETTLEMENT_TIMEOUT`:
```
User or arbitrageur calls SolvexSettlement.refundIntent()
├─ Verify intent deadline passed
├─ Release escrowed token_in back to user
├─ Emit IntentRefunded event
└─ (User can resubmit intent if desired)
```

### Cross-Chain Settlement (Phase 2)

```
User intent specifies no specific chain → Multi-chain execution
├─ TEE queries liquidity on Arbitrum, Base, Optimism
├─ Selects best fill (any chain)
├─ Submits to SolvexSettlement on dest chain
├─ Bridge relayer monitors all SolvexSettlement contracts
├─ Atomic swap: funds locked on source chain until
│  destination settlement confirmed (or reverted)
└─ Message passing ensures atomic execution
```

---

## Security Model

### Threat Model & Mitigations

| Threat | Attack Vector | ENCLAVE Mitigation |
|--------|----------------|-----------------|
| **Quote Sniping** | Solver sees competitor bid, undercuts by 1 wei | TEE seals quotes; no solver sees bids until after selection |
| **Collusive Floor Setting** | Multiple solvers agree to bid floor | TEE randomizes quote order; deterministic argmax prevents negotiation |
| **Settlement Sandwich** | Solver front-runs their own fill | TEE signs fill; settlement verified onchain before execution |
| **Solver Equivocation** | Solver claims different winner to different validators | Merkle chain ensures immutable fill history |
| **TEE Compromise** | Attacker gains TEE memory access | GCP Confidential Space hardware attestation; no operator access to memory |
| **Oracle Manipulation** | Malicious price feed | Optional validator business logic can verify via external API |

### Security Assumptions

| Component | Assumption | Basis |
|-----------|-----------|-------|
| **TEE** | GCP Confidential Space prevents unauthorized memory access | Hardware attestation (Intel TDX, AMD SEV) |
| **Sequencer** | Cannot sign attestations for intents it didn't adjudicate | Cryptographic signature verification in Stylus |
| **Validators** | Cannot falsify Merkle chain of fills | Cryptographic hash chaining verified onchain |
| **User Signature** | Cannot forge user intent | EIP-712 ECDSA signature verification in IntentPool |
| **Solver Key** | Private key remains isolated in TEE | Ephemeral key generation, no export |

### Slashing & Accountability

**Automatic Slashing**:
- Solver submits two conflicting attestations for same intent → Slash 10% of stake
- Solver fails to deliver quoted output (output < min_out) → Reputation penalty (Phase 2)

**Manual Slashing**:
- Protocol governance can slash solver for protocol violations
- Requires multisig vote

**Key Expiration**:
- TEE keys must be re-attested and registered periodically (e.g., every 30 days)
- Expired keys cannot sign new attestations

---

## Gas Cost Analysis

### Comparison: Stylus vs Solidity vs zkVM

```
Per ECDSA Verification:
┌─────────────────────────┬──────────┬──────┐
│ Implementation          │ Gas Cost │ Time │
├─────────────────────────┼──────────┼──────┤
│ Solidity ecrecover      │ ~3,000   │ <1s  │
│ Stylus ECDSA (Rust/WASM)│ ~310     │ <1s  │
│ zkVM proof generation   │ ~0       │ 30m  │
│ zkVM proof verification │ ~80,000  │ <1s  │
└─────────────────────────┴──────────┴──────┘

Stylus Reduction: 310 / 3,000 = 89.7% gas savings per operation
```

### Batch Economics (Example: 50 Intents Filled Per Block)

```
Scenario 1: All Solidity ECDSA
├─ Cost per intent: 3,000 gas
├─ Total: 50 × 3,000 = 150,000 gas
└─ Time: <50ms total

Scenario 2: All Stylus ECDSA
├─ Cost per intent: 310 gas
├─ Total: 50 × 310 = 15,500 gas
└─ Time: <50ms total (WASM execution + EVM precompile overhead)

Scenario 3: zkVM Proof per Intent
├─ Cost per proof: 80,000 gas (verification only; proof generation O/O chain)
├─ Total: 50 × 80,000 = 4,000,000 gas
├─ Time: Wait for ZK computation (30m–3h)
└─ Practical result: ~20 proofs per day max

Savings (Stylus vs zkVM): 4,000,000 / 15,500 ≈ 258× cheaper at scale
```

### Transaction Breakdown

**Cost per Intent Settlement** (Stylus):
```
Component               | Gas  | Cost (at 10 gwei, $2500/ETH)
─────────────────────────────────────────────────────
SolvexVerifier.verify() | 310  | $0.008
IntentPool escrow       | 5,000| $0.125
SolvexSettlement release| 3,000| $0.075
Message passing (Phase 2)| 2,000| $0.050
─────────────────────────────────────────────────────
Total per fill          | 10,310| $0.258
```

**Annual Cost Estimate** (100k intents/day):
```
Stylus: 100k × 365 × 10,310 gas × 10 gwei × $2500/ETH = $935k/year
zkVM:   100k × 365 × 80,000 gas × 10 gwei × $2500/ETH = $7.3M/year
        (+ $28M/year for proof generation compute)

ENCLAVE savings: ~$36.3M/year vs zkVM
```

---

## Development Architecture

### File Structure

```
Enclave/
│
├── README.md
├── SPEC.md (this file)
├── Cargo.toml                      # Workspace root
├── rust-toolchain.toml
├── foundry.toml
├── justfile
│
├── contracts/                      # ── SOLIDITY LAYER ──
│   ├── foundry.toml
│   ├── src/
│   │   ├── types/
│   │   │   ├── DataTypes.sol       # Intent, Attestation
│   │   │   └── Errors.sol          # Custom errors
│   │   ├── interfaces/
│   │   │   ├── ISolvexVerifier.sol
│   │   │   ├── ISolverRegistry.sol
│   │   │   ├── IIntentPool.sol
│   │   │   └── ISolvexSettlement.sol
│   │   ├── SolverRegistry.sol
│   │   ├── IntentPool.sol
│   │   └── SolvexSettlement.sol
│   ├── test/
│   │   ├── SolverRegistry.t.sol
│   │   ├── IntentPool.t.sol
│   │   ├── SolvexSettlement.t.sol
│   │   └── Integration.t.sol
│   ├── script/
│   │   ├── DeployEnclave.s.sol
│   │   └── DeployLocal.s.sol
│   └── stylus/
│       └── solvex-verifier/
│           ├── Cargo.toml
│           ├── rust-toolchain.toml
│           └── src/lib.rs
│
├── crates/                         # ── RUST SERVICES ──
│   ├── enclave-shared/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types/
│   │       │   ├── intent.rs
│   │       │   ├── attestation.rs
│   │       │   └── cbor/mod.rs
│   │       └── config.rs
│   │
│   ├── enclave-solver-engine/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── config.rs
│   │       ├── competition.rs
│   │       ├── attestation.rs
│   │       ├── http_api.rs
│   │       └── registry.rs
│   │
│   ├── enclave-bootstrap/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs
│   │       └── submitter.rs
│   │
│   ├── gcp-attestation/            # ── (Reuse from SyndDB) ──
│   │   └── (symlink or copy)
│   │
│   └── enclave-intent-indexer/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── config.rs
│           ├── monitor.rs
│           └── handlers.rs
│
├── subgraph/                       # ── THE GRAPH INDEXER ──
│   ├── schema.graphql
│   ├── subgraph.yaml
│   └── src/
│       └── mapping.ts
│
├── docker/
│   ├── solver-engine.Dockerfile
│   └── bootstrap.Dockerfile
│
├── deploy/
│   └── terraform/                  # GCP Confidential Space IaC
│       ├── main.tf
│       └── variables.tf
│
└── demo/                           # ── HACKATHON DEMO ──
    ├── index.html                  # Attestation Explorer UI
    └── mev-comparison.html         # MEV Attack Demo
```

### Build & Deployment Commands

```bash
# Build Stylus contract
cd contracts/stylus/solvex-verifier
cargo build --release --target wasm32-unknown-unknown

# Deploy SolvexVerifier to Arbitrum
cargo stylus deploy --release --endpoint https://arbitrum-sepolia-rpc.publicnode.com

# Build and test Solidity contracts
cd contracts
forge build
forge test

# Build Rust services
cargo build --workspace --release

# Deploy to GCP Confidential Space
gcloud compute instances create-with-container enclave-solver-1 \
  --container-image us-central1-docker.pkg.dev/.../solver-engine:latest \
  --confidential-compute \
  --maintenance-policy TERMINATE
```

---

## Key Dependencies

### Solidity

| Package | Version | Purpose |
|---------|---------|---------|
| `forge-std` | Latest | Testing framework |
| `openzeppelin-contracts` | ~5.0 | Standard library (EIP-712, AccessControl) |

### Rust - Workspace

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | ~1.35 | Async runtime |
| `axum` | ~0.7 | HTTP framework |
| `alloy` | ~0.1 | Ethereum primitives + ABIs |
| `k256` | ~0.13 | secp256k1 signing (ECDSA) |
| `serde` | ~1.0 | Serialization |
| `tracing` | ~0.1 | Structured logging |
| `thiserror` | ~1.0 | Error handling |
| `anyhow` | ~1.0 | Error context |

### Stylus-Specific

| Crate | Version | Purpose |
|-------|---------|---------|
| `stylus-sdk` | 0.10+ | Arbitrum Stylus SDK for Rust |
| `alloy-primitives` | Latest | Fixed-size integer types for Solidity ABI |
| `alloy-sol-types` | Latest | Solidity type encoding/decoding |

### GCP Integration

| Tool | Version | Purpose |
|------|---------|---------|
| `gcp-attestation-verifier` | Latest | Verify Confidential Space OIDC tokens |
| `tonic` | ~0.10 | gRPC client (for GCP services) |

### Graph / Indexing

| Package | Version | Purpose |
|---------|---------|---------|
| `@graphprotocol/graph-cli` | Latest | Subgraph scaffolding & deployment |
| `assemblyscript` | Latest | Graph mapping language |

---

## Testing Strategy

### Unit Tests (Per Component)

**SolvexVerifier (Stylus)**:
```bash
cargo test -p enclave-shared --lib
# Tests: EIP-712 hashing, ECDSA recovery mock, Merkle chain validation
```

**Smart Contracts (Solidity)**:
```bash
forge test
# Tests: Intent escrow, solver registration, reputation updates, settlement logic
```

**Rust Services**:
```bash
cargo test --workspace --lib
# Tests: config parsing, HTTP endpoints, quote aggregation, signing
```

### Integration Tests

**Local Anvil + Deployed Contracts**:
```bash
# 1. Start Anvil
anvil

# 2. Deploy contracts locally
forge script DeployLocal --broadcast

# 3. Run integration tests
cargo test --test integration --features integration-tests
```

**Arbitrum Sepolia Testnet**:
```bash
# Deploy to Sepolia
forge script DeployEnclave --broadcast --rpc-url $ARB_SEPOLIA_RPC

# Run end-to-end test
cargo test --test e2e_arbitrum -- --nocapture
```

### Property-Based Testing

**Fuzzing (Solver Competition)**:
```bash
cargo +nightly fuzz run solver_competition_fuzz
# Property: For any set of quotes, argmax selection is deterministic
```

### Performance Testing

**Gas Benchmarking**:
```bash
forge snapshot --snap benchmarks/gas_usage.snap
# Track SolvexVerifier cost over time
```

**Throughput Testing**:
```bash
cargo bench --bench solver_throughput
# Property: solver can process N quotes/second
```

---

## Deployment Roadmap (5-Day Sprint)

### Day 1: Foundation
- [ ] Deploy SolvexVerifier Stylus contract (Arbitrum Sepolia)
- [ ] Deploy SolverRegistry.sol
- [ ] Deploy data type and interface contracts
- **Deliverable**: Contracts compiled, types verified, Sepolia deployment working

### Day 2: State Layer
- [ ] Deploy IntentPool.sol with EIP-712 verification
- [ ] Deploy SolvexSettlement.sol (mocked Stylus calls for testing)
- [ ] Create unit tests for all Solidity contracts
- **Deliverable**: Full Solidity test suite passing, Sepolia contracts initialized

### Day 3: Integration
- [ ] Connect real SolvexVerifier to SolvexSettlement
- [ ] End-to-end integration tests (Anvil)
- [ ] Deploy full stack to Arbitrum Sepolia
- **Deliverable**: Complete settlement flow working end-to-end

### Day 4: Off-Chain Services
- [ ] Build enclave-solver-engine HTTP API
- [ ] Build enclave-bootstrap key registration flow
- [ ] Test TEE bootstrap on GCP Confidential Space (staging)
- **Deliverable**: Solver can register and submit quotes

### Day 5: Demo & Polish
- [ ] Build Attestation Explorer UI
- [ ] Build MEV comparison demo
- [ ] Gas benchmark demo
- [ ] Final integration tests
- **Deliverable**: Hackathon-ready demo + documentation

---

## Glossary

| Term | Definition |
|------|-----------|
| **Attestation** | ECDSA-signed proof from TEE of sealed auction result |
| **Filled Intent** | Completed trade with winning solver outputting minimum or better |
| **Intent** | User's trade request (in ↔ out, min output, deadline) |
| **Nonce Guard** | Bloom filter preventing replay of settled intents |
| **Quote** | Solver's proposed output amount for user's input amount |
| **Sealed Auction** | Solver competition where no quote visible until selection |
| **Settlement** | Release of escrowed funds and distribution of fees |
| **Slashing** | Penalty applied to solver for protocol violations |
| **Solver** | Entity competing to fulfill user intent |
| **Stylus** | Arbitrum's WASM smart contract runtime for Rust |
| **TEE** | Trusted Execution Environment (GCP Confidential Space) |


**Document Version**: 1.0  
**Last Updated**: 2026-06-06  
**Status**: Ready for Development