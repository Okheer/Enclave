

PRISM Protocol
## Private Routing & Intent Settlement Mechanism
A TEE-Sealed Solver Competition with Stylus-Verified Onchain Attestation on Arbitrum
## Executive Summary
PRISM eliminates solver-level MEV from intent-based DEX routing. Today, intent protocols broadcast solver competitions to
a  semi-public  environment:  solvers  see  competitors'  quotes,  collude  on  fee  extraction,  and  sandwich  the  very  users  they
claim to serve. PRISM seals the entire competition inside a Trusted Execution Environment (TEE), then proves the correct
solver  won  using  a  Rust  smart  contract  on  Arbitrum  Stylus  —  replacing  expensive  zkVM  proofs  with  sub-second  ECDSA
batch verification at roughly 10× lower gas cost than equivalent Solidity.
This document details the technical implementation in two phases:
Section  1  (Core  MVP):  The  sealed  TEE  solver  pool,  the  Stylus-based  SolvexVerifier  contract,  and  the  Solidity  settlement
layer. This directly solves solver MEV and the oracle-trust problem in current intent protocols.
Section 2 (Extended Vision): An onchain solver reputation system with reputation-gated fee tiers, cross-chain intent routing,
and a public solver performance dashboard backed by The Graph indexing.
Section 1: PRISM Core MVP — Sealed Solver + Stylus Attestation
- What is to be Built
The core MVP delivers three tightly integrated primitives: a sealed TEE solver pool, a Stylus-native ECDSA attestation
verifier, and a non-custodial Solidity settlement layer. Together they form a complete intent-execution pipeline where no
single component can lie about what happened inside the solver competition.
-  Sealed TEE Solver Pool: Solvers register a stake and a TEE public key onchain. All competition logic runs inside
GCP Confidential Space — a hardware-attested enclave where neither the operator nor other solvers can read the
sealed memory.
-  SolvexVerifier (Stylus/Rust): A Rust contract compiled to WASM via Arbitrum Stylus that verifies ECDSA
attestations emitted by the TEE. Handles batch verification, nonce replay-guard, and Merkle receipt chaining —
operations too gas-expensive for Solidity.
-  IntentPool + Settlement (Solidity): Receives EIP-712 signed intents, escrows funds, and releases them only after
SolvexVerifier confirms a valid TEE attestation.

Figure 1: The Solver MEV Problem & PRISM's Fix.
Left — In traditional intent protocols, solvers see competing quotes, enabling collusion and sandwich attacks. Right — PRISM runs
competition inside a TEE; the Stylus contract verifies the TEE's signed attestation before any funds move.
- Why it is being Built
The  primary  barrier  to  trustless  intent  execution  is  the  solver-trust  assumption  embedded  in  every  major  protocol  today.
CoW  Protocol  mitigates  this  via  batch  auctions  but  requires  a  trusted  coordinator.  1inch  Fusion  and  UniswapX  expose
solver competition publicly, creating a race-to-exploit environment for MEV searchers.
2.1 The Solver MEV Problem
In any protocol where solver competition is observable — even partially — informed solvers can extract value at the user's
expense. Three attack vectors exist:
-  Quote Sniping: A solver observes a competitor's near-winning quote and undercuts by 1 wei, claiming the reward
while providing no real improvement to the user.
-  Collusive Floor Setting: Colluding solvers agree to never bid above a minimum fee threshold, suppressing genuine
competition.
-  Sandwich at Settlement: A solver who controls the settlement transaction can front-run the user's fill at the DEX
level.
2.2 Why TEE + Stylus Solves This
The  TEE  eliminates  all  three  attack  vectors  simultaneously.  Because  the  competition  runs  in  hardware-attested  sealed
memory, no solver — including the TEE operator — can observe peer quotes during the auction. The winning fill is selected
deterministically by argmax(output_amount) with no human-readable intermediate state.
The Stylus verifier closes the remaining trust gap: it proves onchain that the TEE ran correctly before funds are released.
This  replaces  the  alternative  approach  —  zkVM  proofs  —  which  cost  $0.018–$0.13  per  proof  and  take  30  seconds  to  3
minutes to generate. Stylus ECDSA verification costs approximately 310 gas per fill and completes within the same block.
- How it is to be Built (Technical Analysis)

3.1 Arbitrum Stylus (Rust → WASM)
Solidity's  EVM  is  poorly  suited  for  batch  cryptographic  operations.  Each  ecrecover  costs  ~3,000  gas;  chaining  20  solver
attestation checks per block would cost ~60,000 gas in Solidity alone. PRISM's SolvexVerifier is implemented as a unified
Rust  contract  compiled  to  WebAssembly  via  Arbitrum  Stylus,  reducing  per-ECDSA  cost  to  approximately  310  gas  —  an
89.7% reduction that compounds with every intent filled.
3.2 Intent Schema & TEE Attestation Format
Every user intent is structured as an EIP-712 typed hash:
struct Intent {
address user;
address token_in;
address token_out;
uint256 amount_in;
uint256 min_amount_out;
uint64 deadline;
uint64 nonce;
## }
// intent_hash = keccak256(abi.encode(intent))
After the TEE selects the winning fill, it emits a signed attestation covering:
struct Attestation {
bytes32 intent_hash;
address winner_solver;
address fill_route; // DEX router used
uint256 output_amount;
uint64 block_number;
bytes32 prev_attest_hash; // Merkle chain
## }
// tee_sig = ECDSA.sign(pk_tee, keccak256(abi.encode(attest)))
3.3 SolvexVerifier (Rust/Stylus) — Verification Logic
The Stylus contract receives (intent_hash, attestation, tee_sig) and runs three checks in sequence before returning true
to the settlement contract:
-  Nonce Guard: Rejects replay by storing a Bloom filter of settled intent hashes.
-  ECDSA Signature Check: Recovers signer from keccak256(abi.encode(attestation)) and compares against the
TEE public key stored in SolverRegistry.
-  Merkle Chain Continuity: Verifies attest.prev_attest_hash == H(prev_attest) to ensure no past fill was silently
dropped from the chain.
The Rust verification function signature:
## #[external]
pub fn verify(
## &self,
intent_hash: FixedBytes<32>,
attestation: Attestation,
tee_sig: Bytes,
## ) -> Result<bool, Vec<u8>> {

let signer = ecrecover(keccak256(encode(&attestation)), &tee_sig)?;
let reg_key = self.solver_registry.get_pubkey(attestation.winner_solver)?;
ensure!(signer == reg_key, SolvexError::InvalidAttestation);
self.check_nonce(intent_hash)?;
self.verify_chain(attestation.prev_attest_hash)?;
## Ok(true)
## }
Figure 2: Gas Cost Analysis — Stylus vs Solidity vs zkVM.
Left — Per-operation gas cost for key cryptographic primitives. Stylus (Rust/WASM) achieves ~89.7% reduction over Solidity for ECDSA
verification and comparable savings across all compute-heavy operations. Right — Cumulative gas saving over batch fills per block: at 50
fills, Stylus saves ~134,500 gas vs. Solidity, compounding on every block.
Figure 3: PRISM Protocol Full System Architecture.
The four-layer stack: (1) User submits EIP-712 signed intent; (2) TEE runs sealed solver competition and emits ECDSA attestation; (3)
Stylus verifier confirms attestation onchain; (4) Solidity settlement releases escrowed funds. All components sit on Arbitrum One's
fraud-provable WASM execution environment.
- High-Level Architecture & Infrastructure

ComponentTechnology StackPurpose / Function
SolvexVerifierRust / Arbitrum StylusECDSA batch verification of TEE attestations; Merkle receipt chain; nonce guard. ~10x cheaper than Solidity ECDSA.
IntentPool.solSolidity / ERC-712Receives signed intents, validates schema, escrows user funds, stores keccak256 intent hash registry.
SolvexSettlement.solSolidityCalls SolvexVerifier before releasing escrowed funds; distributes solver fees; handles timeouts.
SolverRegistry.solSolidityOnboards solvers with stake + TEE public key. Manages slashing and reputation score updates.
TEE Solver EngineRust binary / GCP Confidential SpaceSealed solver competition: collects quotes, selects argmax(output), signs attestation. No solver sees peers' quotes.
Intent IndexerThe Graph / SubsquidIndexes OmniverseTrade-style unified events; tracks intent state machine (Pending → Filled → Settled).
- Presentation to Judges
The pitch hook is 14 words: "Prove your solver won fairly — without trusting anyone,
including us."
The demo is designed to be visceral and directly falsifiable:
-  The MEV Attack Demo: Tab 1 runs a naive intent protocol. We simulate a colluding solver pair that quote-snipes the
true best fill and skims 40 bps from the user. Tab 2 runs PRISM. The same colluding pair submits quotes into the TEE —
neither sees the other's bid. The TEE selects the true winner. The Stylus verifier confirms onchain in under one second.
-  The Gas Benchmark: We call equivalent ECDSA batch verification (20 fills) via Solidity and via the Stylus verifier live
on Arbitrum Sepolia. The block explorer shows ~60,000 gas vs ~6,200 gas. The difference is the Stylus story in a single
screenshot.
-  The Attestation Explorer: An interactive UI shows the live Merkle chain of intent receipts. Judges can click any
historical fill and cryptographically verify it was executed by the correct solver running the correct TEE.
Section 2: PRISM Extended Vision — Reputation Layer & Cross-Chain Routing
- What is to be Built
Phase  2  introduces  an  onchain  solver  reputation  system  alongside  multi-chain  intent  routing.  While  Phase  1  treats  all
registered solvers as equally eligible, the extended system tracks fill quality history and uses it to gate solver fee tiers and
auction participation weight — creating a meritocratic solver market.
-  Reputation State: Each solver accumulates a score R(s) ∈ [0, 1] based on fill accuracy (actual vs. quoted output),
latency, and slash-free history.
-  Fee-Tier Gating: Solvers with R(s) > 0.85 access a lower fee cap, incentivising quality. Solvers that fall below R(s) =
0.3 are temporarily suspended from auctions.
-  Cross-Chain Routing: The TEE solver pool is extended to query liquidity across Arbitrum One, Base, and Optimism
simultaneously. The best cross-chain fill is attested by the TEE and bridged atomically via a shared settlement contract
on each chain.

- Why it is being Built
Binary  reputation  (registered  /  slashed)  is  insufficient  for  a  competitive  solver  market.  A  solver  that  consistently  delivers
99.8% of quoted output should earn structural advantages over one that delivers 95%. This mirrors how prime brokerage
markets work: counterparty quality determines trade terms, not merely counterparty existence.
Cross-chain  liquidity  fragmentation  is  the  deeper  unsolved  problem.  A  user  intending  to  swap  50  ETH  finds  80%  of  the
liquidity on Base and 20% on Arbitrum. No single-chain intent protocol can access this. PRISM's TEE naturally extends to
multi-chain quote aggregation without requiring the user to know which chain holds the best fill.
- How it is to be Built (Technical Analysis)
## 3.1 Reputation Score Update
After each settled fill, SolvexSettlement calls SolverRegistry to update R(s):
// Called by SolvexSettlement after each confirmed fill
fn update_reputation(solver: address, actual_out: u256, quoted_out: u256) {
let accuracy = actual_out.to_f64() / quoted_out.to_f64();
let alpha = 0.05_f64; // EMA smoothing factor
let prev_r = self.reputation.get(solver);
let new_r = alpha * accuracy + (1.0 - alpha) * prev_r;
self.reputation.insert(solver, new_r.clamp(0.0, 1.0));
## }
The  smoothing  factor  α  =  0.05  means  reputation  responds  to  recent  performance  over  approximately  20  fills,  preventing
single-event manipulation while remaining responsive to genuine quality improvements.
Figure 4: Solver Reputation Dynamics & Fee-Tier Gating.
Left — Reputation score R(s) over time for three solver profiles. A slashing event at block 40 causes exponential decay for the offending
solver, while high-quality solvers maintain stable scores near 1.0. Right — Reputation-gated fee cap (basis points) as a function of R(s).
High-reputation solvers face a lower fee ceiling, compressing their extractable margin and passing savings to users.