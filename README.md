## **Enclave Protocol** 

_A TEE-Sealed Solver Competition with Stylus-Verified Onchain Attestation on Arbitrum_ 

## **Executive Summary** 

Enclave eliminates solver-level MEV from intent-based DEX routing. Today, intent protocols broadcast solver competitions to a semi-public environment: solvers see competitors' quotes, collude on fee extraction, and sandwich the very users they claim to serve. Enclave seals the entire competition inside a Trusted Execution Environment (TEE), then proves the correct solver won using a Rust smart contract on Arbitrum Stylus — replacing expensive zkVM proofs with sub-second ECDSA batch verification at roughly 10× lower gas cost than equivalent Solidity. 

This document details the technical implementation in two phases: 

Section 1 (Core MVP): The sealed TEE solver pool, the Stylus-based SolvexVerifier contract, and the Solidity settlement layer. This directly solves solver MEV and the oracle-trust problem in current intent protocols. 

Section 2 (Extended Vision): An onchain solver reputation system with reputation-gated fee tiers, cross-chain intent routing, and a public solver performance dashboard backed by The Graph indexing. 
