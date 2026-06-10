use alloy_primitives::{Address, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let trimmed = s.trim_start_matches("0x");
    if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with("0x") {
        U256::from_str_radix(trimmed, 16).map_err(serde::de::Error::custom)
    } else {
        trimmed
            .parse::<u128>()
            .map(U256::from)
            .map_err(serde::de::Error::custom)
    }
}

/// User intent structure matching EIP-712 schema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Compute keccak256 hash of the intent for EIP-712 signing
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Keccak256};

        let encoded = format!(
            "{}{}{}{}{}{}{}",
            hex::encode(self.user.as_slice()),
            hex::encode(self.token_in.as_slice()),
            hex::encode(self.token_out.as_slice()),
            self.amount_in,
            self.min_amount_out,
            self.deadline,
            self.nonce
        );

        let mut hasher = Keccak256::new();
        hasher.update(encoded.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Registered solver information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solver {
    pub id: String,
    pub pubkey: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

/// Quote submitted by a solver during sealed auction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteData {
    pub solver_id: String,
    #[serde(deserialize_with = "deserialize_u256")]
    pub output_amount: U256,
    #[serde(deserialize_with = "deserialize_address")]
    pub fill_route: Address,
    #[serde(deserialize_with = "deserialize_u256")]
    pub gas_estimate: U256,
    #[serde(default = "chrono::Utc::now")]
    pub timestamp: DateTime<Utc>,
}

// Add this function — accepts any hex address, no checksum required
fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let hex = s.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(serde::de::Error::custom)?;
    Ok(Address::from_slice(&bytes))
}

/// Sealed solver registration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverRegistration {
    pub solver_id: String,
    pub tee_pubkey: Vec<u8>,
    pub stake_amount: U256,
}

/// Result of sealed competition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitionResult {
    pub winner_solver_id: String,
    pub winning_output: U256,
    pub fill_route: Address,
    pub all_quotes_count: u32,
}

/// Configuration for intent conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConditions {
    pub allows_partial_fill: bool,
    pub requires_single_solver: bool,
    pub max_return_value_loss_bps: u16, // basis points
}

impl Default for IntentConditions {
    fn default() -> Self {
        Self {
            allows_partial_fill: false,
            requires_single_solver: true,
            max_return_value_loss_bps: 50, // 0.5%
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_hash_consistency() {
        let intent = Intent {
            user: Address::ZERO,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: U256::from(1000),
            min_amount_out: U256::from(900),
            deadline: 1234567890,
            nonce: 1,
        };

        let hash1 = intent.hash();
        let hash2 = intent.hash();
        assert_eq!(hash1, hash2);
    }
}
