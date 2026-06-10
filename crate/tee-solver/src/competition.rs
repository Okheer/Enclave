use crate::error::{TeeError, Result};
use crate::types::QuoteData;
use alloy_primitives::U256;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Sealed solver competition - runs inside TEE
/// Collects quotes from solvers and selects winner via argmax(output_amount)
pub struct SolverCompetition {
    /// Map of solver_id -> list of quotes
    quotes: Arc<DashMap<String, Vec<QuoteData>>>,
    /// State: whether auctions can still receive quotes
    is_open: Arc<RwLock<bool>>,
    /// Current auction intent hash (to prevent cross-intent quote mixing)
    current_intent_hash: Arc<RwLock<Option<[u8; 32]>>>,
    /// Statistics tracking
    stats: Arc<RwLock<CompetitionStats>>,
}

#[derive(Debug, Clone, Default)]
struct CompetitionStats {
    total_auctions: u64,
    total_quotes_received: u64,
    average_quotes_per_auction: f64,
}

impl SolverCompetition {
    pub fn new() -> Self {
        Self {
            quotes: Arc::new(DashMap::new()),
            is_open: Arc::new(RwLock::new(true)),
            current_intent_hash: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(CompetitionStats::default())),
        }
    }

    /// Initialize a new competition for a specific intent
    pub fn start_competition(&self, intent_hash: [u8; 32]) -> Result<()> {
        if !*self.is_open.read() {
            return Err(TeeError::AuctionClosed);
        }

        let mut current = self.current_intent_hash.write();
        
        if current.is_some() {
            return Err(TeeError::InternalError(
                "Competition already in progress".to_string(),
            ));
        }

        self.quotes.clear();
        *current = Some(intent_hash);
        Ok(())
    }

    /// Collect a quote from a solver (only visible to TEE, not to other solvers)
    pub fn add_quote(&self, solver_id: String, quote: QuoteData) -> Result<()> {
        if !*self.is_open.read() {
            return Err(TeeError::AuctionClosed);
        }

        // Validate quote structure
        self.validate_quote(&quote)?;

        // Ensure quote is for current auction
        let current_hash = *self.current_intent_hash.read();
        if current_hash.is_none() {
            return Err(TeeError::InternalError("No active auction".to_string()));
        }

        // All quotes are sealed - no visibility to other solvers
        self.quotes
            .entry(solver_id)
            .or_insert_with(Vec::new)
            .push(quote);

        Ok(())
    }

    /// Select winner by argmax(output_amount) - deterministic, no human intervention
    pub fn select_winner(&self) -> Result<QuoteData> {
        if self.quotes.is_empty() {
            return Err(TeeError::NoQuotesSubmitted);
        }

        let mut best_quote: Option<QuoteData> = None;
        let mut best_output = U256::ZERO;

        // Iterate through all quotes to find maximum
        for entry in self.quotes.iter() {
            let quotes_vec = entry.value();
            for quote in quotes_vec {
                if quote.output_amount > best_output {
                    best_output = quote.output_amount;
                    best_quote = Some(quote.clone());
                }
            }
        }

        best_quote.ok_or_else(|| TeeError::NoQuotesSubmitted)
    }

    /// Get all quotes for a specific solver (debugging/audit only - never exposed onchain)
    pub fn get_solver_quotes(&self, solver_id: &str) -> Option<Vec<QuoteData>> {
        self.quotes.get(solver_id).map(|r| r.clone())
    }

    /// Get quote count per solver
    pub fn get_quotes_count(&self) -> Vec<(String, usize)> {
        self.quotes
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().len()))
            .collect()
    }

    /// Close the auction - no more quotes accepted
    pub fn close_auction(&self) -> Result<()> {
        *self.is_open.write() = false;
        Ok(())
    }

    /// Finalize competition - prepare for attestation signing
    pub fn finalize(&self) -> Result<()> {
        if self.quotes.is_empty() {
            return Err(TeeError::NoQuotesSubmitted);
        }

        self.close_auction()?;

        // Update stats
        let mut stats = self.stats.write();
        stats.total_auctions += 1;
        stats.total_quotes_received += self.get_total_quotes() as u64;
        stats.average_quotes_per_auction =
            stats.total_quotes_received as f64 / stats.total_auctions as f64;

        Ok(())
    }

    /// Reset for next auction
    pub fn reset(&self) -> Result<()> {
        self.quotes.clear();
        *self.is_open.write() = true;
        *self.current_intent_hash.write() = None;
        Ok(())
    }

    /// Get total number of quotes received
    fn get_total_quotes(&self) -> usize {
        self.quotes
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Validate quote structure
    fn validate_quote(&self, quote: &QuoteData) -> Result<()> {
        if quote.output_amount == U256::ZERO {
            return Err(TeeError::InvalidQuote("Zero output amount".to_string()));
        }

        if quote.solver_id.is_empty() {
            return Err(TeeError::InvalidQuote("Empty solver ID".to_string()));
        }

        Ok(())
    }

    /// Get competition statistics
    pub fn get_stats(&self) -> CompetitionStats {
        self.stats.read().clone()
    }
}

impl Default for SolverCompetition {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use chrono::Utc;

    fn create_test_quote(solver_id: &str, output: u128) -> QuoteData {
        QuoteData {
            output_amount: U256::from(output),
            fill_route: Address::ZERO,
            gas_estimate: U256::from(100_000),
            timestamp: Utc::now(),
            solver_id: solver_id.to_string(),
        }
    }

    #[test]
    fn test_competition_initialization() {
        let competition = SolverCompetition::new();
        let intent_hash = [1u8; 32];
        competition.start_competition(intent_hash).unwrap();
        assert_eq!(*competition.current_intent_hash.read(), Some(intent_hash));
    }

    #[test]
    fn test_argmax_selection() {
        let competition = SolverCompetition::new();
        let intent_hash = [1u8; 32];
        competition.start_competition(intent_hash).unwrap();

        competition
            .add_quote("solver1".to_string(), create_test_quote("solver1", 1000))
            .unwrap();
        competition
            .add_quote("solver2".to_string(), create_test_quote("solver2", 2000))
            .unwrap();
        competition
            .add_quote("solver3".to_string(), create_test_quote("solver3", 1500))
            .unwrap();

        competition.finalize().unwrap();
        let winner = competition.select_winner().unwrap();

        assert_eq!(winner.solver_id, "solver2");
        assert_eq!(winner.output_amount, U256::from(2000));
    }

    #[test]
    fn test_invalid_quote_rejection() {
        let competition = SolverCompetition::new();
        let intent_hash = [1u8; 32];
        competition.start_competition(intent_hash).unwrap();

        let invalid_quote = QuoteData {
            output_amount: U256::ZERO,
            fill_route: Address::ZERO,
            gas_estimate: U256::from(100_000),
            timestamp: Utc::now(),
            solver_id: "solver1".to_string(),
        };

        let result = competition.add_quote("solver1".to_string(), invalid_quote);
        assert!(result.is_err());
    }

    #[test]
    fn test_auction_closed() {
        let competition = SolverCompetition::new();
        let intent_hash = [1u8; 32];
        competition.start_competition(intent_hash).unwrap();
        competition.close_auction().unwrap();

        let quote = create_test_quote("solver1", 1000);
        let result = competition.add_quote("solver1".to_string(), quote);
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_competition() {
        let competition = SolverCompetition::new();
        let intent_hash = [1u8; 32];
        competition.start_competition(intent_hash).unwrap();
        competition
            .add_quote("solver1".to_string(), create_test_quote("solver1", 1000))
            .unwrap();

        competition.reset().unwrap();

        assert_eq!(*competition.current_intent_hash.read(), None);
        assert_eq!(competition.get_total_quotes(), 0);
        assert!(competition.quotes.is_empty());
    }
}
