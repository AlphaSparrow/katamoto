// Multi-Dimensional Tradeoff Engine and Economic Settlement Cost Model for Circle STARKs on Bitcoin
//
// Analyzes the Pareto frontier across:
// 1. FRI Folding Arity (2, 4, 8, 16)
// 2. Prover Proof-of-Work Grinding (0 to 32 bits)
// 3. Query Count & List-Decoding Soundness
// 4. Tapscript Leaf Sizes & Consensus Limits
// 5. On-Chain Transaction Weight (WU / vBytes)
// 6. Economic Settlement Cost in Satoshis and USD across Mempool Feerates

use crate::security::{ListDecodingCalculator, ProximityRegime};

/// A single evaluated point in the multi-dimensional Circle FRI trade-off space
#[derive(Debug, Clone, PartialEq)]
pub struct TradeoffPoint {
    /// Folding arity: 2 (standard), 4 (skip-layer), 8 (high-arity), or 16 (ultra-compact)
    pub arity: u32,
    /// Log2 of the blowup factor (1 for 2x, 2 for 4x)
    pub log_blowup: u32,
    /// PoW grinding bits required from prover
    pub pow_bits: u32,
    /// FRI query count
    pub query_count: u32,
    /// Target cryptographic security bits (e.g. 96 or 128)
    pub target_security_bits: u32,
    /// Effective soundness bits derived from list-decoding proximity gaps
    pub effective_soundness_bits: f64,
    /// TapLeaf script size in bytes (must be <= 520 bytes standardness limit)
    pub script_bytes: usize,
    /// Peak stack depth during execution (must be <= 1,000 items)
    pub peak_stack_depth: usize,
    /// Total witness bytes across all queries and Merkle paths
    pub witness_bytes: u64,
    /// Total transaction virtual size in vBytes
    pub total_vbytes: u64,
    /// Total transaction weight units (WU)
    pub total_weight_units: u64,
    /// Prover hashing operations (2^pow_bits)
    pub prover_work_hashes: u64,
    /// Estimated prover grinding latency in milliseconds (assuming single-core 1.5 MH/s)
    pub estimated_prover_time_ms: f64,
    /// Settlement cost in Satoshis at the evaluated feerate
    pub settlement_cost_sats: u64,
    /// Settlement cost in USD at the evaluated BTC price
    pub settlement_cost_usd: f64,
}

impl TradeoffPoint {
    /// Returns true if this configuration strictly conforms to all Bitcoin consensus rules:
    /// - Script size <= 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
    /// - Stack depth <= 1,000 items (MAX_STACK_ELEMENTS)
    /// - Soundness >= target security bits
    pub fn is_consensus_valid(&self) -> bool {
        self.script_bytes <= 520
            && self.peak_stack_depth <= 1000
            && self.effective_soundness_bits >= (self.target_security_bits as f64)
    }

    /// Checks if this point Pareto-dominates another point `other`:
    /// A point dominates if it is at least as good in fee and prover time, and strictly better in at least one.
    pub fn dominates(&self, other: &Self) -> bool {
        let fee_better = self.settlement_cost_sats <= other.settlement_cost_sats;
        let prover_better = self.prover_work_hashes <= other.prover_work_hashes;
        let strict_fee = self.settlement_cost_sats < other.settlement_cost_sats;
        let strict_prover = self.prover_work_hashes < other.prover_work_hashes;

        (fee_better && prover_better) && (strict_fee || strict_prover)
    }
}

/// Economic Settlement Cost Model for Bitcoin Layer 1
#[derive(Debug, Clone, Copy)]
pub struct L1SettlementCostModel {
    /// Mempool feerate in Satoshis per virtual byte (sat/vB)
    pub feerate_sat_per_vb: f64,
    /// Bitcoin price in USD (e.g. 95,000.0)
    pub btc_usd_price: f64,
    /// Prover single-core hash throughput in hashes per second (default: 1,500,000 H/s)
    pub prover_hash_rate_per_sec: f64,
}

impl Default for L1SettlementCostModel {
    fn default() -> Self {
        Self {
            feerate_sat_per_vb: 15.0, // Standard non-congested feerate
            btc_usd_price: 95_000.0,
            prover_hash_rate_per_sec: 1_500_000.0, // ~1.5 MH/s CPU core
        }
    }
}

impl L1SettlementCostModel {
    pub fn new(feerate_sat_per_vb: f64, btc_usd_price: f64) -> Self {
        Self {
            feerate_sat_per_vb,
            btc_usd_price,
            prover_hash_rate_per_sec: 1_500_000.0,
        }
    }

    /// Calculates fee in Satoshis for a given virtual size
    pub fn calculate_fee_sats(&self, vbytes: u64) -> u64 {
        ((vbytes as f64) * self.feerate_sat_per_vb).ceil() as u64
    }

    /// Converts Satoshis to USD
    pub fn calculate_cost_usd(&self, fee_sats: u64) -> f64 {
        ((fee_sats as f64) / 100_000_000.0) * self.btc_usd_price
    }

    /// Evaluates a specific configuration tuple in the model
    pub fn evaluate_point(
        &self,
        arity: u32,
        log_blowup: u32,
        pow_bits: u32,
        log_domain_size: u32,
        target_security: u32,
        regime: ProximityRegime,
    ) -> TradeoffPoint {
        let query_count = ListDecodingCalculator::calculate_min_queries(
            target_security,
            pow_bits,
            log_blowup,
            log_domain_size,
            regime,
        );

        let effective_soundness = ListDecodingCalculator::calculate_soundness_bits(
            query_count,
            log_blowup,
            pow_bits,
            log_domain_size,
            regime,
        );

        // Script size and stack depth characteristics by arity
        let (script_bytes, peak_stack_depth, siblings_per_fold, layers_per_fold) = match arity {
            2 => (21, 8, 1u64, 1u32),
            4 => (82, 12, 3u64, 2u32),
            8 => (136, 16, 7u64, 3u32),
            16 => (284, 24, 15u64, 4u32),
            _ => (82, 12, 3u64, 2u32),
        };

        // Witness calculations
        let effective_merkle_layers = (log_domain_size + layers_per_fold - 1) / layers_per_fold;
        let paths_per_query = if arity == 2 { 2u64 } else { 1u64 };
        let merkle_bytes_per_query =
            paths_per_query * (effective_merkle_layers as u64) * (log_domain_size as u64) * 32;
        let field_eval_bytes_per_query = siblings_per_fold * 4; // 4 bytes per M31

        let total_merkle_bytes = (query_count as u64) * merkle_bytes_per_query;
        let total_field_bytes = (query_count as u64) * field_eval_bytes_per_query;
        let fixed_overhead_bytes = 512u64 + 8u64; // OOD transcript + PoW nonce

        let witness_bytes = total_merkle_bytes + total_field_bytes + fixed_overhead_bytes;

        // BIP-341 Taproot weight calculation
        let base_tx_bytes = 40u64; // Tx headers, outpoints, locktime
        let control_block_bytes = 65u64; // 33-byte header + 32-byte merkle sibling
        let witness_weight = witness_bytes + (script_bytes as u64) + control_block_bytes;
        let total_weight_units = (base_tx_bytes * 4) + witness_weight;
        let total_vbytes = (total_weight_units + 3) / 4;

        let prover_work_hashes = 1u64 << pow_bits;
        let estimated_prover_time_ms =
            (prover_work_hashes as f64 / self.prover_hash_rate_per_sec) * 1000.0;

        let settlement_cost_sats = self.calculate_fee_sats(total_vbytes);
        let settlement_cost_usd = self.calculate_cost_usd(settlement_cost_sats);

        TradeoffPoint {
            arity,
            log_blowup,
            pow_bits,
            query_count,
            target_security_bits: target_security,
            effective_soundness_bits: effective_soundness,
            script_bytes,
            peak_stack_depth,
            witness_bytes,
            total_vbytes,
            total_weight_units,
            prover_work_hashes,
            estimated_prover_time_ms,
            settlement_cost_sats,
            settlement_cost_usd,
        }
    }
}

/// Computes multi-dimensional trade-off matrices and discovers Pareto frontiers
pub struct FriTradeoffMatrix;

impl FriTradeoffMatrix {
    /// Generates full trade-off evaluation points across standard candidate parameters
    pub fn evaluate_grid(
        model: &L1SettlementCostModel,
        target_security: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> Vec<TradeoffPoint> {
        let arities = [2u32, 4, 8, 16];
        let blowups = [1u32, 2];
        let pow_levels = [0u32, 8, 16, 20, 24, 28];

        let mut points = Vec::new();
        for &arity in &arities {
            for &blowup in &blowups {
                for &pow in &pow_levels {
                    let point = model.evaluate_point(
                        arity,
                        blowup,
                        pow,
                        log_domain_size,
                        target_security,
                        regime,
                    );
                    if point.is_consensus_valid() {
                        points.push(point);
                    }
                }
            }
        }
        points
    }

    /// Extracts the Pareto-optimal frontier from a set of evaluated points.
    /// A configuration is Pareto-optimal if no other configuration achieves strictly lower settlement fee
    /// and strictly lower prover computation time simultaneously.
    pub fn extract_pareto_frontier(points: &[TradeoffPoint]) -> Vec<TradeoffPoint> {
        let mut frontier = Vec::new();

        for (i, p) in points.iter().enumerate() {
            let mut is_dominated = false;
            for (j, other) in points.iter().enumerate() {
                if i != j && other.dominates(p) {
                    is_dominated = true;
                    break;
                }
            }
            if !is_dominated {
                frontier.push(p.clone());
            }
        }

        // Sort frontier by increasing prover work (which naturally corresponds to decreasing settlement fee)
        frontier.sort_by(|a, b| a.prover_work_hashes.cmp(&b.prover_work_hashes));
        frontier
    }

    /// Finds the globally cheapest settlement configuration that satisfies `target_security`
    pub fn find_cheapest_settlement(
        model: &L1SettlementCostModel,
        target_security: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> Option<TradeoffPoint> {
        let points = Self::evaluate_grid(model, target_security, log_domain_size, regime);
        points.into_iter().min_by_key(|p| p.settlement_cost_sats)
    }

    /// Finds the fastest prover configuration (lowest PoW) that satisfies `target_security`
    pub fn find_fastest_prover(
        model: &L1SettlementCostModel,
        target_security: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> Option<TradeoffPoint> {
        let points = Self::evaluate_grid(model, target_security, log_domain_size, regime);
        points.into_iter().min_by_key(|p| p.prover_work_hashes)
    }

    /// Finds the optimal configuration satisfying user-defined budget and latency constraints
    pub fn optimize_with_constraints(
        model: &L1SettlementCostModel,
        target_security: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
        max_fee_sats: Option<u64>,
        max_prover_time_ms: Option<f64>,
    ) -> Option<TradeoffPoint> {
        let points = Self::evaluate_grid(model, target_security, log_domain_size, regime);

        let filtered: Vec<TradeoffPoint> = points
            .into_iter()
            .filter(|p| {
                if let Some(max_fee) = max_fee_sats {
                    if p.settlement_cost_sats > max_fee {
                        return false;
                    }
                }
                if let Some(max_time) = max_prover_time_ms {
                    if p.estimated_prover_time_ms > max_time {
                        return false;
                    }
                }
                true
            })
            .collect();

        // From valid candidates, pick the one with lowest settlement fee
        filtered.into_iter().min_by_key(|p| p.settlement_cost_sats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_model_fee_and_usd_calculation() {
        let model = L1SettlementCostModel::new(20.0, 100_000.0);
        let vbytes = 1_000;
        let fee_sats = model.calculate_fee_sats(vbytes);
        assert_eq!(fee_sats, 20_000);

        let usd = model.calculate_cost_usd(fee_sats);
        // 20,000 sats at $100,000/BTC = 0.0002 BTC * 100,000 = $20.0
        assert!((usd - 20.0).abs() < 1e-4);
    }

    #[test]
    fn test_tradeoff_point_evaluation_and_consensus_limits() {
        let model = L1SettlementCostModel::default();
        let pt = model.evaluate_point(
            4,
            2,
            20,
            16,
            96,
            ProximityRegime::ListDecodingCapacity,
        );

        assert!(pt.is_consensus_valid());
        assert_eq!(pt.arity, 4);
        assert_eq!(pt.script_bytes, 82);
        assert!(pt.script_bytes <= 520);
        assert!(pt.peak_stack_depth <= 1000);
        assert!(pt.effective_soundness_bits >= 96.0);
        assert!(pt.settlement_cost_sats > 0);
    }

    #[test]
    fn test_pareto_frontier_extraction_is_non_empty_and_sorted() {
        let model = L1SettlementCostModel::default();
        let points = FriTradeoffMatrix::evaluate_grid(
            &model,
            96,
            16,
            ProximityRegime::ListDecodingCapacity,
        );

        assert!(!points.is_empty(), "Evaluated points must not be empty");
        let frontier = FriTradeoffMatrix::extract_pareto_frontier(&points);
        assert!(!frontier.is_empty(), "Pareto frontier must not be empty");

        // Verify that frontier is sorted by prover work hashes ascending
        for i in 1..frontier.len() {
            assert!(frontier[i].prover_work_hashes >= frontier[i - 1].prover_work_hashes);
        }
    }

    #[test]
    fn test_high_arity_reduces_settlement_cost() {
        let model = L1SettlementCostModel::default();
        let pt2 = model.evaluate_point(2, 1, 20, 16, 96, ProximityRegime::ListDecodingCapacity);
        let pt8 = model.evaluate_point(8, 1, 20, 16, 96, ProximityRegime::ListDecodingCapacity);

        // 8-to-1 folding should have significantly lower vBytes and settlement cost than 2-to-1
        assert!(
            pt8.total_vbytes < pt2.total_vbytes,
            "8-to-1 must reduce vBytes compared to 2-to-1"
        );
        assert!(
            pt8.settlement_cost_sats < pt2.settlement_cost_sats,
            "8-to-1 must reduce settlement cost compared to 2-to-1"
        );
    }

    #[test]
    fn test_optimize_with_constraints_honors_bounds() {
        let model = L1SettlementCostModel::default();
        let max_fee = 50_000_000u64; // High fee ceiling
        let max_time_ms = 5_000.0;    // 5 seconds max

        let opt = FriTradeoffMatrix::optimize_with_constraints(
            &model,
            96,
            16,
            ProximityRegime::ListDecodingCapacity,
            Some(max_fee),
            Some(max_time_ms),
        );

        assert!(opt.is_some());
        let res = opt.unwrap();
        assert!(res.settlement_cost_sats <= max_fee);
        assert!(res.estimated_prover_time_ms <= max_time_ms);
        assert!(res.effective_soundness_bits >= 96.0);
    }
}
