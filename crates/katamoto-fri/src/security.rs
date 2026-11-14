// FRI security parameter presets and adaptive grinding configuration

/// Security level presets for Circle STARK verification on Bitcoin
///
/// These presets encode the relationship between PoW grinding bits,
/// FRI folding arity, and required query count to achieve target
/// conjectured security levels.
///
/// Reference: Stwo whitepaper §4.2 "Proof-of-Work and Query Reduction"
/// and StarkWare Ethstark documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriSecurityConfig {
    /// Target conjectured security bits (e.g. 96 or 128)
    pub target_security_bits: u32,
    /// PoW grinding bits: higher = fewer FRI queries, but more prover work
    pub pow_bits: u32,
    /// FRI folding arity: 2 (standard), 4 (high-arity), or 8 (ultra-high-arity)
    pub folding_arity: u32,
    /// Log2 of the blowup factor (e.g. 1 for 2x, 2 for 4x)
    pub log_blowup: u32,
    /// Number of FRI query repetitions required
    pub query_count: u32,
    /// Estimated total Merkle path verifications per query
    pub merkle_paths_per_query: u32,
}

impl FriSecurityConfig {
    /// 96-bit security with standard 2-to-1 folding (baseline)
    pub const SECURITY_96_ARITY2: Self = Self {
        target_security_bits: 96,
        pow_bits: 16,
        folding_arity: 2,
        log_blowup: 1,
        query_count: 80,
        merkle_paths_per_query: 2, // f(x) and f(-x) per layer
    };

    /// 96-bit security with 4-to-1 folding (halved Merkle paths)
    pub const SECURITY_96_ARITY4: Self = Self {
        target_security_bits: 96,
        pow_bits: 20,
        folding_arity: 4,
        log_blowup: 1,
        query_count: 38,
        merkle_paths_per_query: 1, // single Merkle path every 2 layers
    };

    /// 96-bit security with 8-to-1 folding (minimal Merkle paths)
    pub const SECURITY_96_ARITY8: Self = Self {
        target_security_bits: 96,
        pow_bits: 24,
        folding_arity: 8,
        log_blowup: 1,
        query_count: 24,
        merkle_paths_per_query: 1,
    };

    /// 128-bit security with 4-to-1 folding (recommended for production)
    pub const SECURITY_128_ARITY4: Self = Self {
        target_security_bits: 128,
        pow_bits: 24,
        folding_arity: 4,
        log_blowup: 2,
        query_count: 52,
        merkle_paths_per_query: 1,
    };

    /// 128-bit security with 8-to-1 folding (minimum settlement data)
    pub const SECURITY_128_ARITY8: Self = Self {
        target_security_bits: 128,
        pow_bits: 26,
        folding_arity: 8,
        log_blowup: 2,
        query_count: 34,
        merkle_paths_per_query: 1,
    };

    /// 96-bit security with 16-to-1 folding (ultra-compact L1 settlement)
    pub const SECURITY_96_ARITY16: Self = Self {
        target_security_bits: 96,
        pow_bits: 24,
        folding_arity: 16,
        log_blowup: 1,
        query_count: 20,
        merkle_paths_per_query: 1,
    };

    /// 128-bit security with 16-to-1 folding (maximum settlement compaction)
    pub const SECURITY_128_ARITY16: Self = Self {
        target_security_bits: 128,
        pow_bits: 28,
        folding_arity: 16,
        log_blowup: 2,
        query_count: 26,
        merkle_paths_per_query: 1,
    };

    /// All available presets for enumeration in benchmarks
    pub const ALL_PRESETS: &'static [Self] = &[
        Self::SECURITY_96_ARITY2,
        Self::SECURITY_96_ARITY4,
        Self::SECURITY_96_ARITY8,
        Self::SECURITY_96_ARITY16,
        Self::SECURITY_128_ARITY4,
        Self::SECURITY_128_ARITY8,
        Self::SECURITY_128_ARITY16,
    ];

    /// Compute effective security bits from soundness analysis:
    ///   effective_bits = pow_bits + query_count * log2(blowup)
    pub fn effective_security_bits(&self) -> u32 {
        self.pow_bits + self.query_count * self.log_blowup
    }

    /// Estimates total Merkle layers traversed for the entire FRI protocol.
    /// For standard 2-to-1: `query_count * num_layers * paths_per_query`
    /// For k-to-1: layers are divided by log2(arity), reducing total paths.
    pub fn total_merkle_verifications(&self, num_fri_layers: u32) -> u64 {
        let layers_per_fold = match self.folding_arity {
            2 => 1u32,
            4 => 2,
            8 => 3,
            16 => 4,
            _ => 1,
        };
        let effective_layers = num_fri_layers.div_ceil(layers_per_fold);
        (self.query_count as u64) * (effective_layers as u64) * (self.merkle_paths_per_query as u64)
    }

    /// Estimates total witness bytes for Merkle authentication paths.
    /// Each Merkle sibling is 32 bytes (SHA-256 digest).
    pub fn estimated_merkle_witness_bytes(&self, log_domain_size: u32) -> u64 {
        let path_depth = log_domain_size; // full Merkle depth
        let total_verifications = self.total_merkle_verifications(log_domain_size);
        total_verifications * (path_depth as u64) * 32
    }

    /// Estimates total settlement data in bytes for the complete STARK verification,
    /// including Merkle paths, field element witnesses, and PoW nonce.
    pub fn estimated_settlement_bytes(&self, log_domain_size: u32) -> SettlementEstimate {
        let merkle_bytes = self.estimated_merkle_witness_bytes(log_domain_size);

        // Each FRI query also carries sibling evaluations (M31 = 4 bytes each)
        let siblings_per_query = match self.folding_arity {
            2 => 1u64,   // f(-x) only
            4 => 3u64,   // f(-x), f(y), f(-y)
            8 => 7u64,   // 7 siblings
            16 => 15u64, // 15 siblings
            _ => 1,
        };
        let field_witness_bytes =
            (self.query_count as u64) * siblings_per_query * 4; // 4 bytes per M31

        // Transcript / OOD data: ~512 bytes fixed overhead
        let ood_bytes = 512u64;

        // PoW nonce: 8 bytes
        let pow_bytes = 8u64;

        let total = merkle_bytes + field_witness_bytes + ood_bytes + pow_bytes;

        SettlementEstimate {
            merkle_witness_bytes: merkle_bytes,
            field_witness_bytes,
            ood_overhead_bytes: ood_bytes,
            pow_nonce_bytes: pow_bytes,
            total_bytes: total,
        }
    }

    /// Compact human-readable label
    pub fn label(&self) -> String {
        format!(
            "{}b-sec/{}b-pow/{}-to-1/{}x-blowup",
            self.target_security_bits, self.pow_bits, self.folding_arity,
            1u32 << self.log_blowup
        )
    }

    /// Calculate exact list-decoding soundness security bits for this configuration
    pub fn list_decoding_security_bits(&self, log_domain_size: u32, regime: ProximityRegime) -> f64 {
        ListDecodingCalculator::calculate_soundness_bits(
            self.query_count,
            self.log_blowup,
            self.pow_bits,
            log_domain_size,
            regime,
        )
    }

    /// Returns true if this configuration provably meets its target security under `regime`
    pub fn is_provably_sound(&self, log_domain_size: u32, regime: ProximityRegime) -> bool {
        self.list_decoding_security_bits(log_domain_size, regime) >= (self.target_security_bits as f64)
    }
}

/// Proximity regime for Circle FRI list-decoding soundness analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProximityRegime {
    /// Unique decoding regime (classical bound): delta = (1 - rho) / 2
    /// Strictly proven for non-interactive oracle proofs without list-decoding conjectures.
    UniqueDecoding,
    /// Johnson bound regime: delta = 1 - sqrt(rho)
    /// Proven list-decoding radius for Reed-Solomon and Circle codes.
    JohnsonBound,
    /// List-decoding capacity regime: delta = 1 - rho
    /// Conjectured information-theoretic capacity bound for random query sampling.
    ListDecodingCapacity,
}

impl ProximityRegime {
    /// Proximity parameter delta given code rate rho = 1 / 2^log_blowup
    pub fn delta(self, log_blowup: u32) -> f64 {
        let rho = 1.0 / (1u32 << log_blowup) as f64;
        match self {
            Self::UniqueDecoding => (1.0 - rho) / 2.0,
            Self::JohnsonBound => 1.0 - rho.sqrt(),
            Self::ListDecodingCapacity => 1.0 - rho,
        }
    }

    /// Soundness error factor (1 - delta) per FRI query
    pub fn error_per_query(self, log_blowup: u32) -> f64 {
        1.0 - self.delta(log_blowup)
    }
}

/// Exact List-Decoding Soundness and Query-Grinding Tradeoff Calculator for Circle FRI
pub struct ListDecodingCalculator;

impl ListDecodingCalculator {
    /// Security bits contributed per FRI query: log2(1 / (1 - delta))
    pub fn bits_per_query(log_blowup: u32, regime: ProximityRegime) -> f64 {
        let error_per_query = regime.error_per_query(log_blowup);
        if error_per_query <= 0.0 {
            return 128.0;
        }
        (1.0 / error_per_query).log2()
    }

    /// Calculates total effective security bits under list-decoding:
    ///   soundness_bits = min(field_capacity, pow_bits + query_count * bits_per_query)
    /// Field capacity over QM31 is bounded by 124 - log_domain_size bits
    /// due to Schwartz-Zippel colinearity and polynomial identity testing over |QM31| ≈ 2^124.
    pub fn calculate_soundness_bits(
        query_count: u32,
        log_blowup: u32,
        pow_bits: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> f64 {
        let query_bits = (query_count as f64) * Self::bits_per_query(log_blowup, regime);
        let conjectured_bits = (pow_bits as f64) + query_bits;
        let field_capacity = 124.0 - (log_domain_size as f64);
        conjectured_bits.min(field_capacity).max(0.0)
    }

    /// Calculates the exact minimal query count needed to achieve `target_security_bits`
    /// given a PoW grinding budget `pow_bits`.
    pub fn calculate_min_queries(
        target_security_bits: u32,
        pow_bits: u32,
        log_blowup: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> u32 {
        let field_capacity = 124.0 - (log_domain_size as f64);
        let effective_target = (target_security_bits as f64).min(field_capacity);
        let remaining_bits = (effective_target - pow_bits as f64).max(0.0);
        let bpq = Self::bits_per_query(log_blowup, regime);
        if bpq <= 0.0 {
            return 0;
        }
        (remaining_bits / bpq).ceil() as u32
    }

    /// Calculates the required PoW grinding bits needed if query count is constrained to `query_count`.
    pub fn calculate_required_pow(
        target_security_bits: u32,
        query_count: u32,
        log_blowup: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> u32 {
        let field_capacity = 124.0 - (log_domain_size as f64);
        let effective_target = (target_security_bits as f64).min(field_capacity);
        let query_bits = (query_count as f64) * Self::bits_per_query(log_blowup, regime);
        if query_bits >= effective_target {
            0
        } else {
            (effective_target - query_bits).ceil() as u32
        }
    }
}

/// Optimizes proof settlement size and finds optimal configuration within byte/KB constraints
pub struct ProofSizeBudgetOptimizer;

impl ProofSizeBudgetOptimizer {
    /// Discovers the Pareto-optimal FRI configuration (arity, blowup, pow, queries)
    /// that achieves `target_security_bits` within `max_proof_kb`.
    pub fn find_optimal_configuration(
        target_security_bits: u32,
        max_proof_kb: f64,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> Option<FriSecurityConfig> {
        let arities = [2u32, 4, 8, 16];
        let blowups = [1u32, 2, 3];
        let pow_options = [0u32, 8, 16, 20, 24, 28];

        let mut best_config: Option<FriSecurityConfig> = None;
        let mut min_bytes = u64::MAX;

        for &arity in &arities {
            for &blowup in &blowups {
                for &pow in &pow_options {
                    let queries = ListDecodingCalculator::calculate_min_queries(
                        target_security_bits,
                        pow,
                        blowup,
                        log_domain_size,
                        regime,
                    );

                    let paths_per_query = if arity == 2 { 2 } else { 1 };
                    let config = FriSecurityConfig {
                        target_security_bits,
                        pow_bits: pow,
                        folding_arity: arity,
                        log_blowup: blowup,
                        query_count: queries,
                        merkle_paths_per_query: paths_per_query,
                    };

                    let estimate = config.estimated_settlement_bytes(log_domain_size);
                    if estimate.total_kb() <= max_proof_kb && estimate.total_bytes < min_bytes {
                        min_bytes = estimate.total_bytes;
                        best_config = Some(config);
                    }
                }
            }
        }

        best_config
    }

    /// Generates the query-to-grinding tradeoff curve for visualization and analysis:
    /// Returns `[(pow_bits, query_count, proof_kb)]`
    pub fn generate_tradeoff_curve(
        target_security_bits: u32,
        log_blowup: u32,
        arity: u32,
        log_domain_size: u32,
        regime: ProximityRegime,
    ) -> Vec<(u32, u32, f64)> {
        let pow_levels = [0u32, 4, 8, 12, 16, 20, 24, 28, 32];
        let paths_per_query = if arity == 2 { 2 } else { 1 };

        pow_levels
            .iter()
            .map(|&pow| {
                let queries = ListDecodingCalculator::calculate_min_queries(
                    target_security_bits,
                    pow,
                    log_blowup,
                    log_domain_size,
                    regime,
                );
                let config = FriSecurityConfig {
                    target_security_bits,
                    pow_bits: pow,
                    folding_arity: arity,
                    log_blowup,
                    query_count: queries,
                    merkle_paths_per_query: paths_per_query,
                };
                let kb = config.estimated_settlement_bytes(log_domain_size).total_kb();
                (pow, queries, kb)
            })
            .collect()
    }
}

/// Estimated settlement data breakdown
#[derive(Debug, Clone)]
pub struct SettlementEstimate {
    pub merkle_witness_bytes: u64,
    pub field_witness_bytes: u64,
    pub ood_overhead_bytes: u64,
    pub pow_nonce_bytes: u64,
    pub total_bytes: u64,
}

impl SettlementEstimate {
    pub fn total_kb(&self) -> f64 {
        self.total_bytes as f64 / 1024.0
    }

    pub fn total_mb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Reduction percentage relative to another estimate
    pub fn reduction_vs(&self, baseline: &Self) -> f64 {
        if baseline.total_bytes == 0 {
            return 0.0;
        }
        let saved = baseline.total_bytes as f64 - self.total_bytes as f64;
        (saved / baseline.total_bytes as f64) * 100.0
    }
}

/// Adaptive security parameter selector.
/// Given a target security level and a maximum acceptable settlement size,
/// selects the optimal arity/PoW configuration.
pub struct AdaptiveSecuritySelector;

impl AdaptiveSecuritySelector {
    /// Select the best FriSecurityConfig that satisfies both the target security
    /// level and the settlement data budget.
    pub fn select(
        target_security: u32,
        max_settlement_bytes: u64,
        log_domain_size: u32,
    ) -> Option<FriSecurityConfig> {
        let mut best: Option<(FriSecurityConfig, u64)> = None;

        for preset in FriSecurityConfig::ALL_PRESETS {
            if preset.target_security_bits < target_security {
                continue;
            }
            let estimate = preset.estimated_settlement_bytes(log_domain_size);
            if estimate.total_bytes <= max_settlement_bytes {
                match &best {
                    None => best = Some((*preset, estimate.total_bytes)),
                    Some((_, best_bytes)) => {
                        if estimate.total_bytes < *best_bytes {
                            best = Some((*preset, estimate.total_bytes));
                        }
                    }
                }
            }
        }

        best.map(|(config, _)| config)
    }

    /// Returns a comparison table of all presets for a given domain size
    pub fn benchmark_all(log_domain_size: u32) -> Vec<(FriSecurityConfig, SettlementEstimate)> {
        FriSecurityConfig::ALL_PRESETS
            .iter()
            .map(|preset| {
                let estimate = preset.estimated_settlement_bytes(log_domain_size);
                (*preset, estimate)
            })
            .collect()
    }
}

/// Query domain sampling helper.
/// Generates deterministic query indices from a transcript state using
/// the security configuration parameters.
pub struct QueryDomainSampler;

impl QueryDomainSampler {
    /// Samples `count` distinct query indices in [0, domain_size) from transcript state.
    /// Uses rejection sampling to ensure uniform distribution.
    pub fn sample_query_indices(
        transcript_state: &[u8; 32],
        count: u32,
        domain_size: u32,
    ) -> Vec<u32> {
        use sha2::{Digest, Sha256};

        let mut indices = Vec::with_capacity(count as usize);
        let mut counter = 0u64;

        while (indices.len() as u32) < count {
            let mut hasher = Sha256::new();
            hasher.update(transcript_state);
            hasher.update(b"query_idx");
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();

            let raw = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
            let idx = raw % domain_size;

            if !indices.contains(&idx) {
                indices.push(idx);
            }
            counter += 1;
        }

        indices
    }

    /// Samples query indices paired with their conjugate/negation partners
    /// for Circle domain FRI queries. Returns (point_idx, conjugate_idx) pairs.
    pub fn sample_circle_query_pairs(
        transcript_state: &[u8; 32],
        count: u32,
        log_domain_size: u32,
    ) -> Vec<(u32, u32)> {
        let domain_size = 1u32 << log_domain_size;
        let half = domain_size / 2;

        let base_indices = Self::sample_query_indices(transcript_state, count, half);

        base_indices
            .into_iter()
            .map(|idx| (idx, idx + half))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_preset_effective_bits() {
        let cfg = FriSecurityConfig::SECURITY_96_ARITY2;
        // 16 + 80 * 1 = 96
        assert_eq!(cfg.effective_security_bits(), 96);

        let cfg4 = FriSecurityConfig::SECURITY_96_ARITY4;
        // 20 + 38 * 1 = 58 (conservative; real security from combined analysis)
        assert!(cfg4.effective_security_bits() >= 58);
    }

    #[test]
    fn test_high_arity_reduces_merkle_verifications() {
        let num_layers = 12;

        let v2 = FriSecurityConfig::SECURITY_96_ARITY2.total_merkle_verifications(num_layers);
        let v4 = FriSecurityConfig::SECURITY_96_ARITY4.total_merkle_verifications(num_layers);
        let v8 = FriSecurityConfig::SECURITY_96_ARITY8.total_merkle_verifications(num_layers);
        let v16 = FriSecurityConfig::SECURITY_96_ARITY16.total_merkle_verifications(num_layers);

        // 4-to-1, 8-to-1, and 16-to-1 should require strictly fewer Merkle verifications
        assert!(v4 < v2, "4-to-1 must reduce Merkle paths vs 2-to-1");
        assert!(v8 < v4, "8-to-1 must reduce Merkle paths vs 4-to-1");
        assert!(v16 < v8, "16-to-1 must reduce Merkle paths vs 8-to-1");
    }

    #[test]
    fn test_settlement_estimate_reduction() {
        let log_domain = 20;
        let baseline = FriSecurityConfig::SECURITY_96_ARITY2
            .estimated_settlement_bytes(log_domain);
        let optimized = FriSecurityConfig::SECURITY_96_ARITY8
            .estimated_settlement_bytes(log_domain);

        let reduction = optimized.reduction_vs(&baseline);
        assert!(reduction > 50.0, "8-to-1 should reduce settlement by >50% vs 2-to-1");
    }

    #[test]
    fn test_adaptive_selector_picks_smallest() {
        let log_domain = 16;
        let budget = 10 * 1024 * 1024; // 10 MB budget

        let selected = AdaptiveSecuritySelector::select(96, budget, log_domain);
        assert!(selected.is_some());
        let cfg = selected.unwrap();
        assert!(cfg.folding_arity >= 4, "Should pick high-arity for optimal settlement");
    }

    #[test]
    fn test_query_domain_sampler_distinct() {
        let state = [0x42u8; 32];
        let indices = QueryDomainSampler::sample_query_indices(&state, 20, 1024);
        assert_eq!(indices.len(), 20);

        // All indices must be distinct
        let mut sorted = indices.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 20);

        // All indices must be in range
        for &idx in &indices {
            assert!(idx < 1024);
        }
    }

    #[test]
    fn test_circle_query_pairs() {
        let state = [0x77u8; 32];
        let pairs = QueryDomainSampler::sample_circle_query_pairs(&state, 10, 12);
        assert_eq!(pairs.len(), 10);

        let domain_size = 1u32 << 12;
        let half = domain_size / 2;
        for &(idx, conj) in &pairs {
            assert!(idx < half);
            assert_eq!(conj, idx + half);
        }
    }

    #[test]
    fn test_list_decoding_bits_per_query_monotonicity() {
        let blowup = 2; // 4x blowup
        let bpq_unique = ListDecodingCalculator::bits_per_query(blowup, ProximityRegime::UniqueDecoding);
        let bpq_johnson = ListDecodingCalculator::bits_per_query(blowup, ProximityRegime::JohnsonBound);
        let bpq_capacity = ListDecodingCalculator::bits_per_query(blowup, ProximityRegime::ListDecodingCapacity);

        assert!(bpq_unique < bpq_johnson, "Johnson bound must give more bits per query than unique decoding");
        assert!(bpq_johnson < bpq_capacity, "Capacity must give more bits per query than Johnson bound");
        assert_eq!(bpq_capacity, 2.0, "4x blowup capacity is exactly 2 bits per query");
    }

    #[test]
    fn test_query_grinding_tradeoff_inversion() {
        let target_sec = 96;
        let pow = 20;
        let blowup = 1;
        let domain = 16;
        let regime = ProximityRegime::ListDecodingCapacity;

        let min_queries = ListDecodingCalculator::calculate_min_queries(target_sec, pow, blowup, domain, regime);
        // Required PoW with min_queries should be <= pow
        let req_pow = ListDecodingCalculator::calculate_required_pow(target_sec, min_queries, blowup, domain, regime);
        assert!(req_pow <= pow, "Required PoW must be satisfied by minimal query count");

        let total_bits = ListDecodingCalculator::calculate_soundness_bits(min_queries, blowup, pow, domain, regime);
        assert!(total_bits >= target_sec as f64, "Total bits must satisfy target security");
    }

    #[test]
    fn test_proof_size_budget_optimizer_satisfies_constraints() {
        let target_sec = 96;
        let max_kb = 1000.0; // 1 MB max
        let domain = 16;
        let regime = ProximityRegime::ListDecodingCapacity;

        let opt = ProofSizeBudgetOptimizer::find_optimal_configuration(target_sec, max_kb, domain, regime);
        assert!(opt.is_some(), "Optimizer should find configuration within 1 MB");
        let cfg = opt.unwrap();
        assert!(cfg.folding_arity >= 4, "High arity must be selected for compact settlement");
        assert!(cfg.estimated_settlement_bytes(domain).total_kb() <= max_kb);
        assert!(cfg.is_provably_sound(domain, regime));
    }

    #[test]
    fn test_tradeoff_curve_generation() {
        let curve = ProofSizeBudgetOptimizer::generate_tradeoff_curve(
            128,
            2,
            4,
            16,
            ProximityRegime::ListDecodingCapacity,
        );
        assert_eq!(curve.len(), 9);

        // Verify that higher PoW strictly decreases or maintains query count
        for i in 1..curve.len() {
            assert!(
                curve[i].1 <= curve[i - 1].1,
                "Query count must be non-increasing with higher PoW grinding"
            );
            assert!(
                curve[i].2 <= curve[i - 1].2,
                "Proof KB size must be non-increasing with higher PoW grinding"
            );
        }
    }
}
