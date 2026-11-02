# Katamoto

**Zero-Knowledge STARK Verifier & Tapscript Compiler for Bitcoin**

[![Build & Test](https://img.shields.io/badge/tests-90%2F90%20passing-brightgreen?style=flat-square)](https://github.com/AlphaSparrow/katamoto)
[![Rust](https://img.shields.io/badge/rust-2021-blue?style=flat-square)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![BIP-347](https://img.shields.io/badge/BIP--347-OP__CAT-success?style=flat-square)](https://github.com/bitcoin/bips/pull/1628)

Katamoto is an execution engine and Tapscript compiler that verifies Circle STARK (Stwo) proofs directly within Bitcoin Script. It supports both **BIP-347 (`OP_CAT`) covenants** on testbeds like Bitcoin Inquisition, and **optimistic BitVM2 fraud proofs** on Bitcoin mainnet.

---

## Key Features

* **Circle STARKs over Mersenne-31**: Operates on the Circle curve $\mathcal{C}(M_{31}): x^2 + y^2 = 1$ of order $2^{31}$, enabling native power-of-2 FFTs without elliptic curve pairings.
* **Consensus-Strict Arithmetic**: Complies with BIP-342's 4-byte signed `ScriptNum` limit ($[-2^{31}+1, 2^{31}-1]$) using an overflow-free subtraction trick ($a - (p - b)$) for all $M_{31}$ operations.
* **Preimage-Bound Merkle Verification**: Binds polynomial evaluation field elements directly to Merkle leaf preimages (`OP_CAT` + `OP_SHA256`) to ensure proof soundness.
* **High-Arity Circle FRI Folding**: Supports 4-to-1, 8-to-1, and 16-to-1 skip-layer folding, eliminating up to 75% of intermediate Merkle roots.
* **Dual-Backend Support**:
  * **OP_CAT Signet**: Direct on-chain verification in partitioned Taproot leaves.
  * **Mainnet BitVM2**: Optimistic verification using Winternitz OTS (WOTS) state commitments for challenge-dispute resolution.

---

## Workspace Structure

| Crate | Purpose | Key Primitives |
| :--- | :--- | :--- |
| [`katamoto-script`](./crates/katamoto-script) | Tapscript VM & Assembler | Strict 4-byte ScriptNum VM, BIP-347 `OP_CAT`, peephole optimizer, WOTS |
| [`katamoto-field`](./crates/katamoto-field) | Field & Curve Primitives | $M_{31}$, $QM_{31}$, subtraction-trick addition, Montgomery batch inversion |
| [`katamoto-fri`](./crates/katamoto-fri) | FRI & Merkle Tree Gadgets | Preimage-bound Merkle verifiers, 4:1 to 16:1 skip-layer Circle FRI folding |
| [`katamoto-air`](./crates/katamoto-air) | AIR Constraints & Compilers | Fibonacci AIR, LogUp lookups, TapTree compiler, BitVM dispute graphs |
| [`katamoto-stwo`](./crates/katamoto-stwo) | Stwo Bridge & zkVM Verifier | Stwo proof parser, canonical recursive verifier, RV32I zkVM step verifiers |
| [`katamoto-cli`](./crates/katamoto-cli) | Benchmarks & Settlement CLI | Telemetry suite (`bench --json`), descriptor export, transaction emitter |

---

## Technical Details

### 1. Consensus-Safe $M_{31}$ Addition
In BIP-342 Tapscript, arithmetic operands are capped at 4 bytes signed. Direct addition $a + b$ over $M_{31} = 2^{31} - 1$ can produce sums up to $2^{32} - 4$, which requires a 5th sign byte and triggers a consensus error. Katamoto resolves this using an overflow-free subtraction sequence:

$$b' = p - b \in [1, p]$$
$$\text{res} = a - b' = a + b - p \in [-p, p-2]$$
$$\text{if } \text{res} < 0: \quad \text{res} \leftarrow \text{res} + p$$

Every intermediate value stays strictly within $[-2147483647, 2147483647]$.

### 2. Settlement Costs
Taproot spends execute one leaf script at a time. Individual leaf spends are compact, while complete proofs settle across partitioned leaves within standard mempool limits:

| Spend Target | Script Size | Witness Size | Transaction Size | Transaction Weight |
| :--- | :---: | :---: | :---: | :---: |
| Boundary Check (Leaf 0) | 7 B | 139 B | 131 vB | 522 WU |
| OOD Quotient (Leaf 1) | 25 B | 147 B | 136 vB | 542 WU |
| FRI Query Round (Leaves 3–6) | 162 B | ~620 B | ~254 vB | ~1,014 WU |
| **Full Proof (7 Spends)** | **—** | **—** | **~1,426 vB** | **~5,690 WU** |

*Standard mempool transaction weight limit is 400,000 WU; full settlement consumes ~1.4% of that budget.*

### 3. FRI Soundness
Query soundness is governed by code rate and query count:

$$\epsilon_{\text{soundness}} \le \left(1 - \frac{\delta}{2}\right)^q + \frac{d}{|\mathbb{F}|} + 2^{-\text{pow\_bits}}$$

Extension field $|QM_{31}| \approx 2^{124}$ ensures negligible Fiat-Shamir sampling error. Testing configurations use 4 queries for rapid iteration; production configurations target 56–80 queries with Proof-of-Work grinding for 96–128 bits of security.

---

## Quickstart

```bash
# Clone repository
git clone https://github.com/AlphaSparrow/katamoto.git
cd katamoto

# Run complete test suite (90 tests across 6 crates)
cargo test --workspace

# Run benchmarks with JSON telemetry
cargo run -p katamoto-cli -- bench

# Emit a raw Taproot spend transaction and testmempoolaccept payload
cargo run -p katamoto-cli -- emit-tx 0
```

### Testing on Bitcoin Inquisition (Regtest)
To validate transactions against a local node with BIP-347 enabled:
```bash
# 1. Start Bitcoin Inquisition
bitcoind -regtest -txindex -fallbackfee=0.0001 -bip347=1

# 2. Emit transaction and test via RPC
RPC_PAYLOAD=$(cargo run -q -p katamoto-cli -- emit-tx 0 | grep -A1 "Bitcoin Inquisition" | tail -n1)
curl --user rpcuser:rpcpass --data-binary "$RPC_PAYLOAD" -H 'content-type: text/plain;' http://127.0.0.1:18443/
```

---

## License

Licensed under the [MIT License](LICENSE).
