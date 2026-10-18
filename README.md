# Katamoto (刀本)

> **Where `OP_CAT` meets Nakamoto Consensus: Native Zero-Knowledge STARK Verifier & Tapscript Compiler for Bitcoin.**

[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-orange.svg)](https://crates.io)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Bitcoin BIP](https://img.shields.io/badge/BIP--347-OP__CAT-success.svg)](https://github.com/bitcoin/bips/pull/1628)
[![Tapscript](https://img.shields.io/badge/BIP--342-Tapscript-brightgreen.svg)](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
[![BIP-341](https://img.shields.io/badge/BIP--341-Taproot-blueviolet.svg)](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

---

## ⚡ The Breakthrough

Historically, Bitcoin was believed to be mathematically incapable of natively verifying zero-knowledge proofs without consensus hard-forks or massive BitVM-style pre-signed transaction trees.

**Katamoto** proves that **BIP-347 (`OP_CAT`)** combined with **BIP-342 (Tapscript)** and **BIP-341 (Taproot)** is sufficient to execute a **complete STARK / FRI verification pipeline** directly inside Bitcoin Script:

* **Zero Pairings / No Elliptic Curves**: Bypasses the lack of `OP_ECPAIRING` by utilizing hash-based IOPs (STARKs).
* **Mersenne-31 ($2^{31}-1$) & QM31 ($2^{124}$) Field Arithmetic**: Emulates finite base field addition, subtraction, and double-and-add multiplication verification in pure Bitcoin Script without `OP_MUL`, plus degree-4 extension field ($QM31$) for full 124-bit cryptographic soundness.
* **Ultra-Compact Merkle Authentication**: Verifies 16-level Merkle membership paths in **under 75 opcodes** via `OP_CAT` + `OP_SHA256`.
* **In-Script Fiat-Shamir Transcript**: Evolves rolling transcript state and authenticates random challenges directly using `OP_CAT` prefix/suffix decompositions.
* **Non-Interactive Taproot Spends**: Compiles execution trace checks and FRI queries into independent Taproot leaf scripts, maintaining standard witness weights.

```
                      +---------------------------------------+
                      |       STARK Proof (Execution Trace)   |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |           katamoto Compiler           |
                      |  - AST & Constraint Decomposer        |
                      |  - Field Math -> Script Optimizer     |
                      |  - Taproot Merkle Tree Builder        |
                      +---------------------------------------+
                                          |
                 +------------------------+------------------------+
                 |                                                 |
                 v                                                 v
  +-------------------------------+                 +-------------------------------+
  |   Taproot Script Leaf #1      |                 |   Taproot Script Leaf #k      |
  |   - Fiat-Shamir Transcript    |                 |   - Merkle Query Verification |
  |   - OP_CAT + OP_SHA256        |                 |   - FRI Colinearity Folding   |
  +-------------------------------+                 +-------------------------------+
                 |                                                 |
                 +------------------------+------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    Bitcoin L1 Taproot Spend (Witness) |
                      |    - Verified on Bitcoin Core L1      |
                      +---------------------------------------+
```

---

## 📦 Workspace Architecture

The workspace is cleanly partitioned into modular crates:

| Crate | Path | Description |
| :--- | :--- | :--- |
| **`katamoto-script`** | `crates/katamoto-script` | Bitcoin Tapscript VM & Assembler with full BIP-347 `OP_CAT` implementation, 64-bit ScriptNum support, stack budget telemetry, and flow-control. |
| **`katamoto-field`** | `crates/katamoto-field` | Finite field arithmetic primitives (Mersenne-31 and QM31 quartic extension) with Script gadgets for zero-`OP_MUL` witness-assisted verification. |
| **`katamoto-fri`** | `crates/katamoto-fri` | Merkle tree commitment builder, Fiat-Shamir transcript engine, integrated FRI query verifiers, and BIP-341 TapTree compiler. |
| **`katamoto-cli`** | `crates/katamoto-cli` | CLI runner, opcode benchmarking suite, and Tapscript hex & witness spend emitter. |

---

## 🔬 Mathematical Specification: Field Math Without `OP_MUL`

Bitcoin Script only provides signed arithmetic (`OP_ADD`, `OP_SUB`) and lacks multiplication. `Katamoto` solves this for Mersenne-31 ($P = 2^{31} - 1$) and $QM31$:

### 1. Addition & Subtraction Modulo $2^{31}-1$
```text
OP_ADD
OP_DUP <2147483647> OP_GREATERTHANOREQUAL
OP_IF
    <2147483647> OP_SUB
OP_ENDIF
```

### 2. Witness-Assisted Multiplicative Verification
Rather than evaluating wide division in Script, the witness supplies the 31-bit binary decomposition of multiplicand $b = \sum_{i=0}^{30} b_i 2^i$. The script runs a verified 31-round double-and-add loop:
$$\text{acc} \leftarrow \text{acc} + b_i \cdot (2^i a) \pmod P$$
Total opcode cost: **~990 opcodes**, executing with minimal stack overhead using the altstack (`OP_TOALTSTACK` / `OP_FROMALTSTACK`).

### 3. Quartic Extension Field ($QM31$) for 124-bit Security
$$QM31 = CM31[j] / (j^2 - (2 + i)), \quad CM31 = M31[i] / (i^2 + 1)$$
Field capacity $|QM31| = (2^{31}-1)^4 \approx 2^{124}$, meeting standard cryptographic soundness standards for production ZK-STARKs.

---

## 📊 Benchmarks: Merkle Inclusion Proofs via `OP_CAT`

Tested using the embedded Bitcoin Script VM:

| Tree Depth | Leaf Capacity | Script Size (Bytes) | Opcodes Executed | Witness Size (Bytes) | Max Stack Depth | Verification Time |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **4** | 16 | 71 B | 38 | 162 B | 9 | < 45 µs |
| **8** | 256 | 107 B | 74 | 290 B | 17 | < 60 µs |
| **12** | 4,096 | 143 B | 110 | 418 B | 25 | < 75 µs |
| **16** | 65,536 | 179 B | 146 | 546 B | 33 | < 95 µs |
| **20** | 1,048,576 | 215 B | 182 | 674 B | 41 | < 120 µs |

> Notice: Even for a tree committing to **1,048,576 execution trace leaves**, the verification script is **only 215 bytes**!

---

## 🚀 Quickstart

### Run Merkle Telemetry Benchmark:
```bash
cargo run -p katamoto-cli -- benchmark-merkle 16
```

### Verify an M31 Multiplication on Bitcoin Script VM:
```bash
cargo run -p katamoto-cli -- verify-m31 1234567 7654321
```

### Verify QM31 Quartic Extension Field Arithmetic:
```bash
cargo run -p katamoto-cli -- verify-qm31
```

### Verify an Integrated FRI Query Round (Dual Merkle + Colinearity):
```bash
cargo run -p katamoto-cli -- verify-fri-round
```

### Compile a Full BIP-341 Taproot STARK Tree & Witness Spend Package:
```bash
cargo run -p katamoto-cli -- compile-taproot 4
```

### Emit Raw Bitcoin Tapscript Bytecode Hex:
```bash
cargo run -p katamoto-cli -- emit-script 8
```

---

## 📄 License

Dual-licensed under either:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)
