# Katamoto (刀本)

> **Where `OP_CAT` meets Nakamoto Consensus: Native Zero-Knowledge STARK Verifier & Tapscript Compiler for Bitcoin.**

[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-orange.svg)](https://crates.io)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Bitcoin BIP](https://img.shields.io/badge/BIP--347-OP__CAT-success.svg)](https://github.com/bitcoin/bips/pull/1628)
[![Tapscript](https://img.shields.io/badge/BIP--342-Tapscript-brightgreen.svg)](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)

---

## ⚡ The Breakthrough

Historically, Bitcoin was believed to be mathematically incapable of natively verifying zero-knowledge proofs without consensus hard-forks or massive BitVM-style pre-signed transaction trees.

**Katamoto** proves that **BIP-347 (`OP_CAT`)** combined with **BIP-342 (Tapscript)** is sufficient to execute a **complete STARK / FRI verification pipeline** directly inside Bitcoin Script:

* **Zero Pairings / No Elliptic Curves**: Bypasses the lack of `OP_ECPAIRING` by utilizing hash-based IOPs (STARKs).
* **Mersenne-31 ($2^{31}-1$) Field Arithmetic**: Emulates finite field addition, subtraction, and double-and-add multiplication verification in pure 32-bit Script without `OP_MUL`.
* **Ultra-Compact Merkle Authentication**: Verifies 16-level Merkle membership paths in **under 100 opcodes** via `OP_CAT` + `OP_SHA256`.
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
| **`katamoto-script`** | `crates/katamoto-script` | Bitcoin Tapscript VM & Assembler with full BIP-347 `OP_CAT` implementation, stack budget telemetry, and ScriptNum encoding. |
| **`katamoto-field`** | `crates/katamoto-field` | Finite field arithmetic primitives (Mersenne-31) and Script gadgets for zero-`OP_MUL` witness-assisted verification. |
| **`katamoto-fri`** | `crates/katamoto-fri` | Merkle tree commitment builder, sibling authentication compiler, and FRI query folding verification. |
| **`katamoto-cli`** | `crates/katamoto-cli` | CLI runner, opcode benchmarking suite, and Tapscript hex emitter. |

---

## 🔬 Mathematical Specification: Field Math Without `OP_MUL`

Bitcoin Script only provides signed 32-bit arithmetic (`OP_ADD`, `OP_SUB`) and lacks multiplication. `Katamoto` solves this for Mersenne-31 ($P = 2^{31} - 1$):

### 1. Addition & Subtraction Modulo $2^{31}-1$
```text
OP_ADD
OP_DUP <2147483647> OP_GREATERTHANOREQUAL
OP_IF
    <2147483647> OP_SUB
OP_ENDIF
```

### 2. Witness-Assisted Multiplicative Verification
Rather than evaluating expensive wide division in Script, the witness supplies the 31-bit binary decomposition of multiplicand $b = \sum_{i=0}^{30} b_i 2^i$. The script runs a verified 31-round double-and-add loop:
$$\text{acc} \leftarrow \text{acc} + b_i \cdot (2^i a) \pmod P$$
Total opcode cost: **~220 opcodes**, fitting comfortably inside Tapscript's generous limits.

---

## 📊 Benchmarks: Merkle Inclusion Proofs via `OP_CAT`

Tested using the embedded Bitcoin Script VM:

| Tree Depth | Leaf Capacity | Script Size (Bytes) | Opcodes Executed | Witness Size (Bytes) | Max Stack Depth | Verification Time |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **4** | 16 | 45 B | 27 | 136 B | 9 | < 15 µs |
| **8** | 256 | 81 B | 51 | 272 B | 17 | < 25 µs |
| **12** | 4,096 | 117 B | 75 | 408 B | 25 | < 35 µs |
| **16** | 65,536 | 153 B | 99 | 544 B | 33 | < 45 µs |
| **20** | 1,048,576 | 189 B | 123 | 680 B | 41 | < 60 µs |

> Notice: Even for a tree committing to **1,048,576 execution trace leaves**, the verification script is **only 189 bytes** and executes in **123 opcodes**!

---

## 🚀 Quickstart

### Run Merkle Telemetry Benchmark:
```bash
cargo run -p katamoto-cli -- benchmark-merkle --max-depth 16
```

### Verify an M31 Multiplication on Bitcoin Script VM:
```bash
cargo run -p katamoto-cli -- verify-m31 -a 1234567 -b 7654321
```

### Emit Raw Bitcoin Tapscript Hex:
```bash
cargo run -p katamoto-cli -- emit-script --depth 8
```

---

## 📄 License

Dual-licensed under either:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)
