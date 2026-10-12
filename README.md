# zk-dPKI

Decentralized Public Key Infrastructure using Zero-Knowledge Proofs and Distributed Ledger Technology.

**Author**: Mihir Dixit (23BKT0073)
**Course**: BCSE329L - Blockchain and Distributed Ledger Technology, VIT Vellore

## Overview

zk-dPKI replaces a centralized Certificate Authority with a Byzantine Fault Tolerant validator network. Certificate attributes are encrypted with EC-ElGamal before reaching any node. Access rights are proven via Groth16 zk-SNARKs, allowing a verifier to confirm a policy claim without ever seeing the underlying identity data. Revocation is maintained by an on-chain cryptographic accumulator, replacing CRL and OCSP entirely.

## Core Concepts

- **EC-ElGamal on BN128**: additive homomorphic encryption for certificate attributes
- **Groth16 zk-SNARK**: 192-byte constant-size proof verifiable on-chain for 250k gas
- **Threshold DKG (3-of-5)**: distributed key generation so no single node controls signing
- **EigenRep**: power-iteration trust scoring for continuous validator eligibility
- **Shamir Secret Sharing**: (k,n) threshold private key recovery via Lagrange interpolation
- **Cryptographic Accumulator**: Merkle-root revocation with O(1) non-membership witness

## Project Structure

```
.
|-- index.html          # Dashboard shell (6 interactive panels)
|-- css/
|   `-- style.css       # IBM Plex Mono brutalist design system
|-- js/
|   |-- app.js          # Panel controllers and BFT consensus simulator
|   |-- network.js      # P2P state, DAO governance, EigenRep
|   `-- crypto-sim.js   # EC-ElGamal, Groth16, Shamir SSS primitives
|-- merkle_tree/        # Rust: standalone Merkle tree CLI
|-- blockchain_tamper/  # Rust: tamper-evidence demo
|-- reports/            # Academic LaTeX reports (BCSE329L, BCSE330L, BCSE326L)
`-- resumes/            # Resume files (not part of the project)
```

## Running Locally

The dashboard uses the Web Crypto API which requires a server context.

```bash
python -m http.server 3000
```

Then open `http://localhost:3000` in any modern browser.

## Dashboard Panels

| Panel | Function |
|---|---|
| 01 Network | Live BFT consensus simulator, block feed, network topology canvas |
| 02 Certificates | EC-ElGamal issuance pipeline with 4-step progress tracker |
| 03 ZK Proof | Groth16 proof generation and on-chain verification flow |
| 04 Revocation | Cryptographic accumulator root, non-membership witness proof |
| 05 Trust | EigenRep power iteration, Sybil attack simulation, auto-quarantine |
| 06 Key Recovery | Shamir SSS share splitting and Lagrange reconstruction |

## Technology Stack

- **Frontend**: Vanilla HTML/CSS/JS, IBM Plex Mono, zero external dependencies
- **Crypto**: Simulated EC-ElGamal, Groth16, Shamir SSS over GF(2^31 - 1)
- **Rust Modules**: Merkle tree verification, blockchain tamper detection
- **Target L1**: Ethereum-compatible BFT-PoS (BN128 pairing precompiles)

## Merkle Tree Module

```bash
cd merkle_tree
cargo run
```

## Blockchain Tamper Module

```bash
cd blockchain_tamper
cargo run
```

## License

MIT License. See LICENSE for details.
