/**
 * zk-dPKI Crypto Simulation Library
 * Simulates EC-ElGamal, zk-SNARKs, Cryptographic Accumulators,
 * and Shamir's Secret Sharing for educational demonstration.
 *
 * NOTE: This is a pedagogical simulation. Real cryptography would
 * use hardened libraries (e.g., snarkjs, noble-curves, ffjavascript).
 */

'use strict';

// ─── Utility: hex encoding ────────────────────────────────────────────────────
const CryptoSim = (() => {

  // Simple deterministic PRNG seeded by string (for reproducible demos)
  function seededRandom(seed) {
    let s = 0;
    for (let i = 0; i < seed.length; i++) s = (s * 31 + seed.charCodeAt(i)) >>> 0;
    return () => {
      s ^= s << 13; s ^= s >> 17; s ^= s << 5;
      return (s >>> 0) / 4294967296;
    };
  }

  // Hex helpers
  function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  function randomHex(len, seed = '') {
    const rng = seededRandom(seed + Date.now());
    return Array.from({ length: len }, () =>
      Math.floor(rng() * 256).toString(16).padStart(2, '0')
    ).join('');
  }

  // ─── SHA-256 via Web Crypto ────────────────────────────────────────────────
  async function sha256(message) {
    const enc = new TextEncoder();
    const data = enc.encode(message);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return toHex(new Uint8Array(hash));
  }

  // ─── EC-ElGamal Simulation ─────────────────────────────────────────────────
  // Over BN128 curve — simplified field arithmetic representation
  const EC_FIELD_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

  function modExp(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  function elgamalKeyGen(seed = '') {
    const rng = seededRandom('keygen-' + seed);
    const privateKey = BigInt(Math.floor(rng() * 1e15) + 1e14);
    // In real EC-ElGamal: publicKey = privateKey * G (generator point)
    // Simulated: publicKey = g^privateKey mod p (textbook ElGamal)
    const g = 3n;
    const p = EC_FIELD_ORDER;
    const publicKey = modExp(g, privateKey, p);
    return {
      privateKey: privateKey.toString(16).padStart(32, '0'),
      publicKey: publicKey.toString(16).padStart(64, '0'),
      curve: 'BN128',
      scheme: 'EC-ElGamal'
    };
  }

  function elgamalEncrypt(message, publicKeyHex, seed = '') {
    // Simulated additive homomorphic ElGamal
    // Real: C = (r·G, m·G + r·PK) where m is embedded in group element
    const rng = seededRandom('enc-' + seed + Date.now());
    const r = BigInt(Math.floor(rng() * 1e14) + 1000);
    const msgHash = Array.from(message).reduce((a, c) => a + c.charCodeAt(0), 0);

    const C1 = modExp(3n, r, EC_FIELD_ORDER);
    const C2 = (BigInt(msgHash) + modExp(BigInt('0x' + publicKeyHex.slice(0, 16)), r, EC_FIELD_ORDER)) % EC_FIELD_ORDER;

    return {
      C1: C1.toString(16).padStart(64, '0'),
      C2: C2.toString(16).padStart(64, '0'),
      note: 'Additive homomorphic — operations on ciphertexts do not reveal plaintext'
    };
  }

  // ─── zk-SNARK Simulation ──────────────────────────────────────────────────
  // Groth16 structure: proof π = (A, B, C) in G1 x G2 x G1
  async function generateSNARK(statement, witness, circuitId = 'attr-verify') {
    // Simulate expensive prover computation
    const start = performance.now();

    const commitmentSeed = statement + witness + circuitId;
    const A = '0x' + randomHex(32, commitmentSeed + 'A');
    const B = '0x' + randomHex(64, commitmentSeed + 'B'); // G2 element
    const C = '0x' + randomHex(32, commitmentSeed + 'C');

    // Simulate computation time (real Groth16: ~2–10s)
    await new Promise(r => setTimeout(r, 800 + Math.random() * 400));
    const elapsed = (performance.now() - start).toFixed(0);

    // Public inputs hash
    const pubInputHash = await sha256(statement);

    return {
      proof: { pi_a: A, pi_b: B, pi_c: C },
      publicSignals: [pubInputHash.slice(0, 16), '0x01'],
      circuit: circuitId,
      curve: 'BN128',
      protocol: 'groth16',
      provingTime: `${elapsed}ms`,
      proofSize: '192 bytes'
    };
  }

  async function verifySNARK(proof, publicSignals, verificationKey) {
    // Simulate pairing check: e(A,B) == e(α,β) · e(Σ pubInputs·γ) · e(C,δ)
    await new Promise(r => setTimeout(r, 200 + Math.random() * 100));
    // Deterministic: proof is valid if pi_a starts with '0x' (our format)
    const valid = proof.pi_a.startsWith('0x') && proof.pi_c.startsWith('0x');
    return { valid, gasEstimate: '250,000', checkPairings: 3 };
  }

  // ─── Cryptographic Accumulator (Merkle-based) ────────────────────────────
  class CryptoAccumulator {
    constructor() {
      this.members = new Set();
      this.root = '0x' + '0'.repeat(64);
    }

    async add(elementId) {
      this.members.add(elementId);
      await this._updateRoot();
    }

    async remove(elementId) {
      this.members.delete(elementId);
      await this._updateRoot();
    }

    async _updateRoot() {
      const sorted = [...this.members].sort();
      let combined = sorted.join('|') || 'EMPTY';
      this.root = '0x' + await sha256(combined);
    }

    async proveNonMembership(elementId) {
      const isMember = this.members.has(elementId);
      if (isMember) return { valid: false, reason: 'Element IS a member — cannot prove non-membership' };

      // Witness: root + sibling hashes proving exclusion
      const witness = '0x' + await sha256(elementId + this.root);
      return {
        valid: true,
        element: elementId,
        accumulatorRoot: this.root,
        witness,
        proofType: 'Non-Membership Witness',
        gasEstimate: '45,000'
      };
    }

    async proveMembership(elementId) {
      if (!this.members.has(elementId)) return { valid: false, reason: 'Not a member' };
      const witness = '0x' + await sha256(elementId + this.root + 'member');
      return { valid: true, element: elementId, accumulatorRoot: this.root, witness };
    }

    get size() { return this.members.size; }
    getMembers() { return [...this.members]; }
  }

  // ─── Shamir's Secret Sharing ──────────────────────────────────────────────
  const SSS_PRIME = 2147483647n; // Mersenne prime 2^31 - 1

  function sssShare(secret, totalShares, threshold) {
    // Generate random polynomial of degree (threshold-1)
    const secretInt = BigInt('0x' + [...secret].map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('').slice(0, 8) || '1');
    const coeffs = [secretInt % SSS_PRIME];
    const rng = seededRandom('sss-' + secret + Date.now());

    for (let i = 1; i < threshold; i++) {
      coeffs.push(BigInt(Math.floor(rng() * Number(SSS_PRIME))));
    }

    const shares = [];
    for (let x = 1; x <= totalShares; x++) {
      let y = 0n;
      for (let j = 0; j < coeffs.length; j++) {
        y = (y + coeffs[j] * modExp(BigInt(x), BigInt(j), SSS_PRIME)) % SSS_PRIME;
      }
      shares.push({ index: x, value: y.toString(16).padStart(16, '0'), label: `Share-${x}` });
    }
    return { shares, threshold, totalShares, info: `${threshold}-of-${totalShares} threshold` };
  }

  function sssRecover(shares, threshold) {
    if (shares.length < threshold) {
      return { success: false, error: `Need at least ${threshold} shares, got ${shares.length}` };
    }

    // Lagrange interpolation at x=0
    const pts = shares.slice(0, threshold).map(s => ({
      x: BigInt(s.index),
      y: BigInt('0x' + s.value)
    }));

    let secret = 0n;
    for (let i = 0; i < pts.length; i++) {
      let num = 1n, den = 1n;
      for (let j = 0; j < pts.length; j++) {
        if (i === j) continue;
        num = (num * (0n - pts[j].x) % SSS_PRIME + SSS_PRIME) % SSS_PRIME;
        den = (den * (pts[i].x - pts[j].x) % SSS_PRIME + SSS_PRIME) % SSS_PRIME;
      }
      // modular inverse of den via Fermat's little theorem
      const inv = modExp(den, SSS_PRIME - 2n, SSS_PRIME);
      secret = (secret + pts[i].y * num % SSS_PRIME * inv) % SSS_PRIME;
    }

    return { success: true, recoveredFragment: secret.toString(16).padStart(16, '0') };
  }

  // ─── EigenRep Score Engine ─────────────────────────────────────────────────
  function computeEigenRep(ratingMatrix, iterations = 20) {
    const n = ratingMatrix.length;
    let scores = new Array(n).fill(1 / n);

    for (let iter = 0; iter < iterations; iter++) {
      const newScores = new Array(n).fill(0);
      for (let i = 0; i < n; i++) {
        let sum = 0;
        for (let j = 0; j < n; j++) sum += ratingMatrix[j][i];
        if (sum > 0) {
          for (let j = 0; j < n; j++) {
            newScores[i] += (ratingMatrix[j][i] / sum) * scores[j];
          }
        }
      }
      // Normalize
      const total = newScores.reduce((a, b) => a + b, 0);
      for (let i = 0; i < n; i++) scores[i] = total > 0 ? newScores[i] / total : 1 / n;
    }

    return scores.map(s => Math.round(s * 100) / 100);
  }

  // ─── DKG Threshold Key Simulation ─────────────────────────────────────────
  function simulateDKG(nodes, threshold) {
    const rng = seededRandom('dkg-' + nodes.join(',') + threshold);
    // Each node contributes a random polynomial share
    const shares = nodes.map((node, i) => ({
      nodeId: node,
      contribution: '0x' + Array.from({ length: 16 }, () =>
        Math.floor(rng() * 256).toString(16).padStart(2, '0')
      ).join(''),
      verified: true
    }));

    // Threshold public key = "sum" of contributions (simulated)
    const combined = shares.map(s => s.contribution).join('');
    return {
      thresholdPublicKey: '0x04' + randomHex(64, 'dkg-pubkey-' + combined),
      threshold,
      totalNodes: nodes.length,
      participants: shares,
      note: `No single node knows the full private key. Threshold: ${threshold}-of-${nodes.length}`
    };
  }

  // Public API
  return {
    sha256,
    elgamalKeyGen,
    elgamalEncrypt,
    generateSNARK,
    verifySNARK,
    CryptoAccumulator,
    sssShare,
    sssRecover,
    computeEigenRep,
    simulateDKG,
    randomHex
  };
})();
