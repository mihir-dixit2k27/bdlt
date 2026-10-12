/**
 * zk-dPKI Network State Manager
 * Manages the simulated P2P node registry, certificate store,
 * DKG state, and DAO governance for the zk-dPKI showcase.
 */

'use strict';

const Network = (() => {

    // ─── Initial Node Registry ──────────────────────────────────────────────────
    const INITIAL_NODES = [
        { id: 'NODE-001', alias: 'Validator-Alpha', role: 'RA', eigenRep: 0.94, dmRep: 0.91, uptime: 99.8, tx: 4821, status: 'active', region: 'EU-West' },
        { id: 'NODE-002', alias: 'Validator-Beta', role: 'RA', eigenRep: 0.89, dmRep: 0.87, uptime: 99.1, tx: 3940, status: 'active', region: 'US-East' },
        { id: 'NODE-003', alias: 'Relay-Gamma', role: 'RELAY', eigenRep: 0.78, dmRep: 0.82, uptime: 97.4, tx: 2150, status: 'active', region: 'APAC' },
        { id: 'NODE-004', alias: 'Observer-Delta', role: 'OBSERVER', eigenRep: 0.71, dmRep: 0.74, uptime: 96.2, tx: 1043, status: 'active', region: 'US-West' },
        { id: 'NODE-005', alias: 'Validator-Epsilon', role: 'RA', eigenRep: 0.85, dmRep: 0.88, uptime: 98.5, tx: 3600, status: 'active', region: 'EU-Central' },
        { id: 'NODE-006', alias: 'Relay-Zeta', role: 'RELAY', eigenRep: 0.62, dmRep: 0.58, uptime: 94.0, tx: 877, status: 'active', region: 'APAC' },
        { id: 'NODE-007', alias: 'SybilNode-Eta', role: 'OBSERVER', eigenRep: 0.30, dmRep: 0.22, uptime: 71.0, tx: 112, status: 'quarantined', region: 'Unknown' },
        { id: 'NODE-008', alias: 'Validator-Theta', role: 'RA', eigenRep: 0.91, dmRep: 0.93, uptime: 99.5, tx: 5201, status: 'active', region: 'EU-North' },
    ];

    // ─── Certificate Store ──────────────────────────────────────────────────────
    const INITIAL_CERTS = [
        {
            id: 'CERT-2025-0A1F',
            subject: 'did:zkdpki:0x4a3b...f92c',
            commonName: 'Alice Sharma',
            org: 'QuantumTech Inc.',
            role: 'Admin',
            clearanceLevel: 'TOP-SECRET',
            validFrom: '2025-01-15',
            validTo: '2026-01-15',
            issuer: 'DAO-Threshold-Key',
            status: 'VALID',
            encryptedPayload: '0x1f4a...c3e9',
        },
        {
            id: 'CERT-2025-1B2E',
            subject: 'did:zkdpki:0x7f1d...a04b',
            commonName: 'Bob Chen',
            org: 'DefiProtocol Ltd.',
            role: 'Operator',
            clearanceLevel: 'SECRET',
            validFrom: '2025-03-22',
            validTo: '2026-03-22',
            issuer: 'DAO-Threshold-Key',
            status: 'VALID',
            encryptedPayload: '0x9d2b...7f11',
        },
        {
            id: 'CERT-2024-9C3D',
            subject: 'did:zkdpki:0x2c8e...b15a',
            commonName: 'Compromised Entity',
            org: 'MaliciousCorp',
            role: 'Observer',
            clearanceLevel: 'UNCLASSIFIED',
            validFrom: '2024-06-01',
            validTo: '2025-06-01',
            issuer: 'DAO-Threshold-Key',
            status: 'REVOKED',
            encryptedPayload: '0x3a7c...f22d',
        },
    ];

    // ─── State ──────────────────────────────────────────────────────────────────
    let nodes = INITIAL_NODES.map(n => ({ ...n }));
    let certificates = INITIAL_CERTS.map(c => ({ ...c }));
    let dkgState = null;
    let accumulator = null;
    let networkStats = {
        totalCerts: 2,
        revokedCerts: 1,
        activeNodes: 7,
        totalTx: 0,
        blockHeight: 48291,
        avgGas: '142,500',
        lastBlock: new Date().toISOString(),
    };

    // Event emitter
    const listeners = {};
    function on(event, cb) { (listeners[event] = listeners[event] || []).push(cb); }
    function emit(event, data) { (listeners[event] || []).forEach(cb => cb(data)); }

    // ─── Node Operations ────────────────────────────────────────────────────────
    function getNodes() { return nodes.map(n => ({ ...n })); }

    function updateNodeRep(nodeId, eigenDelta, dmDelta) {
        const node = nodes.find(n => n.id === nodeId);
        if (!node) return;
        node.eigenRep = Math.max(0, Math.min(1, node.eigenRep + eigenDelta));
        node.dmRep = Math.max(0, Math.min(1, node.dmRep + dmDelta));
        if (node.eigenRep < 0.25 || node.dmRep < 0.25) node.status = 'quarantined';
        emit('nodeUpdated', node);
    }

    function simulateSybilAttack() {
        // Malicious nodes attempt bad-mouthing of honest nodes
        const malicious = nodes.filter(n => n.id === 'NODE-007');
        malicious.forEach(m => {
            // EigenRep algorithm detects inconsistency — score of malicious node drops
            m.eigenRep = Math.max(0.05, m.eigenRep - 0.15);
            m.dmRep = Math.max(0.05, m.dmRep - 0.12);
            m.status = 'quarantined';
        });

        // Add a new fake Sybil node that gets detected
        const sybilId = `NODE-00${nodes.length + 1}`;
        nodes.push({
            id: sybilId,
            alias: `SybilNode-${CryptoSim.randomHex(2, sybilId)}`,
            role: 'OBSERVER',
            eigenRep: 0.12,
            dmRep: 0.08,
            uptime: 44.0,
            tx: 3,
            status: 'quarantined',
            region: 'Unknown'
        });

        emit('sybilAttack', { detected: malicious.length + 1, quarantined: nodes.filter(n => n.status === 'quarantined').length });
        return { detected: true, message: `Sybil attack detected. ${malicious.length + 1} nodes quarantined by EigenRep.` };
    }

    function resetNodes() {
        nodes = INITIAL_NODES.map(n => ({ ...n }));
        emit('nodesReset', nodes);
    }

    // ─── Certificate Operations ─────────────────────────────────────────────────
    function getCertificates() { return certificates.map(c => ({ ...c })); }

    function issueCertificate(attrs) {
        const id = `CERT-${new Date().getFullYear()}-${CryptoSim.randomHex(4, attrs.commonName).toUpperCase()}`;
        const cert = {
            id,
            subject: `did:zkdpki:0x${CryptoSim.randomHex(16, attrs.commonName)}`,
            commonName: attrs.commonName,
            org: attrs.org,
            role: attrs.role,
            clearanceLevel: attrs.clearanceLevel,
            validFrom: new Date().toISOString().split('T')[0],
            validTo: new Date(Date.now() + 365 * 864e5).toISOString().split('T')[0],
            issuer: 'DAO-Threshold-Key',
            status: 'VALID',
            encryptedPayload: '0x' + CryptoSim.randomHex(32, id + attrs.commonName),
        };
        certificates.push(cert);
        networkStats.totalCerts++;
        networkStats.blockHeight++;
        networkStats.totalTx++;
        emit('certIssued', cert);
        return cert;
    }

    async function revokeCertificate(certId, reason) {
        const cert = certificates.find(c => c.id === certId);
        if (!cert) return null;
        if (cert.status === 'REVOKED') return { alreadyRevoked: true };

        cert.status = 'REVOKED';
        cert.revocationReason = reason;
        cert.revocationTime = new Date().toISOString();

        // Update accumulator
        if (accumulator) await accumulator.add(certId);

        networkStats.revokedCerts++;
        networkStats.blockHeight++;
        emit('certRevoked', { certId, reason, accRoot: accumulator?.root });
        return cert;
    }

    // ─── DKG ────────────────────────────────────────────────────────────────────
    function performDKG(threshold = 3) {
        const eligibleNodes = nodes.filter(n => n.eigenRep >= 0.75 && n.status === 'active');
        if (eligibleNodes.length < threshold) {
            return { error: 'Not enough qualified nodes for DKG' };
        }
        const selectedIds = eligibleNodes.slice(0, Math.min(5, eligibleNodes.length)).map(n => n.id);
        dkgState = CryptoSim.simulateDKG(selectedIds, threshold);
        emit('dkgComplete', dkgState);
        return dkgState;
    }

    function getDKGState() { return dkgState; }

    // ─── Accumulator init ───────────────────────────────────────────────────────
    function initAccumulator() {
        accumulator = new CryptoSim.CryptoAccumulator();
        // Pre-populate with revoked certs
        INITIAL_CERTS.filter(c => c.status === 'REVOKED').forEach(c => {
            accumulator.members.add(c.id);
        });
        accumulator._updateRoot();
        return accumulator;
    }

    function getAccumulator() { return accumulator; }
    function getNetworkStats() { return { ...networkStats, activeNodes: nodes.filter(n => n.status === 'active').length }; }

    // Live block counter
    setInterval(() => {
        networkStats.blockHeight++;
        networkStats.totalTx += Math.floor(Math.random() * 3);
        networkStats.lastBlock = new Date().toISOString();
        emit('newBlock', networkStats);
    }, 5000);

    return {
        getNodes, updateNodeRep, simulateSybilAttack, resetNodes,
        getCertificates, issueCertificate, revokeCertificate,
        performDKG, getDKGState,
        initAccumulator, getAccumulator,
        getNetworkStats,
        on, emit
    };
})();
