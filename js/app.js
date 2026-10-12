/**
 * zk-dPKI App Controller v3
 * Panels: Network, Certificates, ZK Proof, Revocation, Trust, Key Recovery
 */
'use strict';

let accumulator;

document.addEventListener('DOMContentLoaded', async () => {
    accumulator = Network.initAccumulator();
    initNav();
    initNetworkPanel();
    initCertPanel();
    initZKPanel();
    initRevPanel();
    initTrustPanel();
    initKeyPanel();
    showPanel('net');
    Network.performDKG(3);
});

// ── Navigation ─────────────────────────────────────────────────────
function initNav() {
    document.querySelectorAll('.nav-tab[data-panel]').forEach(t =>
        t.addEventListener('click', () => showPanel(t.dataset.panel))
    );
}
function showPanel(id) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('panel-' + id)?.classList.add('active');
    document.querySelector(`.nav-tab[data-panel="${id}"]`)?.classList.add('active');
    if (id === 'trust') renderNodes();
    if (id === 'cert') renderCertTable();
    if (id === 'net') drawCanvas();
}

// ── Utilities ──────────────────────────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));
const $ = id => document.getElementById(id);

function log(elId, cls, msg) {
    const el = $(elId); if (!el) return;
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const s = document.createElement('span');
    s.className = 'll';
    s.innerHTML = `<span class="log-ts">${ts}</span><span class="${cls}"> ${msg}</span>`;
    el.appendChild(s); el.scrollTop = el.scrollHeight;
}

function alert_(elId, cls, msg) {
    const el = $(elId); if (!el) return;
    el.className = `alert ${cls} show`;
    el.innerHTML = `<span>${msg}</span>`;
}

function set(id, v) { const e = $(id); if (e) e.textContent = v; }

function prow(k, v) {
    return `<div class="proof-row"><div class="proof-k">${k}</div><div class="proof-v">${v}</div></div>`;
}

function certRow(k, v) {
    return `<div style="display:flex;gap:12px;padding:4px 0;border-bottom:1px solid var(--border)">
    <span style="font-family:var(--mono);font-size:10px;color:var(--grey-lo);min-width:90px;padding-top:1px">${k}</span>
    <span style="font-family:var(--mono);font-size:11.5px;color:var(--grey);word-break:break-all">${v}</span>
  </div>`;
}

function setStep(id, status) {
    const el = $(id); if (!el) return;
    el.className = `pipe-n ${status}`;
    el.textContent = status === 'done' ? '✓' : status === 'active' ? '·' : (el.dataset.n || el.textContent);
}

// ══════════════════════════════════════════════════════════════════
// PANEL 01 — NETWORK
// ══════════════════════════════════════════════════════════════════
function initNetworkPanel() {
    updateStats();
    Network.on('newBlock', () => { updateStats(); pushBlockFeed(); });
    Network.on('certIssued', updateStats);
    Network.on('certRevoked', updateStats);

    initConsensusSimulator();
}

function updateStats() {
    const s = Network.getNetworkStats();
    const dkg = Network.getDKGState();
    set('s-block', s.blockHeight.toLocaleString());
    set('s-certs', s.totalCerts);
    set('s-revoked', s.revokedCerts);
    set('s-nodes', s.activeNodes);
    set('s-dkg', dkg ? `${dkg.threshold}-of-${dkg.totalNodes} threshold\nActive since block #${s.blockHeight - 12}` : 'Initializing...');
}

function drawCanvas() {
    const canvas = $('canvas'); if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.offsetWidth;
    canvas.height = 260;
    const nodes = Network.getNodes();
    const W = canvas.width, H = 260;
    const cx = W / 2, cy = H / 2;
    const R = Math.min(W, H) * 0.35;

    const pos = nodes.map((n, i) => {
        const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
        return { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a), n };
    });

    ctx.clearRect(0, 0, W, H);

    // edges — variable opacity by trust
    pos.forEach((a, i) => pos.forEach((b, j) => {
        if (i >= j || a.n.status !== 'active' || b.n.status !== 'active') return;
        const strength = (a.n.eigenRep + b.n.eigenRep) / 2;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = `rgba(185,251,69,${strength * 0.16})`;
        ctx.lineWidth = strength * 1.2; ctx.stroke();
    }));

    // nodes
    pos.forEach(({ x, y, n }) => {
        const isQ = n.status === 'quarantined';
        const col = isQ ? '#ff3d2e' : n.role === 'RA' ? '#b9fb45' : '#7a7668';
        const r = 7 + n.eigenRep * 8;

        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.strokeStyle = col; ctx.lineWidth = 1.5;
        ctx.fillStyle = col + '18'; ctx.fill(); ctx.stroke();

        // label
        ctx.fillStyle = '#ebe5d5';
        ctx.font = '9px JetBrains Mono';
        ctx.textAlign = 'center';
        const parts = n.alias.split('-');
        ctx.fillText(`${parts[0]?.charAt(0) || ''}${parts[1]?.charAt(0) || ''}`, x, y + 3);
        ctx.fillText(n.alias.split('-').slice(0, 2).join('-'), x, y + r + 12);
    });

    // DAO hub
    ctx.beginPath(); ctx.arc(cx, cy, 16, 0, Math.PI * 2);
    ctx.strokeStyle = '#b9fb45'; ctx.lineWidth = 1;
    ctx.fillStyle = 'rgba(185,251,69,0.07)'; ctx.fill(); ctx.stroke();
    ctx.fillStyle = '#b9fb45';
    ctx.font = 'bold 9px DM Sans';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('DAO', cx, cy);
}

// BFT Consensus Simulator
const VALIDATOR_IDS = ['V-01', 'V-02', 'V-03', 'V-04', 'V-05', 'V-06', 'V-07'];
let faultyIdx = -1;

function initConsensusSimulator() {
    renderValidatorGrid();
    startBlockFeed();

    $('btn-consensus')?.addEventListener('click', async () => {
        const btn = $('btn-consensus');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> RUNNING';
        await runConsensusRound();
        btn.disabled = false; btn.textContent = 'RUN CONSENSUS ROUND';
    });

    $('btn-inject-fault')?.addEventListener('click', () => {
        faultyIdx = Math.floor(Math.random() * VALIDATOR_IDS.length);
        log('consensus-log', 'log-err', `Byzantine fault injected: ${VALIDATOR_IDS[faultyIdx]} will equivocate`);
        renderValidatorGrid();
    });
}

function renderValidatorGrid(states = {}) {
    const el = $('consensus-grid'); if (!el) return;
    el.innerHTML = VALIDATOR_IDS.map((vid, i) => {
        const state = states[vid] || 'idle';
        const isFaulty = i === faultyIdx;
        const cls = isFaulty ? 'faulty' : state;
        return `<div class="vcard ${cls}" id="vc-${vid}">
          <div class="vn">${vid}</div>
          <div class="vs">${isFaulty ? 'BYZANTINE' : (state === 'idle' ? 'READY' : state.toUpperCase())}</div>
        </div>`;
    }).join('');
}

async function runConsensusRound() {
    const blockNum = Network.getNetworkStats().blockHeight + 1;
    log('consensus-log', 'log-info', `--- Block #${blockNum} proposal ---`);

    // Propose
    const leader = VALIDATOR_IDS[blockNum % VALIDATOR_IDS.length];
    log('consensus-log', 'log-info', `Leader ${leader} broadcasts block proposal`);
    renderValidatorGrid({ [leader]: 'voting' });
    await delay(400);

    // Prevote phase
    const prevoteStates = {};
    for (const vid of VALIDATOR_IDS) {
        const isFaulty = VALIDATOR_IDS.indexOf(vid) === faultyIdx;
        prevoteStates[vid] = isFaulty ? 'faulty' : 'voting';
    }
    renderValidatorGrid(prevoteStates);
    log('consensus-log', 'log-info', `Prevote phase: ${VALIDATOR_IDS.length} validators broadcasting`);
    await delay(500);

    // Count votes
    const honest = VALIDATOR_IDS.filter((_, i) => i !== faultyIdx).length;
    const threshold = Math.ceil((VALIDATOR_IDS.length * 2) / 3);
    const reached = honest >= threshold;

    const finalStates = {};
    VALIDATOR_IDS.forEach((vid, i) => {
        finalStates[vid] = i === faultyIdx ? 'faulty' : (reached ? 'agreed' : 'voting');
    });
    renderValidatorGrid(finalStates);

    if (reached) {
        log('consensus-log', 'log-ok', `Precommit: ${honest}/${VALIDATOR_IDS.length} honest votes (need ${threshold})`);
        await delay(300);
        log('consensus-log', 'log-ok', `Block #${blockNum} FINALIZED. BFT guarantee: no revert possible`);
        if (faultyIdx >= 0) {
            log('consensus-log', 'log-err', `${VALIDATOR_IDS[faultyIdx]} equivocated — slash initiated`);
            faultyIdx = -1;
        }
    } else {
        log('consensus-log', 'log-err', `Consensus FAILED: only ${honest}/${VALIDATOR_IDS.length} votes (need ${threshold})`);
        log('consensus-log', 'log-err', `View change triggered — new leader elected`);
    }
}

function startBlockFeed() {
    const el = $('block-feed'); if (!el) return;
    pushBlockFeed();
}

function pushBlockFeed() {
    const s = Network.getNetworkStats();
    log('block-feed', 'log-info', `#${s.blockHeight}  txs=${2 + Math.floor(Math.random() * 4)}  gas=${(120000 + Math.floor(Math.random() * 40000)).toLocaleString()}  ts=${new Date().toISOString().substring(11, 19)}`);
}

// ══════════════════════════════════════════════════════════════════
// PANEL 02 — CERTIFICATES
// ══════════════════════════════════════════════════════════════════
function initCertPanel() {
    $('btn-issue')?.addEventListener('click', async () => {
        const cn = $('cn').value.trim();
        const org = $('org').value.trim();
        const role = $('role').value;
        const lvl = $('lvl').value;
        if (!cn || !org) { alert_('cert-alert', 'al-err', 'Common Name and Organization are required.'); return; }

        const btn = $('btn-issue');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> PROCESSING';

        ['ps1', 'ps2', 'ps3', 'ps4'].forEach(s => setStep(s, ''));

        setStep('ps1', 'active');
        log('cert-log', 'log-info', 'Generating EC-ElGamal keypair on BN128...');
        await delay(500);
        const keys = CryptoSim.elgamalKeyGen(cn + org);
        $('pk-out').textContent = `PK = 0x${keys.publicKey.slice(0, 24)}...`;
        log('cert-log', 'log-ok', `Keypair ready. PK = 0x${keys.publicKey.slice(0, 16)}...`);

        setStep('ps1', 'done'); setStep('ps2', 'active');
        log('cert-log', 'log-info', 'Encrypting certificate attributes...');
        await delay(600);
        const ct = CryptoSim.elgamalEncrypt(JSON.stringify({ cn, org, role, lvl }), keys.publicKey, cn);
        $('ct-out').textContent = `C1=0x${ct.C1.slice(0, 16)}... C2=0x${ct.C2.slice(0, 16)}...`;
        log('cert-log', 'log-ok', 'Ciphertext computed. Pushed to IPFS.');

        setStep('ps2', 'done'); setStep('ps3', 'active');
        log('cert-log', 'log-info', 'Awaiting DAO threshold signature (3-of-5)...');
        await delay(700);
        const dkg = Network.getDKGState();
        log('cert-log', 'log-ok', `${dkg?.threshold || 3} validators co-signed. Threshold met.`);

        setStep('ps3', 'done'); setStep('ps4', 'active');
        log('cert-log', 'log-info', 'Writing commitment to BFT ledger...');
        await delay(400);
        const cert = Network.issueCertificate({ commonName: cn, org, role, clearanceLevel: lvl });
        log('cert-log', 'log-ok', `${cert.id} minted. Gas ~142,000.`);
        setStep('ps4', 'done');

        renderNewCert(cert, keys);
        renderCertTable();
        alert_('cert-alert', 'al-ok', `${cert.id} issued and anchored on-chain.`);
        btn.disabled = false; btn.textContent = 'ISSUE CERTIFICATE';
    });
}

function renderNewCert(cert, keys) {
    const el = $('new-cert'); if (!el) return;
    el.innerHTML = `<div style="background:var(--bg);border:1px solid var(--border-hi);padding:16px;margin-top:4px">
    <div style="font-family:var(--mono);font-size:11px;color:var(--lime);font-weight:700;margin-bottom:10px">
      ${cert.id} <span style="color:var(--green);font-size:9px;border:1px solid var(--green);padding:2px 6px;margin-left:6px">VALID</span>
    </div>
    ${certRow('DID', cert.subject)}
    ${certRow('Common Name', cert.commonName)}
    ${certRow('Org', cert.org)}
    ${certRow('Role / MAC', cert.role + ' / ' + cert.clearanceLevel)}
    ${certRow('Validity', cert.validFrom + ' to ' + cert.validTo)}
    ${certRow('Public Key', '0x' + keys.publicKey.slice(0, 32) + '...')}
    ${certRow('Enc. Payload', cert.encryptedPayload)}
  </div>`;
}

function renderCertTable() {
    const el = $('cert-tbody'); if (!el) return;
    el.innerHTML = Network.getCertificates().map(c =>
        `<tr>
      <td style="color:var(--hi)">${c.id}</td>
      <td>${c.commonName}</td><td>${c.org}</td>
      <td>${c.role}</td><td>${c.clearanceLevel}</td><td>${c.validTo}</td>
      <td><span class="tag tag-${c.status === 'VALID' ? 'ok' : 'err'}">${c.status}</span></td>
    </tr>`
    ).join('');
}

// ══════════════════════════════════════════════════════════════════
// PANEL 03 — ZK PROOF
// ══════════════════════════════════════════════════════════════════
function initZKPanel() {
    let currentProof = null;

    // Populate cert selector
    const sel = $('zk-cert');
    Network.getCertificates().filter(c => c.status === 'VALID').forEach(c => {
        const o = document.createElement('option');
        o.value = c.id; o.textContent = `${c.id} — ${c.commonName}`;
        sel?.appendChild(o);
    });

    $('btn-prove')?.addEventListener('click', async () => {
        const certId = $('zk-cert').value;
        const claim = $('zk-claim').value;
        if (!certId) { alert_('zk-alert', 'al-err', 'Select a certificate first.'); return; }

        const btn = $('btn-prove');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> PROVING';
        $('btn-verify').disabled = true;

        ['zs1', 'zs2', 'zs3'].forEach(s => setStep(s, ''));
        setStep('zs1', 'active');
        log('zk-log', 'log-info', 'Compiling Circom circuit constraints...');
        await delay(600);
        setStep('zs1', 'done'); setStep('zs2', 'active');
        log('zk-log', 'log-info', 'Running Groth16 prover — FFT + witness generation...');

        currentProof = await CryptoSim.generateSNARK(claim, certId, 'attr-verify');
        log('zk-log', 'log-ok', `Proving time: ${currentProof.provingTime} | Size: ${currentProof.proofSize}`);
        setStep('zs2', 'done'); setStep('zs3', 'active');
        await delay(300);

        $('proof-out').innerHTML = `<div class="proof-block" style="width:100%">
      ${prow('Protocol', currentProof.protocol + ' / ' + currentProof.curve)}
      ${prow('Circuit', currentProof.circuit)}
      ${prow('pi_a (G1)', currentProof.proof.pi_a)}
      ${prow('pi_b (G2)', currentProof.proof.pi_b.slice(0, 72) + '...')}
      ${prow('pi_c (G1)', currentProof.proof.pi_c)}
      ${prow('publicSignals', currentProof.publicSignals.join(', '))}
      ${prow('Proof Size', currentProof.proofSize + ' — constant')}
    </div>`;

        setStep('zs3', 'done');
        log('zk-log', 'log-ok', 'Proof ready. Click VERIFY ON-CHAIN to submit.');
        $('btn-verify').disabled = false;
        btn.disabled = false; btn.textContent = 'GENERATE PROOF';
    });

    $('btn-verify')?.addEventListener('click', async () => {
        if (!currentProof) return;
        const btn = $('btn-verify');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> VERIFYING';
        log('zk-log', 'log-info', 'Calling Verifier.sol — 3 pairing checks on BN128...');
        const res = await CryptoSim.verifySNARK(currentProof.proof, currentProof.publicSignals, 'vk');

        $('zk-result').innerHTML = res.valid
            ? `<div style="text-align:center;padding:20px">
          <div style="font-family:var(--mono);font-size:32px;color:var(--green);font-weight:700">VALID</div>
          <div style="font-family:var(--mono);font-size:10px;color:var(--grey-lo);margin-top:8px">
            PAIRINGS: ${res.checkPairings} &nbsp;|&nbsp; GAS: ${res.gasEstimate}<br/>
            Verifier confirmed claim. Zero private data revealed.
          </div>
        </div>`
            : `<div style="text-align:center;padding:20px;font-family:var(--mono);color:var(--red);font-weight:700">INVALID</div>`;

        log('zk-log', res.valid ? 'log-ok' : 'log-err',
            res.valid ? `Verifier returned TRUE. Gas: ${res.gasEstimate}` : 'Verification failed.');
        btn.disabled = false; btn.textContent = 'VERIFY ON-CHAIN';
    });
}

// ══════════════════════════════════════════════════════════════════
// PANEL 04 — REVOCATION
// ══════════════════════════════════════════════════════════════════
function initRevPanel() {
    const sel = $('rev-sel');
    Network.getCertificates().filter(c => c.status === 'VALID').forEach(c => {
        const o = document.createElement('option');
        o.value = c.id; o.textContent = `${c.id} — ${c.commonName}`;
        sel?.appendChild(o);
    });
    updateAccDisplay();

    $('btn-revoke')?.addEventListener('click', async () => {
        const certId = $('rev-sel').value;
        const reason = $('rev-reason').value;
        if (!certId) { alert_('rev-alert', 'al-err', 'Select a certificate.'); return; }

        const btn = $('btn-revoke');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> REVOKING';

        log('rev-log', 'log-info', `Revoking ${certId}...`);
        await delay(400);
        log('rev-log', 'log-info', 'Verifying RA authority — EigenRep check...');
        await delay(400);

        const result = await Network.revokeCertificate(certId, reason);
        if (result?.alreadyRevoked) {
            alert_('rev-alert', 'al-info', 'Certificate already revoked.');
        } else {
            await accumulator.add(certId);
            log('rev-log', 'log-ok', `Accumulator root: ...${accumulator.root.slice(-14)}`);
            log('rev-log', 'log-ok', 'Gas: 65,000 — O(1) constant regardless of list size');
            updateAccDisplay();
            alert_('rev-alert', 'al-ok', `${certId} revoked. Accumulator updated on-chain.`);
            sel.querySelector(`option[value="${certId}"]`)?.remove();
        }
        btn.disabled = false; btn.textContent = 'REVOKE CERTIFICATE';
    });

    $('btn-nonmem')?.addEventListener('click', async () => {
        const testId = $('rev-testid').value.trim();
        if (!testId) { alert_('rev-alert', 'al-err', 'Enter a certificate ID to test.'); return; }

        const btn = $('btn-nonmem');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> COMPUTING';
        log('rev-log', 'log-info', `Computing non-membership witness for ${testId}...`);
        await delay(500);

        const proof = await accumulator.proveNonMembership(testId);
        $('nonmem-result').innerHTML = proof.valid
            ? `<div class="proof-block">
          ${prow('Result', '<span style="color:var(--green)">NON-MEMBER — certificate is NOT revoked</span>')}
          ${prow('Element', proof.element)}
          ${prow('Acc Root', proof.accumulatorRoot)}
          ${prow('Witness', proof.witness)}
          ${prow('Gas', proof.gasEstimate + ' — O(1) constant')}
        </div>`
            : `<div class="alert al-err show" style="margin-top:0">Certificate IS revoked — non-membership cannot be proven</div>`;

        log('rev-log', proof.valid ? 'log-ok' : 'log-err',
            proof.valid ? `Non-membership proven. Gas: ${proof.gasEstimate}` : proof.reason);
        btn.disabled = false; btn.textContent = 'PROVE NON-MEMBERSHIP';
    });
}

function updateAccDisplay() {
    const el = $('acc-root'); if (!el) return;
    el.innerHTML = `<div class="acc-k">Accumulator Root — On-Chain State</div>
    ${accumulator.root}
    <div style="margin-top:8px;font-size:10px;color:var(--grey-lo)">
      Revoked members: ${accumulator.size} &nbsp;|&nbsp; Proof size: O(1) constant
    </div>`;
}

// ══════════════════════════════════════════════════════════════════
// PANEL 05 — TRUST
// ══════════════════════════════════════════════════════════════════
function initTrustPanel() {
    $('btn-sybil')?.addEventListener('click', async () => {
        const btn = $('btn-sybil');
        btn.disabled = true; btn.innerHTML = '<span class="spin"></span> RUNNING';
        await delay(800);
        const result = Network.simulateSybilAttack();
        renderNodes();
        alert_('trust-alert', 'al-info', result.message);
        btn.disabled = false; btn.textContent = 'SIMULATE SYBIL ATTACK';
    });

    $('btn-eigen')?.addEventListener('click', () => {
        const nodes = Network.getNodes();
        const matrix = nodes.map((a) =>
            nodes.map((b, j) => a.eigenRep * b.dmRep * (a.status === 'quarantined' ? 0.05 : 1))
        );
        // Zero self-ratings
        matrix.forEach((row, i) => { row[i] = 0; });
        const scores = CryptoSim.computeEigenRep(matrix);
        const sorted = nodes.map((n, i) => ({ ...n, gs: scores[i] }))
            .sort((a, b) => b.gs - a.gs);

        $('eigen-out').innerHTML = `<div class="term">${sorted.map((n, i) =>
            `<span class="${n.status === 'quarantined' ? 't-red' : i === 0 ? 't-lime' : ''}">` +
            `${String(i + 1).padStart(2, '0')}  [${n.id}]  ${n.alias.padEnd(22)}` +
            `  score=${(n.gs * 100).toFixed(3)}%` +
            `${n.status === 'quarantined' ? '  QUARANTINED' : ''}` +
            `</span>`
        ).join('\n')}</div>`;

        alert_('trust-alert', 'al-ok', 'EigenRep converged after 20 power iterations.');
    });

    $('btn-reset')?.addEventListener('click', () => {
        Network.resetNodes();
        renderNodes();
        $('trust-alert').classList.remove('show');
        $('eigen-out').textContent = 'Run EigenRep Iteration to see power-iteration convergence.';
    });
}

function renderNodes() {
    const el = $('node-grid'); if (!el) return;
    el.innerHTML = Network.getNodes().map(n => {
        const eq = n.eigenRep >= 0.7 ? 'g' : n.eigenRep >= 0.4 ? '' : 'r';
        const dq = n.dmRep >= 0.7 ? 'g' : n.dmRep >= 0.4 ? '' : 'r';
        return `<div class="ncard ${n.status}">
          <div class="nc-id">${n.id} &middot; ${n.region}</div>
          <div class="nc-alias">${n.alias}</div>
          <span class="tag tag-${n.status === 'active' ? 'dim' : 'err'}">${n.status === 'active' ? n.role : 'QUARANTINED'}</span>
          <div class="nb">
            <div class="bar-row"><span class="bk">EigenRep</span><span class="bv">${(n.eigenRep * 100).toFixed(0)}%</span></div>
            <div class="bar-track"><div class="bar-fill ${eq}" style="width:${n.eigenRep * 100}%"></div></div>
          </div>
          <div class="nb">
            <div class="bar-row"><span class="bk">DMRep</span><span class="bv">${(n.dmRep * 100).toFixed(0)}%</span></div>
            <div class="bar-track"><div class="bar-fill ${dq}" style="width:${n.dmRep * 100}%"></div></div>
          </div>
        </div>`;
    }).join('');
}

// ══════════════════════════════════════════════════════════════════
// PANEL 06 — KEY RECOVERY
// ══════════════════════════════════════════════════════════════════
function initKeyPanel() {
    $('btn-genkey')?.addEventListener('click', () => {
        const k = '0x' + CryptoSim.randomHex(32, 'master-' + Date.now());
        const el = $('master-key');
        el.textContent = k.slice(0, 42) + '...';
        el.dataset.full = k;
        alert_('kr-alert', 'al-info', 'Key generated locally. Never sent to any server.');
    });

    $('btn-split')?.addEventListener('click', () => {
        const k = $('master-key').dataset.full || 'no-key-generated';
        const n = +$('kr-n').value;
        const t = +$('kr-t').value;
        if (t > n) { alert_('kr-alert', 'al-err', 'Threshold cannot exceed total shares.'); return; }

        const result = CryptoSim.sssShare(k, n, t);
        window._sss = { shares: result.shares, t };

        $('share-grid').innerHTML = result.shares.map(s =>
            `<div class="sp" data-i="${s.index}" onclick="this.classList.toggle('selected')">
              <div class="sp-id">${s.label}</div>
              <div class="sp-val">${s.value.slice(0, 14)}...</div>
            </div>`
        ).join('');

        $('kr-shares').style.display = 'block';
        alert_('kr-alert', 'al-ok', `Split into ${n} shares. Any ${t} reconstruct the key.`);
    });

    $('btn-recover')?.addEventListener('click', () => {
        const selected = [...document.querySelectorAll('.sp.selected')].map(el => {
            const i = +el.dataset.i;
            return window._sss?.shares.find(s => s.index === i);
        }).filter(Boolean);

        const t = window._sss?.t || 3;
        const result = CryptoSim.sssRecover(selected, t);
        const recovered = $('kr-recovered');

        if (result.success) {
            recovered.textContent = '0x' + result.recoveredFragment + '... key reconstructed';
            alert_('kr-alert', 'al-ok', `Key recovered from ${selected.length} shares via Lagrange interpolation.`);
        } else {
            recovered.textContent = result.error;
            alert_('kr-alert', 'al-err', result.error);
        }
    });
}
