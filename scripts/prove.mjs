import fs from 'node:fs';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {rpc, receipt, source, read, digest} from './check.mjs';

const code = 'contracts/CAAPolicyAudit.py';
const publisher = {name: 'studio-proof-deployer', address: '0x7a413BB4AB62E31d62d4cD9efC8C8a8Dae37FB42'};
const journal = 'PROOFS.json';
const commit = process.argv[2];
const verifyOnly = process.argv.includes('--verify-only');
assert(/^[a-f0-9]{40}$/.test(commit ?? ''));
const proof = fs.existsSync(journal)
  ? JSON.parse(fs.readFileSync(journal, 'utf8'))
  : {network: 'StudioNet', source_commit: commit, transactions: []};
assert.equal(proof.source_commit, commit);
const save = () => fs.writeFileSync(journal, JSON.stringify(proof, null, 2) + '\n');

function send(args, signer, entry) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/run-cli.cjs', ...args], {
      windowsHide: true,
      env: {...process.env, CAA_TEST_ACCOUNT: signer.name},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let pending = '';
    child.stderr.resume();
    child.stdout.on('data', chunk => {
      const lines = (pending + chunk.toString()).split(/\r?\n/);
      pending = lines.pop();
      for (const line of lines) {
        const matched = /^BROADCAST_HASH (0x[0-9a-f]{64})$/i.exec(line);
        if (matched) {
          entry.hash = matched[1];
          save();
          console.log(entry.step, entry.hash);
        }
      }
    });
    child.on('error', reject);
    child.on('close', resolve);
  });
}

async function transaction(step, args, signer) {
  let entry = proof.transactions.find(item => item.step === step);
  if (!entry) {
    assert(!verifyOnly, 'Verification requires an original broadcast journal');
    const nonce = await rpc('eth_getTransactionCount', [signer.address, 'latest']);
    assert.equal(await rpc('eth_getTransactionCount', [signer.address, 'pending']), nonce);
    entry = {step, args, signer: signer.address, nonce};
    proof.transactions.push(entry);
    save();
    await send(args, signer, entry);
  }
  assert.deepEqual(entry.args, args);
  assert.equal(entry.signer, signer.address);
  assert(entry.hash, 'Broadcast status unknown. Inspect account history before any retry.');
  entry.receipt = await receipt(entry.hash);
  save();
  assert(entry.receipt.committed, 'Transaction did not commit');
  const native = await rpc('eth_getTransactionByHash', [entry.hash]);
  assert.equal(native.from_address.toLowerCase(), signer.address.toLowerCase());
  assert.equal(BigInt(native.nonce), BigInt(entry.nonce));
  assert.equal(BigInt(native.value), 0n);
  console.log(step, entry.receipt.status, entry.receipt.execution);
  return entry.receipt.address;
}


assert.equal(await rpc('eth_chainId', []), '0xf22f');
proof.address = await transaction('deploy', ['deploy', '--contract', code], publisher);
proof.source = await source(proof.address);
proof.observations ??= {};
save();

const scenarios = [
  {
    name: 'www.cloudflare.com', path: ['www.cloudflare.com', 'cloudflare.com'],
    checks: [
      {issuer: 'letsencrypt.org', wildcard: false, property: 'issue', status: 'MATCH'},
      {issuer: 'letsencrypt.org', wildcard: true, property: 'issuewild', status: 'MATCH'},
      {issuer: 'pki.goog', wildcard: false, property: 'issue', status: 'CONDITIONAL'},
      {issuer: 'example.com', wildcard: true, property: 'issuewild', status: 'EXCLUDED'},
    ],
  },
  {
    name: 'dns.google', path: ['dns.google'],
    checks: [
      {issuer: 'pki.goog', wildcard: false, property: 'issue', status: 'MATCH'},
      {issuer: 'pki.goog', wildcard: true, property: 'issue', status: 'MATCH'},
      {issuer: 'letsencrypt.org', wildcard: true, property: 'issue', status: 'EXCLUDED'},
    ],
  },
];

for (const {name, path, checks} of scenarios) {
  assert.equal(await transaction('observe-' + name, ['write', proof.address, 'observe', '--args', name], publisher), proof.address);
  const id = await read(proof.address, 'get_latest', [name.toUpperCase() + '.']);
  const observation = await read(proof.address, 'get_observation', [id]);
  const result = {id, observation, assessments: []};
  proof.observations[name] = result;
  save();
  assert.equal(id, digest({contract: proof.address, ...observation}));
  const {evidence, observed_at} = observation;
  assert(Number.isSafeInteger(observed_at));
  assert.equal(evidence.name, name);
  assert.equal(evidence.effective_name, path.at(-1));
  assert.deepEqual(evidence.path.map(step => step.name), path);
  assert(evidence.path.every(step => step.authenticated));
  assert(evidence.path.slice(0, -1).every(step => step.records.length === 0));
  assert(evidence.path.at(-1).records.length > 0);
  for (const {issuer, wildcard, property, status} of checks) {
    const answer = await read(proof.address, 'assess', [id, issuer, wildcard]);
    result.assessments.push(answer);
    save();
    assert.deepEqual(answer, {observation_id: id, observed_at, name, effective_name: path.at(-1),
      issuer, wildcard, property, status}, 'Unexpected live DNS policy. Actual result retained in journal.');
    console.log(name, issuer, property, status);
  }
}
const history = await rpc('sim_getTransactionsForAddress', [proof.address]);
assert.deepEqual(history.map(t => t.hash).sort(), proof.transactions.map(t => t.hash).sort());
proof.verified = true;
save();
console.log('Verified three finalized transactions and seven assessments.');
