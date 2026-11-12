import fs from 'node:fs';
import assert from 'node:assert/strict';

const proof = JSON.parse(fs.readFileSync('PROOFS.json', 'utf8'));
const {address, source_commit: commit, source, transactions, observations} = proof;
assert(proof.verified && source.source_match);
assert.equal(transactions.length, 3);
assert(transactions.every(t => t.receipt.committed && t.receipt.status === 'FINALIZED' && t.receipt.agree_votes >= 2));

const repository = 'https://github.com/Starling-spell/caa-policy-audit';
const explorer = 'https://explorer-studio.genlayer.com';
const deployed = '[StudioNet contract](' + explorer + '/address/' + address + ')';
const sourceLink = '[Exact deployed source](' + repository + '/blob/' + commit + '/contracts/CAAPolicyAudit.py)';
const labels = {
  deploy: 'Deploy contract',
  'observe-www.cloudflare.com': 'Capture inherited CAA policy for www.cloudflare.com',
  'observe-dns.google': 'Capture direct CAA policy for dns.google',
};
const txLink = t => '[' + labels[t.step] + '](' + explorer + '/tx/' + t.hash + ')';
const observationRows = Object.entries(observations).map(([name, {id, observation}]) => {
  const {observed_at, evidence} = observation;
  const path = evidence.path.map(step => step.name + ' (' + step.records.length + ' records)').join(' → ');
  return '| ' + name + ' | ' + new Date(observed_at * 1000).toISOString() + ' | ' + path + ' | ' + id + ' |';
});
const assessments = Object.values(observations).flatMap(entry => entry.assessments);
assert.equal(assessments.length, 7);

fs.writeFileSync('LIVE_PROOFS.md', [
  '# StudioNet evidence', '',
  '- ' + deployed,
  '- ' + sourceLink,
  '- [Finalized receipts and normalized contract readbacks](PROOFS.json)',
  '- Deployed source SHA-256 ' + source.sha256,
  '', '| Finalized transaction | Execution | Agree votes |', '|---|---|---:|',
  ...transactions.map(t => '| ' + txLink(t) + ' | ' + t.receipt.execution + ' | ' + t.receipt.agree_votes + ' |'), '',
  '| Query | Transaction time (UTC) | Authenticated path | Observation ID |', '|---|---|---|---|',
  ...observationRows, '',
  '| Domain | Issuer | Request | Selected tag | Result |', '|---|---|---|---|---|',
  ...assessments.map(a => '| ' + a.name + ' | ' + a.issuer + ' | ' + (a.wildcard ? 'Wildcard' : 'Regular') +
    ' | ' + a.property + ' | ' + a.status + ' |'), '',
  'These observations use real public DNS responses. The contract trusts the validating resolvers for DNSSEC, compares normalized record sets, and exposes historical policy assessments.',
  '', 'Thirteen local tests also cover resolver disagreement, unsupported DNS replies, and wildcard exclusions.', '',
].join('\n'));

const description = [
  'CAAPolicyAudit records which DNS CAA record set governs a domain. Each GenLayer validator independently queries Google and Cloudflare DNS over HTTPS, validates the DNS question and authenticated-data flags, and walks the domain suffixes. Consensus requires exact agreement on every normalized record set and authenticated empty step.',
  'A reusable observation preserves the effective owner, source records, timestamp and compiled regular and wildcard rules. Issuer queries distinguish a match, exclusion, or issuer-specific parameters requiring interpretation.',
  'StudioNet verified inherited policy for www.cloudflare.com and direct policy for dns.google, including both wildcard rule selection and fallback. The contract relies on DNSSEC validation by both resolvers and exposes historical policy assessments. Thirteen tests passed.',
].join('\n\n');
assert(description.length <= 1000);
fs.writeFileSync('SUBMISSION.md', [
  '# CAAPolicyAudit', '', '**Contribution type** Builder → Intelligent Contracts', '',
  '**Description**', '', description, '',
  '**Evidence**', '', '- [GitHub repository](' + repository + ')', '- ' + sourceLink, '- ' + deployed,
  '- [Live proof matrix](' + repository + '/blob/main/LIVE_PROOFS.md)',
  ...transactions.map(t => '- ' + txLink(t)), '',
].join('\n'));
