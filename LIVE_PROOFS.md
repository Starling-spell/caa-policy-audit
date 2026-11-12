# StudioNet evidence

- [StudioNet contract](https://explorer-studio.genlayer.com/address/0xbbD828A3B8BB001AA86e5f16Ffe7e7B1C118a624)
- [Exact deployed source](https://github.com/Starling-spell/caa-policy-audit/blob/fd3f6630c18f9d872c6c3ecb736a353322c83889/contracts/CAAPolicyAudit.py)
- [Finalized receipts and normalized contract readbacks](PROOFS.json)
- Deployed source SHA-256 3c8014bba1b7f6c1a23a7c4dcdc9a65e6ab676791fa1b84eda8aeaeb1b20a249

| Finalized transaction | Execution | Agree votes |
|---|---|---:|
| [Deploy contract](https://explorer-studio.genlayer.com/tx/0x8c5c90a1e054f6b234f2e5d66317b5cb61619c7b72b7fdf457f5d6252f1fcbcd) | SUCCESS | 3 |
| [Capture inherited CAA policy for www.cloudflare.com](https://explorer-studio.genlayer.com/tx/0xc9212bc0b3e5023d1cf10f374e072b808381407dc28f59e31bc4e17b93da1c3e) | SUCCESS | 3 |
| [Capture direct CAA policy for dns.google](https://explorer-studio.genlayer.com/tx/0x124d9d990a7ba323c195884e831b5c83bd0b29b1a6bdce4124fa9c5e2972d082) | SUCCESS | 3 |

| Query | Transaction time (UTC) | Authenticated path | Observation ID |
|---|---|---|---|
| www.cloudflare.com | 2026-11-12T06:51:37.000Z | www.cloudflare.com (0 records) → cloudflare.com (11 records) | 2948687a8537b65f77d9fd874a0970127ef8ee3abea2bc5067df58bb8d5d2b56 |
| dns.google | 2026-11-12T06:54:00.000Z | dns.google (2 records) | 5d54bd8bc3d2c591eb9053cb34686f1742a219c29ebb73015e0e8380c3b0d9d7 |

| Domain | Issuer | Request | Selected tag | Result |
|---|---|---|---|---|
| www.cloudflare.com | letsencrypt.org | Regular | issue | MATCH |
| www.cloudflare.com | letsencrypt.org | Wildcard | issuewild | MATCH |
| www.cloudflare.com | pki.goog | Regular | issue | CONDITIONAL |
| www.cloudflare.com | example.com | Wildcard | issuewild | EXCLUDED |
| dns.google | pki.goog | Regular | issue | MATCH |
| dns.google | pki.goog | Wildcard | issue | MATCH |
| dns.google | letsencrypt.org | Wildcard | issue | EXCLUDED |

These observations use real public DNS responses. The contract trusts the validating resolvers for DNSSEC, compares normalized record sets, and exposes historical policy assessments.

Thirteen local tests also cover resolver disagreement, unsupported DNS replies, and wildcard exclusions.
