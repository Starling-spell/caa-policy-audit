# CAAPolicyAudit

**Contribution type** Builder → Intelligent Contracts

**Description**

CAAPolicyAudit records which DNS CAA record set governs a domain. Each GenLayer validator independently queries Google and Cloudflare DNS over HTTPS, validates the DNS question and authenticated-data flags, and walks the domain suffixes. Consensus requires exact agreement on every normalized record set and authenticated empty step.

A reusable observation preserves the effective owner, source records, timestamp and compiled regular and wildcard rules. Issuer queries distinguish a match, exclusion, or issuer-specific parameters requiring interpretation.

StudioNet verified inherited policy for www.cloudflare.com and direct policy for dns.google, including both wildcard rule selection and fallback. The contract relies on DNSSEC validation by both resolvers and exposes historical policy assessments. Thirteen tests passed.

**Evidence**

- [GitHub repository](https://github.com/Starling-spell/caa-policy-audit)
- [Exact deployed source](https://github.com/Starling-spell/caa-policy-audit/blob/fd3f6630c18f9d872c6c3ecb736a353322c83889/contracts/CAAPolicyAudit.py)
- [StudioNet contract](https://explorer-studio.genlayer.com/address/0xbbD828A3B8BB001AA86e5f16Ffe7e7B1C118a624)
- [Live proof matrix](https://github.com/Starling-spell/caa-policy-audit/blob/main/LIVE_PROOFS.md)
- [Deploy contract](https://explorer-studio.genlayer.com/tx/0x8c5c90a1e054f6b234f2e5d66317b5cb61619c7b72b7fdf457f5d6252f1fcbcd)
- [Capture inherited CAA policy for www.cloudflare.com](https://explorer-studio.genlayer.com/tx/0xc9212bc0b3e5023d1cf10f374e072b808381407dc28f59e31bc4e17b93da1c3e)
- [Capture direct CAA policy for dns.google](https://explorer-studio.genlayer.com/tx/0x124d9d990a7ba323c195884e831b5c83bd0b29b1a6bdce4124fa9c5e2972d082)
