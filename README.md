# CAAPolicyAudit

Inspect the public DNS policy that constrains which certificate authorities may issue for a domain. A subdomain can have its own CAA record set or inherit a parent's policy. A wildcard request can use a different rule set from a regular request.

Anyone can call `observe(name)`. The leader and each validator independently query Google Public DNS and Cloudflare over HTTPS, starting at the named domain and climbing its labels until both find the first authenticated CAA record set. They require authenticated `NOERROR` responses, the exact requested DNS name and record type, and matching normalized records at every step. DNS label spelling, record order, quoting, and resolver TTL differences are normalized. The first relevant record set and every preceding authenticated empty answer are stored together. If all suffixes are empty, the report records that complete path. [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html) · [Google JSON DNS API](https://developers.google.com/speed/public-dns/docs/doh/json) · [Cloudflare JSON DNS API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)

`get_latest(name)` returns the ID of the last committed observation. `get_observation(id)` returns its timestamp, path and compiled rules. `assess(id, issuer, wildcard)` applies the selected branch to an issuer identifier. Wildcard requests use `issuewild` when present, with `issue` as the fallback. An empty issuer excludes every issuer from that entry.

| Result | Meaning |
|---|---|
| MATCH | An applicable record lists the issuer without parameters |
| CONDITIONAL | The issuer is listed with parameters that need separate interpretation |
| EXCLUDED | Applicable records restrict issuance and do not list the issuer |
| UNRESTRICTED | The recorded path contains no applicable issuance restriction |
| UNSUPPORTED | The record set has an unknown critical tag or unsupported issuer syntax |

The contract records timestamped observations from two DNSSEC-validating resolvers. It trusts their authenticated-data flags and does not validate DNSSEC signatures in the VM. The supported subset covers direct answers and authenticated `NOERROR` absence, with up to six labels and 32 records per response. Alias responses, NXDOMAIN, unauthenticated data and resolver disagreements fail closed. Assessments interpret historical CAA evidence. Actual issuance also requires the issuing CA's current DNS checks, parameter handling and domain validation.

```sh
python -m pip install -r requirements-dev.txt
genvm-lint check contracts/CAAPolicyAudit.py
python -m pytest tests -q
```

StudioNet deployment pending.
