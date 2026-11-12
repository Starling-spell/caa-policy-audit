# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from datetime import datetime, timezone
import hashlib
import json
import re


RESOLVERS = (
    ("https://dns.google/resolve", "cd=0"),
    ("https://cloudflare-dns.com/dns-query", "cd=false"),
)
CAA = 257
KNOWN_TAGS = ("issue", "issuewild", "iodef")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def fail(message):
    raise gl.vm.UserError("[EXPECTED] " + message)


def domain(value):
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 254:
        raise ValueError("Invalid domain")
    name = value.removesuffix(".").lower()
    if len(name) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in name.split(".")
    ):
        raise ValueError("Invalid domain")
    return name


def checked_domain(value):
    try:
        return domain(value)
    except ValueError:
        fail("Invalid domain")


def unique_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate DNS JSON key")
        result[key] = value
    return result


def record_value(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Invalid CAA record")
    match = re.fullmatch(r'([0-9]{1,3}) +([A-Za-z0-9]{1,255}) +(.*)', value)
    if match is None:
        raise ValueError("Invalid CAA record")
    flag, tag, text = match.groups()
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        text = text[1:-1]
    result = [int(flag), tag.lower(), text]
    check_record(result)
    return result


def check_record(record):
    if not isinstance(record, list) or len(record) != 3:
        raise ValueError("Invalid normalized record")
    flag, tag, value = record
    if (type(flag) is not int or not 0 <= flag <= 255 or not isinstance(tag, str)
            or not re.fullmatch(r"[a-z0-9]{1,255}", tag) or not isinstance(value, str)
            or len(value) > 1024 or any(not 32 <= ord(c) < 127 or c in '"\\' for c in value)):
        raise ValueError("Unsupported CAA presentation")


def parse_response(data, expected):
    if (not isinstance(data, dict) or type(data.get("Status")) is not int
            or data["Status"] != 0 or data.get("TC") is not False
            or data.get("CD") is not False or data.get("AD") is not True):
        raise ValueError("DNS reply was not authenticated NOERROR")
    question = data.get("Question")
    if (not isinstance(question, list) or len(question) != 1 or not isinstance(question[0], dict)
            or question[0].get("type") != CAA or domain(question[0].get("name")) != expected):
        raise ValueError("Wrong DNS question")
    answers = data.get("Answer", [])
    if not isinstance(answers, list) or len(answers) > 32:
        raise ValueError("Invalid DNS answer list")
    records = []
    for answer in answers:
        if (not isinstance(answer, dict) or answer.get("type") != CAA
                or domain(answer.get("name")) != expected):
            raise ValueError("Alias or unexpected DNS answer")
        records.append(record_value(answer.get("data")))
    return [list(row) for row in sorted(set(tuple(row) for row in records))]


def suffixes(name):
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def profile(records, tag):
    entries = []
    for _, property_tag, value in records:
        if property_tag != tag:
            continue
        issuer, _, parameters = value.partition(";")
        issuer = issuer.strip()
        try:
            parsed = domain(issuer) if issuer else ""
        except ValueError:
            parsed = None
        entries.append({"issuer": parsed, "parameters": parameters.strip()})
    return {"tag": tag, "entries": entries}


def build_evidence(name, path):
    candidates = suffixes(name)
    if not isinstance(path, list) or not 1 <= len(path) <= len(candidates):
        raise ValueError("Invalid DNS path")
    for i, item in enumerate(path):
        if (not isinstance(item, dict) or set(item) != {"name", "authenticated", "records"}
                or item["name"] != candidates[i] or item["authenticated"] is not True
                or not isinstance(item["records"], list) or len(item["records"]) > 32):
            raise ValueError("Invalid DNS step")
        for record in item["records"]:
            check_record(record)
        canonical_records = [list(row) for row in sorted(set(tuple(row) for row in item["records"]))]
        if canonical_records != item["records"] or (i < len(path) - 1 and canonical_records):
            raise ValueError("Invalid ancestor precedence")
    records = path[-1]["records"]
    if not records and len(path) != len(candidates):
        raise ValueError("Incomplete absence path")
    wildcard_tag = "issuewild" if any(tag == "issuewild" for _, tag, _ in records) else "issue"
    return {
        "name": name, "path": path, "effective_name": path[-1]["name"] if records else None,
        "unknown_critical": sorted({tag for flag, tag, _ in records if flag & 128 and tag not in KNOWN_TAGS}),
        "plain": profile(records, "issue"), "wildcard": profile(records, wildcard_tag),
    }


def acquire(name):
    def evaluate():
        path = []
        try:
            for candidate in suffixes(name):
                replies = []
                for url, flags in RESOLVERS:
                    response = gl.nondet.web.get(
                        f"{url}?name={candidate}&type=257&{flags}",
                        headers={"Accept": "application/dns-json"},
                    )
                    if response.status != 200 or not 1 <= len(response.body) <= 16000:
                        raise ValueError("Invalid DoH response")
                    data = json.loads(response.body.decode("utf-8"), object_pairs_hook=unique_keys)
                    replies.append(parse_response(data, candidate))
                if replies[0] != replies[1]:
                    raise ValueError("Resolver RRsets disagreed")
                records = replies[0]
                path.append({"name": candidate, "authenticated": True, "records": records})
                if records:
                    break
            return build_evidence(name, path)
        except Exception:
            raise gl.vm.UserError("[DNS_ERROR] CAA path unavailable, unsupported or inconsistent")

    def validator(result):
        if not isinstance(result, gl.vm.Return):
            return False
        try:
            return canonical(evaluate()) == canonical(result.calldata)
        except Exception:
            return False

    result = gl.vm.run_nondet_unsafe(evaluate, validator)
    try:
        if canonical(result) != canonical(build_evidence(name, result["path"])):
            raise ValueError("Substituted evidence")
    except Exception:
        raise gl.vm.UserError("[DNS_ERROR] Invalid consensus evidence")
    return result


def classify(evidence, issuer, wildcard):
    selected = evidence["wildcard" if wildcard else "plain"]
    entries = selected["entries"]
    if evidence["unknown_critical"] or any(entry["issuer"] is None for entry in entries):
        return "UNSUPPORTED"
    if not entries:
        return "UNRESTRICTED"
    matches = [entry for entry in entries if entry["issuer"] == issuer]
    if any(not entry["parameters"] for entry in matches):
        return "MATCH"
    return "CONDITIONAL" if matches else "EXCLUDED"


class CAAPolicyAudit(gl.Contract):
    observations: TreeMap[str, str]
    latest: TreeMap[str, str]

    def __init__(self):
        pass

    @gl.public.write
    def observe(self, name: str) -> str:
        name = checked_domain(name)
        if not 2 <= len(name.split(".")) <= 6:
            fail("Domain must have two to six labels")
        evidence = acquire(name)
        observation = {"observed_at": int(datetime.now(timezone.utc).timestamp()), "evidence": evidence}
        observation_id = digest({"contract": str(gl.message.contract_address), **observation})
        self.observations[observation_id] = canonical(observation)
        self.latest[name] = observation_id
        return observation_id

    @gl.public.view
    def get_latest(self, name: str) -> str:
        name = checked_domain(name)
        if name not in self.latest:
            fail("No observation")
        return self.latest[name]

    @gl.public.view
    def get_observation(self, observation_id: str) -> dict:
        if observation_id not in self.observations:
            fail("Unknown observation")
        return json.loads(self.observations[observation_id])

    @gl.public.view
    def assess(self, observation_id: str, issuer: str, wildcard: bool) -> dict:
        issuer = checked_domain(issuer)
        if type(wildcard) is not bool:
            fail("Wildcard must be Boolean")
        observation = self.get_observation(observation_id)
        evidence = observation["evidence"]
        selected = evidence["wildcard" if wildcard else "plain"]
        return {"observation_id": observation_id, "observed_at": observation["observed_at"],
                "name": evidence["name"], "effective_name": evidence["effective_name"],
                "issuer": issuer, "wildcard": wildcard, "property": selected["tag"],
                "status": classify(evidence, issuer, wildcard)}
