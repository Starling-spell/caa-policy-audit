import ast
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "contracts/CAAPolicyAudit.py"


def reply(name, records=(), **fields):
    return {"Status": 0, "TC": False, "AD": True, "CD": False,
            "Question": [{"name": name, "type": 257}],
            "Answer": [{"name": name, "type": 257, "data": data} for data in records],
            **fields}


@pytest.fixture
def core():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    module.body = [node for node in module.body if not isinstance(node, ast.ClassDef)
                   and not (isinstance(node, ast.ImportFrom) and node.module == "genlayer")]
    ns = {}
    exec(compile(module, str(SOURCE), "exec"), ns)
    return ns


@pytest.mark.parametrize("change", [
    {"AD": False}, {"TC": True}, {"CD": True}, {"Status": 3}, {"Status": 2},
    {"Question": [{"name": "other.example", "type": 257}]},
    {"Answer": [{"name": "example", "type": 5, "data": "other.example"}]},
    {"Answer": [{"name": "other.example", "type": 257, "data": '0 issue "ca.example"'}]},
])
def test_insecure_or_unsupported_dns_responses_are_rejected(core, change):
    with pytest.raises(ValueError):
        core["parse_response"](reply("example", **change), "example")


def test_normalize_order_quoting_case_and_ttl(core):
    a = reply("Example.", ('0 issuewild ";"', '0 ISSUE "ca.example"'))
    b = reply("example", ('0 issue ca.example', '0 issuewild ";"', '0 issue ca.example'))
    for answer in a["Answer"]:
        answer["TTL"] = 10
    for answer in b["Answer"]:
        answer["TTL"] = 100
    assert core["parse_response"](a, "example") == core["parse_response"](b, "example") == [
        [0, "issue", "ca.example"], [0, "issuewild", ";"],
    ]


def test_observation_classification_and_precedence(core):
    path = [
        {"name": "test.example", "authenticated": True, "records": []},
        {"name": "example", "authenticated": True, "records": [
            [0, "issue", "ca.example"], [0, "issuewild", "wild.example; accounturi=https://a.example/1"],
        ]},
    ]
    evidence = core["build_evidence"]("test.example", path)
    assert evidence["effective_name"] == "example"
    assert core["classify"](evidence, "ca.example", False) == "MATCH"
    assert core["classify"](evidence, "ca.example", True) == "EXCLUDED"
    assert core["classify"](evidence, "wild.example", True) == "CONDITIONAL"
    path[1]["records"] = [[0, "iodef", "mailto:a@example"], [128, "unknown", "x"]]
    critical = core["build_evidence"]("test.example", path)
    assert core["classify"](critical, "ca.example", False) == "UNSUPPORTED"
    path[1]["records"] = [[0, "issue", ";"]]
    assert core["classify"](core["build_evidence"]("test.example", path), "ca.example", True) == "EXCLUDED"
    path[1]["records"] = [[0, "issuewild", ";"]]
    assert core["classify"](core["build_evidence"]("test.example", path), "ca.example", False) == "UNRESTRICTED"


def test_absence_requires_entire_path_and_records_shadow_parent(core):
    child = {"name": "test.example", "authenticated": True, "records": []}
    parent = {"name": "example", "authenticated": True, "records": []}
    with pytest.raises(ValueError, match="Incomplete"):
        core["build_evidence"]("test.example", [child])
    report = core["build_evidence"]("test.example", [child, parent])
    assert report["effective_name"] is None
    assert core["classify"](report, "ca.example", False) == "UNRESTRICTED"
    child["records"] = [[0, "iodef", "mailto:a@example"]]
    with pytest.raises(ValueError, match="precedence"):
        core["build_evidence"]("test.example", [child, parent])
    assert core["build_evidence"]("test.example", [child])["effective_name"] == "test.example"


def test_validators_refetch_the_full_path_and_reject_substitution(core):
    calls = []
    mismatch = False

    def get(url, headers):
        assert headers["Accept"] == "application/dns-json"
        host = urlsplit(url).hostname
        name = parse_qs(urlsplit(url).query)["name"][0]
        calls.append((host, name))
        records = ()
        if name == "example":
            records = ('0 issue "other.example"',) if mismatch and host == "dns.google" else ('0 issue "ca.example"',)
        return SimpleNamespace(status=200, body=json.dumps(reply(name, records)).encode())

    def run(leader, validator):
        nonlocal mismatch
        result = leader()
        assert validator(SimpleNamespace(calldata=result))
        forged = core["build_evidence"]("test.example", [
            result["path"][0],
            {"name": "example", "authenticated": True, "records": [[0, "issue", "other.example"]]},
        ])
        assert not validator(SimpleNamespace(calldata=forged))
        mismatch = True
        assert not validator(SimpleNamespace(calldata=result))
        return result

    core["gl"] = SimpleNamespace(
        nondet=SimpleNamespace(web=SimpleNamespace(get=get)),
        vm=SimpleNamespace(Return=SimpleNamespace, UserError=ValueError, run_nondet_unsafe=run),
    )
    assert core["acquire"]("test.example")["plain"]["entries"] == [{"issuer": "ca.example", "parameters": ""}]
    expected = [(relay, name) for name in ("test.example", "example")
                for relay in ("dns.google", "cloudflare-dns.com")]
    assert calls == expected * 4


def test_direct_vm_permissions_path_and_failed_observation(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(str(SOURCE))
    for name, data in (
        ("test.example", reply("test.example.")),
        ("example", reply("example.", ('0 issue "ca.example"', '0 issuewild ";"'))),
        ("insecure.example", reply("insecure.example.", AD=False)),
    ):
        direct_vm.mock_web(r".*\?name=" + name.replace(".", r"\.") + r"&type=257&.*", {
            "response": {"status": 200, "headers": {}, "body": json.dumps(data).encode()}, "method": "GET",
        })

    direct_vm.sender = direct_alice
    first = contract.observe("TEST.Example.")
    direct_vm.sender = direct_bob
    assert contract.get_latest("test.example") == first
    report = contract.get_observation(first)
    assert [step["name"] for step in report["evidence"]["path"]] == ["test.example", "example"]
    assert contract.assess(first, "CA.Example.", False)["status"] == "MATCH"
    assert contract.assess(first, "ca.example", True)["status"] == "EXCLUDED"
    with direct_vm.expect_revert("CAA path unavailable, unsupported or inconsistent"):
        contract.observe("insecure.example")
    with direct_vm.expect_revert("No observation"):
        contract.get_latest("insecure.example")
    assert contract.get_latest("test.example") == first
