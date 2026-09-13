#!/usr/bin/env python
"""Resume harness: the deploy + scenario A request already succeeded
(contract 0x0F4f…, ll-1 CREATED). Run the remaining assessment + scenarios
B/C against the EXISTING deployment — never redeploy (proven skill rule)."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

ADDR = "0x0F4f09Ac9fB036Ca295C1B7c589E411409589ff0"
DEPLOY_TX = "0xecf392ee13580040d808f7937e1978eaf9118311dd74b68efcd8d3f86121d0bd"
LOG = ROOT / "docs" / "deployment_log.json"
KEYFILE = ROOT / "scripts" / "smoke_deployer.json"


def wait_final(client, tx_hash, label):
    for attempt in range(4):
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_hash,
                status=TransactionStatus.FINALIZED,
                full_transaction=True,
                retries=60,
                interval=3000,
            )
            break
        except Exception:
            if attempt == 3:
                raise
            time.sleep(5)
    if not isinstance(receipt, dict):
        receipt = dict(receipt or {})
    result_name = receipt.get("result_name")
    exec_name = receipt.get("tx_execution_result_name")
    leader = None
    try:
        leader = receipt.get("consensus_data", {}).get("leader_receipt", [None])[0]
    except Exception:
        pass
    exec_res = exec_name or (leader or {}).get("execution_result")
    votes = None
    try:
        votes = receipt.get("consensus_data", {}).get("votes")
    except Exception:
        pass
    print(f"[{label}] vote={result_name} exec={exec_res} rounds={receipt.get('num_of_rounds')}")
    ok = result_name in (None, "MAJORITY_AGREE") and (
        exec_res == "FINISHED_WITH_RETURN" or exec_res == "SUCCESS"
    )
    if not ok:
        stderr = ""
        try:
            stderr = str(leader.get("genvm_result", {}).get("stderr", ""))[-1500:]
        except Exception:
            pass
        print(f"[{label}] FAILED. stderr tail:\n{stderr}")
    return receipt, ok


def read_json(client, fn, args):
    raw = client.read_contract(address=ADDR, function_name=fn, args=args)
    return json.loads(raw) if isinstance(raw, str) else json.loads(str(raw))


def main():
    account = create_account(
        account_private_key=json.loads(KEYFILE.read_text())["private_key"]
    )
    client = create_client(chain=studionet, account=account)
    print("contract:", ADDR, "(existing deployment)")

    log_entry = {
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "deploy_tx": DEPLOY_TX,
        "contract_address": ADDR,
        "deployer": account.address,
        "network": "studionet",
        "note": "resumed harness; ll-1 request tx 0x7cd32dd684a3a88f1655479c54a3f7afc09d8d0dd9bb9de7ecbcea2476086082 (ACCEPTED, 5/5 agree) from prior run",
        "scenarios": [],
    }

    total = read_json(client, "total_assessments", [])
    print("existing assessments:", total)
    n_before = int(total["total"])

    scenarios = [
        {"name": "A-markitdown-permissive",
         "existing_id": "ll-1",  # created by prior run, still CREATED
         "repo": "https://github.com/microsoft/markitdown", "revision": "main",
         "policy": "permissive-redistribution", "expect": "COMPATIBLE"},
        {"name": "B-linux-gpl-permissive", "existing_id": None,
         "repo": "https://github.com/torvalds/linux", "revision": "v6.9",
         "policy": "permissive-redistribution", "expect": "INCOMPATIBLE"},
        {"name": "C-helloworld-nolicense-permissive", "existing_id": None,
         "repo": "https://github.com/octocat/Hello-World", "revision": "master",
         "policy": "permissive-redistribution", "expect": "INDETERMINATE"},
    ]

    for sc in scenarios:
        print(f"\n=== {sc['name']} ===")
        aid = sc["existing_id"]
        if aid is None:
            tx1 = client.write_contract(
                address=ADDR, function_name="request_assessment",
                args=[sc["repo"], sc["revision"], sc["policy"], ""],
                account=client.local_account)
            _, ok1 = wait_final(client, tx1, sc["name"] + "-request")
            if not ok1:
                log_entry["scenarios"].append({**sc, "status": "request_failed"})
                continue
            total = read_json(client, "total_assessments", [])
            aid = "ll-" + str(total["total"])
        rec = read_json(client, "get_assessment", [aid])
        if rec.get("status") != "CREATED":
            print(f"ll record {aid} status={rec.get('status')} — run already done; reading back only")
        else:
            print("assessment_id:", aid, "status:", rec.get("status"))
            time.sleep(3)
            sealed = False
            last_err = ""
            for attempt in range(1, 4):
                try:
                    tx2 = client.write_contract(
                        address=ADDR, function_name="run_assessment",
                        args=[aid], account=client.local_account)
                    _, ok2 = wait_final(client, tx2, f"{sc['name']}-run(attempt {attempt})")
                    if ok2:
                        sealed = True
                        break
                    last_err = "execution failed on chain"
                except Exception as e:
                    last_err = str(e)
                    msg = str(e)
                    if "assessment_not_created" in msg:
                        # consensus accepted it but our read raced — re-read
                        r2 = read_json(client, "get_assessment", [aid])
                        if r2.get("status") == "ACCEPTED":
                            sealed = True
                            break
                time.sleep(10)
            if not sealed:
                log_entry["scenarios"].append({**sc, "assessment_id": aid, "status": "run_failed", "error": last_err})
                continue
        rec = read_json(client, "get_assessment", [aid])
        decision = rec.get("decision")
        matches = decision == sc["expect"]
        print(f"decision={decision} expected={sc['expect']} match={matches}")
        print(f"resolved_sha={rec.get('resolved_commit_sha')}")
        print(f"evidence_root={rec.get('evidence_root')}")
        print(f"result_hash={rec.get('result_hash')}")
        print(f"families={rec.get('detected_license_families')}")
        print(f"reason_codes={rec.get('reason_codes')}")
        print(f"summary={rec.get('summary')}")
        log_entry["scenarios"].append({
            "scenario": sc["name"], "repo": sc["repo"],
            "revision": sc["revision"], "policy": sc["policy"],
            "assessment_id": aid, "decision": decision,
            "expected": sc["expect"], "matches_expectation": matches,
            "resolved_commit_sha": rec.get("resolved_commit_sha"),
            "evidence_root": rec.get("evidence_root"),
            "result_hash": rec.get("result_hash"),
            "detected_license_families": rec.get("detected_license_families"),
            "reason_codes": rec.get("reason_codes"),
            "summary": rec.get("summary"),
        })
        time.sleep(10)

    LOG.parent.mkdir(exist_ok=True)
    prev = json.loads(LOG.read_text()) if LOG.exists() else []
    prev.append(log_entry)
    LOG.write_text(json.dumps(prev, indent=2))
    print("\nlog appended ->", LOG)


if __name__ == "__main__":
    main()
