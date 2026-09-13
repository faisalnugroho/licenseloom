"""LicenseLoom deploy + smoke harness (Studionet).

Deploys contracts/licenseloom.py with FULL consensus (not leader_only),
then runs the demo scenarios end-to-end:
  A. microsoft/markitdown @ main  (permissive)      -> expect COMPATIBLE
  B. torvalds/linux @ v6.9         (permissive)      -> expect INCOMPATIBLE
  C. octocat/Hello-World @ master (permissive)      -> expect INDETERMINATE
Each scenario: request_assessment -> run_assessment (consensus) ->
read back state -> verify binding fields. Results appended to
docs/deployment_log.json.

Usage:
  ~/genlayer-venv/bin/python scripts/deploy_smoke.py [--deploy-only]
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

CONTRACT = ROOT / "contracts" / "licenseloom.py"
KEYFILE = ROOT / "scripts" / "smoke_deployer.json"
LOG = ROOT / "docs" / "deployment_log.json"

POLL_SECONDS = 120  # studionet RPC quota discipline


def load_account():
    d = json.loads(KEYFILE.read_text())
    return create_account(account_private_key=d["private_key"])


def wait_final(client, tx_hash, label):
    """Wait FINALIZED; parse BOTH consensus vote AND execution result."""
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash,
        status=TransactionStatus.FINALIZED,
        full_transaction=True,
    )
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
    # GATE on BOTH: vote must be MAJORITY_AGREE (or absent on deterministic
    # deploys) AND execution must have succeeded — FINALIZED alone is not
    # success (verified pitfall).
    vote_ok = result_name in (None, "MAJORITY_AGREE")
    ok = vote_ok and (
        exec_res == "FINISHED_WITH_RETURN" or exec_res == "SUCCESS"
    )
    print(f"[{label}] result_name={result_name} exec={exec_res} "
          f"rounds={receipt.get('num_of_rounds')}")
    if not ok:
        stderr = ""
        try:
            stderr = str(leader.get("genvm_result", {}).get("stderr", ""))[-1500:]
        except Exception:
            pass
        print(f"[{label}] EXECUTION FAILED. stderr tail:\n{stderr}")
    return receipt, ok


def main():
    deploy_only = "--deploy-only" in sys.argv
    account = load_account()
    client = create_client(chain=studionet, account=account)
    print("deployer:", account.address)

    code = CONTRACT.read_text()

    print("deploying (FULL consensus)...")
    tx_hash = client.deploy_contract(
        code=code, account=client.local_account, args=[], leader_only=False
    )
    print("deploy tx:", tx_hash)
    receipt, ok = wait_final(client, tx_hash, "deploy")
    if not ok:
        sys.exit(1)
    data = receipt.get("data") or {}
    addr = data.get("contract_address") if isinstance(data, dict) else None
    if not addr:
        addr = receipt.get("to_address") or receipt.get("contract_address")
    print("contract:", addr)

    log_entry = {
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "deploy_tx": tx_hash,
        "contract_address": addr,
        "deployer": account.address,
        "network": "studionet",
        "scenarios": [],
    }

    if deploy_only:
        LOG.parent.mkdir(exist_ok=True)
        prev = json.loads(LOG.read_text()) if LOG.exists() else []
        prev.append(log_entry)
        LOG.write_text(json.dumps(prev, indent=2))
        print("deployment recorded. --deploy-only; skipping scenarios.")
        return

    scenarios = [
        {
            "name": "A-markitdown-permissive",
            "repo": "https://github.com/microsoft/markitdown",
            "revision": "main",
            "policy": "permissive-redistribution",
            "expect": "COMPATIBLE",
        },
        {
            "name": "B-linux-gpl-permissive",
            "repo": "https://github.com/torvalds/linux",
            "revision": "v6.9",
            "policy": "permissive-redistribution",
            "expect": "INCOMPATIBLE",
        },
        {
            "name": "C-helloworld-nolicense-permissive",
            "repo": "https://github.com/octocat/Hello-World",
            "revision": "master",
            "policy": "permissive-redistribution",
            "expect": "INDETERMINATE",
        },
    ]

    for sc in scenarios:
        print(f"\n=== scenario {sc['name']} ===")
        tx1 = client.write_contract(
            address=addr, function_name="request_assessment",
            args=[sc["repo"], sc["revision"], sc["policy"], ""],
            account=client.local_account,
        )
        r1, ok1 = wait_final(client, tx1, f"{sc['name']}-request")
        aid = None
        if ok1:
            # read the id via the view
            total = client.read_contract(
                address=addr, function_name="total_assessments", args=[]
            )
            n = json.loads(total)["total"] if isinstance(total, str) else total
            aid = f"ll-{n}"
        if not ok1 or aid is None:
            log_entry["scenarios"].append({**sc, "status": "request_failed"})
            continue
        print("assessment_id:", aid)
        time.sleep(3)

        tx2 = client.write_contract(
            address=addr, function_name="run_assessment",
            args=[aid], account=client.local_account,
        )
        r2, ok2 = wait_final(client, tx2, f"{sc['name']}-run")
        rec_raw = client.read_contract(
            address=addr, function_name="get_assessment", args=[aid]
        )
        rec = json.loads(rec_raw) if isinstance(rec_raw, str) else json.loads(str(rec_raw))
        decision = rec.get("decision")
        matches = decision == sc["expect"]
        print(f"decision={decision} expected={sc['expect']} match={matches}")
        print(f"resolved_sha={rec.get('resolved_commit_sha')}")
        print(f"evidence_root={rec.get('evidence_root')}")
        print(f"result_hash={rec.get('result_hash')}")
        print(f"families={rec.get('detected_license_families')}")
        print(f"reason_codes={rec.get('reason_codes')}")
        print(f"summary={rec.get('summary')}")
        entry = {
            **sc,
            "assessment_id": aid,
            "request_tx": tx1,
            "run_tx": tx2,
            "decision": decision,
            "expected": sc["expect"],
            "matches_expectation": matches,
            "resolved_commit_sha": rec.get("resolved_commit_sha"),
            "evidence_root": rec.get("evidence_root"),
            "result_hash": rec.get("result_hash"),
            "detected_license_families": rec.get("detected_license_families"),
            "reason_codes": rec.get("reason_codes"),
            "summary": rec.get("summary"),
        }
        log_entry["scenarios"].append(entry)
        # RPC quota discipline between consensus-heavy scenarios
        time.sleep(10)

    LOG.parent.mkdir(exist_ok=True)
    prev = json.loads(LOG.read_text()) if LOG.exists() else []
    prev.append(log_entry)
    LOG.write_text(json.dumps(prev, indent=2))
    print("\nlog appended ->", LOG)


if __name__ == "__main__":
    main()
