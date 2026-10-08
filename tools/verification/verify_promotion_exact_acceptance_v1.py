#!/usr/bin/env python3
"""Fail-closed verifier for promotion of a graph-only reconciliation revision.

This verifier composes three independent evidence classes:
1. an armed canonical 203-profile acceptance for the accepted source tree,
2. an exact graph-equivalence proof showing the reconciliation revision has the
   identical tree while incorporating the required private histories, and
3. a fresh exact-revision executable boundary verification of the reconciliation
   revision itself.

The evidence manifest is intentionally external to this file so final run IDs and
public head SHAs can be pinned only after those runs actually exist.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO = "oyzitjfzj/Shree-ji"
SCHEMA = "las-promotion-exact-acceptance-v1"

CURRENT_PRIVATE_SNAPSHOT_PROOF = "d893f63ec5c6e07f1541691204a7e701ea7e435df45c3877ba4ffe1fbebb994f"
RECON_PRIVATE_SNAPSHOT_PROOF = "f62e6c099ae6006056eecd4bfd7b7f61225f032d54de8e5675e98ef56b212139"
PRIVATE_TREE_PROOF = "217826cd728dfe665a6aa3b3f53d961c7a56963ad44e9b1f5a966e1bc9975b1b"
RECON_REF_HASH = "1416c7dee8ae53f075ee7aa0b53e6548265f7feffb8ce6eb644784b387809ded"

GRAPH_RUN_ID = 37744053832
GRAPH_HEAD_SHA = "a4865b055d020d11d52ff2acc12de0795c7753c6"
GRAPH_WORKFLOW_BLOB = "37c6806cf63003b41aa8796ead46d75f376f6749"
GRAPH_WORKFLOW_PATH = ".github/workflows/promotion-graph-equivalence.yml"

BOUNDARY_RUN_ID = 37745072656
BOUNDARY_HEAD_SHA = "50d6e71200e2d32ba35acec27edfb627c6c7d1d3"
BOUNDARY_WORKFLOW_BLOB = "9e979a0f808b14f40a764fb73570561b20e70840"
BOUNDARY_WORKFLOW_PATH = ".github/workflows/private-current-boundary.yml"
BOUNDARY_CONTROL_PATH = "RUN_CURRENT_BOUNDARY"

CURRENT_203_WORKFLOW_PATH = ".github/workflows/canonical-current-203-acceptance.yml"
CURRENT_203_VERIFIER_PATH = "tools/verification/verify_canonical_current_203_acceptance_v2.py"
CURRENT_203_ARM_PATH = ".verification/canonical-current-203-acceptance.arm"

HEX40 = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidencePin:
    run_id: int
    head_sha: str
    workflow_blob: str
    verifier_blob: str | None = None


@dataclass(frozen=True)
class Manifest:
    current_203: EvidencePin
    graph_equivalence: EvidencePin
    exact_boundary: EvidencePin


def fail(message: str) -> None:
    raise EvidenceError(message)


def require_hex40(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX40.fullmatch(value) is None:
        fail(f"{label}: expected lowercase 40-hex SHA")
    return value


def require_positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label}: expected positive integer")
    return value


def parse_pin(obj: object, label: str, *, verifier_required: bool) -> EvidencePin:
    if not isinstance(obj, dict):
        fail(f"{label}: expected object")
    expected = {"run_id", "head_sha", "workflow_blob"}
    if verifier_required:
        expected.add("verifier_blob")
    if set(obj) != expected:
        fail(f"{label}: unexpected keys: {sorted(set(obj) ^ expected)}")
    verifier = None
    if verifier_required:
        verifier = require_hex40(obj["verifier_blob"], f"{label}.verifier_blob")
    return EvidencePin(
        run_id=require_positive_int(obj["run_id"], f"{label}.run_id"),
        head_sha=require_hex40(obj["head_sha"], f"{label}.head_sha"),
        workflow_blob=require_hex40(obj["workflow_blob"], f"{label}.workflow_blob"),
        verifier_blob=verifier,
    )


def parse_manifest_obj(obj: object) -> Manifest:
    if not isinstance(obj, dict):
        fail("manifest: expected object")
    expected = {
        "schema",
        "private_reconciliation_snapshot_proof",
        "private_tree_proof",
        "current_203",
        "graph_equivalence",
        "exact_boundary",
    }
    if set(obj) != expected:
        fail(f"manifest: unexpected keys: {sorted(set(obj) ^ expected)}")
    if obj["schema"] != SCHEMA:
        fail("manifest: schema mismatch")
    if obj["private_reconciliation_snapshot_proof"] != RECON_PRIVATE_SNAPSHOT_PROOF:
        fail("manifest: reconciliation snapshot proof mismatch")
    if obj["private_tree_proof"] != PRIVATE_TREE_PROOF:
        fail("manifest: private tree proof mismatch")

    manifest = Manifest(
        current_203=parse_pin(obj["current_203"], "current_203", verifier_required=True),
        graph_equivalence=parse_pin(
            obj["graph_equivalence"], "graph_equivalence", verifier_required=False
        ),
        exact_boundary=parse_pin(obj["exact_boundary"], "exact_boundary", verifier_required=False),
    )

    graph = manifest.graph_equivalence
    if (graph.run_id, graph.head_sha, graph.workflow_blob) != (
        GRAPH_RUN_ID,
        GRAPH_HEAD_SHA,
        GRAPH_WORKFLOW_BLOB,
    ):
        fail("manifest: graph-equivalence evidence pin mismatch")

    boundary = manifest.exact_boundary
    if (boundary.run_id, boundary.head_sha, boundary.workflow_blob) != (
        BOUNDARY_RUN_ID,
        BOUNDARY_HEAD_SHA,
        BOUNDARY_WORKFLOW_BLOB,
    ):
        fail("manifest: exact-boundary evidence pin mismatch")

    return manifest


def load_manifest(path: str) -> Manifest:
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot load evidence manifest: {exc}")
    return parse_manifest_obj(obj)


def curl_bytes(url: str, token: str, *, follow: bool = False) -> bytes:
    cmd = [
        "curl",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--fail-with-body",
        "--retry",
        "3",
        "--silent",
        "--show-error",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
        "-H",
        f"Authorization: Bearer {token}",
    ]
    if follow:
        cmd[1:1] = ["--location", "--max-redirs", "5", "--proto-redir", "=https"]
    cmd.append(url)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode:
        fail(
            f"GitHub fetch failed rc={proc.returncode}: "
            f"{proc.stderr.decode(errors='replace')[:500]}"
        )
    return proc.stdout


def api_json(path: str, token: str) -> dict:
    raw = curl_bytes(f"https://api.github.com/repos/{REPO}{path}", token)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON for {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"unexpected GitHub JSON type for {path}")
    return value


def content_payload(path: str, ref: str, token: str) -> dict:
    return api_json(f"/contents/{path}?ref={ref}", token)


def content_text(path: str, ref: str, token: str) -> str:
    payload = content_payload(path, ref, token)
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        fail(f"malformed content response for {path}@{ref}")
    try:
        return base64.b64decode(payload["content"].replace("\n", "")).decode("utf-8")
    except Exception as exc:
        fail(f"cannot decode {path}@{ref}: {exc}")


def require_blob(path: str, ref: str, expected_blob: str, token: str) -> str:
    payload = content_payload(path, ref, token)
    actual = payload.get("sha")
    if actual != expected_blob:
        fail(f"blob mismatch for {path}: expected={expected_blob} actual={actual}")
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        fail(f"malformed content response for {path}@{ref}")
    try:
        return base64.b64decode(payload["content"].replace("\n", "")).decode("utf-8")
    except Exception as exc:
        fail(f"cannot decode {path}@{ref}: {exc}")


def list_jobs(run_id: int, token: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        payload = api_json(f"/actions/runs/{run_id}/jobs?per_page=100&page={page}", token)
        rows = payload.get("jobs")
        if not isinstance(rows, list):
            fail(f"jobs payload malformed for run {run_id}")
        out.extend(rows)
        if len(rows) < 100:
            return out
        page += 1
        if page > 10:
            fail(f"unexpected pagination depth for run {run_id}")


def single_success_job(jobs: list[dict], name: str, label: str) -> dict:
    hits = [job for job in jobs if job.get("name") == name]
    if len(hits) != 1:
        fail(f"{label}: expected one job {name!r}, got {len(hits)}")
    job = hits[0]
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        fail(f"{label}: required job is not successful")
    return job


def job_log(job_id: int, token: str) -> str:
    return curl_bytes(
        f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs",
        token,
        follow=True,
    ).decode("utf-8", errors="replace")


def require_actual_marker(log: str, marker: str) -> None:
    if re.search(r"(?m)^.*Z " + re.escape(marker) + r"\r?$", log) is None:
        fail(f"required marker missing: {marker}")


def validate_run(pin: EvidencePin, path: str, job_name: str, label: str, token: str) -> tuple[str, str]:
    run = api_json(f"/actions/runs/{pin.run_id}", token)
    if run.get("id") != pin.run_id:
        fail(f"{label}: run id mismatch")
    if run.get("head_sha") != pin.head_sha:
        fail(f"{label}: public head SHA mismatch")
    if run.get("path") != path:
        fail(f"{label}: workflow path mismatch")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        fail(
            f"{label}: run not successful status={run.get('status')} "
            f"conclusion={run.get('conclusion')}"
        )
    workflow = require_blob(path, pin.head_sha, pin.workflow_blob, token)
    job = single_success_job(list_jobs(pin.run_id, token), job_name, label)
    return workflow, job_log(int(job["id"]), token)


def validate_current_203(pin: EvidencePin, token: str) -> None:
    if pin.verifier_blob is None:
        fail("current_203: missing verifier blob")
    workflow, log = validate_run(pin, CURRENT_203_WORKFLOW_PATH, "accept", "current_203", token)
    require_blob(CURRENT_203_VERIFIER_PATH, pin.head_sha, pin.verifier_blob, token)
    if pin.verifier_blob not in workflow:
        fail("current_203: workflow does not bind the pinned verifier blob")
    arm = content_text(CURRENT_203_ARM_PATH, pin.head_sha, token)
    if arm != "armed\n":
        fail("current_203: acceptance arm missing or malformed")

    markers = (
        "LAS_CANONICAL_CURRENT_203_COVERAGE_PARTITION=PASS",
        "LAS_CANONICAL_CURRENT_203_FAST190=PASS",
        "LAS_CANONICAL_CURRENT_203_PRE_TLC=PASS",
        "LAS_CANONICAL_CURRENT_203_FORMAL_EQUIVALENCE=PASS",
        "LAS_CANONICAL_CURRENT_203_SLOW12_APPLICABILITY=PASS",
        "LAS_CANONICAL_CURRENT_203_SLOW12_AUDIT=PASS",
        "LAS_CANONICAL_CURRENT_203_PROFILE39=PASS",
        f"LAS_CANONICAL_CURRENT_203_PRIVATE_SNAPSHOT_PROOF={CURRENT_PRIVATE_SNAPSHOT_PROOF}",
        f"LAS_CANONICAL_CURRENT_203_PRIVATE_TREE_PROOF={PRIVATE_TREE_PROOF}",
        "LAS_CANONICAL_CURRENT_203_PROFILE_COUNT=203",
        "LAS_CANONICAL_CURRENT_203_ACCEPTANCE=PASS",
        "LAS_CANONICAL_CURRENT_203_ARMED_ACCEPTANCE=PASS",
    )
    for marker in markers:
        require_actual_marker(log, marker)
    print("LAS_PROMOTION_CURRENT_203_ACCEPTANCE=PASS")


def validate_graph(pin: EvidencePin, token: str) -> None:
    _, log = validate_run(pin, GRAPH_WORKFLOW_PATH, "prove", "graph_equivalence", token)
    markers = (
        "LAS_PROMOTION_GRAPH_EXACT_HEADS=PASS",
        "LAS_PROMOTION_GRAPH_TREE_IDENTITY=PASS",
        "LAS_PROMOTION_GRAPH_ZERO_SOURCE_DELTA=PASS",
        "LAS_PROMOTION_GRAPH_CURRENT_ANCESTOR=PASS",
        "LAS_PROMOTION_GRAPH_MAIN_ANCESTOR=PASS",
        "LAS_PROMOTION_GRAPH_WORK_ANCESTOR=PASS",
        "LAS_PROMOTION_GRAPH_FIRST_PARENT_TREE_STABILITY=PASS",
        "LAS_PROMOTION_GRAPH_VERIFIER_IDENTITY=PASS",
        "LAS_PROMOTION_GRAPH_HEAD_LEASES=PASS",
        "LAS_PROMOTION_GRAPH_EQUIVALENCE=PASS",
    )
    for marker in markers:
        require_actual_marker(log, marker)
    print("LAS_PROMOTION_GRAPH_EVIDENCE=PASS")


def validate_boundary(pin: EvidencePin, token: str) -> None:
    _, log = validate_run(pin, BOUNDARY_WORKFLOW_PATH, "verify", "exact_boundary", token)
    control = content_text(BOUNDARY_CONTROL_PATH, pin.head_sha, token)
    expected_control = (
        f"TARGET_REF_HASH={RECON_REF_HASH}\n"
        f"EXPECTED_PRIVATE_SNAPSHOT_PROOF={RECON_PRIVATE_SNAPSHOT_PROOF}\n"
        "EXPECT=PASS\n"
    )
    if control != expected_control:
        fail("exact_boundary: public control request mismatch")
    markers = (
        f"LAS_BOUNDARY_SNAPSHOT_PROOF={RECON_PRIVATE_SNAPSHOT_PROOF}",
        "LAS_BOUNDARY_RC=0",
        "LAS_BOUNDARY_RESULT=PASS",
    )
    for marker in markers:
        require_actual_marker(log, marker)
    print("LAS_PROMOTION_EXACT_BOUNDARY=PASS")


def validate_real(manifest: Manifest, token: str) -> None:
    validate_current_203(manifest.current_203, token)
    validate_graph(manifest.graph_equivalence, token)
    validate_boundary(manifest.exact_boundary, token)
    print(f"LAS_PROMOTION_PRIVATE_RECONCILIATION_SNAPSHOT_PROOF={RECON_PRIVATE_SNAPSHOT_PROOF}")
    print(f"LAS_PROMOTION_PRIVATE_TREE_PROOF={PRIVATE_TREE_PROOF}")
    print("LAS_PROMOTION_EXACT_ACCEPTANCE=PASS")


def expect_failure(fn, label: str) -> None:
    try:
        fn()
    except EvidenceError:
        return
    raise AssertionError(f"mutation unexpectedly passed: {label}")


def self_test() -> None:
    good = {
        "schema": SCHEMA,
        "private_reconciliation_snapshot_proof": RECON_PRIVATE_SNAPSHOT_PROOF,
        "private_tree_proof": PRIVATE_TREE_PROOF,
        "current_203": {
            "run_id": 1,
            "head_sha": "1" * 40,
            "workflow_blob": "2" * 40,
            "verifier_blob": "3" * 40,
        },
        "graph_equivalence": {
            "run_id": GRAPH_RUN_ID,
            "head_sha": GRAPH_HEAD_SHA,
            "workflow_blob": GRAPH_WORKFLOW_BLOB,
        },
        "exact_boundary": {
            "run_id": BOUNDARY_RUN_ID,
            "head_sha": BOUNDARY_HEAD_SHA,
            "workflow_blob": BOUNDARY_WORKFLOW_BLOB,
        },
    }
    parsed = parse_manifest_obj(good)
    assert parsed.graph_equivalence.run_id == GRAPH_RUN_ID
    assert parsed.exact_boundary.run_id == BOUNDARY_RUN_ID

    bad = json.loads(json.dumps(good))
    bad["private_tree_proof"] = "0" * 64
    expect_failure(lambda: parse_manifest_obj(bad), "tree proof drift")

    bad = json.loads(json.dumps(good))
    bad["graph_equivalence"]["run_id"] += 1
    expect_failure(lambda: parse_manifest_obj(bad), "graph run substitution")

    bad = json.loads(json.dumps(good))
    bad["exact_boundary"]["head_sha"] = "0" * 40
    expect_failure(lambda: parse_manifest_obj(bad), "boundary head substitution")

    bad = json.loads(json.dumps(good))
    bad["current_203"]["extra"] = True
    expect_failure(lambda: parse_manifest_obj(bad), "unexpected manifest field")

    good_log = "2026-10-08T00:00:00Z LAS_PROMOTION_GRAPH_EQUIVALENCE=PASS\n"
    require_actual_marker(good_log, "LAS_PROMOTION_GRAPH_EQUIVALENCE=PASS")
    expect_failure(
        lambda: require_actual_marker(
            "LAS_PROMOTION_GRAPH_EQUIVALENCE=PASS\n",
            "LAS_PROMOTION_GRAPH_EQUIVALENCE=PASS",
        ),
        "unframed marker",
    )
    print("LAS_PROMOTION_EXACT_ACCEPTANCE_V1_SELF_TEST=PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--manifest")
    parser.add_argument("--token")
    args = parser.parse_args()

    if args.self_test:
        if args.manifest or args.token:
            parser.error("--self-test cannot be combined with --manifest or --token")
        self_test()
        return 0

    if not args.manifest or not args.token:
        parser.error("real verification requires --manifest and --token")
    manifest = load_manifest(args.manifest)
    validate_real(manifest, args.token)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
