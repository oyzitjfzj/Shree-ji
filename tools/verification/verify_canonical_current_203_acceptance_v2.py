#!/usr/bin/env python3
"""Fail-closed public verifier for the exact current 203-profile canonical closure."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable

REPO = "oyzitjfzj/Shree-ji"
CURRENT_SNAPSHOT_PROOF = "d893f63ec5c6e07f1541691204a7e701ea7e435df45c3877ba4ffe1fbebb994f"
CURRENT_TREE_PROOF = "217826cd728dfe665a6aa3b3f53d961c7a56963ad44e9b1f5a966e1bc9975b1b"
BASE624_SNAPSHOT_PROOF = "abb7edc70bc685527a44c36f8997b45c863891b54fe9307e3c8c1c7cfe81c48d"
FROZEN242_SNAPSHOT_PROOF = "b5112adc429935d9024eb5805c9c49dd2c0f2cb161849cc987f7ba20af212f5c"
SLOW12_MANIFEST = "bc739bbb46a25e97531297ac4fd4dbf9e1c8264ce7f7e2c44f5861ef5687fa85"
PROFILE39_COUNTS = (16_789_249, 7_063_296)

SLOW12 = frozenset({2, 28, 29, 36, 110, 115, 133, 145, 156, 157, 168, 172})
PROFILE39 = frozenset({39})
ALL203 = frozenset(range(203))
FAST190 = ALL203 - SLOW12 - PROFILE39


class EvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class RunSpec:
    label: str
    run_id: int
    head_sha: str
    workflow_path: str
    job_name: str | None
    markers: tuple[str, ...]
    workflow_bindings: tuple[str, ...]


RUNS = {
    "fast190": RunSpec(
        "fast190", 37724331030,
        "2ca200235d9e94b5a7d438e3565c1cfc92b356bc",
        ".github/workflows/canonical-exact-current-fast190.yml", None, (),
        (
            f"EXPECTED_PRIVATE_SNAPSHOT_PROOF: {BASE624_SNAPSHOT_PROOF}",
            'EXPECTED_FAST_PROFILE_COUNT: "190"',
            'EXPECTED_TLC_PROFILE_COUNT: "203"',
        ),
    ),
    "pre_tlc": RunSpec(
        "pre_tlc", 37726967857,
        "7f37db59c890d5d49e0d104578ad8e62114e0f5a",
        ".github/workflows/canonical-exact-current-pre-tlc.yml", "pre_tlc",
        (
            "LAS_CURRENT_PRE_TLC_EXACT_RECOVERY=PASS",
            "LAS_CURRENT_PRE_TLC_ISOLATION=PASS",
            "LAS_CURRENT_PRE_TLC_PYTHON_CACHE_RELOCATION=PASS",
            "LAS_CURRENT_PRE_TLC_TLA_SHA256_PIN=PASS",
            "LAS_CURRENT_PRE_TLC_RESULT=PASS",
        ),
        (
            f"EXPECTED_PRIVATE_SNAPSHOT_PROOF: {CURRENT_SNAPSHOT_PROOF}",
            f"EXPECTED_PRIVATE_TREE_PROOF: {CURRENT_TREE_PROOF}",
        ),
    ),
    "formal_equivalence": RunSpec(
        "formal_equivalence", 37728288021,
        "18b734f2cd7a07f8cfdd83afdf56567e896ed856",
        ".github/workflows/canonical-formal-equivalence.yml", "prove",
        (
            "LAS_FORMAL_EQ_EXACT_RECOVERY=PASS",
            "LAS_FORMAL_EQ_WRAPPER_ONLY_DELTA=PASS",
            "LAS_FORMAL_EQ_SPEC_TREE=PASS",
            "LAS_FORMAL_EQ_CANONICAL_ENGINE=PASS",
            "LAS_FORMAL_EQ_PROFILE39_RUNNER=PASS",
            "LAS_FORMAL_EQ_TLA_TOOLCHAIN=PASS",
            "LAS_FORMAL_EQ_NEGATIVE_SPEC_DRIFT=PASS",
            "LAS_FORMAL_INPUT_EQUIVALENCE=PASS",
        ),
        (
            f"BASE_SNAPSHOT_PROOF: {BASE624_SNAPSHOT_PROOF}",
            f"HEAD_SNAPSHOT_PROOF: {CURRENT_SNAPSHOT_PROOF}",
        ),
    ),
    "slow12_applicability": RunSpec(
        "slow12_applicability", 37728914109,
        "482c0af1d99975a356c7b8fa95e9241343bd8e77",
        ".github/workflows/canonical-slow12-applicability.yml", "prove",
        (
            "LAS_SLOW12_EXACT_RECOVERY=PASS",
            "LAS_SLOW12_ALLOWED_DELTA=PASS",
            "LAS_SLOW12_CANONICAL_ENGINE_EQUIVALENCE=PASS",
            "LAS_SLOW12_SPEC_TREE_EQUIVALENCE=PASS",
            "LAS_SLOW12_CANONICAL_MAP_EQUIVALENCE=PASS",
            "LAS_SLOW12_PROFILE_COUNT=12",
            f"LAS_SLOW12_INPUT_MANIFEST_SHA256={SLOW12_MANIFEST}",
            "LAS_SLOW12_INPUT_BYTES_EQUIVALENCE=PASS",
            "LAS_SLOW12_TLA_TOOLCHAIN=PASS",
            "LAS_SLOW12_NEGATIVE_INPUT_DRIFT=PASS",
            "LAS_SLOW12_APPLICABILITY=PASS",
        ),
        (
            f"BASE_SNAPSHOT_PROOF: {FROZEN242_SNAPSHOT_PROOF}",
            f"HEAD_SNAPSHOT_PROOF: {CURRENT_SNAPSHOT_PROOF}",
            f"HEAD_TREE_PROOF: {CURRENT_TREE_PROOF}",
            'EXPECTED_SLOW_COUNT: "12"',
        ),
    ),
    "slow12_audit": RunSpec(
        "slow12_audit", 37729334979,
        "8ee0944f271f92cc803ed54448d386fcc8181cc0",
        ".github/workflows/canonical-slow12-chain-audit.yml", "audit",
        (
            "LAS_SLOW12_CHAIN_EVIDENCE_COLLECTION=PASS",
            "LAS_SLOW12_CHAIN_TERMINAL_PASS_COUNT=12",
            "LAS_SLOW12_CHAIN_ACTIVE_OR_PENDING_COUNT=0",
            "LAS_SLOW12_CHAIN_INTEGRITY=PASS",
            "LAS_SLOW12_CHAIN_AUDIT=PASS",
        ),
        (
            'BOOTSTRAP_RUN_ID: "37572378728"',
            'CONTINUATION_WORKFLOW_ID: "372166115"',
            "FROZEN_BRANCH: verify/current-exact-resumable-24244fc8",
        ),
    ),
    "profile39": RunSpec(
        "profile39", 37729246987,
        "363c51310872053671c3a67bae3932032d9c120b",
        ".github/workflows/canonical-profile39-current.yml", "validate",
        (
            "LAS_CURRENT_PROFILE39_EXACT_RECOVERY=PASS",
            "LAS_CURRENT_PROFILE39_TOOLCHAIN=PASS",
            "LAS_CURRENT_PROFILE39_NEGATIVE_TOOLCHAIN=PASS",
            "LAS_CURRENT_PROFILE39_NEGATIVE_INPUT_DRIFT=PASS",
            f"LAS_CURRENT_PROFILE39_TRIPLE_FP_STATE_COUNTS={PROFILE39_COUNTS[0]},{PROFILE39_COUNTS[1]}",
            "LAS_CURRENT_PROFILE39_TRIPLE_FP_STATESET_CONSISTENCY=PASS",
            "LAS_CURRENT_PROFILE39_FULL_VALIDATION=PASS",
        ),
        (
            f"EXPECTED_PRIVATE_SNAPSHOT_PROOF: {CURRENT_SNAPSHOT_PROOF}",
            f"EXPECTED_PRIVATE_TREE_PROOF: {CURRENT_TREE_PROOF}",
            'EXPECTED_PREFIX_GENERATED_STATES: "16789249"',
            'EXPECTED_PREFIX_DISTINCT_STATES: "7063296"',
        ),
    ),
}


def fail(msg: str) -> None:
    raise EvidenceError(msg)


def validate_partition(fast: Iterable[int], slow: Iterable[int], p39: Iterable[int]) -> None:
    a, b, c = set(fast), set(slow), set(p39)
    if len(a) != 190 or len(b) != 12 or c != {39}:
        fail(f"coverage cardinality mismatch fast={len(a)} slow={len(b)} profile39={sorted(c)}")
    if a & b or a & c or b & c:
        fail("coverage sets overlap")
    if a | b | c != set(ALL203):
        fail(f"coverage union mismatch missing={sorted(set(ALL203)-(a|b|c))} extra={sorted((a|b|c)-set(ALL203))}")


def require_actual_marker(log: str, marker: str) -> None:
    if re.search(r"(?m)^.*Z " + re.escape(marker) + r"\r?$", log) is None:
        fail(f"required marker missing: {marker}")


def validate_bindings(text: str, bindings: Iterable[str], label: str) -> None:
    for binding in bindings:
        if binding not in text:
            fail(f"{label}: workflow binding missing: {binding}")


def validate_fast_jobs(jobs: list[dict]) -> int:
    found: dict[int, dict] = {}
    aggregate: list[dict] = []
    for job in jobs:
        name = str(job.get("name", ""))
        m = re.fullmatch(r"tlc_fast \((\d+)\)", name)
        if m:
            idx = int(m.group(1))
            if idx in found:
                fail(f"duplicate fast ordinal job: {idx}")
            found[idx] = job
        elif name == "aggregate":
            aggregate.append(job)
    if set(found) != set(FAST190):
        fail(f"fast coverage mismatch missing={sorted(set(FAST190)-set(found))} extra={sorted(set(found)-set(FAST190))}")
    for idx, job in found.items():
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            fail(f"fast ordinal not successful: {idx}")
    if len(aggregate) != 1:
        fail(f"expected exactly one aggregate job, got {len(aggregate)}")
    if aggregate[0].get("status") != "completed" or aggregate[0].get("conclusion") != "success":
        fail("fast aggregate not successful")
    return int(aggregate[0]["id"])


def curl_bytes(url: str, token: str, follow: bool = False) -> bytes:
    cmd = ["curl", "--proto", "=https", "--tlsv1.2", "--fail-with-body", "--retry", "3",
           "--silent", "--show-error", "-H", "Accept: application/vnd.github+json",
           "-H", "X-GitHub-Api-Version: 2022-11-28", "-H", f"Authorization: Bearer {token}"]
    if follow:
        # No --location-trusted: Authorization is not forwarded to a different host.
        cmd[1:1] = ["--location", "--max-redirs", "5", "--proto-redir", "=https"]
    cmd.append(url)
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if p.returncode:
        fail(f"GitHub fetch failed rc={p.returncode}: {p.stderr.decode(errors='replace')[:500]}")
    return p.stdout


def api_json(path: str, token: str) -> dict:
    raw = curl_bytes(f"https://api.github.com/repos/{REPO}{path}", token)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON for {path}: {exc}")


def workflow_source(spec: RunSpec, token: str) -> str:
    path = spec.workflow_path.lstrip("/")
    payload = api_json(f"/contents/{path}?ref={spec.head_sha}", token)
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        fail(f"{spec.label}: workflow content response malformed")
    try:
        return base64.b64decode(payload["content"].replace("\n", "")).decode("utf-8")
    except Exception as exc:
        fail(f"{spec.label}: cannot decode pinned workflow source: {exc}")


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


def job_log(job_id: int, token: str) -> str:
    return curl_bytes(f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs", token, True).decode("utf-8", errors="replace")


def validate_run(spec: RunSpec, token: str) -> list[dict]:
    run = api_json(f"/actions/runs/{spec.run_id}", token)
    if run.get("id") != spec.run_id or run.get("head_sha") != spec.head_sha or run.get("path") != spec.workflow_path:
        fail(f"{spec.label}: public run identity mismatch")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        fail(f"{spec.label}: run not successful status={run.get('status')} conclusion={run.get('conclusion')}")
    validate_bindings(workflow_source(spec, token), spec.workflow_bindings, spec.label)
    return list_jobs(spec.run_id, token)


def single_success_job(jobs: list[dict], name: str, label: str) -> dict:
    hits = [j for j in jobs if j.get("name") == name]
    if len(hits) != 1:
        fail(f"{label}: expected one job {name!r}, got {len(hits)}")
    j = hits[0]
    if j.get("status") != "completed" or j.get("conclusion") != "success":
        fail(f"{label}: required job is not successful")
    return j


def validate_real(token: str) -> None:
    validate_partition(FAST190, SLOW12, PROFILE39)
    print("LAS_CANONICAL_CURRENT_203_COVERAGE_PARTITION=PASS")

    fast_jobs = validate_run(RUNS["fast190"], token)
    aggregate_id = validate_fast_jobs(fast_jobs)
    require_actual_marker(job_log(aggregate_id, token), "LAS_CURRENT_FAST190_ACCEPTANCE=PASS")
    print("LAS_CANONICAL_CURRENT_203_FAST190=PASS")

    for key in ("pre_tlc", "formal_equivalence", "slow12_applicability", "slow12_audit", "profile39"):
        spec = RUNS[key]
        jobs = validate_run(spec, token)
        if spec.job_name is None:
            fail(f"{key}: internal verifier configuration missing job name")
        job = single_success_job(jobs, spec.job_name, spec.label)
        log = job_log(int(job["id"]), token)
        for marker in spec.markers:
            require_actual_marker(log, marker)
        print(f"LAS_CANONICAL_CURRENT_203_{key.upper()}=PASS")

    print(f"LAS_CANONICAL_CURRENT_203_PRIVATE_SNAPSHOT_PROOF={CURRENT_SNAPSHOT_PROOF}")
    print(f"LAS_CANONICAL_CURRENT_203_PRIVATE_TREE_PROOF={CURRENT_TREE_PROOF}")
    print("LAS_CANONICAL_CURRENT_203_PROFILE_COUNT=203")
    print("LAS_CANONICAL_CURRENT_203_ACCEPTANCE=PASS")


def expect_failure(fn, label: str) -> None:
    try:
        fn()
    except EvidenceError:
        return
    raise AssertionError(f"mutation unexpectedly passed: {label}")


def self_test() -> None:
    validate_partition(FAST190, SLOW12, PROFILE39)
    expect_failure(lambda: validate_partition(set(FAST190)-{0}, SLOW12, PROFILE39), "missing ordinal")
    expect_failure(lambda: validate_partition(set(FAST190)|{2}, SLOW12, PROFILE39), "overlap")
    expect_failure(lambda: validate_partition(FAST190, set(SLOW12)|{203}, PROFILE39), "extra ordinal")
    expect_failure(lambda: validate_partition(FAST190, SLOW12, {38}), "wrong p39")

    sample = "2026-10-08T00:00:00.0000000Z LAS_SAMPLE=PASS\n"
    require_actual_marker(sample, "LAS_SAMPLE=PASS")
    expect_failure(lambda: require_actual_marker(sample, "LAS_SAMPLE=FAIL"), "wrong marker")
    validate_bindings("A\nB\n", ("A", "B"), "sample")
    expect_failure(lambda: validate_bindings("A\n", ("A", "B"), "sample"), "missing workflow binding")

    jobs = [{"id": n+1, "name": f"tlc_fast ({idx})", "status": "completed", "conclusion": "success"}
            for n, idx in enumerate(sorted(FAST190))]
    jobs.append({"id": 9999, "name": "aggregate", "status": "completed", "conclusion": "success"})
    if validate_fast_jobs(jobs) != 9999:
        raise AssertionError("aggregate id mismatch")
    expect_failure(lambda: validate_fast_jobs(jobs[:-2] + jobs[-1:]), "missing fast job")
    expect_failure(lambda: validate_fast_jobs(jobs + [dict(jobs[0])]), "duplicate fast job")
    failed = [dict(j) for j in jobs]; failed[0]["conclusion"] = "failure"
    expect_failure(lambda: validate_fast_jobs(failed), "failed fast job")
    print("LAS_CANONICAL_CURRENT_203_ACCEPTANCE_V2_SELF_TEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--token", default=os.environ.get("GH_TOKEN", ""))
    ns = ap.parse_args()
    try:
        if ns.self_test:
            self_test()
        else:
            if not ns.token:
                fail("GitHub token required")
            validate_real(ns.token)
        return 0
    except (EvidenceError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
