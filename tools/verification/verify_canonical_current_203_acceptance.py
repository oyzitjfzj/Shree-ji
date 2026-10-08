#!/usr/bin/env python3
"""Public fail-closed acceptance verifier for the exact current 203-profile closure.

This verifier consumes only public GitHub Actions evidence. Private source identities are
represented by the opaque proofs already emitted/bound by those public workflows.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable

REPO = "oyzitjfzj/Shree-ji"
CURRENT_PRIVATE_SNAPSHOT_PROOF = "d893f63ec5c6e07f1541691204a7e701ea7e435df45c3877ba4ffe1fbebb994f"
CURRENT_PRIVATE_TREE_PROOF = "217826cd728dfe665a6aa3b3f53d961c7a56963ad44e9b1f5a966e1bc9975b1b"
SLOW12_MANIFEST_SHA256 = "bc739bbb46a25e97531297ac4fd4dbf9e1c8264ce7f7e2c44f5861ef5687fa85"
PROFILE39_GENERATED = 16_789_249
PROFILE39_DISTINCT = 7_063_296

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
    job_name: str | None = None
    markers: tuple[str, ...] = ()


RUNS = {
    "fast190": RunSpec(
        "fast190",
        37724331030,
        "2ca200235d9e94b5a7d438e3565c1cfc92b356bc",
        ".github/workflows/canonical-exact-current-fast190.yml",
    ),
    "pre_tlc": RunSpec(
        "pre_tlc",
        37726967857,
        "7f37db59c890d5d49e0d104578ad8e62114e0f5a",
        ".github/workflows/canonical-exact-current-pre-tlc.yml",
        "pre_tlc",
        (
            "LAS_CURRENT_PRE_TLC_EXACT_RECOVERY=PASS",
            "LAS_CURRENT_PRE_TLC_ISOLATION=PASS",
            "LAS_CURRENT_PRE_TLC_PYTHON_CACHE_RELOCATION=PASS",
            "LAS_CURRENT_PRE_TLC_TLA_SHA256_PIN=PASS",
            "LAS_CURRENT_PRE_TLC_RESULT=PASS",
        ),
    ),
    "formal_equivalence": RunSpec(
        "formal_equivalence",
        37728288021,
        "18b734f2cd7a07f8cfdd83afdf56567e896ed856",
        ".github/workflows/canonical-formal-equivalence.yml",
        "prove",
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
    ),
    "slow12_applicability": RunSpec(
        "slow12_applicability",
        37728914109,
        "482c0af1d99975a356c7b8fa95e9241343bd8e77",
        ".github/workflows/canonical-slow12-applicability.yml",
        "prove",
        (
            "LAS_SLOW12_EXACT_RECOVERY=PASS",
            "LAS_SLOW12_ALLOWED_DELTA=PASS",
            "LAS_SLOW12_CANONICAL_ENGINE_EQUIVALENCE=PASS",
            "LAS_SLOW12_SPEC_TREE_EQUIVALENCE=PASS",
            "LAS_SLOW12_CANONICAL_MAP_EQUIVALENCE=PASS",
            "LAS_SLOW12_PROFILE_COUNT=12",
            f"LAS_SLOW12_INPUT_MANIFEST_SHA256={SLOW12_MANIFEST_SHA256}",
            "LAS_SLOW12_INPUT_BYTES_EQUIVALENCE=PASS",
            "LAS_SLOW12_TLA_TOOLCHAIN=PASS",
            "LAS_SLOW12_NEGATIVE_INPUT_DRIFT=PASS",
            "LAS_SLOW12_APPLICABILITY=PASS",
        ),
    ),
    "slow12_audit": RunSpec(
        "slow12_audit",
        37729334979,
        "8ee0944f271f92cc803ed54448d386fcc8181cc0",
        ".github/workflows/canonical-slow12-chain-audit.yml",
        "audit",
        (
            "LAS_SLOW12_CHAIN_EVIDENCE_COLLECTION=PASS",
            "LAS_SLOW12_CHAIN_TERMINAL_PASS_COUNT=12",
            "LAS_SLOW12_CHAIN_ACTIVE_OR_PENDING_COUNT=0",
            "LAS_SLOW12_CHAIN_INTEGRITY=PASS",
            "LAS_SLOW12_CHAIN_AUDIT=PASS",
        ),
    ),
    "profile39": RunSpec(
        "profile39",
        37729246987,
        "363c51310872053671c3a67bae3932032d9c120b",
        ".github/workflows/canonical-profile39-current.yml",
        "validate",
        (
            "LAS_CURRENT_PROFILE39_EXACT_RECOVERY=PASS",
            "LAS_CURRENT_PROFILE39_TOOLCHAIN=PASS",
            "LAS_CURRENT_PROFILE39_NEGATIVE_TOOLCHAIN=PASS",
            "LAS_CURRENT_PROFILE39_NEGATIVE_INPUT_DRIFT=PASS",
            f"LAS_CURRENT_PROFILE39_TRIPLE_FP_STATE_COUNTS={PROFILE39_GENERATED},{PROFILE39_DISTINCT}",
            "LAS_CURRENT_PROFILE39_TRIPLE_FP_STATESET_CONSISTENCY=PASS",
            "LAS_CURRENT_PROFILE39_FULL_VALIDATION=PASS",
        ),
    ),
}


def fail(message: str) -> None:
    raise EvidenceError(message)


def validate_partition(fast: Iterable[int], slow: Iterable[int], profile39: Iterable[int]) -> None:
    groups = [set(fast), set(slow), set(profile39)]
    if len(groups[0]) != 190:
        fail(f"fast coverage cardinality != 190: {len(groups[0])}")
    if len(groups[1]) != 12:
        fail(f"slow coverage cardinality != 12: {len(groups[1])}")
    if groups[2] != {39}:
        fail(f"profile39 coverage is not exactly {{39}}: {sorted(groups[2])}")
    if groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]:
        fail("coverage sets overlap")
    union = groups[0] | groups[1] | groups[2]
    if union != set(ALL203):
        missing = sorted(set(ALL203) - union)
        extra = sorted(union - set(ALL203))
        fail(f"coverage union mismatch missing={missing} extra={extra}")


def require_actual_marker(log: str, marker: str) -> None:
    # GitHub job logs prefix actual stdout/stderr with an ISO timestamp ending in Z.
    # Echo commands in the shell trace contain ANSI control sequences and therefore do
    # not satisfy this exact output-line pattern.
    pat = re.compile(r"(?m)^.*Z " + re.escape(marker) + r"\r?$")
    if not pat.search(log):
        fail(f"required marker missing: {marker}")


def validate_fast_jobs(jobs: list[dict]) -> int:
    found: dict[int, dict] = {}
    aggregate = []
    for job in jobs:
        name = str(job.get("name", ""))
        m = re.fullmatch(r"tlc_fast \((\d+)\)", name)
        if m:
            ordinal = int(m.group(1))
            if ordinal in found:
                fail(f"duplicate fast ordinal job: {ordinal}")
            found[ordinal] = job
        elif name == "aggregate":
            aggregate.append(job)
    if set(found) != set(FAST190):
        fail(
            f"fast job coverage mismatch missing={sorted(set(FAST190)-set(found))} "
            f"extra={sorted(set(found)-set(FAST190))}"
        )
    for ordinal, job in found.items():
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            fail(f"fast ordinal not successful: {ordinal}")
    if len(aggregate) != 1:
        fail(f"expected one fast aggregate job, got {len(aggregate)}")
    if aggregate[0].get("status") != "completed" or aggregate[0].get("conclusion") != "success":
        fail("fast aggregate job is not successful")
    return int(aggregate[0]["id"])


def curl_bytes(url: str, token: str, follow: bool = False) -> bytes:
    cmd = [
        "curl", "--proto", "=https", "--tlsv1.2", "--fail-with-body", "--retry", "3",
        "--silent", "--show-error", "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28", "-H", f"Authorization: Bearer {token}",
    ]
    if follow:
        # curl intentionally strips Authorization on a cross-host redirect unless
        # --location-trusted is used. We never use --location-trusted here.
        cmd[1:1] = ["--location", "--max-redirs", "5", "--proto-redir", "=https"]
    cmd.append(url)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        fail(f"GitHub evidence fetch failed rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:500]}")
    return proc.stdout


def api_json(path: str, token: str) -> dict:
    data = curl_bytes(f"https://api.github.com/repos/{REPO}{path}", token)
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON for {path}: {exc}")


def list_jobs(run_id: int, token: str) -> list[dict]:
    jobs: list[dict] = []
    page = 1
    while True:
        payload = api_json(f"/actions/runs/{run_id}/jobs?per_page=100&page={page}", token)
        rows = payload.get("jobs")
        if not isinstance(rows, list):
            fail(f"jobs response malformed for run {run_id}")
        jobs.extend(rows)
        if len(rows) < 100:
            break
        page += 1
        if page > 10:
            fail(f"unexpected job pagination depth for run {run_id}")
    return jobs


def job_log(job_id: int, token: str) -> str:
    raw = curl_bytes(f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs", token, follow=True)
    return raw.decode("utf-8", errors="replace")


def validate_run(spec: RunSpec, token: str) -> tuple[dict, list[dict]]:
    run = api_json(f"/actions/runs/{spec.run_id}", token)
    if run.get("id") != spec.run_id:
        fail(f"run id mismatch for {spec.label}")
    if run.get("head_sha") != spec.head_sha:
        fail(f"public head SHA mismatch for {spec.label}")
    if run.get("path") != spec.workflow_path:
        fail(f"workflow path mismatch for {spec.label}: {run.get('path')!r}")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        fail(f"run not successful for {spec.label}: status={run.get('status')} conclusion={run.get('conclusion')}")
    jobs = list_jobs(spec.run_id, token)
    return run, jobs


def require_single_job(jobs: list[dict], name: str, label: str) -> dict:
    hits = [j for j in jobs if j.get("name") == name]
    if len(hits) != 1:
        fail(f"{label}: expected one job named {name!r}, got {len(hits)}")
    job = hits[0]
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        fail(f"{label}: required job is not successful")
    return job


def validate_real(token: str) -> None:
    validate_partition(FAST190, SLOW12, PROFILE39)
    print("LAS_CANONICAL_CURRENT_203_COVERAGE_PARTITION=PASS")

    # Fast 190: exact matrix coverage + aggregate acceptance.
    _, fast_jobs = validate_run(RUNS["fast190"], token)
    aggregate_id = validate_fast_jobs(fast_jobs)
    require_actual_marker(job_log(aggregate_id, token), "LAS_CURRENT_FAST190_ACCEPTANCE=PASS")
    print("LAS_CANONICAL_CURRENT_203_FAST190=PASS")

    # Every other evidence leg is single-job and marker-bound to a pinned public commit.
    for key in ("pre_tlc", "formal_equivalence", "slow12_applicability", "slow12_audit", "profile39"):
        spec = RUNS[key]
        _, jobs = validate_run(spec, token)
        assert spec.job_name is not None
        job = require_single_job(jobs, spec.job_name, spec.label)
        log = job_log(int(job["id"]), token)
        for marker in spec.markers:
            require_actual_marker(log, marker)
        print(f"LAS_CANONICAL_CURRENT_203_{key.upper()}=PASS")

    print(f"LAS_CANONICAL_CURRENT_203_PRIVATE_SNAPSHOT_PROOF={CURRENT_PRIVATE_SNAPSHOT_PROOF}")
    print(f"LAS_CANONICAL_CURRENT_203_PRIVATE_TREE_PROOF={CURRENT_PRIVATE_TREE_PROOF}")
    print("LAS_CANONICAL_CURRENT_203_PROFILE_COUNT=203")
    print("LAS_CANONICAL_CURRENT_203_ACCEPTANCE=PASS")


def expect_failure(fn, label: str) -> None:
    try:
        fn()
    except EvidenceError:
        return
    raise AssertionError(f"self-test mutation unexpectedly passed: {label}")


def self_test() -> None:
    validate_partition(FAST190, SLOW12, PROFILE39)
    expect_failure(lambda: validate_partition(set(FAST190) - {0}, SLOW12, PROFILE39), "missing fast ordinal")
    expect_failure(lambda: validate_partition(set(FAST190) | {2}, SLOW12, PROFILE39), "coverage overlap")
    expect_failure(lambda: validate_partition(FAST190, set(SLOW12) | {203}, PROFILE39), "extra ordinal")
    expect_failure(lambda: validate_partition(FAST190, SLOW12, {38}), "wrong profile39 ordinal")

    good_log = (
        "2026-10-08T00:00:00.0000000Z LAS_SELFTEST_ALPHA=PASS\n"
        "2026-10-08T00:00:01.0000000Z LAS_SELFTEST_BETA=12\n"
    )
    require_actual_marker(good_log, "LAS_SELFTEST_ALPHA=PASS")
    require_actual_marker(good_log, "LAS_SELFTEST_BETA=12")
    expect_failure(lambda: require_actual_marker(good_log, "LAS_SELFTEST_ALPHA=FAIL"), "wrong marker")

    jobs = [
        {"id": i + 1, "name": f"tlc_fast ({ordinal})", "status": "completed", "conclusion": "success"}
        for i, ordinal in enumerate(sorted(FAST190))
    ]
    jobs.append({"id": 9999, "name": "aggregate", "status": "completed", "conclusion": "success"})
    if validate_fast_jobs(jobs) != 9999:
        raise AssertionError("aggregate id mismatch")
    expect_failure(lambda: validate_fast_jobs(jobs[:-2] + jobs[-1:]), "missing fast job")
    duplicated = jobs + [dict(jobs[0])]
    expect_failure(lambda: validate_fast_jobs(duplicated), "duplicate fast job")
    failed = [dict(j) for j in jobs]
    failed[0]["conclusion"] = "failure"
    expect_failure(lambda: validate_fast_jobs(failed), "failed fast job")

    if len(FAST190) != 190 or len(SLOW12) != 12 or len(PROFILE39) != 1:
        raise AssertionError("coverage cardinality self-test failed")
    print("LAS_CANONICAL_CURRENT_203_ACCEPTANCE_SELF_TEST=PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--token", default=os.environ.get("GH_TOKEN", ""))
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            if not args.token:
                fail("GitHub token is required")
            validate_real(args.token)
        return 0
    except (EvidenceError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
