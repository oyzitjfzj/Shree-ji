#!/usr/bin/env python3
"""Mechanically audit the frozen exact 203-profile baseline acceptance run.

The baseline run stopped because ten long-running profiles exceeded the single-run window.
Two additional profiles (133 and 145) were later included in the conservative resumable
set even though they had already completed successfully here.  This auditor proves the
immutable workflow binding, exact private candidate proofs, pre-TLC success, and exact
baseline set algebra from GitHub's job evidence rather than from a hand-written handoff.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

RUN_ID = 37559465092
RUN_HEAD_SHA = "a18f409ccca3178d50ce8d5485480ec8a4b2a50c"
WORKFLOW_PATH = ".github/workflows/private-current-exact-canonical-202-minus39.yml"
WORKFLOW_BLOB = "cf42e3281b6c50d9cc2ad5861709d89b451162a2"
EXPECTED_PRIVATE_SNAPSHOT_PROOF = "b5112adc429935d9024eb5805c9c49dd2c0f2cb161849cc987f7ba20af212f5c"
EXPECTED_PRIVATE_TREE_PROOF = "07b34736f34510f45a7cf6200057da51df415958c1f04281a583e87e4743fe97"
EXPECTED_VERIFIER_BLOB = "8ea6dbe77db10592baf8f56c9719626c36687f9a"
EXPECTED_PROFILE39_RUNNER_BLOB = "39475a3fd64dcac34998f9eb947cd3acf7d9d653"
EXPECTED_PROFILE_COUNT = 203
BASELINE_DEFERRED = frozenset({2, 28, 29, 36, 110, 115, 156, 157, 168, 172})
CONSERVATIVE_RESUMABLE = frozenset(
    {2, 28, 29, 36, 110, 115, 133, 145, 156, 157, 168, 172}
)
REDUNDANT_REVERIFY = CONSERVATIVE_RESUMABLE - BASELINE_DEFERRED
TLC_NAME = re.compile(r"tlc \((\d+)\)")


class AuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AuditError(message)


def headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "living-assurance-baseline-auditor",
    }


def get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers=headers(token))
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"GitHub API HTTP {exc.code} for {url}: {body[:500]}")
    except urllib.error.URLError as exc:
        fail(f"GitHub API request failed for {url}: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON from {url}: {exc}")


def fetch_all_jobs(api: str, repo: str, token: str) -> list[dict]:
    jobs: list[dict] = []
    page = 1
    while True:
        data = get_json(
            f"{api}/repos/{repo}/actions/runs/{RUN_ID}/jobs?per_page=100&page={page}",
            token,
        )
        batch = data.get("jobs") or []
        if not isinstance(batch, list):
            fail("jobs payload is not a list")
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 10:
            fail("unexpectedly large baseline job set")
    return jobs


def verify_workflow_source(api: str, repo: str, token: str) -> None:
    quoted = urllib.parse.quote(WORKFLOW_PATH, safe="/")
    data = get_json(
        f"{api}/repos/{repo}/contents/{quoted}?ref={RUN_HEAD_SHA}", token
    )
    if data.get("sha") != WORKFLOW_BLOB:
        fail(
            f"baseline workflow blob mismatch: expected={WORKFLOW_BLOB} actual={data.get('sha')}"
        )
    if data.get("encoding") != "base64":
        fail("baseline workflow content is not base64 encoded")
    try:
        text = base64.b64decode(data.get("content") or "", validate=False).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        fail(f"unable to decode baseline workflow source: {exc}")

    required = (
        f"EXPECTED_PRIVATE_SNAPSHOT_PROOF: {EXPECTED_PRIVATE_SNAPSHOT_PROOF}",
        f"EXPECTED_PRIVATE_TREE_PROOF: {EXPECTED_PRIVATE_TREE_PROOF}",
        f"EXPECTED_VERIFIER_BLOB: {EXPECTED_VERIFIER_BLOB}",
        f"EXPECTED_PROFILE39_RUNNER_BLOB: {EXPECTED_PROFILE39_RUNNER_BLOB}",
        'EXPECTED_TLC_PROFILE_COUNT: "203"',
        'TLC_SHARD_COUNT: "203"',
        'test "$selected" -eq 1',
        'echo "LAS_CURRENT_203_SHARD_RESULT=PASS"',
    )
    for needle in required:
        if needle not in text:
            fail(f"baseline workflow lost required exact binding: {needle}")

    matrix = re.search(r"matrix:\s*\n\s*shard:\s*\[([^\]]+)\]", text)
    if not matrix:
        fail("unable to recover canonical shard matrix")
    try:
        shards = [int(x.strip()) for x in matrix.group(1).split(",") if x.strip()]
    except ValueError as exc:
        fail(f"invalid canonical shard matrix: {exc}")
    if shards != list(range(EXPECTED_PROFILE_COUNT)):
        fail("baseline matrix is not exact 0..202 one-profile-per-shard coverage")


def step_conclusion(job: dict, step_name: str) -> str | None:
    for step in job.get("steps") or []:
        if step.get("name") == step_name:
            return step.get("conclusion")
    return None


def audit() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not repo or not token:
        fail("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    run = get_json(f"{api}/repos/{repo}/actions/runs/{RUN_ID}", token)
    if run.get("head_sha") != RUN_HEAD_SHA:
        fail("baseline run head SHA mismatch")
    if run.get("path") != WORKFLOW_PATH:
        fail("baseline run workflow path mismatch")
    if run.get("event") != "push" or run.get("run_attempt") != 1:
        fail("baseline run event/attempt contract changed")
    if run.get("status") != "completed" or run.get("conclusion") != "cancelled":
        fail("baseline run is not the expected completed/cancelled execution")

    verify_workflow_source(api, repo, token)
    jobs = fetch_all_jobs(api, repo, token)
    if len(jobs) != EXPECTED_PROFILE_COUNT + 2:
        fail(f"expected 205 baseline jobs, found {len(jobs)}")

    pre = [job for job in jobs if job.get("name") == "pre_tlc"]
    aggregate = [job for job in jobs if job.get("name") == "aggregate"]
    if len(pre) != 1 or len(aggregate) != 1:
        fail("baseline pre_tlc/aggregate job cardinality mismatch")
    if pre[0].get("conclusion") != "success":
        fail("baseline pre_tlc did not succeed")
    if step_conclusion(pre[0], "Recover exact private materialized revision") != "success":
        fail("baseline pre_tlc exact private recovery did not succeed")
    if step_conclusion(pre[0], "Run exact canonical pre-TLC verifier stage") != "success":
        fail("baseline exact canonical pre-TLC verifier did not succeed")

    profiles: dict[int, dict] = {}
    for job in jobs:
        match = TLC_NAME.fullmatch(str(job.get("name") or ""))
        if not match:
            continue
        index = int(match.group(1))
        if index in profiles:
            fail(f"duplicate baseline TLC job for profile {index}")
        profiles[index] = job

    if set(profiles) != set(range(EXPECTED_PROFILE_COUNT)):
        missing = sorted(set(range(EXPECTED_PROFILE_COUNT)) - set(profiles))
        extra = sorted(set(profiles) - set(range(EXPECTED_PROFILE_COUNT))
        fail(f"baseline TLC index coverage mismatch: missing={missing} extra={extra}")

    success: set[int] = set()
    cancelled: set[int] = set()
    other: dict[int, str | None] = {}
    for index, job in profiles.items():
        conclusion = job.get("conclusion")
        recovery = step_conclusion(job, "Recover exact private materialized revision")
        shard = step_conclusion(job, "Run exact canonical TLC shard")
        if conclusion == "success":
            if recovery != "success" or shard != "success":
                fail(f"profile {index} success lacks successful recovery/shard steps")
            success.add(index)
        elif conclusion == "cancelled":
            if recovery != "success" or shard != "cancelled":
                fail(f"profile {index} cancellation is not a long-running TLC cancellation")
            cancelled.add(index)
        else:
            other[index] = conclusion

    if other:
        fail(f"baseline contains non-success/non-cancelled TLC outcomes: {other}")
    if cancelled != set(BASELINE_DEFERRED):
        fail(
            f"baseline deferred set mismatch: expected={sorted(BASELINE_DEFERRED)} actual={sorted(cancelled)}"
        )
    expected_success = set(range(EXPECTED_PROFILE_COUNT)) - set(BASELINE_DEFERRED)
    if success != expected_success:
        fail("baseline success set is not exactly canonical minus deferred-10")
    if not REDUNDANT_REVERIFY <= success:
        fail("conservative resumable extras were not already successful in baseline")
    if REDUNDANT_REVERIFY != {133, 145}:
        fail(f"unexpected redundant reverify set: {sorted(REDUNDANT_REVERIFY)}")

    print(f"LAS_CURRENT_203_BASELINE_RUN_ID={RUN_ID}")
    print(f"LAS_CURRENT_203_BASELINE_WORKFLOW_SHA={RUN_HEAD_SHA}")
    print(f"LAS_CURRENT_203_BASELINE_WORKFLOW_BLOB={WORKFLOW_BLOB}")
    print(f"LAS_CURRENT_203_BASELINE_TOTAL_PROFILE_COUNT={len(profiles)}")
    print(f"LAS_CURRENT_203_BASELINE_SUCCESS_PROFILE_COUNT={len(success)}")
    print(f"LAS_CURRENT_203_BASELINE_DEFERRED_PROFILE_COUNT={len(cancelled)}")
    print("LAS_CURRENT_203_BASELINE_DEFERRED_PROFILES=" + ",".join(map(str, sorted(cancelled))))
    print("LAS_CURRENT_203_BASELINE_REDUNDANT_REVERIFY_PROFILES=" + ",".join(map(str, sorted(REDUNDANT_REVERIFY))))
    print("LAS_CURRENT_203_BASELINE_EXACT_PRIVATE_BINDING=PASS")
    print("LAS_CURRENT_203_BASELINE_PRE_TLC=PASS")
    print("LAS_CURRENT_203_BASELINE_SET_ALGEBRA=PASS")
    print("LAS_CURRENT_203_BASELINE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except AuditError as exc:
        print(f"LAS_CURRENT_203_BASELINE_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
