#!/usr/bin/env python3
"""Audit the frozen exact resumable TLC lineage from GitHub Actions evidence.

This script is intentionally independent of the active acceptance workflow. It reads
GitHub's run/job/log evidence, proves that every target run used the frozen public runner
revision, reconstructs each canonical profile's completed segment chain, and reports the
current terminal/checkpoint frontier without trusting hand-written status notes.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

TARGET_HEAD_SHA = "f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb"
EXPECTED_PROFILES = (2, 28, 29, 36, 110, 115, 133, 145, 156, 157, 168, 172)
CONTINUATION_PATH = ".github/workflows/private-assurance-slow-tlc-continuation.yml"
BOOTSTRAP_PATH = ".github/workflows/current-exact-resumable-frozen-bootstrap.yml"
REUSABLE_PATH = ".github/workflows/_private-assurance-tlc-continuation-slice.yml"

INDEX_RE = re.compile(r"LAS_CURRENT_RESUME_INDEX=(\d+)")
SEGMENT_RE = re.compile(r"LAS_CURRENT_RESUME_SEGMENT=(\d+)")
RESULT_RE = re.compile(r"LAS_CURRENT_RESUME_RESULT=(PASS|SLICE_CHECKPOINT|FAIL_CLOSED|FAIL)")
BOOTSTRAP_INDEX_RE = re.compile(r"bootstrap \((\d+)\) / slice")


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class SegmentEvidence:
    profile: int
    segment: int
    result: str
    run_id: int
    job_id: int
    run_number: int
    created_at: str


def fail(message: str) -> None:
    raise AuditError(message)


def request_bytes(url: str, token: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "living-assurance-lineage-auditor",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"GitHub API HTTP {exc.code} for {url}: {body[:500]}")
    except urllib.error.URLError as exc:
        fail(f"GitHub API request failed for {url}: {exc}")


def request_json(url: str, token: str) -> dict:
    try:
        return json.loads(request_bytes(url, token).decode("utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON from {url}: {exc}")


def paginate_runs(api: str, repo: str, token: str) -> list[dict]:
    runs: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode(
            {"head_sha": TARGET_HEAD_SHA, "per_page": 100, "page": page}
        )
        data = request_json(f"{api}/repos/{repo}/actions/runs?{query}", token)
        batch = data.get("workflow_runs") or []
        if not isinstance(batch, list):
            fail("workflow_runs is not a list")
        runs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 20:
            fail("unexpectedly large exact-run history")
    return runs


def fetch_jobs(api: str, repo: str, token: str, run_id: int) -> list[dict]:
    data = request_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100", token
    )
    jobs = data.get("jobs") or []
    if not isinstance(jobs, list):
        fail(f"jobs is not a list for run {run_id}")
    return jobs


def fetch_job_log(api: str, repo: str, token: str, job_id: int) -> str:
    raw = request_bytes(f"{api}/repos/{repo}/actions/jobs/{job_id}/logs", token)
    return raw.decode("utf-8-sig", errors="replace")


def validate_runner_binding(repo: str, run: dict) -> None:
    run_id = run.get("id")
    if run.get("head_sha") != TARGET_HEAD_SHA:
        fail(f"run {run_id} head SHA drifted")
    if run.get("path") not in {CONTINUATION_PATH, BOOTSTRAP_PATH}:
        fail(f"run {run_id} has unexpected workflow path: {run.get('path')!r}")
    expected = f"{repo}/{REUSABLE_PATH}@{TARGET_HEAD_SHA}"
    refs = run.get("referenced_workflows") or []
    matches = [
        item
        for item in refs
        if item.get("sha") == TARGET_HEAD_SHA and item.get("path") == expected
    ]
    if len(matches) != 1 or len(refs) != 1:
        fail(
            f"run {run_id} does not bind exactly one frozen reusable workflow: {refs!r}"
        )


def parse_completed_job(run: dict, job: dict, log: str) -> SegmentEvidence | None:
    result_matches = RESULT_RE.findall(log)
    if not result_matches:
        return None
    result = result_matches[-1]

    index_matches = INDEX_RE.findall(log)
    segment_matches = SEGMENT_RE.findall(log)
    if index_matches and segment_matches:
        profile = int(index_matches[-1])
        segment = int(segment_matches[-1])
    else:
        name = str(job.get("name") or "")
        bootstrap = BOOTSTRAP_INDEX_RE.fullmatch(name)
        if not bootstrap:
            fail(
                f"completed TLC job {job.get('id')} has result but no index/segment markers"
            )
        profile = int(bootstrap.group(1))
        segment = 1

    return SegmentEvidence(
        profile=profile,
        segment=segment,
        result=result,
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        run_number=int(run.get("run_number") or 0),
        created_at=str(run.get("created_at") or ""),
    )


def audit() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not repo or not token:
        fail("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    all_exact = paginate_runs(api, repo, token)
    target_runs = [
        run for run in all_exact if run.get("path") in {CONTINUATION_PATH, BOOTSTRAP_PATH}
    ]
    if not target_runs:
        fail("no exact frozen resumable runs found")

    for run in target_runs:
        validate_runner_binding(repo, run)

    bootstrap_runs = [run for run in target_runs if run.get("path") == BOOTSTRAP_PATH]
    if len(bootstrap_runs) != 1:
        fail(f"expected one frozen bootstrap run, found {len(bootstrap_runs)}")
    bootstrap = bootstrap_runs[0]
    if bootstrap.get("event") != "push" or bootstrap.get("conclusion") != "success":
        fail("frozen bootstrap run is not a successful push execution")

    evidence: dict[int, dict[int, SegmentEvidence]] = {
        profile: {} for profile in EXPECTED_PROFILES
    }
    open_runs = 0
    failed_runs: list[tuple[int, str | None]] = []

    for run in target_runs:
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status != "completed":
            open_runs += 1
            continue
        if conclusion != "success":
            failed_runs.append((int(run["id"]), conclusion))
            continue

        for job in fetch_jobs(api, repo, token, int(run["id"])):
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                continue
            name = str(job.get("name") or "")
            if name != "continuation / slice" and not BOOTSTRAP_INDEX_RE.fullmatch(name):
                continue
            log = fetch_job_log(api, repo, token, int(job["id"]))
            item = parse_completed_job(run, job, log)
            if item is None:
                continue
            if item.profile not in evidence:
                fail(f"unexpected canonical profile in exact lineage: {item.profile}")
            existing = evidence[item.profile].get(item.segment)
            if existing and existing != item:
                fail(
                    f"duplicate conflicting evidence for profile {item.profile} segment {item.segment}"
                )
            evidence[item.profile][item.segment] = item

    if failed_runs:
        fail(f"non-success exact resumable runs present: {failed_runs}")

    terminal = 0
    checkpointed = 0
    print(f"LAS_RESUMABLE_LINEAGE_EXACT_RUN_COUNT={len(target_runs)}")
    print(f"LAS_RESUMABLE_LINEAGE_OPEN_RUN_COUNT={open_runs}")
    for profile in EXPECTED_PROFILES:
        segments = evidence[profile]
        if not segments:
            fail(f"profile {profile} has no completed segment evidence")
        ordered = sorted(segments)
        expected = list(range(1, ordered[-1] + 1))
        if ordered != expected:
            fail(
                f"profile {profile} segment chain is non-contiguous: actual={ordered}, expected={expected}"
            )
        latest = segments[ordered[-1]]
        if any(item.result.startswith("FAIL") for item in segments.values()):
            fail(f"profile {profile} contains fail-closed/fail evidence")
        if latest.result == "PASS":
            terminal += 1
            state = "PASS"
        elif latest.result == "SLICE_CHECKPOINT":
            checkpointed += 1
            state = f"CHECKPOINT_NEXT_{latest.segment + 1}"
        else:
            fail(f"profile {profile} latest result is unexpected: {latest.result}")
        print(
            "LAS_RESUMABLE_PROFILE="
            f"{profile};LAST_COMPLETED_SEGMENT={latest.segment};STATE={state};"
            f"RUN_ID={latest.run_id};JOB_ID={latest.job_id}"
        )

    print(f"LAS_RESUMABLE_LINEAGE_TERMINAL_PROFILE_COUNT={terminal}")
    print(f"LAS_RESUMABLE_LINEAGE_CHECKPOINT_PROFILE_COUNT={checkpointed}")
    if terminal + checkpointed != len(EXPECTED_PROFILES):
        fail("profile accounting mismatch")
    if open_runs > checkpointed:
        fail(
            f"more open exact runs ({open_runs}) than checkpointed profiles ({checkpointed})"
        )
    print("LAS_RESUMABLE_LINEAGE_RUNNER_IDENTITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_SEGMENT_CONTIGUITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except AuditError as exc:
        print(f"LAS_RESUMABLE_LINEAGE_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
