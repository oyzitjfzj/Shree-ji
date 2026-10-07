#!/usr/bin/env python3
"""Audit the frozen exact resumable TLC lineage from GitHub Actions evidence.

The auditor is read-only with respect to the acceptance lane. It proves the frozen
public runner identity, reconstructs successful canonical segment chains from job
logs, classifies failed attempts, and reports the current terminal/checkpoint
frontier without trusting hand-written status notes.
"""

from __future__ import annotations

import concurrent.futures
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

ACTUAL_INDEX_RE = re.compile(r"Z LAS_CURRENT_RESUME_INDEX=(\d+)\s*$", re.MULTILINE)
ACTUAL_SEGMENT_RE = re.compile(r"Z LAS_CURRENT_RESUME_SEGMENT=(\d+)\s*$", re.MULTILINE)
ACTUAL_RESULT_RE = re.compile(
    r"Z LAS_CURRENT_RESUME_RESULT=(PASS|SLICE_CHECKPOINT|FAIL_CLOSED|FAIL)\s*$",
    re.MULTILINE,
)
INPUT_INDEX_RE = re.compile(r"Z\s+index:\s+(\d+)\s*$", re.MULTILINE)
INPUT_SEGMENT_RE = re.compile(r"Z\s+segment:\s+(\d+)\s*$", re.MULTILINE)
BOOTSTRAP_INDEX_RE = re.compile(r"bootstrap \((\d+)\) / slice")
REDIRECT_CODES = {301, 302, 303, 307, 308}


class AuditError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Expose redirects so bearer credentials never cross origin boundaries."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class SegmentEvidence:
    profile: int
    segment: int
    result: str
    run_id: int
    job_id: int
    run_number: int
    created_at: str


@dataclass(frozen=True)
class IsolatedFailure:
    profile: int
    segment: int
    run_id: int
    job_id: int
    failure_class: str


def fail(message: str) -> None:
    raise AuditError(message)


def github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "living-assurance-lineage-auditor",
    }


def request_bytes(url: str, token: str) -> bytes:
    req = urllib.request.Request(url, headers=github_headers(token))
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


def request_github_redirect_target(url: str, token: str) -> str:
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers=github_headers(token))
    try:
        with opener.open(req, timeout=60) as response:
            if response.status not in REDIRECT_CODES:
                fail(f"expected redirect from GitHub log endpoint, got HTTP {response.status}")
            location = response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        if exc.code not in REDIRECT_CODES:
            body = exc.read().decode("utf-8", errors="replace")
            fail(f"GitHub log endpoint HTTP {exc.code} for {url}: {body[:500]}")
        location = exc.headers.get("Location")
    except urllib.error.URLError as exc:
        fail(f"GitHub log endpoint request failed for {url}: {exc}")

    if not location:
        fail("GitHub log endpoint redirect is missing Location")
    parsed = urllib.parse.urlparse(location)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"unsafe GitHub log redirect target: {location!r}")
    return location


def request_unsigned_https(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "living-assurance-lineage-auditor"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"signed log download HTTP {exc.code}: {body[:500]}")
    except urllib.error.URLError as exc:
        fail(f"signed log download failed: {exc}")


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
            return runs
        page += 1
        if page > 20:
            fail("unexpectedly large exact-run history")


def fetch_jobs(api: str, repo: str, token: str, run_id: int) -> list[dict]:
    data = request_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100", token
    )
    jobs = data.get("jobs") or []
    if not isinstance(jobs, list):
        fail(f"jobs is not a list for run {run_id}")
    return jobs


def fetch_job_log(api: str, repo: str, token: str, job_id: int) -> str:
    endpoint = f"{api}/repos/{repo}/actions/jobs/{job_id}/logs"
    signed_url = request_github_redirect_target(endpoint, token)
    return request_unsigned_https(signed_url).decode("utf-8-sig", errors="replace")


def validate_runner_binding(repo: str, run: dict) -> None:
    run_id = run.get("id")
    if run.get("head_sha") != TARGET_HEAD_SHA:
        fail(f"run {run_id} head SHA drifted")
    if run.get("path") not in {CONTINUATION_PATH, BOOTSTRAP_PATH}:
        fail(f"run {run_id} has unexpected workflow path: {run.get('path')!r}")
    expected = f"{repo}/{REUSABLE_PATH}@{TARGET_HEAD_SHA}"
    refs = run.get("referenced_workflows") or []
    if len(refs) != 1:
        fail(f"run {run_id} does not reference exactly one reusable workflow: {refs!r}")
    item = refs[0]
    if item.get("sha") != TARGET_HEAD_SHA or item.get("path") != expected:
        fail(f"run {run_id} reusable workflow identity drifted: {refs!r}")


def parse_successful_job(run: dict, job: dict, log: str) -> SegmentEvidence | None:
    result_matches = ACTUAL_RESULT_RE.findall(log)
    if not result_matches:
        return None
    index_matches = ACTUAL_INDEX_RE.findall(log)
    segment_matches = ACTUAL_SEGMENT_RE.findall(log)
    if index_matches and segment_matches:
        profile = int(index_matches[-1])
        segment = int(segment_matches[-1])
    else:
        name = str(job.get("name") or "")
        bootstrap = BOOTSTRAP_INDEX_RE.fullmatch(name)
        if not bootstrap:
            fail(f"completed TLC job {job.get('id')} has result but no index/segment markers")
        profile = int(bootstrap.group(1))
        segment = 1
    return SegmentEvidence(
        profile=profile,
        segment=segment,
        result=result_matches[-1],
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        run_number=int(run.get("run_number") or 0),
        created_at=str(run.get("created_at") or ""),
    )


def process_successful_run(
    api: str, repo: str, token: str, run: dict
) -> list[SegmentEvidence]:
    found: list[SegmentEvidence] = []
    for job in fetch_jobs(api, repo, token, int(run["id"])):
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            continue
        name = str(job.get("name") or "")
        if name != "continuation / slice" and not BOOTSTRAP_INDEX_RE.fullmatch(name):
            continue
        item = parse_successful_job(
            run, job, fetch_job_log(api, repo, token, int(job["id"]))
        )
        if item is not None:
            found.append(item)
    return found


def classify_failed_run(
    api: str, repo: str, token: str, run: dict
) -> IsolatedFailure:
    jobs = fetch_jobs(api, repo, token, int(run["id"]))
    slice_jobs = [job for job in jobs if job.get("name") == "continuation / slice"]
    if len(slice_jobs) != 1:
        fail(f"failed run {run['id']} has unexpected slice-job shape")
    job = slice_jobs[0]
    if job.get("status") != "completed" or job.get("conclusion") != "failure":
        fail(f"failed run {run['id']} does not contain one completed failed slice job")
    steps = {str(step.get("name")): step.get("conclusion") for step in job.get("steps") or []}
    required = {
        "Validate continuation request": "success",
        "Reclaim runner storage for exhaustive TLC": "success",
        "Recover exact private frozen candidate": "success",
        "Download prior authenticated encrypted checkpoint": "success",
        "Authenticate and restore prior checkpoint": "failure",
        "Run exact canonical TLC slice": "skipped",
        "Seal authenticated encrypted checkpoint": "skipped",
        "Upload authenticated encrypted checkpoint": "skipped",
        "Dispatch next slice": "skipped",
    }
    for name, expected in required.items():
        if steps.get(name) != expected:
            fail(
                f"failed run {run['id']} is not isolated pre-TLC restore failure: "
                f"step={name!r} actual={steps.get(name)!r} expected={expected!r}"
            )
    log = fetch_job_log(api, repo, token, int(job["id"]))
    if ACTUAL_RESULT_RE.search(log):
        fail(f"failed run {run['id']} emitted a TLC semantic result marker")
    index_matches = INPUT_INDEX_RE.findall(log)
    segment_matches = INPUT_SEGMENT_RE.findall(log)
    if not index_matches or not segment_matches:
        fail(f"failed run {run['id']} has no exact input index/segment evidence")
    profile = int(index_matches[-1])
    segment = int(segment_matches[-1])
    if profile not in EXPECTED_PROFILES or segment <= 1:
        fail(f"failed run {run['id']} has unexpected profile/segment {profile}/{segment}")
    return IsolatedFailure(
        profile=profile,
        segment=segment,
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        failure_class="PRE_TLC_RESTORE_FAILURE",
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

    completed_success = [
        run
        for run in target_runs
        if run.get("status") == "completed" and run.get("conclusion") == "success"
    ]
    completed_failure = [
        run
        for run in target_runs
        if run.get("status") == "completed" and run.get("conclusion") != "success"
    ]
    open_runs = [run for run in target_runs if run.get("status") != "completed"]

    evidence: dict[int, dict[int, SegmentEvidence]] = {
        profile: {} for profile in EXPECTED_PROFILES
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(process_successful_run, api, repo, token, run)
            for run in completed_success
        ]
        for future in concurrent.futures.as_completed(futures):
            for item in future.result():
                if item.profile not in evidence:
                    fail(f"unexpected canonical profile in exact lineage: {item.profile}")
                existing = evidence[item.profile].get(item.segment)
                if existing and existing != item:
                    fail(
                        f"duplicate conflicting evidence for profile {item.profile} "
                        f"segment {item.segment}"
                    )
                evidence[item.profile][item.segment] = item

    isolated_failures = [
        classify_failed_run(api, repo, token, run) for run in completed_failure
    ]

    terminal = 0
    checkpointed = 0
    print(f"LAS_RESUMABLE_LINEAGE_EXACT_RUN_COUNT={len(target_runs)}")
    print(f"LAS_RESUMABLE_LINEAGE_OPEN_RUN_COUNT={len(open_runs)}")
    print(f"LAS_RESUMABLE_LINEAGE_ISOLATED_FAILURE_COUNT={len(isolated_failures)}")
    for item in sorted(isolated_failures, key=lambda x: (x.profile, x.segment, x.run_id)):
        print(
            "LAS_RESUMABLE_ISOLATED_FAILURE="
            f"{item.profile}/{item.segment};CLASS={item.failure_class};"
            f"RUN_ID={item.run_id};JOB_ID={item.job_id}"
        )

    for profile in EXPECTED_PROFILES:
        segments = evidence[profile]
        if not segments:
            fail(f"profile {profile} has no completed segment evidence")
        ordered = sorted(segments)
        expected = list(range(1, ordered[-1] + 1))
        if ordered != expected:
            fail(
                f"profile {profile} segment chain is non-contiguous: "
                f"actual={ordered}, expected={expected}"
            )
        if any(item.result.startswith("FAIL") for item in segments.values()):
            fail(f"profile {profile} contains fail/fail-closed TLC evidence")
        latest = segments[ordered[-1]]
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

    if terminal + checkpointed != len(EXPECTED_PROFILES):
        fail("profile accounting mismatch")
    if len(open_runs) > checkpointed:
        fail(
            f"more open exact runs ({len(open_runs)}) than checkpointed profiles "
            f"({checkpointed})"
        )

    print(f"LAS_RESUMABLE_LINEAGE_TERMINAL_PROFILE_COUNT={terminal}")
    print(f"LAS_RESUMABLE_LINEAGE_CHECKPOINT_PROFILE_COUNT={checkpointed}")
    print("LAS_RESUMABLE_LINEAGE_RUNNER_IDENTITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_SEGMENT_CONTIGUITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_FAILED_ATTEMPTS_CLASSIFIED=PASS")
    print("LAS_RESUMABLE_LINEAGE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except AuditError as exc:
        print(f"LAS_RESUMABLE_LINEAGE_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
