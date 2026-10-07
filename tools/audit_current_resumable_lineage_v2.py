#!/usr/bin/env python3
"""Strong lineage audit for the frozen exact resumable TLC acceptance lane.

Acceptance rule:
* every run is bound to the frozen public runner revision;
* every successful segment recovers the exact previous successful segment checkpoint;
* successful segment numbers are contiguous from 1;
* a failed attempt is admissible only when it failed before TLC during checkpoint restore
  and a later successful attempt re-executed the exact same profile/segment from the
  exact same parent run and artifact;
* no semantic TLC failure may be hidden by a retry.
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
REDIRECT_CODES = {301, 302, 303, 307, 308}

ACTUAL_INDEX_RE = re.compile(r"LAS_CURRENT_RESUME_INDEX=(\d+)")
ACTUAL_SEGMENT_RE = re.compile(r"LAS_CURRENT_RESUME_SEGMENT=(\d+)")
ACTUAL_RESULT_RE = re.compile(
    r"LAS_CURRENT_RESUME_RESULT=(PASS|SLICE_CHECKPOINT|FAIL_CLOSED|FAIL)"
)
INPUT_INDEX_RE = re.compile(r"\bindex:\s+(\d+)\s*$", re.MULTILINE)
INPUT_SEGMENT_RE = re.compile(r"\bsegment:\s+(\d+)\s*$", re.MULTILINE)
INPUT_RESUME_RUN_RE = re.compile(r"\bresume_run_id:\s*([^\s]*)\s*$", re.MULTILINE)
INPUT_RESUME_ARTIFACT_RE = re.compile(r"\bresume_artifact:\s*([^\s]*)\s*$", re.MULTILINE)
BOOTSTRAP_INDEX_RE = re.compile(r"bootstrap \((\d+)\) / slice")


class AuditError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class Attempt:
    profile: int
    segment: int
    run_id: int
    job_id: int
    created_at: str
    run_number: int
    resume_run_id: int | None
    resume_artifact: str
    result: str | None
    outcome: str


@dataclass(frozen=True)
class RunBundle:
    run: dict
    jobs: list[dict]


def fail(message: str) -> None:
    raise AuditError(message)


def headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "living-assurance-lineage-v2-auditor",
    }


def get_bytes(url: str, token: str) -> bytes:
    req = urllib.request.Request(url, headers=headers(token))
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"GitHub API HTTP {exc.code} for {url}: {body[:500]}")
    except urllib.error.URLError as exc:
        fail(f"GitHub API request failed for {url}: {exc}")


def get_json(url: str, token: str) -> dict:
    try:
        return json.loads(get_bytes(url, token).decode("utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid GitHub JSON from {url}: {exc}")


def resolve_log_redirect(url: str, token: str) -> str:
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers=headers(token))
    try:
        with opener.open(req, timeout=60) as response:
            if response.status not in REDIRECT_CODES:
                fail(f"expected log redirect, got HTTP {response.status}")
            location = response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        if exc.code not in REDIRECT_CODES:
            body = exc.read().decode("utf-8", errors="replace")
            fail(f"log endpoint HTTP {exc.code}: {body[:500]}")
        location = exc.headers.get("Location")
    except urllib.error.URLError as exc:
        fail(f"log redirect request failed: {exc}")
    if not location:
        fail("log redirect missing Location")
    parsed = urllib.parse.urlparse(location)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"unsafe log redirect: {location!r}")
    return location


def fetch_unsigned(url: str) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "living-assurance-lineage-v2-auditor"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        fail(f"signed log HTTP {exc.code}: {body[:500]}")
    except urllib.error.URLError as exc:
        fail(f"signed log download failed: {exc}")


def fetch_log(api: str, repo: str, token: str, job_id: int) -> str:
    signed = resolve_log_redirect(
        f"{api}/repos/{repo}/actions/jobs/{job_id}/logs", token
    )
    return fetch_unsigned(signed).decode("utf-8-sig", errors="replace")


def paginate_runs(api: str, repo: str, token: str) -> list[dict]:
    out: list[dict] = []
    for page in range(1, 21):
        query = urllib.parse.urlencode(
            {"head_sha": TARGET_HEAD_SHA, "per_page": 100, "page": page}
        )
        data = get_json(f"{api}/repos/{repo}/actions/runs?{query}", token)
        batch = data.get("workflow_runs") or []
        if not isinstance(batch, list):
            fail("workflow_runs is not a list")
        out.extend(batch)
        if len(batch) < 100:
            return out
    fail("unexpectedly large frozen run history")


def fetch_jobs(api: str, repo: str, token: str, run_id: int) -> list[dict]:
    data = get_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100", token
    )
    jobs = data.get("jobs") or []
    if not isinstance(jobs, list):
        fail(f"jobs payload is not a list for run {run_id}")
    return jobs


def validate_run_binding(repo: str, run: dict) -> None:
    run_id = run.get("id")
    if run.get("head_sha") != TARGET_HEAD_SHA:
        fail(f"run {run_id} head SHA drifted")
    if run.get("path") not in {CONTINUATION_PATH, BOOTSTRAP_PATH}:
        fail(f"run {run_id} unexpected workflow path: {run.get('path')!r}")
    refs = run.get("referenced_workflows") or []
    expected_path = f"{repo}/{REUSABLE_PATH}@{TARGET_HEAD_SHA}"
    if len(refs) != 1:
        fail(f"run {run_id} does not reference exactly one reusable workflow")
    if refs[0].get("sha") != TARGET_HEAD_SHA or refs[0].get("path") != expected_path:
        fail(f"run {run_id} reusable workflow identity drifted: {refs!r}")


def step_map(job: dict) -> dict[str, str | None]:
    return {
        str(step.get("name")): step.get("conclusion") for step in job.get("steps") or []
    }


def last_int(regex: re.Pattern[str], text: str, label: str) -> int:
    matches = regex.findall(text)
    if not matches:
        fail(f"missing {label} in job log")
    return int(matches[-1])


def last_text(regex: re.Pattern[str], text: str, label: str) -> str:
    matches = regex.findall(text)
    if not matches:
        fail(f"missing {label} in job log")
    return matches[-1].strip()


def parse_inputs(log: str) -> tuple[int, int, int | None, str]:
    profile = last_int(INPUT_INDEX_RE, log, "input index")
    segment = last_int(INPUT_SEGMENT_RE, log, "input segment")
    raw_parent = last_text(INPUT_RESUME_RUN_RE, log, "input resume_run_id")
    artifact = last_text(INPUT_RESUME_ARTIFACT_RE, log, "input resume_artifact")
    parent = int(raw_parent) if raw_parent else None
    return profile, segment, parent, artifact


def parse_success(run: dict, job: dict, log: str) -> Attempt:
    name = str(job.get("name") or "")
    bootstrap_match = BOOTSTRAP_INDEX_RE.fullmatch(name)
    if bootstrap_match:
        profile = int(bootstrap_match.group(1))
        segment = 1
        parent = None
        artifact = ""
    else:
        profile, segment, parent, artifact = parse_inputs(log)

    actual_index = ACTUAL_INDEX_RE.findall(log)
    actual_segment = ACTUAL_SEGMENT_RE.findall(log)
    results = ACTUAL_RESULT_RE.findall(log)
    if not results:
        fail(f"successful run {run['id']} job {job['id']} has no TLC result marker")
    if actual_index and int(actual_index[-1]) != profile:
        fail(f"run {run['id']} input/result profile mismatch")
    if actual_segment and int(actual_segment[-1]) != segment:
        fail(f"run {run['id']} input/result segment mismatch")
    result = results[-1]
    if result not in {"PASS", "SLICE_CHECKPOINT"}:
        fail(f"successful run {run['id']} contains semantic failure marker {result}")

    return Attempt(
        profile=profile,
        segment=segment,
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        created_at=str(run.get("created_at") or ""),
        run_number=int(run.get("run_number") or 0),
        resume_run_id=parent,
        resume_artifact=artifact,
        result=result,
        outcome="SUCCESS",
    )


def parse_failed_restore(run: dict, job: dict, log: str) -> Attempt:
    steps = step_map(job)
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
    for step_name, expected in required.items():
        if steps.get(step_name) != expected:
            fail(
                f"run {run['id']} is not an isolated pre-TLC restore failure: "
                f"{step_name}={steps.get(step_name)!r} expected={expected!r}"
            )
    if ACTUAL_RESULT_RE.search(log):
        fail(f"failed restore run {run['id']} emitted a TLC result marker")
    profile, segment, parent, artifact = parse_inputs(log)
    if segment <= 1 or parent is None:
        fail(f"failed restore run {run['id']} has invalid ancestry")
    return Attempt(
        profile=profile,
        segment=segment,
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        created_at=str(run.get("created_at") or ""),
        run_number=int(run.get("run_number") or 0),
        resume_run_id=parent,
        resume_artifact=artifact,
        result=None,
        outcome="PRE_TLC_RESTORE_FAILURE",
    )


def process_completed_run(
    api: str, repo: str, token: str, run: dict
) -> list[Attempt]:
    jobs = fetch_jobs(api, repo, token, int(run["id"]))
    candidates = [
        job
        for job in jobs
        if job.get("name") == "continuation / slice"
        or BOOTSTRAP_INDEX_RE.fullmatch(str(job.get("name") or ""))
    ]
    if run.get("path") == BOOTSTRAP_PATH:
        if run.get("conclusion") != "success":
            fail("frozen bootstrap run is not successful")
        attempts: list[Attempt] = []
        for job in candidates:
            if job.get("conclusion") != "success":
                fail(f"bootstrap job {job.get('id')} did not succeed")
            attempts.append(
                parse_success(
                    run, job, fetch_log(api, repo, token, int(job["id"]))
                )
            )
        return attempts

    if len(candidates) != 1:
        fail(f"continuation run {run['id']} has {len(candidates)} slice jobs")
    job = candidates[0]
    log = fetch_log(api, repo, token, int(job["id"]))
    if run.get("conclusion") == "success" and job.get("conclusion") == "success":
        return [parse_success(run, job, log)]
    if run.get("conclusion") == "failure" and job.get("conclusion") == "failure":
        return [parse_failed_restore(run, job, log)]
    fail(
        f"continuation run {run['id']} has unsupported conclusion shape: "
        f"run={run.get('conclusion')!r} job={job.get('conclusion')!r}"
    )


def audit() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not repo or not token:
        fail("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    runs = [
        run
        for run in paginate_runs(api, repo, token)
        if run.get("path") in {CONTINUATION_PATH, BOOTSTRAP_PATH}
    ]
    if not runs:
        fail("no frozen resumable runs found")
    for run in runs:
        validate_run_binding(repo, run)

    bootstrap = [run for run in runs if run.get("path") == BOOTSTRAP_PATH]
    if len(bootstrap) != 1:
        fail(f"expected exactly one bootstrap run, found {len(bootstrap)}")
    if bootstrap[0].get("event") != "push":
        fail("frozen bootstrap provenance event changed")

    completed = [run for run in runs if run.get("status") == "completed"]
    open_runs = [run for run in runs if run.get("status") != "completed"]
    attempts: list[Attempt] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(process_completed_run, api, repo, token, run)
            for run in completed
        ]
        for future in concurrent.futures.as_completed(futures):
            attempts.extend(future.result())

    successes = [a for a in attempts if a.outcome == "SUCCESS"]
    failures = [a for a in attempts if a.outcome == "PRE_TLC_RESTORE_FAILURE"]
    if any(a.profile not in EXPECTED_PROFILES for a in attempts):
        bad = sorted({a.profile for a in attempts if a.profile not in EXPECTED_PROFILES})
        fail(f"unexpected profiles in resumable lane: {bad}")

    by_profile_segment: dict[int, dict[int, list[Attempt]]] = {
        profile: {} for profile in EXPECTED_PROFILES
    }
    for attempt in successes:
        by_profile_segment[attempt.profile].setdefault(attempt.segment, []).append(attempt)

    canonical: dict[int, dict[int, Attempt]] = {p: {} for p in EXPECTED_PROFILES}
    for profile in EXPECTED_PROFILES:
        for segment, items in by_profile_segment[profile].items():
            ordered_items = sorted(items, key=lambda x: (x.created_at, x.run_id))
            first = ordered_items[0]
            for other in ordered_items[1:]:
                if (
                    other.resume_run_id != first.resume_run_id
                    or other.resume_artifact != first.resume_artifact
                    or other.result != first.result
                ):
                    fail(
                        f"conflicting successful retries for profile {profile} segment {segment}"
                    )
            canonical[profile][segment] = first

    # Prove exact successful parent chain and contiguous segments.
    for profile in EXPECTED_PROFILES:
        segments = canonical[profile]
        if not segments:
            fail(f"profile {profile} has no successful segment evidence")
        numbers = sorted(segments)
        expected = list(range(1, numbers[-1] + 1))
        if numbers != expected:
            fail(
                f"profile {profile} successful segment chain is non-contiguous: "
                f"actual={numbers} expected={expected}"
            )
        root = segments[1]
        if root.resume_run_id is not None or root.resume_artifact:
            fail(f"profile {profile} segment 1 unexpectedly resumes prior state")
        for segment in numbers[1:]:
            current = segments[segment]
            previous = segments[segment - 1]
            expected_artifact = f"tlc-state-{profile}-{segment - 1}"
            if current.resume_run_id != previous.run_id:
                fail(
                    f"profile {profile} segment {segment} parent run mismatch: "
                    f"expected={previous.run_id} actual={current.resume_run_id}"
                )
            if current.resume_artifact != expected_artifact:
                fail(
                    f"profile {profile} segment {segment} artifact mismatch: "
                    f"expected={expected_artifact!r} actual={current.resume_artifact!r}"
                )
            if previous.result != "SLICE_CHECKPOINT":
                fail(
                    f"profile {profile} segment {segment} follows non-checkpoint result "
                    f"{previous.result!r}"
                )
        pass_segments = [n for n, item in segments.items() if item.result == "PASS"]
        if pass_segments and pass_segments != [numbers[-1]]:
            fail(f"profile {profile} PASS is not terminal: {pass_segments}")

    # Failed restore attempts must be exact retries of the same parent checkpoint.
    for failed in failures:
        candidates = [
            a
            for a in successes
            if a.profile == failed.profile
            and a.segment == failed.segment
            and a.resume_run_id == failed.resume_run_id
            and a.resume_artifact == failed.resume_artifact
            and (a.created_at, a.run_id) > (failed.created_at, failed.run_id)
        ]
        if not candidates:
            fail(
                f"failed restore attempt was not superseded by exact retry: "
                f"profile={failed.profile} segment={failed.segment} run={failed.run_id} "
                f"parent={failed.resume_run_id} artifact={failed.resume_artifact!r}"
            )

    terminal = 0
    checkpointed = 0
    print(f"LAS_RESUMABLE_V2_EXACT_RUN_COUNT={len(runs)}")
    print(f"LAS_RESUMABLE_V2_OPEN_RUN_COUNT={len(open_runs)}")
    print(f"LAS_RESUMABLE_V2_SUPERSEDED_RESTORE_FAILURE_COUNT={len(failures)}")
    for failed in sorted(failures, key=lambda a: (a.profile, a.segment, a.run_id)):
        print(
            "LAS_RESUMABLE_V2_SUPERSEDED_FAILURE="
            f"{failed.profile}/{failed.segment};RUN_ID={failed.run_id};"
            f"PARENT={failed.resume_run_id};ARTIFACT={failed.resume_artifact}"
        )

    for profile in EXPECTED_PROFILES:
        last_segment = max(canonical[profile])
        latest = canonical[profile][last_segment]
        if latest.result == "PASS":
            terminal += 1
            state = "PASS"
        elif latest.result == "SLICE_CHECKPOINT":
            checkpointed += 1
            state = f"CHECKPOINT_NEXT_{last_segment + 1}"
        else:
            fail(f"profile {profile} unexpected terminal result {latest.result!r}")
        print(
            "LAS_RESUMABLE_V2_PROFILE="
            f"{profile};LAST_COMPLETED_SEGMENT={last_segment};STATE={state};"
            f"RUN_ID={latest.run_id};JOB_ID={latest.job_id}"
        )

    if terminal + checkpointed != len(EXPECTED_PROFILES):
        fail("profile accounting mismatch")
    print(f"LAS_RESUMABLE_V2_TERMINAL_PROFILE_COUNT={terminal}")
    print(f"LAS_RESUMABLE_V2_CHECKPOINT_PROFILE_COUNT={checkpointed}")
    print("LAS_RESUMABLE_V2_RUNNER_IDENTITY=PASS")
    print("LAS_RESUMABLE_V2_PARENT_CHAIN=PASS")
    print("LAS_RESUMABLE_V2_RETRY_SUPERSESSION=PASS")
    print("LAS_RESUMABLE_V2_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except AuditError as exc:
        print(f"LAS_RESUMABLE_V2_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
