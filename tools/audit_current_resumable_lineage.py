#!/usr/bin/env python3
"""Audit the frozen exact resumable TLC lineage from GitHub Actions evidence.

The auditor is read-only with respect to the acceptance lane. It proves frozen
runner identity, reconstructs successful canonical segment chains, preserves
workflow re-run attempt history, and only accepts a pre-TLC restore failure when
a later successful attempt executes the exact same profile/segment from the exact
same predecessor run and artifact.
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
INPUT_RESUME_RUN_ID_RE = re.compile(r"Z\s+resume_run_id:\s*([^\r\n]*)$", re.MULTILINE)
INPUT_RESUME_ARTIFACT_RE = re.compile(r"Z\s+resume_artifact:\s*([^\r\n]*)$", re.MULTILINE)
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
    run_attempt: int
    created_at: str
    resume_run_id: str
    resume_artifact: str


@dataclass(frozen=True)
class RestoreFailure:
    profile: int
    segment: int
    run_id: int
    job_id: int
    run_attempt: int
    resume_run_id: str
    resume_artifact: str
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


def fetch_attempt(api: str, repo: str, token: str, run_id: int, attempt: int) -> dict:
    return request_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}", token
    )


def fetch_attempt_jobs(
    api: str, repo: str, token: str, run_id: int, attempt: int
) -> list[dict]:
    data = request_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
        token,
    )
    jobs = data.get("jobs") or []
    if not isinstance(jobs, list):
        fail(f"attempt jobs is not a list for run {run_id} attempt {attempt}")
    return jobs


def fetch_job_log(api: str, repo: str, token: str, job_id: int) -> str:
    endpoint = f"{api}/repos/{repo}/actions/jobs/{job_id}/logs"
    signed_url = request_github_redirect_target(endpoint, token)
    return request_unsigned_https(signed_url).decode("utf-8-sig", errors="replace")


def validate_runner_binding(repo: str, run: dict, label: str = "run") -> None:
    run_id = run.get("id")
    if run.get("head_sha") != TARGET_HEAD_SHA:
        fail(f"{label} {run_id} head SHA drifted")
    if run.get("path") not in {CONTINUATION_PATH, BOOTSTRAP_PATH}:
        fail(f"{label} {run_id} has unexpected workflow path: {run.get('path')!r}")
    expected = f"{repo}/{REUSABLE_PATH}@{TARGET_HEAD_SHA}"
    refs = run.get("referenced_workflows") or []
    if len(refs) != 1:
        fail(f"{label} {run_id} does not reference exactly one reusable workflow: {refs!r}")
    item = refs[0]
    if item.get("sha") != TARGET_HEAD_SHA or item.get("path") != expected:
        fail(f"{label} {run_id} reusable workflow identity drifted: {refs!r}")


def last_match(pattern: re.Pattern[str], log: str, name: str, required: bool = True) -> str:
    matches = pattern.findall(log)
    if not matches:
        if required:
            fail(f"job log is missing {name}")
        return ""
    return str(matches[-1]).strip()


def parse_predecessor(log: str, segment: int) -> tuple[str, str]:
    resume_run_id = last_match(
        INPUT_RESUME_RUN_ID_RE, log, "resume_run_id input", required=segment > 1
    )
    resume_artifact = last_match(
        INPUT_RESUME_ARTIFACT_RE, log, "resume_artifact input", required=segment > 1
    )
    if segment == 1:
        if resume_run_id or resume_artifact:
            fail("segment 1 unexpectedly has resume predecessor inputs")
    else:
        if not resume_run_id.isdigit():
            fail(f"segment {segment} has invalid resume_run_id {resume_run_id!r}")
        if not resume_artifact:
            fail(f"segment {segment} has empty resume_artifact")
    return resume_run_id, resume_artifact


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
    resume_run_id, resume_artifact = parse_predecessor(log, segment)
    return SegmentEvidence(
        profile=profile,
        segment=segment,
        result=result_matches[-1],
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        run_number=int(run.get("run_number") or 0),
        run_attempt=int(run.get("run_attempt") or 1),
        created_at=str(run.get("created_at") or ""),
        resume_run_id=resume_run_id,
        resume_artifact=resume_artifact,
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


def classify_restore_failure(
    api: str,
    repo: str,
    token: str,
    run: dict,
    jobs: list[dict],
    attempt: int,
) -> RestoreFailure:
    slice_jobs = [job for job in jobs if job.get("name") == "continuation / slice"]
    if len(slice_jobs) != 1:
        fail(f"failed run {run['id']} attempt {attempt} has unexpected slice-job shape")
    job = slice_jobs[0]
    if job.get("status") != "completed" or job.get("conclusion") != "failure":
        fail(f"run {run['id']} attempt {attempt} is not one completed failed slice job")
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
                f"run {run['id']} attempt {attempt} is not isolated pre-TLC restore failure: "
                f"step={name!r} actual={steps.get(name)!r} expected={expected!r}"
            )
    log = fetch_job_log(api, repo, token, int(job["id"]))
    if ACTUAL_RESULT_RE.search(log):
        fail(f"failed run {run['id']} attempt {attempt} emitted TLC semantic result")
    profile = int(last_match(INPUT_INDEX_RE, log, "index input"))
    segment = int(last_match(INPUT_SEGMENT_RE, log, "segment input"))
    if profile not in EXPECTED_PROFILES or segment <= 1:
        fail(f"failed run {run['id']} attempt {attempt} has unexpected {profile}/{segment}")
    resume_run_id, resume_artifact = parse_predecessor(log, segment)
    return RestoreFailure(
        profile=profile,
        segment=segment,
        run_id=int(run["id"]),
        job_id=int(job["id"]),
        run_attempt=attempt,
        resume_run_id=resume_run_id,
        resume_artifact=resume_artifact,
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
    current_failures = [
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

    restore_failures: list[RestoreFailure] = []
    for run in target_runs:
        run_id = int(run["id"])
        current_attempt = int(run.get("run_attempt") or 1)
        for attempt in range(1, current_attempt):
            prior = fetch_attempt(api, repo, token, run_id, attempt)
            validate_runner_binding(repo, prior, label=f"run-attempt-{attempt}")
            if prior.get("status") != "completed":
                fail(f"historical run {run_id} attempt {attempt} is not completed")
            if prior.get("conclusion") == "success":
                fail(
                    f"run {run_id} has historical successful attempt {attempt}; "
                    "duplicate semantic execution requires explicit review"
                )
            restore_failures.append(
                classify_restore_failure(
                    api,
                    repo,
                    token,
                    prior,
                    fetch_attempt_jobs(api, repo, token, run_id, attempt),
                    attempt,
                )
            )

    for run in current_failures:
        restore_failures.append(
            classify_restore_failure(
                api,
                repo,
                token,
                run,
                fetch_jobs(api, repo, token, int(run["id"])),
                int(run.get("run_attempt") or 1),
            )
        )

    unrecovered: list[RestoreFailure] = []
    recovered: list[tuple[RestoreFailure, SegmentEvidence]] = []
    for failure in restore_failures:
        success = evidence.get(failure.profile, {}).get(failure.segment)
        if success is None:
            unrecovered.append(failure)
            continue
        exact_recovery = (
            success.run_id == failure.run_id
            and success.run_attempt > failure.run_attempt
            and success.resume_run_id == failure.resume_run_id
            and success.resume_artifact == failure.resume_artifact
        )
        if not exact_recovery:
            fail(
                f"restore failure {failure.profile}/{failure.segment} has non-exact recovery: "
                f"failure_run={failure.run_id}/attempt{failure.run_attempt} "
                f"success_run={success.run_id}/attempt{success.run_attempt} "
                f"failure_predecessor={failure.resume_run_id}:{failure.resume_artifact} "
                f"success_predecessor={success.resume_run_id}:{success.resume_artifact}"
            )
        recovered.append((failure, success))

    terminal = 0
    checkpointed = 0
    print(f"LAS_RESUMABLE_LINEAGE_EXACT_RUN_COUNT={len(target_runs)}")
    print(f"LAS_RESUMABLE_LINEAGE_OPEN_RUN_COUNT={len(open_runs)}")
    print(f"LAS_RESUMABLE_LINEAGE_RESTORE_FAILURE_COUNT={len(restore_failures)}")
    print(f"LAS_RESUMABLE_LINEAGE_RECOVERED_FAILURE_COUNT={len(recovered)}")
    print(f"LAS_RESUMABLE_LINEAGE_UNRECOVERED_FAILURE_COUNT={len(unrecovered)}")
    for failure, success in sorted(recovered, key=lambda x: (x[0].profile, x[0].segment)):
        print(
            "LAS_RESUMABLE_RECOVERED_FAILURE="
            f"{failure.profile}/{failure.segment};RUN_ID={failure.run_id};"
            f"FAILED_ATTEMPT={failure.run_attempt};RECOVERED_ATTEMPT={success.run_attempt};"
            f"PREDECESSOR_RUN={failure.resume_run_id};ARTIFACT={failure.resume_artifact}"
        )
    for failure in sorted(unrecovered, key=lambda x: (x.profile, x.segment)):
        print(
            "LAS_RESUMABLE_UNRECOVERED_FAILURE="
            f"{failure.profile}/{failure.segment};RUN_ID={failure.run_id};"
            f"FAILED_ATTEMPT={failure.run_attempt};"
            f"PREDECESSOR_RUN={failure.resume_run_id};ARTIFACT={failure.resume_artifact}"
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
            f"RUN_ID={latest.run_id};JOB_ID={latest.job_id};ATTEMPT={latest.run_attempt}"
        )

    if terminal + checkpointed != len(EXPECTED_PROFILES):
        fail("profile accounting mismatch")
    if len(open_runs) > checkpointed + len(unrecovered):
        fail(
            f"unexpected open-run count {len(open_runs)} for checkpointed={checkpointed} "
            f"unrecovered={len(unrecovered)}"
        )
    if unrecovered:
        fail(
            "unrecovered pre-TLC restore failures remain: "
            + ", ".join(
                f"{x.profile}/{x.segment}@run{x.run_id}/attempt{x.run_attempt}"
                for x in unrecovered
            )
        )

    print(f"LAS_RESUMABLE_LINEAGE_TERMINAL_PROFILE_COUNT={terminal}")
    print(f"LAS_RESUMABLE_LINEAGE_CHECKPOINT_PROFILE_COUNT={checkpointed}")
    print("LAS_RESUMABLE_LINEAGE_RUNNER_IDENTITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_SEGMENT_CONTIGUITY=PASS")
    print("LAS_RESUMABLE_LINEAGE_RETRY_RECOVERY_BINDING=PASS")
    print("LAS_RESUMABLE_LINEAGE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except AuditError as exc:
        print(f"LAS_RESUMABLE_LINEAGE_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
