#!/usr/bin/env python3
"""Attempt-history-aware audit for the frozen exact resumable TLC lane.

This layer reuses the ancestry-aware v2 parser/transport primitives, but it does
not trust GitHub's current run record alone after a job re-run. Every historical
workflow attempt is recovered from `/attempts/{n}` and included in the proof.
A pre-TLC restore failure is admissible only if a later attempt of the *same run*
executes the same profile/segment from the same predecessor run+artifact and
produces successful TLC evidence. Semantic failures remain fatal.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
from dataclasses import dataclass

import audit_current_resumable_lineage_v2 as base


@dataclass(frozen=True)
class RecordedAttempt:
    evidence: base.Attempt
    run_attempt: int


def fetch_attempt_run(
    api: str, repo: str, token: str, run_id: int, run_attempt: int
) -> dict:
    return base.get_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/attempts/{run_attempt}", token
    )


def fetch_attempt_jobs(
    api: str, repo: str, token: str, run_id: int, run_attempt: int
) -> list[dict]:
    data = base.get_json(
        f"{api}/repos/{repo}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100",
        token,
    )
    jobs = data.get("jobs") or []
    if not isinstance(jobs, list):
        base.fail(f"attempt jobs payload is not a list for run {run_id}/{run_attempt}")
    return jobs


def process_bundle(
    api: str,
    repo: str,
    token: str,
    run: dict,
    jobs: list[dict],
) -> list[base.Attempt]:
    candidates = [
        job
        for job in jobs
        if job.get("name") == "continuation / slice"
        or base.BOOTSTRAP_INDEX_RE.fullmatch(str(job.get("name") or ""))
    ]
    if run.get("path") == base.BOOTSTRAP_PATH:
        if run.get("conclusion") != "success":
            base.fail("frozen bootstrap attempt is not successful")
        out: list[base.Attempt] = []
        for job in candidates:
            if job.get("conclusion") != "success":
                base.fail(f"bootstrap job {job.get('id')} did not succeed")
            out.append(
                base.parse_success(
                    run, job, base.fetch_log(api, repo, token, int(job["id"]))
                )
            )
        return out

    if len(candidates) != 1:
        base.fail(
            f"continuation run {run['id']} attempt {run.get('run_attempt')} "
            f"has {len(candidates)} slice jobs"
        )
    job = candidates[0]
    log = base.fetch_log(api, repo, token, int(job["id"]))
    if run.get("conclusion") == "success" and job.get("conclusion") == "success":
        return [base.parse_success(run, job, log)]
    if run.get("conclusion") == "failure" and job.get("conclusion") == "failure":
        return [base.parse_failed_restore(run, job, log)]
    base.fail(
        f"continuation run {run['id']} attempt {run.get('run_attempt')} has unsupported "
        f"conclusion shape: run={run.get('conclusion')!r} job={job.get('conclusion')!r}"
    )


def record_completed_bundle(
    api: str,
    repo: str,
    token: str,
    run: dict,
    jobs: list[dict],
) -> list[RecordedAttempt]:
    run_attempt = int(run.get("run_attempt") or 1)
    return [
        RecordedAttempt(evidence=item, run_attempt=run_attempt)
        for item in process_bundle(api, repo, token, run, jobs)
    ]


def audit() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not repo or not token:
        base.fail("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    runs = [
        run
        for run in base.paginate_runs(api, repo, token)
        if run.get("path") in {base.CONTINUATION_PATH, base.BOOTSTRAP_PATH}
    ]
    if not runs:
        base.fail("no frozen resumable runs found")
    for run in runs:
        base.validate_run_binding(repo, run)

    bootstrap = [run for run in runs if run.get("path") == base.BOOTSTRAP_PATH]
    if len(bootstrap) != 1:
        base.fail(f"expected exactly one bootstrap run, found {len(bootstrap)}")
    if bootstrap[0].get("event") != "push":
        base.fail("frozen bootstrap provenance event changed")

    recorded: list[RecordedAttempt] = []
    historical_work: list[tuple[dict, list[dict]]] = []
    current_work: list[tuple[dict, list[dict]]] = []
    open_runs: list[dict] = []

    # Preserve every historical run attempt before looking at the mutable current view.
    for current in runs:
        run_id = int(current["id"])
        current_attempt = int(current.get("run_attempt") or 1)
        for attempt_number in range(1, current_attempt):
            prior = fetch_attempt_run(api, repo, token, run_id, attempt_number)
            base.validate_run_binding(repo, prior)
            if int(prior.get("run_attempt") or 0) != attempt_number:
                base.fail(
                    f"historical run {run_id} returned wrong attempt number: "
                    f"expected={attempt_number} actual={prior.get('run_attempt')}"
                )
            if prior.get("status") != "completed":
                base.fail(f"historical run {run_id}/{attempt_number} is not completed")
            historical_work.append(
                (
                    prior,
                    fetch_attempt_jobs(api, repo, token, run_id, attempt_number),
                )
            )

        if current.get("status") == "completed":
            current_work.append(
                (current, base.fetch_jobs(api, repo, token, run_id))
            )
        else:
            open_runs.append(current)

    all_work = historical_work + current_work
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(record_completed_bundle, api, repo, token, run, jobs)
            for run, jobs in all_work
        ]
        for future in concurrent.futures.as_completed(futures):
            recorded.extend(future.result())

    successes = [r for r in recorded if r.evidence.outcome == "SUCCESS"]
    failures = [
        r
        for r in recorded
        if r.evidence.outcome == "PRE_TLC_RESTORE_FAILURE"
    ]
    unknown = [
        r
        for r in recorded
        if r.evidence.outcome not in {"SUCCESS", "PRE_TLC_RESTORE_FAILURE"}
    ]
    if unknown:
        base.fail(f"unsupported recorded outcomes: {[x.evidence.outcome for x in unknown]}")
    if any(r.evidence.profile not in base.EXPECTED_PROFILES for r in recorded):
        bad = sorted(
            {
                r.evidence.profile
                for r in recorded
                if r.evidence.profile not in base.EXPECTED_PROFILES
            }
        )
        base.fail(f"unexpected profiles in resumable lane: {bad}")

    by_profile_segment: dict[int, dict[int, list[RecordedAttempt]]] = {
        profile: {} for profile in base.EXPECTED_PROFILES
    }
    for record in successes:
        item = record.evidence
        by_profile_segment[item.profile].setdefault(item.segment, []).append(record)

    canonical: dict[int, dict[int, RecordedAttempt]] = {
        profile: {} for profile in base.EXPECTED_PROFILES
    }
    for profile in base.EXPECTED_PROFILES:
        for segment, items in by_profile_segment[profile].items():
            ordered = sorted(
                items,
                key=lambda r: (
                    r.evidence.created_at,
                    r.evidence.run_id,
                    r.run_attempt,
                    r.evidence.job_id,
                ),
            )
            first = ordered[0]
            for other in ordered[1:]:
                if (
                    other.evidence.resume_run_id != first.evidence.resume_run_id
                    or other.evidence.resume_artifact != first.evidence.resume_artifact
                    or other.evidence.result != first.evidence.result
                ):
                    base.fail(
                        f"conflicting successful executions for profile {profile} segment {segment}"
                    )
            canonical[profile][segment] = first

    # Prove successful checkpoint ancestry end-to-end.
    for profile in base.EXPECTED_PROFILES:
        segments = canonical[profile]
        if not segments:
            base.fail(f"profile {profile} has no successful segment evidence")
        numbers = sorted(segments)
        expected = list(range(1, numbers[-1] + 1))
        if numbers != expected:
            base.fail(
                f"profile {profile} successful chain non-contiguous: "
                f"actual={numbers} expected={expected}"
            )
        root = segments[1].evidence
        if root.resume_run_id is not None or root.resume_artifact:
            base.fail(f"profile {profile} segment 1 unexpectedly resumes state")
        for segment in numbers[1:]:
            current = segments[segment].evidence
            previous = segments[segment - 1].evidence
            expected_artifact = f"tlc-state-{profile}-{segment - 1}"
            if current.resume_run_id != previous.run_id:
                base.fail(
                    f"profile {profile} segment {segment} parent mismatch: "
                    f"expected={previous.run_id} actual={current.resume_run_id}"
                )
            if current.resume_artifact != expected_artifact:
                base.fail(
                    f"profile {profile} segment {segment} artifact mismatch: "
                    f"expected={expected_artifact!r} actual={current.resume_artifact!r}"
                )
            if previous.result != "SLICE_CHECKPOINT":
                base.fail(
                    f"profile {profile} segment {segment} follows non-checkpoint "
                    f"result {previous.result!r}"
                )
        pass_segments = [
            number
            for number, record in segments.items()
            if record.evidence.result == "PASS"
        ]
        if pass_segments and pass_segments != [numbers[-1]]:
            base.fail(f"profile {profile} PASS is not terminal: {pass_segments}")

    # A historical restore failure must be superseded by a later successful attempt
    # of the very same workflow run and exact predecessor checkpoint.
    superseded: list[tuple[RecordedAttempt, RecordedAttempt]] = []
    unrecovered: list[RecordedAttempt] = []
    for failed in failures:
        f = failed.evidence
        candidates = [
            success
            for success in successes
            if success.evidence.profile == f.profile
            and success.evidence.segment == f.segment
            and success.evidence.run_id == f.run_id
            and success.run_attempt > failed.run_attempt
            and success.evidence.resume_run_id == f.resume_run_id
            and success.evidence.resume_artifact == f.resume_artifact
        ]
        if not candidates:
            unrecovered.append(failed)
            continue
        winner = min(candidates, key=lambda r: (r.run_attempt, r.evidence.job_id))
        superseded.append((failed, winner))

    print(f"LAS_RESUMABLE_V3_EXACT_RUN_COUNT={len(runs)}")
    print(f"LAS_RESUMABLE_V3_HISTORICAL_ATTEMPT_COUNT={len(historical_work)}")
    print(f"LAS_RESUMABLE_V3_OPEN_RUN_COUNT={len(open_runs)}")
    print(f"LAS_RESUMABLE_V3_RESTORE_FAILURE_COUNT={len(failures)}")
    print(f"LAS_RESUMABLE_V3_SUPERSEDED_FAILURE_COUNT={len(superseded)}")
    print(f"LAS_RESUMABLE_V3_UNRECOVERED_FAILURE_COUNT={len(unrecovered)}")
    for failed, recovered in sorted(
        superseded,
        key=lambda pair: (
            pair[0].evidence.profile,
            pair[0].evidence.segment,
            pair[0].evidence.run_id,
        ),
    ):
        f = failed.evidence
        r = recovered.evidence
        print(
            "LAS_RESUMABLE_V3_SUPERSEDED_FAILURE="
            f"{f.profile}/{f.segment};RUN_ID={f.run_id};"
            f"FAILED_ATTEMPT={failed.run_attempt};RECOVERED_ATTEMPT={recovered.run_attempt};"
            f"PARENT={f.resume_run_id};ARTIFACT={f.resume_artifact};RECOVERY_JOB={r.job_id}"
        )
    for failed in sorted(
        unrecovered,
        key=lambda item: (
            item.evidence.profile,
            item.evidence.segment,
            item.evidence.run_id,
        ),
    ):
        f = failed.evidence
        print(
            "LAS_RESUMABLE_V3_UNRECOVERED_FAILURE="
            f"{f.profile}/{f.segment};RUN_ID={f.run_id};FAILED_ATTEMPT={failed.run_attempt};"
            f"PARENT={f.resume_run_id};ARTIFACT={f.resume_artifact}"
        )

    terminal = 0
    checkpointed = 0
    for profile in base.EXPECTED_PROFILES:
        last_segment = max(canonical[profile])
        latest = canonical[profile][last_segment]
        item = latest.evidence
        if item.result == "PASS":
            terminal += 1
            state = "PASS"
        elif item.result == "SLICE_CHECKPOINT":
            checkpointed += 1
            state = f"CHECKPOINT_NEXT_{last_segment + 1}"
        else:
            base.fail(f"profile {profile} unexpected terminal result {item.result!r}")
        print(
            "LAS_RESUMABLE_V3_PROFILE="
            f"{profile};LAST_COMPLETED_SEGMENT={last_segment};STATE={state};"
            f"RUN_ID={item.run_id};JOB_ID={item.job_id};ATTEMPT={latest.run_attempt}"
        )

    if terminal + checkpointed != len(base.EXPECTED_PROFILES):
        base.fail("profile accounting mismatch")
    if unrecovered:
        base.fail(
            "unrecovered exact restore retries remain: "
            + ", ".join(
                f"{x.evidence.profile}/{x.evidence.segment}@"
                f"run{x.evidence.run_id}/attempt{x.run_attempt}"
                for x in unrecovered
            )
        )

    print(f"LAS_RESUMABLE_V3_TERMINAL_PROFILE_COUNT={terminal}")
    print(f"LAS_RESUMABLE_V3_CHECKPOINT_PROFILE_COUNT={checkpointed}")
    print("LAS_RESUMABLE_V3_RUNNER_IDENTITY=PASS")
    print("LAS_RESUMABLE_V3_PARENT_CHAIN=PASS")
    print("LAS_RESUMABLE_V3_ATTEMPT_HISTORY=PASS")
    print("LAS_RESUMABLE_V3_RETRY_SUPERSESSION=PASS")
    print("LAS_RESUMABLE_V3_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except base.AuditError as exc:
        print(f"LAS_RESUMABLE_V3_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
