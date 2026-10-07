#!/usr/bin/env python3
"""Dispatch-stall-aware audit for the frozen exact resumable TLC lane.

This layer preserves every v3 attempt-history, runner-identity, checkpoint-ancestry,
and retry-supersession invariant. It adds one narrowly defined infrastructure
failure class: TLC reached a valid SLICE_CHECKPOINT, the authenticated checkpoint
was sealed and uploaded, and only the next workflow dispatch failed.

Such a run is valid computational evidence for its completed segment, but it is a
hard lineage stall until the uploaded artifact is present and an exact later child
run is observed with profile+1 ancestry bound to that run and artifact. All other
failed-run shapes remain fail-closed through the v3/v2 parser.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
from dataclasses import dataclass

import audit_current_resumable_lineage_v2 as base
import audit_current_resumable_lineage_v3 as v3


@dataclass(frozen=True)
class PostDispatchFailure:
    evidence: base.Attempt
    run_attempt: int


POST_DISPATCH: dict[tuple[int, int], PostDispatchFailure] = {}
ORIGINAL_PARSE_FAILED_RESTORE = base.parse_failed_restore


def parse_failed_or_dispatch(run: dict, job: dict, log: str) -> base.Attempt:
    """Classify only the exact post-TLC dispatch-failure shape as valid segment evidence."""

    steps = base.step_map(job)
    dispatch_shape = {
        "Validate continuation request": "success",
        "Reclaim runner storage for exhaustive TLC": "success",
        "Recover exact private frozen candidate": "success",
        "Download prior authenticated encrypted checkpoint": "success",
        "Authenticate and restore prior checkpoint": "success",
        "Run exact canonical TLC slice": "success",
        "Seal authenticated encrypted checkpoint": "success",
        "Upload authenticated encrypted checkpoint": "success",
        "Dispatch next slice": "failure",
    }
    if all(steps.get(name) == expected for name, expected in dispatch_shape.items()):
        profile, segment, parent, artifact = base.parse_inputs(log)
        if segment <= 1 or parent is None:
            base.fail(f"post-TLC dispatch failure run {run['id']} has invalid ancestry")

        actual_index = base.ACTUAL_INDEX_RE.findall(log)
        actual_segment = base.ACTUAL_SEGMENT_RE.findall(log)
        results = base.ACTUAL_RESULT_RE.findall(log)
        if not actual_index or int(actual_index[-1]) != profile:
            base.fail(f"post-TLC dispatch failure run {run['id']} profile marker mismatch")
        if not actual_segment or int(actual_segment[-1]) != segment:
            base.fail(f"post-TLC dispatch failure run {run['id']} segment marker mismatch")
        if not results or results[-1] != "SLICE_CHECKPOINT":
            base.fail(
                f"post-TLC dispatch failure run {run['id']} did not end in SLICE_CHECKPOINT"
            )

        evidence = base.Attempt(
            profile=profile,
            segment=segment,
            run_id=int(run["id"]),
            job_id=int(job["id"]),
            created_at=str(run.get("created_at") or ""),
            run_number=int(run.get("run_number") or 0),
            resume_run_id=parent,
            resume_artifact=artifact,
            result="SLICE_CHECKPOINT",
            outcome="SUCCESS",
        )
        run_attempt = int(run.get("run_attempt") or 1)
        POST_DISPATCH[(evidence.run_id, run_attempt)] = PostDispatchFailure(
            evidence=evidence,
            run_attempt=run_attempt,
        )
        return evidence

    return ORIGINAL_PARSE_FAILED_RESTORE(run, job, log)


def verify_uploaded_artifact(
    api: str, repo: str, token: str, failure: PostDispatchFailure
) -> None:
    item = failure.evidence
    expected_name = f"tlc-state-{item.profile}-{item.segment}"
    data = base.get_json(
        f"{api}/repos/{repo}/actions/runs/{item.run_id}/artifacts?per_page=100", token
    )
    artifacts = data.get("artifacts") or []
    if not isinstance(artifacts, list):
        base.fail(f"artifact payload is not a list for dispatch-stalled run {item.run_id}")
    matches = [artifact for artifact in artifacts if artifact.get("name") == expected_name]
    if len(matches) != 1:
        base.fail(
            f"dispatch-stalled run {item.run_id} does not expose exactly one "
            f"{expected_name!r} artifact"
        )
    artifact = matches[0]
    if artifact.get("expired") is not False:
        base.fail(f"dispatch-stalled artifact {expected_name!r} is expired or ambiguous")
    digest = str(artifact.get("digest") or "")
    if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
        base.fail(f"dispatch-stalled artifact {expected_name!r} lacks SHA-256 digest")
    workflow_run = artifact.get("workflow_run") or {}
    if int(workflow_run.get("id") or 0) != item.run_id:
        base.fail(f"dispatch-stalled artifact {expected_name!r} run binding mismatch")
    if workflow_run.get("head_sha") != base.TARGET_HEAD_SHA:
        base.fail(f"dispatch-stalled artifact {expected_name!r} runner SHA mismatch")


def parse_completed_candidate(
    api: str, repo: str, token: str, run: dict
) -> tuple[int, int, int | None, str, int] | None:
    if run.get("path") != base.CONTINUATION_PATH or run.get("status") != "completed":
        return None
    base.validate_run_binding(repo, run)
    jobs = base.fetch_jobs(api, repo, token, int(run["id"]))
    candidates = [job for job in jobs if job.get("name") == "continuation / slice"]
    if len(candidates) != 1:
        base.fail(f"candidate child run {run['id']} has {len(candidates)} slice jobs")
    log = v3.fetch_log_resilient(api, repo, token, int(candidates[0]["id"]))
    profile, segment, parent, artifact = base.parse_inputs(log)
    return profile, segment, parent, artifact, int(run["id"])


def verify_dispatch_supersession(
    api: str,
    repo: str,
    token: str,
    failures: list[PostDispatchFailure],
) -> tuple[list[tuple[PostDispatchFailure, int]], list[PostDispatchFailure]]:
    if not failures:
        return [], []

    min_run_number = min(item.evidence.run_number for item in failures)
    runs = [
        run
        for run in base.paginate_runs(api, repo, token)
        if run.get("path") == base.CONTINUATION_PATH
        and run.get("status") == "completed"
        and int(run.get("run_number") or 0) > min_run_number
    ]

    parsed: list[tuple[int, int, int | None, str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(parse_completed_candidate, api, repo, token, run) for run in runs]
        for future in concurrent.futures.as_completed(futures):
            value = future.result()
            if value is not None:
                parsed.append(value)

    recovered: list[tuple[PostDispatchFailure, int]] = []
    unresolved: list[PostDispatchFailure] = []
    for failure in failures:
        f = failure.evidence
        expected_segment = f.segment + 1
        expected_artifact = f"tlc-state-{f.profile}-{f.segment}"
        matches = [
            run_id
            for profile, segment, parent, artifact, run_id in parsed
            if profile == f.profile
            and segment == expected_segment
            and parent == f.run_id
            and artifact == expected_artifact
        ]
        if not matches:
            unresolved.append(failure)
            continue
        recovered.append((failure, min(matches)))
    return recovered, unresolved


def audit() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not repo or not token:
        base.fail("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    base.parse_failed_restore = parse_failed_or_dispatch
    try:
        rc = v3.audit()
    finally:
        base.parse_failed_restore = ORIGINAL_PARSE_FAILED_RESTORE
    if rc != 0:
        base.fail(f"v3 lineage audit returned unexpected status {rc}")

    failures = sorted(
        POST_DISPATCH.values(),
        key=lambda item: (
            item.evidence.profile,
            item.evidence.segment,
            item.evidence.run_id,
            item.run_attempt,
        ),
    )
    for failure in failures:
        verify_uploaded_artifact(api, repo, token, failure)

    recovered, unresolved = verify_dispatch_supersession(api, repo, token, failures)
    print(f"LAS_RESUMABLE_V4_POST_TLC_DISPATCH_FAILURE_COUNT={len(failures)}")
    print(f"LAS_RESUMABLE_V4_SUPERSEDED_DISPATCH_FAILURE_COUNT={len(recovered)}")
    print(f"LAS_RESUMABLE_V4_UNRESOLVED_DISPATCH_FAILURE_COUNT={len(unresolved)}")
    for failure, child_run in recovered:
        f = failure.evidence
        print(
            "LAS_RESUMABLE_V4_SUPERSEDED_DISPATCH_FAILURE="
            f"{f.profile}/{f.segment};RUN_ID={f.run_id};RUN_ATTEMPT={failure.run_attempt};"
            f"ARTIFACT=tlc-state-{f.profile}-{f.segment};CHILD_RUN_ID={child_run}"
        )
    for failure in unresolved:
        f = failure.evidence
        print(
            "LAS_RESUMABLE_V4_UNRESOLVED_DISPATCH_FAILURE="
            f"{f.profile}/{f.segment};RUN_ID={f.run_id};RUN_ATTEMPT={failure.run_attempt};"
            f"ARTIFACT=tlc-state-{f.profile}-{f.segment};NEXT_SEGMENT={f.segment + 1}"
        )

    if unresolved:
        base.fail(
            "post-TLC dispatch failures remain without exact completed child runs: "
            + ", ".join(
                f"{item.evidence.profile}/{item.evidence.segment}@{item.evidence.run_id}"
                for item in unresolved
            )
        )

    print("LAS_RESUMABLE_V4_DISPATCH_STALL_SUPERSESSION=PASS")
    print("LAS_RESUMABLE_V4_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(audit())
    except base.AuditError as exc:
        print(f"LAS_RESUMABLE_V4_AUDIT=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
