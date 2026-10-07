#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from verify_resumable_acceptance_chain import GitHubClient, VerificationError, require, step_map, verify_chain
from verify_resumable_acceptance_chain_v2 import verify_timing_chain

EXPECTED_PROFILE_COUNT = 203
EXPECTED_CANONICAL_PUBLIC_SHA = "a18f409ccca3178d50ce8d5485480ec8a4b2a50c"
EXPECTED_CANONICAL_WORKFLOW = ".github/workflows/private-current-exact-canonical-202-minus39.yml"
EXPECTED_RUNNER_BRANCH = "verify/current-exact-resumable-24244fc8"
EXPECTED_RUNNER_SHA = "f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb"
EXPECTED_SLICE_SECONDS = 1800
DIRECT_TIMEOUT_SECONDS = 360 * 60
DIRECT_TIMEOUT_TOLERANCE_SECONDS = 120


@dataclass(frozen=True)
class Coverage:
    direct: tuple[int, ...]
    fallback: tuple[int, ...]


def parse_utc(value: str | None, label: str) -> datetime:
    require(isinstance(value, str) and value, f"missing {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError(f"invalid {label}: {value!r}") from exc
    require(parsed.tzinfo is not None, f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def parse_fallback(values: list[str]) -> dict[int, int]:
    result: dict[int, int] = {}
    for raw in values:
        parts = raw.split("=", 1)
        require(len(parts) == 2 and all(parts), f"invalid --fallback {raw!r}; expected INDEX=RUN_ID")
        try:
            index = int(parts[0])
            run_id = int(parts[1])
        except ValueError as exc:
            raise VerificationError(f"invalid --fallback {raw!r}") from exc
        require(0 <= index < EXPECTED_PROFILE_COUNT, f"fallback index out of range: {index}")
        require(run_id > 0, f"invalid fallback run id for index {index}")
        require(index not in result, f"duplicate fallback index {index}")
        result[index] = run_id
    return result


def collect_all_jobs(client: GitHubClient, run_id: int) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = client.json(f"/actions/runs/{run_id}/jobs?per_page=100&page={page}")
        batch = payload.get("jobs") or []
        require(isinstance(batch, list), "jobs payload is not a list")
        jobs.extend(batch)
        if len(batch) < 100:
            total = payload.get("total_count")
            if isinstance(total, int):
                require(len(jobs) == total, f"job pagination incomplete: got={len(jobs)} expected={total}")
            break
        page += 1
        require(page <= 10, "unexpectedly large job pagination")
    return jobs


def indexed_tlc_jobs(jobs: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    prefix = "tlc ("
    for job in jobs:
        name = job.get("name")
        if not isinstance(name, str) or not (name.startswith(prefix) and name.endswith(")")):
            continue
        raw = name[len(prefix):-1]
        require(raw.isdigit(), f"malformed TLC job name {name!r}")
        index = int(raw)
        require(0 <= index < EXPECTED_PROFILE_COUNT, f"unexpected TLC job index {index}")
        require(index not in result, f"duplicate TLC job index {index}")
        result[index] = job
    require(set(result) == set(range(EXPECTED_PROFILE_COUNT)),
            f"canonical job coverage mismatch: got={len(result)} expected={EXPECTED_PROFILE_COUNT}")
    return result


def require_success_job(job: dict[str, Any], *, index: int) -> None:
    require(job.get("status") == "completed", f"direct profile {index} is not completed")
    require(job.get("conclusion") == "success", f"direct profile {index} is not success")
    steps = step_map(job)
    require(steps.get("Recover exact private materialized revision", {}).get("conclusion") == "success",
            f"direct profile {index} exact recovery did not succeed")
    require(steps.get("Run exact canonical TLC shard", {}).get("conclusion") == "success",
            f"direct profile {index} TLC step did not succeed")


def require_timeout_job(job: dict[str, Any], *, index: int) -> float:
    require(job.get("status") == "completed", f"fallback profile {index} direct job is not completed")
    # Only GitHub cancellation is substitutable. A direct semantic/tool failure is never overridden.
    require(job.get("conclusion") == "cancelled",
            f"fallback profile {index} direct conclusion is not cancelled: {job.get('conclusion')!r}")
    steps = step_map(job)
    require(steps.get("Recover exact private materialized revision", {}).get("conclusion") == "success",
            f"fallback profile {index} direct exact recovery did not succeed")
    tlc = steps.get("Run exact canonical TLC shard")
    require(tlc is not None, f"fallback profile {index} missing direct TLC step")
    require(tlc.get("conclusion") == "cancelled",
            f"fallback profile {index} direct TLC step was not cancelled")
    started = parse_utc(tlc.get("started_at"), f"profile {index} direct TLC started_at")
    completed = parse_utc(tlc.get("completed_at"), f"profile {index} direct TLC completed_at")
    elapsed = (completed - started).total_seconds()
    lower = DIRECT_TIMEOUT_SECONDS - DIRECT_TIMEOUT_TOLERANCE_SECONDS
    upper = DIRECT_TIMEOUT_SECONDS + DIRECT_TIMEOUT_TOLERANCE_SECONDS
    require(lower <= elapsed <= upper,
            f"fallback profile {index} cancellation not at 360-minute wall: elapsed={elapsed:.3f}s")
    # No later step may report semantic PASS/FAIL; timeout must be the terminal event.
    require(job.get("completed_at") is not None, f"fallback profile {index} missing job completion timestamp")
    return elapsed


def require_pre_tlc(jobs: list[dict[str, Any]]) -> None:
    matches = [j for j in jobs if j.get("name") == "pre_tlc"]
    require(len(matches) == 1, f"expected exactly one pre_tlc job, got {len(matches)}")
    job = matches[0]
    require(job.get("status") == "completed" and job.get("conclusion") == "success",
            "canonical pre_tlc did not succeed")
    steps = step_map(job)
    require(steps.get("Recover exact private materialized revision", {}).get("conclusion") == "success",
            "pre_tlc exact recovery did not succeed")
    require(steps.get("Run exact canonical pre-TLC verifier stage", {}).get("conclusion") == "success",
            "canonical pre_tlc verifier stage did not succeed")


def verify_run_identity(run: dict[str, Any], *, run_id: int) -> None:
    require(run.get("id") == run_id, "canonical run id mismatch")
    require(run.get("head_sha") == EXPECTED_CANONICAL_PUBLIC_SHA,
            f"canonical public workflow revision drifted: {run.get('head_sha')!r}")
    require(run.get("path") == EXPECTED_CANONICAL_WORKFLOW,
            f"unexpected canonical workflow path: {run.get('path')!r}")
    require(run.get("name") == "Current exact canonical 203 acceptance",
            f"unexpected canonical workflow name: {run.get('name')!r}")


def verify_mixed(
    client: GitHubClient,
    *,
    canonical_run_id: int,
    fallback_runs: dict[int, int],
) -> Coverage:
    run = client.json(f"/actions/runs/{canonical_run_id}")
    verify_run_identity(run, run_id=canonical_run_id)
    jobs = collect_all_jobs(client, canonical_run_id)
    require_pre_tlc(jobs)
    profiles = indexed_tlc_jobs(jobs)

    direct: list[int] = []
    fallback: list[int] = []
    for index in range(EXPECTED_PROFILE_COUNT):
        job = profiles[index]
        if index not in fallback_runs:
            require_success_job(job, index=index)
            direct.append(index)
            continue

        require_timeout_job(job, index=index)
        final_run_id = fallback_runs[index]
        chain = verify_chain(
            client,
            final_run_id=final_run_id,
            index=index,
            expected_branch=EXPECTED_RUNNER_BRANCH,
            expected_runner_sha=EXPECTED_RUNNER_SHA,
        )
        verify_timing_chain(
            client,
            chain,
            index=index,
            slice_seconds=EXPECTED_SLICE_SECONDS,
        )
        fallback.append(index)

    require(len(direct) + len(fallback) == EXPECTED_PROFILE_COUNT, "mixed coverage count mismatch")
    require(set(direct).isdisjoint(fallback), "direct/fallback coverage overlaps")
    require(set(direct) | set(fallback) == set(range(EXPECTED_PROFILE_COUNT)), "mixed coverage has gaps")
    return Coverage(tuple(direct), tuple(fallback))


def self_test() -> None:
    require(parse_fallback(["2=100", "28=200"]) == {2: 100, 28: 200}, "fallback parser positive test failed")
    for bad in (["2=100", "2=101"], ["203=1"], ["x=1"], ["2=0"], ["2"]):
        try:
            parse_fallback(list(bad))
        except VerificationError:
            pass
        else:
            raise VerificationError(f"fallback parser accepted invalid input {bad!r}")

    success_job = {
        "status": "completed",
        "conclusion": "success",
        "steps": [
            {"name": "Recover exact private materialized revision", "conclusion": "success"},
            {"name": "Run exact canonical TLC shard", "conclusion": "success"},
        ],
    }
    require_success_job(success_job, index=7)

    timeout_job = {
        "status": "completed",
        "conclusion": "cancelled",
        "completed_at": "2026-10-07T06:00:05Z",
        "steps": [
            {"name": "Recover exact private materialized revision", "conclusion": "success"},
            {
                "name": "Run exact canonical TLC shard",
                "conclusion": "cancelled",
                "started_at": "2026-10-07T00:00:05Z",
                "completed_at": "2026-10-07T06:00:05Z",
            },
        ],
    }
    elapsed = require_timeout_job(timeout_job, index=28)
    require(elapsed == DIRECT_TIMEOUT_SECONDS, "timeout positive test failed")

    semantic_failure = dict(timeout_job)
    semantic_failure["conclusion"] = "failure"
    try:
        require_timeout_job(semantic_failure, index=28)
    except VerificationError:
        pass
    else:
        raise VerificationError("semantic failure was incorrectly substitutable")

    early_cancel = dict(timeout_job)
    early_cancel["steps"] = [
        {"name": "Recover exact private materialized revision", "conclusion": "success"},
        {
            "name": "Run exact canonical TLC shard",
            "conclusion": "cancelled",
            "started_at": "2026-10-07T00:00:05Z",
            "completed_at": "2026-10-07T00:20:05Z",
        },
    ]
    try:
        require_timeout_job(early_cancel, index=28)
    except VerificationError:
        pass
    else:
        raise VerificationError("early cancellation was incorrectly substitutable")


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed mixed direct/resumable verifier for current canonical 203-profile acceptance.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default="oyzitjfzj/Shree-ji")
    parser.add_argument("--token")
    parser.add_argument("--canonical-run-id", type=int)
    parser.add_argument("--fallback", action="append", default=[], metavar="INDEX=FINAL_RUN_ID")
    args = parser.parse_args()
    try:
        self_test()
        if args.self_test and args.canonical_run_id is None:
            print("LAS_CURRENT_203_MIXED_SELF_TEST=PASS")
            return 0
        require(args.canonical_run_id is not None and args.canonical_run_id > 0, "--canonical-run-id is required")
        require(bool(args.token), "--token is required")
        fallback_runs = parse_fallback(args.fallback)
        client = GitHubClient(args.repo, args.token)
        coverage = verify_mixed(
            client,
            canonical_run_id=args.canonical_run_id,
            fallback_runs=fallback_runs,
        )
        print(f"LAS_CURRENT_203_MIXED_DIRECT_COUNT={len(coverage.direct)}")
        print(f"LAS_CURRENT_203_MIXED_FALLBACK_COUNT={len(coverage.fallback)}")
        if coverage.fallback:
            print("LAS_CURRENT_203_MIXED_FALLBACK_INDICES=" + ",".join(map(str, coverage.fallback)))
        print(f"LAS_CURRENT_203_MIXED_CANONICAL_RUN_ID={args.canonical_run_id}")
        print(f"LAS_CURRENT_203_MIXED_CANONICAL_PUBLIC_SHA={EXPECTED_CANONICAL_PUBLIC_SHA}")
        print(f"LAS_CURRENT_203_MIXED_RUNNER_SHA={EXPECTED_RUNNER_SHA}")
        print("LAS_CURRENT_203_MIXED_ACCEPTANCE=PASS")
        return 0
    except VerificationError as exc:
        print(f"LAS_CURRENT_203_MIXED_ACCEPTANCE=FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
