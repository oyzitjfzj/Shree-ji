#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone

from verify_resumable_acceptance_chain import (
    ALLOWED_SLICE_RCS,
    GitHubClient,
    SliceEvidence,
    VerificationError,
    choose_job,
    require,
    self_test as base_self_test,
    step_map,
    verify_chain,
)

DEFAULT_SLICE_SECONDS = 1800
MIN_WALL_TOLERANCE_SECONDS = 5
MAX_WALL_OVERHEAD_SECONDS = 120


def parse_utc(value: str, label: str) -> datetime:
    require(isinstance(value, str) and value, f"missing {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError(f"invalid {label}: {value!r}") from exc
    require(parsed.tzinfo is not None, f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def validate_checkpoint_timing(
    step: dict,
    evidence: SliceEvidence,
    *,
    slice_seconds: int,
) -> float:
    require(evidence.result == "SLICE_CHECKPOINT", "timing audit requires checkpoint slice")
    require(evidence.rc in ALLOWED_SLICE_RCS, f"unexpected checkpoint rc={evidence.rc}")
    started = parse_utc(step.get("started_at"), "TLC step started_at")
    completed = parse_utc(step.get("completed_at"), "TLC step completed_at")
    elapsed = (completed - started).total_seconds()
    require(elapsed >= 0, "negative TLC step duration")
    lower = max(0, slice_seconds - MIN_WALL_TOLERANCE_SECONDS)
    upper = slice_seconds + MAX_WALL_OVERHEAD_SECONDS
    require(
        lower <= elapsed <= upper,
        f"checkpoint slice rc={evidence.rc} did not occur at configured wall: "
        f"elapsed={elapsed:.3f}s expected={slice_seconds}s",
    )
    return elapsed


def verify_timing_chain(
    client: GitHubClient,
    chain: list[SliceEvidence],
    *,
    index: int,
    slice_seconds: int,
) -> None:
    require(slice_seconds > 0, "slice seconds must be positive")
    checked = 0
    for evidence in chain:
        if evidence.result != "SLICE_CHECKPOINT":
            continue
        payload = client.json(f"/actions/runs/{evidence.run_id}/jobs?per_page=100")
        jobs = payload.get("jobs") or []
        require(payload.get("total_count", len(jobs)) == len(jobs),
                "job list pagination would hide timing evidence")
        job = choose_job(jobs, index=index, segment=evidence.segment)
        steps = step_map(job)
        require("Run exact canonical TLC slice" in steps, "missing TLC slice step")
        validate_checkpoint_timing(
            steps["Run exact canonical TLC slice"],
            evidence,
            slice_seconds=slice_seconds,
        )
        checked += 1
    require(checked == max(0, len(chain) - 1),
            "every non-final segment must have timing evidence")


def self_test() -> None:
    base_self_test()
    evidence = SliceEvidence(
        run_id=1,
        segment=1,
        index=28,
        result="SLICE_CHECKPOINT",
        rc=137,
        queue=10,
        resume_run_id=None,
        resume_artifact="",
    )
    good = {
        "started_at": "2026-10-07T00:00:00Z",
        "completed_at": "2026-10-07T00:30:01Z",
    }
    elapsed = validate_checkpoint_timing(good, evidence, slice_seconds=1800)
    require(elapsed == 1801, "positive timing self-test failed")

    too_early = {
        "started_at": "2026-10-07T00:00:00Z",
        "completed_at": "2026-10-07T00:04:00Z",
    }
    try:
        validate_checkpoint_timing(too_early, evidence, slice_seconds=1800)
    except VerificationError:
        pass
    else:
        raise VerificationError("early rc=137 was incorrectly accepted as timeout slice")

    too_late = {
        "started_at": "2026-10-07T00:00:00Z",
        "completed_at": "2026-10-07T00:40:00Z",
    }
    try:
        validate_checkpoint_timing(too_late, evidence, slice_seconds=1800)
    except VerificationError:
        pass
    else:
        raise VerificationError("unbounded checkpoint timing was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hardened fail-closed verifier for exact resumable TLC acceptance chains."
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default="oyzitjfzj/Shree-ji")
    parser.add_argument("--token")
    parser.add_argument("--final-run-id", type=int)
    parser.add_argument("--index", type=int)
    parser.add_argument("--runner-branch", default="verify/current-exact-resumable-24244fc8")
    parser.add_argument("--runner-sha", default="f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb")
    parser.add_argument("--slice-seconds", type=int, default=DEFAULT_SLICE_SECONDS)
    args = parser.parse_args()

    try:
        self_test()
        if args.self_test and args.final_run_id is None:
            print("LAS_RESUMABLE_CHAIN_V2_SELF_TEST=PASS")
            return 0
        require(args.final_run_id is not None, "--final-run-id is required")
        require(args.index is not None and args.index >= 0,
                "--index must be a non-negative integer")
        require(bool(args.token), "--token is required")
        require(args.slice_seconds > 0, "--slice-seconds must be positive")

        client = GitHubClient(args.repo, args.token)
        chain = verify_chain(
            client,
            final_run_id=args.final_run_id,
            index=args.index,
            expected_branch=args.runner_branch,
            expected_runner_sha=args.runner_sha,
        )
        verify_timing_chain(
            client,
            chain,
            index=args.index,
            slice_seconds=args.slice_seconds,
        )
        print(f"LAS_RESUMABLE_CHAIN_V2_PROFILE_INDEX={args.index}")
        print(f"LAS_RESUMABLE_CHAIN_V2_SEGMENTS={len(chain)}")
        print(f"LAS_RESUMABLE_CHAIN_V2_FINAL_RUN_ID={args.final_run_id}")
        print(f"LAS_RESUMABLE_CHAIN_V2_RUNNER_SHA={args.runner_sha}")
        print("LAS_RESUMABLE_CHAIN_V2_ACCEPTANCE=PASS")
        return 0
    except VerificationError as exc:
        print(f"LAS_RESUMABLE_CHAIN_V2_ACCEPTANCE=FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
