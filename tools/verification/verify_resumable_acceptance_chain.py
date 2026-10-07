#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

API_VERSION = "2022-11-28"
REAL_MARKER_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[^ ]+Z (LAS_[A-Z0-9_]+)=(.*)$"
)
INPUT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[^ ]+Z {3}(index|segment|resume_run_id|resume_artifact):\s*(.*)$"
)
ALLOWED_SLICE_RCS = {124, 137, 143}


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ParsedLog:
    markers: dict[str, str]
    inputs: dict[str, str]


@dataclass(frozen=True)
class SliceEvidence:
    run_id: int
    segment: int
    index: int
    result: str
    rc: int
    queue: int
    resume_run_id: int | None
    resume_artifact: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def parse_timestamped_log(text: str) -> ParsedLog:
    markers_multi: dict[str, list[str]] = {}
    inputs_multi: dict[str, list[str]] = {}

    for raw in text.splitlines():
        marker = REAL_MARKER_RE.match(raw)
        if marker:
            markers_multi.setdefault(marker.group(1), []).append(marker.group(2).strip())
            continue
        inp = INPUT_RE.match(raw)
        if inp:
            inputs_multi.setdefault(inp.group(1), []).append(inp.group(2).strip())

    duplicate_markers = sorted(k for k, v in markers_multi.items() if len(v) != 1)
    require(not duplicate_markers, f"duplicate timestamped marker(s): {duplicate_markers}")
    duplicate_inputs = sorted(k for k, v in inputs_multi.items() if len(v) != 1)
    require(not duplicate_inputs, f"duplicate timestamped input(s): {duplicate_inputs}")

    return ParsedLog(
        markers={k: v[0] for k, v in markers_multi.items()},
        inputs={k: v[0] for k, v in inputs_multi.items()},
    )


def required_marker(parsed: ParsedLog, name: str) -> str:
    require(name in parsed.markers, f"missing marker: {name}")
    return parsed.markers[name]


def parse_nonnegative_int(value: str, label: str) -> int:
    require(re.fullmatch(r"\d+", value) is not None, f"{label} is not a non-negative integer")
    return int(value)


def parse_input_int(parsed: ParsedLog, name: str) -> int:
    require(name in parsed.inputs, f"missing workflow input: {name}")
    return parse_nonnegative_int(parsed.inputs[name], f"input {name}")


def classify_slice_log(
    text: str,
    *,
    expected_index: int,
    expected_segment: int | None = None,
    require_final_pass: bool = False,
) -> SliceEvidence:
    parsed = parse_timestamped_log(text)

    require(required_marker(parsed, "LAS_CURRENT_RESUME_REQUEST") == "PASS",
            "continuation request validation did not pass")
    require(required_marker(parsed, "LAS_CURRENT_RESUME_EXACT_RECOVERY") == "PASS",
            "exact private recovery did not pass")

    index = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_INDEX"), "marker index"
    )
    segment = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_SEGMENT"), "marker segment"
    )
    rc = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_RC"), "marker rc"
    )
    queue = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_QUEUE"), "marker queue"
    )
    generated = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_GENERATED"), "marker generated"
    )
    distinct = parse_nonnegative_int(
        required_marker(parsed, "LAS_CURRENT_RESUME_DISTINCT"), "marker distinct"
    )
    result = required_marker(parsed, "LAS_CURRENT_RESUME_RESULT")
    log_sha256 = required_marker(parsed, "LAS_CURRENT_RESUME_LOG_SHA256")
    require(re.fullmatch(r"[0-9a-f]{64}", log_sha256) is not None,
            "private TLC log digest is not a lowercase SHA-256")

    require(index == expected_index, f"profile index mismatch: {index} != {expected_index}")
    require(parse_input_int(parsed, "index") == expected_index, "workflow input index mismatch")
    require(parse_input_int(parsed, "segment") == segment, "workflow input segment mismatch")
    if expected_segment is not None:
        require(segment == expected_segment, f"segment mismatch: {segment} != {expected_segment}")
    require(segment >= 1, "segment must be >= 1")
    require(generated >= distinct >= queue, "impossible TLC progress counters")
    require(generated > 0 and distinct > 0, "TLC progress counters are vacuous")

    resume_run_text = parsed.inputs.get("resume_run_id", "")
    resume_artifact = parsed.inputs.get("resume_artifact", "")
    if segment == 1:
        require(resume_run_text == "", "segment 1 unexpectedly has resume_run_id")
        require(resume_artifact == "", "segment 1 unexpectedly has resume_artifact")
        resume_run_id = None
    else:
        require(re.fullmatch(r"\d+", resume_run_text) is not None,
                "resumed segment missing numeric resume_run_id")
        resume_run_id = int(resume_run_text)
        expected_artifact = f"tlc-state-{expected_index}-{segment - 1}"
        require(resume_artifact == expected_artifact,
                f"resume artifact mismatch: {resume_artifact!r} != {expected_artifact!r}")
        require(required_marker(parsed, "LAS_CURRENT_RESUME_CHECKPOINT_AUTH") == "PASS",
                "checkpoint authentication did not pass")
        require(required_marker(parsed, "LAS_CURRENT_RESUME_RECOVER_DIR") == "PASS",
                "checkpoint recovery directory was not validated")

    if result == "PASS":
        require(rc == 0, "PASS must have rc=0")
        require(queue == 0, "PASS must have queue=0")
    elif result == "SLICE_CHECKPOINT":
        require(rc in ALLOWED_SLICE_RCS, f"slice checkpoint has unexpected rc={rc}")
        meta_bytes = parse_nonnegative_int(
            required_marker(parsed, "LAS_CURRENT_RESUME_METADATA_BYTES"), "checkpoint metadata bytes"
        )
        artifact_bytes = parse_nonnegative_int(
            required_marker(parsed, "LAS_CURRENT_RESUME_ARTIFACT_BYTES"), "checkpoint artifact bytes"
        )
        next_segment = parse_nonnegative_int(
            required_marker(parsed, "LAS_CURRENT_RESUME_NEXT_SEGMENT"), "next segment"
        )
        require(meta_bytes > 0, "checkpoint metadata is empty")
        require(artifact_bytes > 0, "encrypted checkpoint artifact is empty")
        require(next_segment == segment + 1, "dispatched next segment is not contiguous")
    else:
        raise VerificationError(f"unexpected result marker: {result!r}")

    if require_final_pass:
        require(result == "PASS", "final segment is not PASS")

    return SliceEvidence(
        run_id=-1,
        segment=segment,
        index=index,
        result=result,
        rc=rc,
        queue=queue,
        resume_run_id=resume_run_id,
        resume_artifact=resume_artifact,
    )


class GitHubClient:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token

    def _request(self, url: str, *, accept: str = "application/vnd.github+json") -> bytes:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": accept,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "las-resumable-acceptance-verifier/1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            raise VerificationError(f"GitHub API request failed: {type(exc).__name__}") from exc

    def json(self, path_or_url: str) -> Any:
        url = path_or_url
        if not url.startswith("https://"):
            url = f"https://api.github.com/repos/{self.repo}{path_or_url}"
        return json.loads(self._request(url).decode("utf-8"))

    def text(self, path_or_url: str) -> str:
        data = self._request(path_or_url, accept="application/vnd.github+json")
        return data.decode("utf-8", errors="replace")


def step_map(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    steps = job.get("steps") or []
    out: dict[str, dict[str, Any]] = {}
    for step in steps:
        name = step.get("name")
        require(isinstance(name, str) and name, "job step missing name")
        require(name not in out, f"duplicate job step name: {name}")
        out[name] = step
    return out


def require_step(steps: dict[str, dict[str, Any]], name: str, conclusion: str) -> None:
    require(name in steps, f"missing job step: {name}")
    step = steps[name]
    require(step.get("status") == "completed", f"step not completed: {name}")
    require(step.get("conclusion") == conclusion,
            f"step {name!r} conclusion {step.get('conclusion')!r} != {conclusion!r}")


def validate_run_metadata(
    run: dict[str, Any],
    *,
    expected_branch: str,
    expected_runner_sha: str,
    segment: int | None,
) -> None:
    require(run.get("head_branch") == expected_branch, "public runner branch mismatch")
    require(run.get("head_sha") == expected_runner_sha, "public runner revision mismatch")
    referenced = run.get("referenced_workflows") or []
    require(len(referenced) == 1, "expected exactly one referenced reusable workflow")
    ref = referenced[0]
    require(ref.get("sha") == expected_runner_sha, "reusable workflow SHA mismatch")
    require(ref.get("ref") == f"refs/heads/{expected_branch}", "reusable workflow ref mismatch")
    if segment == 1:
        require(run.get("event") == "push", "segment 1 must originate from frozen bootstrap push")
        require(str(run.get("path", "")).endswith(
            ".github/workflows/current-exact-resumable-frozen-bootstrap.yml"
        ), "segment 1 workflow path mismatch")
    elif segment is not None:
        require(run.get("event") == "workflow_dispatch", "continued segment must be workflow_dispatch")
        require(str(run.get("path", "")).endswith(
            ".github/workflows/private-assurance-slow-tlc-continuation.yml"
        ), "continuation workflow path mismatch")


def choose_job(jobs: Iterable[dict[str, Any]], *, index: int, segment: int) -> dict[str, Any]:
    jobs = list(jobs)
    if segment == 1:
        expected_name = f"bootstrap ({index}) / slice"
        matches = [j for j in jobs if j.get("name") == expected_name]
    else:
        matches = [j for j in jobs if j.get("name") == "continuation / slice"]
    require(len(matches) == 1, f"expected one exact slice job, found {len(matches)}")
    return matches[0]


def validate_job(job: dict[str, Any], *, result: str, segment: int) -> None:
    require(job.get("status") == "completed", "slice job not completed")
    require(job.get("conclusion") == "success", "slice job conclusion is not success")
    steps = step_map(job)
    for name in (
        "Set up job",
        "Validate continuation request",
        "Reclaim runner storage for exhaustive TLC",
        "Recover exact private frozen candidate",
        "Run exact canonical TLC slice",
        "Complete job",
    ):
        require_step(steps, name, "success")

    if segment == 1:
        require_step(steps, "Download prior authenticated encrypted checkpoint", "skipped")
        require_step(steps, "Authenticate and restore prior checkpoint", "skipped")
    else:
        require_step(steps, "Download prior authenticated encrypted checkpoint", "success")
        require_step(steps, "Authenticate and restore prior checkpoint", "success")

    if result == "SLICE_CHECKPOINT":
        for name in (
            "Seal authenticated encrypted checkpoint",
            "Upload authenticated encrypted checkpoint",
            "Dispatch next slice",
        ):
            require_step(steps, name, "success")
    else:
        for name in (
            "Seal authenticated encrypted checkpoint",
            "Upload authenticated encrypted checkpoint",
            "Dispatch next slice",
        ):
            require_step(steps, name, "skipped")


def verify_chain(
    client: GitHubClient,
    *,
    final_run_id: int,
    index: int,
    expected_branch: str,
    expected_runner_sha: str,
) -> list[SliceEvidence]:
    current_run_id = final_run_id
    expected_segment: int | None = None
    reverse_chain: list[SliceEvidence] = []
    seen: set[int] = set()
    first = True

    while True:
        require(current_run_id not in seen, "cycle detected in resume_run_id chain")
        seen.add(current_run_id)

        run = client.json(f"/actions/runs/{current_run_id}")
        jobs_payload = client.json(f"/actions/runs/{current_run_id}/jobs?per_page=100")
        jobs = jobs_payload.get("jobs") or []
        require(jobs_payload.get("total_count", len(jobs)) == len(jobs),
                "job list pagination would hide evidence")

        candidate_jobs = [
            j for j in jobs
            if j.get("name") == "continuation / slice"
            or j.get("name") == f"bootstrap ({index}) / slice"
        ]
        require(len(candidate_jobs) == 1, f"expected one candidate slice job, found {len(candidate_jobs)}")
        job = candidate_jobs[0]
        log_url = f"https://api.github.com/repos/{client.repo}/actions/jobs/{job['id']}/logs"
        log_text = client.text(log_url)
        evidence = classify_slice_log(
            log_text,
            expected_index=index,
            expected_segment=expected_segment,
            require_final_pass=first,
        )
        evidence = SliceEvidence(
            run_id=current_run_id,
            segment=evidence.segment,
            index=evidence.index,
            result=evidence.result,
            rc=evidence.rc,
            queue=evidence.queue,
            resume_run_id=evidence.resume_run_id,
            resume_artifact=evidence.resume_artifact,
        )

        validate_run_metadata(
            run,
            expected_branch=expected_branch,
            expected_runner_sha=expected_runner_sha,
            segment=evidence.segment,
        )
        validate_job(job, result=evidence.result, segment=evidence.segment)

        if not first:
            require(evidence.result == "SLICE_CHECKPOINT",
                    "non-final predecessor segment must be a checkpoint slice")
        reverse_chain.append(evidence)

        if evidence.segment == 1:
            require(evidence.resume_run_id is None, "segment 1 has predecessor")
            break

        require(evidence.resume_run_id is not None, "resumed segment has no predecessor run")
        expected_segment = evidence.segment - 1
        current_run_id = evidence.resume_run_id
        first = False

    chain = list(reversed(reverse_chain))
    require(chain[0].segment == 1, "chain does not begin at segment 1")
    require(chain[-1].run_id == final_run_id, "chain does not end at requested final run")
    for left, right in zip(chain, chain[1:]):
        require(right.segment == left.segment + 1, "non-contiguous segment chain")
        require(right.resume_run_id == left.run_id, "resume_run_id does not link to predecessor")
        require(right.resume_artifact == f"tlc-state-{index}-{left.segment}",
                "resume artifact does not link to predecessor segment")
    require(chain[-1].result == "PASS", "chain final result is not PASS")
    return chain


def _ts(payload: str) -> str:
    return f"2026-10-07T00:00:00.0000000Z {payload}"


def _synthetic_log(
    *,
    index: int,
    segment: int,
    result: str,
    rc: int,
    queue: int,
    resume_run_id: str = "",
    resume_artifact: str = "",
) -> str:
    rows = [
        _ts("##[group] Inputs"),
        _ts(f"  index: {index}"),
        _ts(f"  segment: {segment}"),
        _ts(f"  resume_run_id: {resume_run_id}"),
        _ts(f"  resume_artifact: {resume_artifact}"),
        _ts("##[endgroup]"),
        _ts("LAS_CURRENT_RESUME_REQUEST=PASS"),
        _ts("LAS_CURRENT_RESUME_EXACT_RECOVERY=PASS"),
    ]
    if segment > 1:
        rows += [
            _ts("LAS_CURRENT_RESUME_CHECKPOINT_AUTH=PASS"),
            _ts("LAS_CURRENT_RESUME_RECOVER_DIR=PASS"),
        ]
    rows += [
        _ts(f"LAS_CURRENT_RESUME_INDEX={index}"),
        _ts(f"LAS_CURRENT_RESUME_SEGMENT={segment}"),
        _ts("LAS_CURRENT_RESUME_GENERATED=100"),
        _ts("LAS_CURRENT_RESUME_DISTINCT=80"),
        _ts(f"LAS_CURRENT_RESUME_QUEUE={queue}"),
        _ts(f"LAS_CURRENT_RESUME_RC={rc}"),
        _ts("LAS_CURRENT_RESUME_LOG_SHA256=" + "a" * 64),
        _ts(f"LAS_CURRENT_RESUME_RESULT={result}"),
    ]
    if result == "SLICE_CHECKPOINT":
        rows += [
            _ts("LAS_CURRENT_RESUME_METADATA_BYTES=1000"),
            _ts("LAS_CURRENT_RESUME_ARTIFACT_BYTES=500"),
            _ts(f"LAS_CURRENT_RESUME_NEXT_SEGMENT={segment + 1}"),
        ]
    return "\n".join(rows) + "\n"


def self_test() -> None:
    ev = classify_slice_log(
        _synthetic_log(index=2, segment=1, result="PASS", rc=0, queue=0),
        expected_index=2,
        expected_segment=1,
        require_final_pass=True,
    )
    require(ev.result == "PASS", "positive segment1 self-test failed")

    ev = classify_slice_log(
        _synthetic_log(
            index=28, segment=2, result="SLICE_CHECKPOINT", rc=137, queue=10,
            resume_run_id="123", resume_artifact="tlc-state-28-1",
        ),
        expected_index=28,
        expected_segment=2,
    )
    require(ev.resume_run_id == 123, "positive resumed self-test failed")

    fake = (
        _ts("\x1b[36;1mecho \"LAS_CURRENT_RESUME_REQUEST=PASS\"\x1b[0m") + "\n" +
        _ts("\x1b[36;1mecho \"LAS_CURRENT_RESUME_RESULT=PASS\"\x1b[0m") + "\n"
    )
    try:
        classify_slice_log(fake, expected_index=2)
    except VerificationError:
        pass
    else:
        raise VerificationError("script-echo-only evidence was incorrectly accepted")

    try:
        classify_slice_log(
            _synthetic_log(index=2, segment=1, result="PASS", rc=0, queue=1),
            expected_index=2,
            require_final_pass=True,
        )
    except VerificationError:
        pass
    else:
        raise VerificationError("nonzero final queue was accepted")

    try:
        classify_slice_log(
            _synthetic_log(
                index=28, segment=2, result="SLICE_CHECKPOINT", rc=137, queue=10,
                resume_run_id="123", resume_artifact="tlc-state-28-9",
            ),
            expected_index=28,
        )
    except VerificationError:
        pass
    else:
        raise VerificationError("wrong resume artifact was accepted")

    broken = _synthetic_log(
        index=28, segment=2, result="SLICE_CHECKPOINT", rc=137, queue=10,
        resume_run_id="123", resume_artifact="tlc-state-28-1",
    ).replace(_ts("LAS_CURRENT_RESUME_CHECKPOINT_AUTH=PASS") + "\n", "")
    try:
        classify_slice_log(broken, expected_index=28)
    except VerificationError:
        pass
    else:
        raise VerificationError("missing checkpoint auth was accepted")

    dup = _synthetic_log(index=2, segment=1, result="PASS", rc=0, queue=0)
    dup += _ts("LAS_CURRENT_RESUME_RESULT=PASS") + "\n"
    try:
        classify_slice_log(dup, expected_index=2)
    except VerificationError:
        pass
    else:
        raise VerificationError("duplicate result marker was accepted")

    class FakeClient:
        repo = "oyzitjfzj/Shree-ji"

        def __init__(self):
            self.runner_sha = "f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb"
            self.branch = "verify/current-exact-resumable-24244fc8"
            self.logs = {
                101: _synthetic_log(
                    index=28, segment=1, result="SLICE_CHECKPOINT", rc=137, queue=10
                ),
                102: _synthetic_log(
                    index=28, segment=2, result="PASS", rc=0, queue=0,
                    resume_run_id="1001", resume_artifact="tlc-state-28-1",
                ),
            }

        @staticmethod
        def _steps(segment, result):
            rows = [
                ("Set up job", "success"),
                ("Validate continuation request", "success"),
                ("Reclaim runner storage for exhaustive TLC", "success"),
                ("Recover exact private frozen candidate", "success"),
                ("Download prior authenticated encrypted checkpoint",
                 "skipped" if segment == 1 else "success"),
                ("Authenticate and restore prior checkpoint",
                 "skipped" if segment == 1 else "success"),
                ("Run exact canonical TLC slice", "success"),
                ("Seal authenticated encrypted checkpoint",
                 "success" if result == "SLICE_CHECKPOINT" else "skipped"),
                ("Upload authenticated encrypted checkpoint",
                 "success" if result == "SLICE_CHECKPOINT" else "skipped"),
                ("Dispatch next slice",
                 "success" if result == "SLICE_CHECKPOINT" else "skipped"),
                ("Complete job", "success"),
            ]
            return [
                {"name": name, "status": "completed", "conclusion": conclusion, "number": i + 1}
                for i, (name, conclusion) in enumerate(rows)
            ]

        def _run(self, run_id, segment):
            return {
                "id": run_id,
                "head_branch": self.branch,
                "head_sha": self.runner_sha,
                "event": "push" if segment == 1 else "workflow_dispatch",
                "path": (
                    ".github/workflows/current-exact-resumable-frozen-bootstrap.yml"
                    if segment == 1
                    else ".github/workflows/private-assurance-slow-tlc-continuation.yml"
                ),
                "referenced_workflows": [{
                    "sha": self.runner_sha,
                    "ref": f"refs/heads/{self.branch}",
                }],
            }

        def json(self, path_or_url):
            if path_or_url == "/actions/runs/1002":
                return self._run(1002, 2)
            if path_or_url == "/actions/runs/1001":
                return self._run(1001, 1)
            if path_or_url == "/actions/runs/1002/jobs?per_page=100":
                job = {
                    "id": 102, "name": "continuation / slice",
                    "status": "completed", "conclusion": "success",
                    "steps": self._steps(2, "PASS"),
                }
                return {"total_count": 1, "jobs": [job]}
            if path_or_url == "/actions/runs/1001/jobs?per_page=100":
                job = {
                    "id": 101, "name": "bootstrap (28) / slice",
                    "status": "completed", "conclusion": "success",
                    "steps": self._steps(1, "SLICE_CHECKPOINT"),
                }
                return {"total_count": 1, "jobs": [job]}
            raise AssertionError(path_or_url)

        def text(self, url):
            job_id = int(url.rstrip("/").split("/")[-2])
            return self.logs[job_id]

    chain = verify_chain(
        FakeClient(),
        final_run_id=1002,
        index=28,
        expected_branch="verify/current-exact-resumable-24244fc8",
        expected_runner_sha="f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb",
    )
    require([x.segment for x in chain] == [1, 2], "full chain self-test segment order failed")
    require(chain[-1].result == "PASS", "full chain self-test final result failed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed verifier for an exact Living Assurance resumable TLC acceptance chain."
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default="oyzitjfzj/Shree-ji")
    parser.add_argument("--token")
    parser.add_argument("--final-run-id", type=int)
    parser.add_argument("--index", type=int)
    parser.add_argument("--runner-branch", default="verify/current-exact-resumable-24244fc8")
    parser.add_argument("--runner-sha", default="f0c9f9fbb77292cb2aae2c0d02545f1e45f028cb")
    args = parser.parse_args()

    try:
        self_test()
        if args.self_test and args.final_run_id is None:
            print("LAS_RESUMABLE_CHAIN_SELF_TEST=PASS")
            return 0

        require(args.final_run_id is not None, "--final-run-id is required")
        require(args.index is not None and args.index >= 0, "--index must be a non-negative integer")
        require(bool(args.token), "--token is required")

        chain = verify_chain(
            GitHubClient(args.repo, args.token),
            final_run_id=args.final_run_id,
            index=args.index,
            expected_branch=args.runner_branch,
            expected_runner_sha=args.runner_sha,
        )
        print(f"LAS_RESUMABLE_CHAIN_PROFILE_INDEX={args.index}")
        print(f"LAS_RESUMABLE_CHAIN_SEGMENTS={len(chain)}")
        print(f"LAS_RESUMABLE_CHAIN_FINAL_RUN_ID={args.final_run_id}")
        print(f"LAS_RESUMABLE_CHAIN_RUNNER_SHA={args.runner_sha}")
        print("LAS_RESUMABLE_CHAIN_ACCEPTANCE=PASS")
        return 0
    except VerificationError as exc:
        print(f"LAS_RESUMABLE_CHAIN_ACCEPTANCE=FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
