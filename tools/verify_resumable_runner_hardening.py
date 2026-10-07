#!/usr/bin/env python3
"""Fail-closed structural and adversarial verifier for resumable TLC runner v2."""

from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_private-assurance-tlc-continuation-slice-v2.yml"
CALLER = ROOT / ".github/workflows/private-assurance-slow-tlc-continuation-v2.yml"


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def require_once(text: str, needle: str, label: str) -> None:
    count = text.count(needle)
    if count != 1:
        fail(f"{label}: expected exactly one occurrence, found {count}")


def require_present(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"{label}: required construct missing")


def require_order(text: str, first: str, second: str, label: str) -> None:
    a = text.find(first)
    b = text.find(second)
    if a < 0 or b < 0 or a >= b:
        fail(f"{label}: required ordering not preserved")


def verify_contract(workflow: str, caller: str) -> None:
    exact = (
        ("RUNNER_WORKFLOW_SHA: ${{ job.workflow_sha }}", "job workflow SHA binding"),
        ("RUNNER_WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}", "job repository binding"),
        ("RUNNER_WORKFLOW_PATH: ${{ job.workflow_file_path }}", "job workflow path binding"),
        ('test "$GITHUB_SHA" = "$RUNNER_WORKFLOW_SHA"', "caller/callee commit equality"),
        ('test "$EXPECTED_WORKFLOW_SHA" = "$RUNNER_WORKFLOW_SHA"', "continuation SHA equality"),
        ('test "$RESUME_ARTIFACT" = "tlc-state-${TARGET_INDEX}-$((SEGMENT - 1))"', "artifact chain binding"),
        ('data.get("head_sha") != expected_sha', "prior run SHA provenance"),
        ('data.get("path") not in allowed_paths', "prior workflow provenance"),
        ('data.get("event") != "workflow_dispatch"', "prior event provenance"),
        ('".github/workflows/private-assurance-slow-tlc-continuation-v2.yml"', "continuation allowlist"),
        ('".github/workflows/current-exact-resumable-frozen-bootstrap-v2.yml"', "bootstrap allowlist"),
        ('workflow_sha=$RUNNER_WORKFLOW_SHA', "manifest workflow SHA"),
        ('workflow_path=$RUNNER_WORKFLOW_PATH', "manifest workflow path"),
        ('producer_run=$GITHUB_RUN_ID', "manifest producer run"),
        ('grep -qx "producer_run=$RESUME_RUN_ID"', "producer run restore binding"),
        ('TLA_TOOLS_SHA256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88', "TLC SHA-256 pin"),
        ('TLA_TOOLS_SHA1: bee4a54f3ee3d4afc347c3240ec2d9e93b075104', "upstream TLC SHA-1 pin"),
        ('echo "$TLA_TOOLS_SHA256  $TLA_JAR" | sha256sum --check --strict', "TLC SHA-256 enforcement"),
        ('echo "$TLA_TOOLS_SHA1  $TLA_JAR" | sha1sum --check --strict', "TLC SHA-1 enforcement"),
        ('"ref": ref_name', "same-ref continuation dispatch"),
        ('"expected_workflow_sha": workflow_sha', "next-segment SHA handoff"),
    )
    for needle, label in exact:
        require_present(workflow, needle, label)

    for forbidden, label in (
        ('"ref":"verify/current-exact-resumable-24244fc8"', "hard-coded mutable branch dispatch"),
        ("tar -xzf \"$archive\" -C \"$RUNNER_TEMP\"", "unhardened tar extraction form"),
    ):
        if forbidden in workflow:
            fail(f"{label}: forbidden construct present")

    # Encryption is encrypt-then-MAC: ciphertext authenticity must be checked before decryption.
    require_order(
        workflow,
        'test "$actual_mac" = "$expected_mac"',
        'openssl enc -d -aes-256-cbc',
        "authenticate before decrypt",
    )
    require_order(
        workflow,
        'print("LAS_CURRENT_RESUME_V2_ARCHIVE_PREFLIGHT=PASS")',
        'tar -xzf "$archive" --no-same-owner --no-same-permissions',
        "archive preflight before extraction",
    )
    require_order(
        workflow,
        "Validate prior run provenance",
        "Download prior authenticated encrypted checkpoint",
        "provenance before artifact download",
    )

    # Domain separation and runner identity must affect both confidentiality and authenticity keys.
    for suffix in ("enc", "mac"):
        marker = f"$GITHUB_REPOSITORY\" \"$RUNNER_WORKFLOW_SHA\" \"$RUNNER_WORKFLOW_PATH\" | sha256sum"
        require_present(workflow, marker, f"{suffix} key runner binding")

    # Pinned third-party artifact actions only; floating tags are forbidden in this gate.
    require_present(workflow, "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093", "download action pin")
    require_present(workflow, "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "upload action pin")
    if "actions/download-artifact@v" in workflow or "actions/upload-artifact@v" in workflow:
        fail("floating artifact action tag present")

    # The caller must pass every chain-binding input without reinterpretation.
    for needle in (
        "uses: ./.github/workflows/_private-assurance-tlc-continuation-slice-v2.yml",
        "expected_workflow_sha: ${{ inputs.expected_workflow_sha }}",
        "resume_run_id: ${{ inputs.resume_run_id }}",
        "resume_artifact: ${{ inputs.resume_artifact }}",
    ):
        require_present(caller, needle, "caller forwarding contract")


def extract_archive_preflight(workflow: str) -> str:
    start_marker = '          python3 - "$archive" <<\'PY\'\n'
    end_marker = "\n          PY\n          tar -xzf \"$archive\" --no-same-owner --no-same-permissions -C \"$RUNNER_TEMP\""
    require_once(workflow, start_marker, "archive preflight start")
    require_once(workflow, end_marker, "archive preflight end")
    start = workflow.index(start_marker) + len(start_marker)
    end = workflow.index(end_marker, start)
    return textwrap.dedent(workflow[start:end])


def add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    tf.addfile(info, io.BytesIO(data))


def make_good(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        directory = tarfile.TarInfo("tlc-meta")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o700
        tf.addfile(directory)
        add_bytes(tf, "tlc-meta/queue.chkpt", b"queue")
        add_bytes(tf, "tlc-meta/vars.chkpt", b"vars")


def make_traversal(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        add_bytes(tf, "tlc-meta/../../escape", b"bad")


def make_absolute(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        add_bytes(tf, "/tmp/escape", b"bad")


def make_symlink(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        link = tarfile.TarInfo("tlc-meta/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp/escape"
        tf.addfile(link)


def run_preflight(script: Path, archive: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), str(archive)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def verify_archive_preflight_exact_code(workflow: str) -> None:
    code = extract_archive_preflight(workflow)
    with tempfile.TemporaryDirectory(prefix="las-hardening-") as td:
        root = Path(td)
        script = root / "preflight.py"
        script.write_text(code + "\n", encoding="utf-8")

        cases = (
            ("good", make_good, True),
            ("traversal", make_traversal, False),
            ("absolute", make_absolute, False),
            ("symlink", make_symlink, False),
        )
        for name, maker, should_pass in cases:
            archive = root / f"{name}.tar.gz"
            maker(archive)
            result = run_preflight(script, archive)
            passed = result.returncode == 0
            if passed != should_pass:
                fail(
                    f"archive preflight case {name!r} unexpected result rc={result.returncode}; "
                    f"stdout={result.stdout!r}; stderr={result.stderr!r}"
                )


def expect_contract_rejected(workflow: str, caller: str, old: str, new: str, label: str) -> None:
    if workflow.count(old) != 1:
        fail(f"self-test fixture {label!r} is not unique")
    bad = workflow.replace(old, new, 1)
    try:
        verify_contract(bad, caller)
    except VerificationError:
        return
    fail(f"hardening verifier self-test accepted invalid drift: {label}")


def self_test(workflow: str, caller: str) -> None:
    expect_contract_rejected(
        workflow,
        caller,
        'test "$GITHUB_SHA" = "$RUNNER_WORKFLOW_SHA"',
        'test -n "$RUNNER_WORKFLOW_SHA"',
        "remove caller/callee commit equality",
    )
    expect_contract_rejected(
        workflow,
        caller,
        'test "$actual_mac" = "$expected_mac"',
        'test -n "$actual_mac"',
        "remove ciphertext authentication equality",
    )
    expect_contract_rejected(
        workflow,
        caller,
        '"expected_workflow_sha": workflow_sha',
        '"expected_workflow_sha": ""',
        "remove next-segment runner identity handoff",
    )


def main() -> int:
    if not WORKFLOW.is_file() or not CALLER.is_file():
        fail("required v2 hardening workflow files are missing")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    caller = CALLER.read_text(encoding="utf-8")
    verify_contract(workflow, caller)
    verify_archive_preflight_exact_code(workflow)
    self_test(workflow, caller)
    print("LAS_RESUMABLE_RUNNER_V2_CONTRACT=PASS")
    print("LAS_RESUMABLE_RUNNER_V2_ARCHIVE_PREFLIGHT=PASS")
    print("LAS_RESUMABLE_RUNNER_V2_SELFTEST=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"LAS_RESUMABLE_RUNNER_V2=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
