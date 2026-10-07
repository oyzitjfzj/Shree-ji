#!/usr/bin/env python3
"""Adversarial, fail-closed verifier for the hardened resumable TLC runner."""

from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / ".github/workflows/_private-assurance-tlc-continuation-slice-v2.yml"
CONTINUATION = ROOT / ".github/workflows/private-assurance-slow-tlc-continuation-v2.yml"
BOOTSTRAP = ROOT / ".github/workflows/current-exact-resumable-frozen-bootstrap-v2.yml"

class Error(RuntimeError):
    pass

def fail(msg: str) -> None:
    raise Error(msg)

def once(text: str, needle: str, label: str) -> None:
    count = text.count(needle)
    if count != 1:
        fail(f"{label}: expected one occurrence, found {count}")

def present(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"{label}: missing")

def ordered(text: str, first: str, second: str, label: str) -> None:
    a, b = text.find(first), text.find(second)
    if a < 0 or b < 0 or a >= b:
        fail(f"{label}: ordering broken")

def verify_runner_contract(text: str) -> None:
    requirements = {
        "job SHA": "RUNNER_WORKFLOW_SHA: ${{ job.workflow_sha }}",
        "job repo": "RUNNER_WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}",
        "job path": "RUNNER_WORKFLOW_PATH: ${{ job.workflow_file_path }}",
        "same repo": 'test "$RUNNER_WORKFLOW_REPOSITORY" = "$GITHUB_REPOSITORY"',
        "exact reusable path": 'test "$RUNNER_WORKFLOW_PATH" = ".github/workflows/_private-assurance-tlc-continuation-slice-v2.yml"',
        "same caller/callee commit": 'test "$GITHUB_SHA" = "$RUNNER_WORKFLOW_SHA"',
        "continuation SHA lease": 'test "$EXPECTED_WORKFLOW_SHA" = "$RUNNER_WORKFLOW_SHA"',
        "artifact chain": 'test "$RESUME_ARTIFACT" = "tlc-state-${TARGET_INDEX}-$((SEGMENT - 1))"',
        "prior run SHA": 'data.get("head_sha") != expected_sha',
        "prior repo": 'repo != expected_repo',
        "prior path": 'data.get("path") not in allowed_paths',
        "prior event": 'data.get("event") != "workflow_dispatch"',
        "prior conclusion": 'data.get("conclusion") not in {None, "success"}',
        "continuation provenance path": '".github/workflows/private-assurance-slow-tlc-continuation-v2.yml"',
        "bootstrap provenance path": '".github/workflows/current-exact-resumable-frozen-bootstrap-v2.yml"',
        "manifest restore workflow SHA": 'grep -qx "workflow_sha=$RUNNER_WORKFLOW_SHA"',
        "manifest restore workflow path": 'grep -qx "workflow_path=$RUNNER_WORKFLOW_PATH"',
        "manifest restore producer": 'grep -qx "producer_run=$RESUME_RUN_ID"',
        "SHA256 pin": "TLA_TOOLS_SHA256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
        "official SHA1 pin": "TLA_TOOLS_SHA1: bee4a54f3ee3d4afc347c3240ec2d9e93b075104",
        "SHA256 enforcement": 'echo "$TLA_TOOLS_SHA256  $TLA_JAR" | sha256sum --check --strict',
        "SHA1 enforcement": 'echo "$TLA_TOOLS_SHA1  $TLA_JAR" | sha1sum --check --strict',
        "same-ref next dispatch": '"ref": ref_name',
        "next SHA handoff": '"expected_workflow_sha": workflow_sha',
        "pinned download action": "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "pinned upload action": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    }
    for label, needle in requirements.items():
        present(text, needle, label)

    for forbidden in (
        '"ref":"verify/current-exact-resumable-24244fc8"',
        "actions/download-artifact@v",
        "actions/upload-artifact@v",
        'tar -xzf "$archive" -C "$RUNNER_TEMP"',
    ):
        if forbidden in text:
            fail(f"forbidden construct present: {forbidden}")

    ordered(text, 'test "$actual_mac" = "$expected_mac"', "openssl enc -d -aes-256-cbc", "MAC before decrypt")
    ordered(text, "Validate prior run provenance", "Download prior authenticated encrypted checkpoint", "provenance before artifact")
    ordered(text, 'print("LAS_CURRENT_RESUME_V2_ARCHIVE_PREFLIGHT=PASS")', 'tar -xzf "$archive" --no-same-owner --no-same-permissions', "preflight before extract")

    tokens = [
        '"$PRIVATE_TOKEN"', '"$EXPECTED_PRIVATE_SNAPSHOT_PROOF"', '"$EXPECTED_PRIVATE_TREE_PROOF"',
        '"$EXPECTED_VERIFIER_BLOB"', '"$TARGET_INDEX"', '"$GITHUB_REPOSITORY"',
        '"$RUNNER_WORKFLOW_SHA"', '"$RUNNER_WORKFLOW_PATH"',
    ]
    for variable, domain in (("LAS_CHECKPOINT_SECRET", "enc"), ("LAS_CHECKPOINT_MAC_KEY", "mac")):
        lines = [line.strip() for line in text.splitlines() if line.strip().startswith(f'{variable}="$(printf ')]
        if len(lines) != 2:
            fail(f"{variable}: expected restore+seal derivations, got {len(lines)}")
        for n, line in enumerate(lines, 1):
            positions = [line.find(token) for token in tokens]
            if any(p < 0 for p in positions) or positions != sorted(positions) or len(set(positions)) != len(positions):
                fail(f"{variable} derivation {n}: identity binding incomplete/reordered")
            if f"\\0{domain}'" not in line:
                fail(f"{variable} derivation {n}: domain separator missing")
            if "| sha256sum | awk '{print $1}')\"" not in line:
                fail(f"{variable} derivation {n}: derivation hash changed")

    fmt = "printf 'snapshot=%s\\ntree=%s\\nverifier=%s\\nindex=%s\\nsegment=%s\\nworkflow_sha=%s\\nworkflow_path=%s\\nproducer_run=%s\\nproducer_attempt=%s\\n'"
    present(text, fmt, "manifest exact schema")
    arg1 = '"$EXPECTED_PRIVATE_SNAPSHOT_PROOF" "$EXPECTED_PRIVATE_TREE_PROOF" "$EXPECTED_VERIFIER_BLOB"'
    arg2 = '"$TARGET_INDEX" "$SEGMENT" "$RUNNER_WORKFLOW_SHA" "$RUNNER_WORKFLOW_PATH"'
    arg3 = '"$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" >"$meta/las-resume-manifest.txt"'
    present(text, arg1, "manifest proof arguments")
    present(text, arg2, "manifest runner arguments")
    present(text, arg3, "manifest producer arguments")

def verify_callers(continuation: str, bootstrap: str) -> None:
    for text, label in ((continuation, "continuation"), (bootstrap, "bootstrap")):
        present(text, "uses: ./.github/workflows/_private-assurance-tlc-continuation-slice-v2.yml", f"{label} local reusable binding")
        present(text, "secrets: inherit", f"{label} secret forwarding")
    for needle in (
        "expected_workflow_sha: ${{ inputs.expected_workflow_sha }}",
        "resume_run_id: ${{ inputs.resume_run_id }}",
        "resume_artifact: ${{ inputs.resume_artifact }}",
    ):
        present(continuation, needle, "continuation input forwarding")
    present(continuation, "workflow_dispatch:", "continuation dispatch-only entry")
    present(bootstrap, "workflow_dispatch:", "bootstrap dispatch-only entry")
    if "push:" in bootstrap or "pull_request:" in bootstrap:
        fail("bootstrap must not create resumable provenance from a push/PR event")
    expected = "index: [2, 28, 29, 36, 110, 115, 133, 145, 156, 157, 168, 172]"
    present(bootstrap, expected, "exact frozen remaining profile set")
    present(bootstrap, 'expected_workflow_sha: ""', "bootstrap segment-1 identity contract")

def extract_preflight(text: str) -> str:
    start = '          python3 - "$archive" <<\'PY\'\n'
    end = '\n          PY\n          tar -xzf "$archive" --no-same-owner --no-same-permissions -C "$RUNNER_TEMP"'
    once(text, start, "preflight start")
    once(text, end, "preflight end")
    a = text.index(start) + len(start)
    b = text.index(end, a)
    return textwrap.dedent(text[a:b])

def add_file(tf: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))

def archive(path: Path, kind: str) -> None:
    with tarfile.open(path, "w:gz") as tf:
        if kind == "good":
            d = tarfile.TarInfo("tlc-meta"); d.type = tarfile.DIRTYPE; tf.addfile(d)
            add_file(tf, "tlc-meta/vars.chkpt")
            add_file(tf, "tlc-meta/queue.chkpt")
        elif kind == "traversal":
            add_file(tf, "tlc-meta/../../escape")
        elif kind == "absolute":
            add_file(tf, "/tmp/escape")
        elif kind == "symlink":
            s = tarfile.TarInfo("tlc-meta/link"); s.type = tarfile.SYMTYPE; s.linkname = "/tmp/x"; tf.addfile(s)
        elif kind == "hardlink":
            h = tarfile.TarInfo("tlc-meta/link"); h.type = tarfile.LNKTYPE; h.linkname = "tlc-meta/vars.chkpt"; tf.addfile(h)
        elif kind == "outside":
            add_file(tf, "other/file")
        else:
            raise AssertionError(kind)

def verify_exact_preflight(text: str) -> None:
    code = extract_preflight(text)
    with tempfile.TemporaryDirectory(prefix="las-v2-") as td:
        root = Path(td)
        script = root / "preflight.py"
        script.write_text(code + "\n", encoding="utf-8")
        for kind in ("good", "traversal", "absolute", "symlink", "hardlink", "outside"):
            tar = root / f"{kind}.tgz"
            archive(tar, kind)
            cp = subprocess.run([sys.executable, str(script), str(tar)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            should_pass = kind == "good"
            if (cp.returncode == 0) != should_pass:
                fail(f"exact preflight {kind}: rc={cp.returncode}, out={cp.stdout!r}, err={cp.stderr!r}")

def mutate_and_expect_reject(runner: str, continuation: str, bootstrap: str, old: str, new: str, label: str) -> None:
    if runner.count(old) != 1:
        fail(f"self-test fixture {label}: expected unique target, got {runner.count(old)}")
    bad = runner.replace(old, new, 1)
    try:
        verify_runner_contract(bad)
        verify_callers(continuation, bootstrap)
    except Error:
        return
    fail(f"self-test accepted invalid runner drift: {label}")

def mutate_kdf_and_expect_reject(runner: str, continuation: str, bootstrap: str, variable: str, token: str, label: str) -> None:
    lines = runner.splitlines()
    candidates = [i for i, line in enumerate(lines) if line.strip().startswith(f'{variable}="$(printf ')]
    if len(candidates) != 2:
        fail(f"self-test fixture {label}: expected two {variable} derivations, got {len(candidates)}")
    target = candidates[0]
    if token not in lines[target]:
        fail(f"self-test fixture {label}: token missing from selected derivation")
    lines[target] = lines[target].replace(token, '""', 1)
    bad = "\n".join(lines) + ("\n" if runner.endswith("\n") else "")
    try:
        verify_runner_contract(bad)
        verify_callers(continuation, bootstrap)
    except Error:
        return
    fail(f"self-test accepted invalid KDF drift: {label}")

def self_test(runner: str, continuation: str, bootstrap: str) -> None:
    mutations = (
        ('test "$GITHUB_SHA" = "$RUNNER_WORKFLOW_SHA"', 'test -n "$RUNNER_WORKFLOW_SHA"', "remove commit equality"),
        ('test "$actual_mac" = "$expected_mac"', 'test -n "$actual_mac"', "remove MAC equality"),
        ('"expected_workflow_sha": workflow_sha', '"expected_workflow_sha": ""', "remove SHA handoff"),
    )
    for old, new, label in mutations:
        mutate_and_expect_reject(runner, continuation, bootstrap, old, new, label)
    mutate_kdf_and_expect_reject(
        runner, continuation, bootstrap,
        "LAS_CHECKPOINT_SECRET", '"$RUNNER_WORKFLOW_SHA"',
        "remove workflow SHA from one encryption-key derivation",
    )
    mutate_kdf_and_expect_reject(
        runner, continuation, bootstrap,
        "LAS_CHECKPOINT_MAC_KEY", '"$RUNNER_WORKFLOW_PATH"',
        "remove workflow path from one MAC-key derivation",
    )

def main() -> int:
    for path in (RUNNER, CONTINUATION, BOOTSTRAP):
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")
    runner = RUNNER.read_text(encoding="utf-8")
    continuation = CONTINUATION.read_text(encoding="utf-8")
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    verify_runner_contract(runner)
    verify_callers(continuation, bootstrap)
    verify_exact_preflight(runner)
    self_test(runner, continuation, bootstrap)
    print("LAS_RESUMABLE_RUNNER_HARDENING_V2_CONTRACT=PASS")
    print("LAS_RESUMABLE_RUNNER_HARDENING_V2_PREFLIGHT=PASS")
    print("LAS_RESUMABLE_RUNNER_HARDENING_V2_SELFTEST=PASS")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Error as exc:
        print(f"LAS_RESUMABLE_RUNNER_HARDENING_V2=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
