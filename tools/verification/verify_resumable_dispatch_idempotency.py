#!/usr/bin/env python3
"""Fail-closed idempotency contract for resumable TLC continuation dispatches."""
from __future__ import annotations

import argparse
from dataclasses import dataclass


class ContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class SliceIdentity:
    index: int
    segment: int
    resume_run_id: int | None
    resume_artifact: str

    def validate(self) -> None:
        if self.index < 0 or self.index >= 203 or self.index == 39:
            raise ContractError("invalid canonical index")
        if self.segment < 1:
            raise ContractError("invalid segment")
        if self.segment == 1:
            if self.resume_run_id is not None or self.resume_artifact:
                raise ContractError("segment-1 must not have resume parent")
        else:
            if self.resume_run_id is None or self.resume_run_id <= 0:
                raise ContractError("continued segment requires positive parent run id")
            expected = f"tlc-state-{self.index}-{self.segment-1}"
            if self.resume_artifact != expected:
                raise ContractError("resume artifact does not match canonical predecessor")


def canonical_key(s: SliceIdentity) -> str:
    s.validate()
    parent = "root" if s.resume_run_id is None else str(s.resume_run_id)
    artifact = "root" if not s.resume_artifact else s.resume_artifact
    return f"idx={s.index};seg={s.segment};parent={parent};artifact={artifact}"


def choose_authoritative(s: SliceIdentity, successful_same_identity: list[int]) -> tuple[str, int | None]:
    """Return RUN for first execution, SUPERSEDED for a duplicate.

    The smallest completed-success run id is the immutable authoritative execution for
    this exact logical identity. A later duplicate must not execute TLC or dispatch a child.
    """
    s.validate()
    unique = sorted(set(successful_same_identity))
    if not unique:
        return "RUN", None
    if any(r <= 0 for r in unique):
        raise ContractError("invalid evidence run id")
    return "SUPERSEDED", unique[0]


def self_test() -> None:
    root = SliceIdentity(2, 1, None, "")
    assert canonical_key(root) == "idx=2;seg=1;parent=root;artifact=root"
    continued = SliceIdentity(115, 40, 37725288732, "tlc-state-115-39")
    assert canonical_key(continued).startswith("idx=115;seg=40;")
    assert choose_authoritative(continued, []) == ("RUN", None)
    assert choose_authoritative(continued, [400, 398, 400]) == ("SUPERSEDED", 398)

    invalid = (
        SliceIdentity(39, 1, None, ""),
        SliceIdentity(2, 0, None, ""),
        SliceIdentity(2, 1, 7, "tlc-state-2-0"),
        SliceIdentity(2, 2, None, ""),
        SliceIdentity(2, 2, 7, "tlc-state-2-9"),
    )
    for item in invalid:
        try:
            canonical_key(item)
        except ContractError:
            pass
        else:
            raise AssertionError(f"invalid identity unexpectedly accepted: {item}")

    try:
        choose_authoritative(continued, [0])
    except ContractError:
        pass
    else:
        raise AssertionError("invalid successful run id unexpectedly accepted")

    print("LAS_RESUMABLE_DISPATCH_IDEMPOTENCY_SELFTEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ns = ap.parse_args()
    if ns.self_test:
        self_test()
        return 0
    raise SystemExit("only --self-test is supported; live integration is intentionally separate")


if __name__ == "__main__":
    raise SystemExit(main())
