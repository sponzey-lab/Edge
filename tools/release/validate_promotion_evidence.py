#!/usr/bin/env python3
"""Fail closed unless clean-host evidence matches one immutable candidate."""

import argparse
import json
import re
import sys
from pathlib import Path


SEMVER = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE = re.compile(r"^ghcr\.io/sponzey-lab/sponzey-edge:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$")
MATRIX = {
    ("compose", "linux-amd64"),
    ("compose", "linux-arm64"),
    ("systemd", "linux-amd64"),
    ("systemd", "linux-arm64"),
}


class PromotionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise PromotionError(code, message)


def validate(evidence_path: Path, tag: str, commit: str, image: str) -> dict[str, object]:
    if SEMVER.fullmatch(tag) is None or COMMIT.fullmatch(commit) is None or IMAGE.fullmatch(image) is None:
        fail("PROMOTION_ARGUMENT_INVALID", "expected candidate identity is invalid")
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail("PROMOTION_EVIDENCE_INVALID", f"cannot parse evidence: {error}")
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        fail("PROMOTION_EVIDENCE_INVALID", "evidence schema_version must be 1")
    if any(evidence.get(key) != expected for key, expected in (("tag", tag), ("commit", commit), ("image", image))):
        fail("PROMOTION_IDENTITY_MISMATCH", "evidence must match the candidate tag, commit, and immutable image")
    if evidence.get("source_quality") != "passed" or evidence.get("support_bundle") != "passed":
        fail("PROMOTION_EVIDENCE_INCOMPLETE", "source quality and support bundle evidence must pass")
    if evidence.get("manual_or_private_pki_only") is not True or evidence.get("certificate_automation_deferred") is not True:
        fail("PROMOTION_SCOPE_INVALID", "promotion must retain manual/private PKI scope and deferred automation")
    matrix = evidence.get("matrix")
    cells: set[tuple[str, str]] = set()
    if not isinstance(matrix, list):
        fail("PROMOTION_MATRIX_INCOMPLETE", "matrix must contain the required clean-host cells")
    for item in matrix:
        if not isinstance(item, dict) or item.get("status") != "passed":
            fail("PROMOTION_MATRIX_INCOMPLETE", "every matrix cell must be a passed object")
        deployment, platform = item.get("deployment"), item.get("platform")
        if not isinstance(deployment, str) or not isinstance(platform, str):
            fail("PROMOTION_MATRIX_INCOMPLETE", "matrix cell identity is invalid")
        cells.add((deployment, platform))
    if cells != MATRIX or len(matrix) != len(MATRIX):
        fail("PROMOTION_MATRIX_INCOMPLETE", "matrix must contain each Compose/systemd Linux architecture once")
    return {"matrix_cells": len(cells), "tag": tag}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image", required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.evidence, arguments.tag, arguments.commit, arguments.image)
    except PromotionError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
