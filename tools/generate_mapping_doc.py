"""Regenerate docs/control-mapping.md from the check registry.

Run from the repository root:  python tools/generate_mapping_doc.py
CI runs it with --check to make sure the doc never drifts from the code.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from e8checker.checks import REGISTRY  # noqa: E402
from e8checker.mappings import describe_iso, describe_nist  # noqa: E402
from e8checker.models import Strategy  # noqa: E402

DOC = ROOT / "docs" / "control-mapping.md"


def render() -> str:
    lines = [
        "# Control mapping",
        "",
        "Generated from the check registry by `tools/generate_mapping_doc.py`. Do not edit by hand.",
        "",
        "Every check maps to an ASD Essential Eight requirement (or a supporting control), a NIST",
        "Cybersecurity Framework 2.0 subcategory and an ISO/IEC 27001:2022 Annex A control. Level 2 checks",
        "run only with `--level 2` and are reported as readiness findings, not as an ML2 verdict.",
        "The NIST and ISO mappings are indicative, not an official crosswalk.",
        "",
    ]
    for strategy in Strategy:
        specs = sorted((s for s in REGISTRY if s.strategy is strategy), key=lambda s: (s.level, s.check_id))
        if not specs:
            continue
        lines += [
            f"## {strategy.value}",
            "",
            "| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for s in specs:
            nist = "<br>".join(f"{c} {describe_nist(c)}" for c in s.nist_csf)
            iso = "<br>".join(f"A.{c} {describe_iso(c)}" for c in s.iso27001)
            kind = "Manual" if s.manual else "Automated"
            lines.append(f"| {s.check_id} | {s.level} | {kind} | {s.title} | {s.severity.value} | {nist} | {iso} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    content = render()
    if "--check" in sys.argv:
        if not DOC.exists() or DOC.read_text(encoding="utf-8") != content:
            print("docs/control-mapping.md is out of date. Run: python tools/generate_mapping_doc.py")
            return 1
        print("docs/control-mapping.md is up to date.")
        return 0
    DOC.write_text(content, encoding="utf-8")
    print(f"Wrote {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
