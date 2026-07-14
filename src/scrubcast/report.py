"""Human- and machine-readable reporting of findings.

The text report goes to stderr so it never contaminates a scrubbed stream
written to stdout; the JSON report is a stable shape for CI tooling. Neither
ever includes a full secret — only :meth:`Finding.preview` output.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .engine import Finding

__all__ = ["describe_location", "text_report", "json_report"]


def describe_location(finding: Finding) -> str:
    """One short human string for wherever the finding lives."""
    loc = finding.location or {}
    if "line" in loc:
        return f"line {loc['line']}, col {loc['column']}"
    if "event" in loc:
        return f"event {loc['event']} (t={loc['time']:.3f}s, stream {loc['stream']!r})"
    if "field" in loc:
        return f"header field {loc['field']}"
    return "unknown location"


def text_report(path: str, fmt: str, findings: List[Finding]) -> str:
    """Render the per-file summary printed after scrub/scan."""
    if not findings:
        return f"{path}: clean ({fmt}), no secrets found"
    noun = "secret" if len(findings) == 1 else "secrets"
    lines = [f"{path}: {len(findings)} {noun} found ({fmt})"]
    for finding in findings:
        lines.append(
            f"  {finding.rule:<24} {describe_location(finding):<36} {finding.preview()}"
        )
    return "\n".join(lines)


def finding_dict(finding: Finding) -> Dict[str, Any]:
    """The JSON shape of one finding (no secret material)."""
    return {
        "rule": finding.rule,
        "origin": finding.origin,
        "location": finding.location or {},
        "preview": finding.preview(),
        "length": len(finding.secret),
    }


def json_report(path: str, fmt: str, findings: List[Finding]) -> str:
    """Render the machine-readable report for one file."""
    payload = {
        "file": path,
        "format": fmt,
        "count": len(findings),
        "findings": [finding_dict(f) for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
