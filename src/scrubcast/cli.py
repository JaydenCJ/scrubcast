"""The ``scrubcast`` command-line interface.

Three subcommands:

* ``scrub`` — rewrite a recording/log with secrets replaced (the default
  workflow); scrubbed content to stdout or ``-o``, findings summary to
  stderr.
* ``scan`` — detect only; exit 1 when anything is found, so it slots into a
  pre-share or pre-commit gate.
* ``rules`` — list the built-in detectors.

Exit codes: 0 success (``scan``: clean), 1 ``scan`` found secrets,
2 usage/config/parse error.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .cast import looks_like_cast, scrub_cast
from .config import RuleSet, default_ruleset, load_rules_file
from .engine import Finding, ScrubOptions, ScrubResult, scrub_log
from .errors import ScrubcastError
from .report import json_report, text_report

__all__ = ["main", "build_parser"]

_FORMATS = ("auto", "cast", "log")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrubcast",
        description=(
            "Redact secrets from terminal recordings (asciicast v2) and ANSI"
            " logs without breaking escape sequences or playback."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"scrubcast {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_detection_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--format",
            choices=_FORMATS,
            default="auto",
            help="input format (default: auto-detect from content)",
        )
        p.add_argument(
            "--rules",
            metavar="FILE",
            help="JSON rules file with extra rules / allowlist / overrides",
        )
        p.add_argument(
            "--disable",
            metavar="RULE",
            action="append",
            default=[],
            help="disable a built-in rule by name (repeatable)",
        )
        p.add_argument(
            "--allow",
            metavar="REGEX",
            action="append",
            default=[],
            help="drop findings whose secret matches REGEX (repeatable)",
        )
        p.add_argument(
            "--no-entropy",
            action="store_true",
            help="disable the entropy detector (rules only)",
        )
        p.add_argument(
            "--entropy-threshold",
            type=float,
            metavar="BITS",
            help="bits/char required for mixed-alphabet candidates (default 4.0)",
        )
        p.add_argument(
            "--min-length",
            type=int,
            metavar="N",
            help="minimum candidate length for entropy detection (default 20)",
        )
        p.add_argument(
            "--json", action="store_true", help="emit the findings report as JSON"
        )

    scrub = sub.add_parser("scrub", help="rewrite input with secrets redacted")
    scrub.add_argument("input", help="input file, or - for stdin")
    scrub.add_argument(
        "-o", "--output", metavar="FILE", help="output file (default: stdout)"
    )
    scrub.add_argument(
        "--in-place", action="store_true", help="rewrite the input file itself"
    )
    scrub.add_argument(
        "--style",
        choices=("label", "hash", "mask"),
        default="label",
        help=(
            "replacement style: label=[REDACTED:rule], hash=label+stable digest,"
            " mask=length-preserving characters (default: label)"
        ),
    )
    scrub.add_argument(
        "--mask-char",
        default="*",
        metavar="C",
        help="character used by --style mask (default: *)",
    )
    scrub.add_argument(
        "-q", "--quiet", action="store_true", help="suppress the findings summary"
    )
    add_detection_flags(scrub)

    scan = sub.add_parser(
        "scan", help="detect secrets without rewriting; exit 1 if any are found"
    )
    scan.add_argument("input", help="input file, or - for stdin")
    add_detection_flags(scan)

    rules = sub.add_parser("rules", help="list the built-in detection rules")
    rules.add_argument(
        "--json", action="store_true", help="emit the rule list as JSON"
    )
    return parser


def _build_ruleset(args: argparse.Namespace) -> RuleSet:
    ruleset = default_ruleset()
    if args.rules:
        ruleset = load_rules_file(args.rules, base=ruleset)
    if args.disable:
        ruleset.disable(args.disable)
    if args.allow:
        ruleset.add_allow(args.allow)
    overrides = {}
    if args.no_entropy:
        overrides["enabled"] = False
    if args.entropy_threshold is not None:
        overrides["threshold"] = args.entropy_threshold
    if args.min_length is not None:
        overrides["min_length"] = args.min_length
    if overrides:
        ruleset.entropy = dataclasses.replace(ruleset.entropy, **overrides)
    return ruleset


def _read_input(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text(encoding="utf-8")


def _detect_format(args: argparse.Namespace, text: str) -> str:
    if args.format != "auto":
        return args.format
    return "cast" if looks_like_cast(text) else "log"


def _process(text: str, fmt: str, ruleset: RuleSet, options: ScrubOptions):
    if fmt == "cast":
        scrubbed, findings = scrub_cast(text, ruleset, options)
        return scrubbed, findings
    result: ScrubResult = scrub_log(text, ruleset, options)
    return result.text, result.findings


def _report(
    path: str, fmt: str, findings: List[Finding], as_json: bool, stream
) -> None:
    if as_json:
        print(json_report(path, fmt, findings), file=stream)
    else:
        print(text_report(path, fmt, findings), file=stream)


def _cmd_scrub(args: argparse.Namespace) -> int:
    if args.in_place and args.input == "-":
        raise ScrubcastError("--in-place needs a real file, not stdin")
    if args.in_place and args.output:
        raise ScrubcastError("--in-place and --output are mutually exclusive")
    ruleset = _build_ruleset(args)
    options = ScrubOptions(style=args.style, mask_char=args.mask_char)
    text = _read_input(args.input)
    fmt = _detect_format(args, text)
    scrubbed, findings = _process(text, fmt, ruleset, options)

    if args.in_place:
        Path(args.input).write_text(scrubbed, encoding="utf-8")
    elif args.output:
        Path(args.output).write_text(scrubbed, encoding="utf-8")
    else:
        sys.stdout.write(scrubbed)
    if not args.quiet:
        _report(args.input, fmt, findings, args.json, sys.stderr)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    ruleset = _build_ruleset(args)
    text = _read_input(args.input)
    fmt = _detect_format(args, text)
    _, findings = _process(text, fmt, ruleset, ScrubOptions())
    _report(args.input, fmt, findings, args.json, sys.stdout)
    return 1 if findings else 0


def _cmd_rules(args: argparse.Namespace) -> int:
    ruleset = default_ruleset()
    if args.json:
        print(
            json.dumps(
                [
                    {"name": rule.name, "description": rule.description}
                    for rule in ruleset.rules
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    width = max(len(rule.name) for rule in ruleset.rules)
    for rule in ruleset.rules:
        print(f"{rule.name:<{width}}  {rule.description}")
    print(f"{'entropy':<{width}}  high-entropy string detector (see README)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scrub":
            return _cmd_scrub(args)
        if args.command == "scan":
            return _cmd_scan(args)
        return _cmd_rules(args)
    except ScrubcastError as exc:
        print(f"scrubcast: error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # The downstream consumer (e.g. `scrubcast rules | head`) closed the
        # pipe; that is not an error. Point stdout at devnull so the
        # interpreter's shutdown flush cannot raise a second time.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except OSError as exc:
        print(f"scrubcast: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
