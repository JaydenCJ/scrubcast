"""End-to-end CLI behavior through main().

Everything runs in-process except the broken-pipe test, which needs a real
OS pipe to reproduce what `scrubcast ... | head` does.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scrubcast import __version__
from scrubcast.cli import main

from conftest import FAKE_GITHUB, make_cast


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture()
def cast_file(tmp_path):
    path = tmp_path / "demo.cast"
    path.write_text(
        make_cast([[0.1, "o", f"export TOKEN={FAKE_GITHUB}\r\n"]]), encoding="utf-8"
    )
    return path


@pytest.fixture()
def log_file(tmp_path):
    path = tmp_path / "ci.log"
    path.write_text(f"\x1b[32mok\x1b[0m token {FAKE_GITHUB}\n", encoding="utf-8")
    return path


# --- scrub -----------------------------------------------------------------


def test_scrub_cast_to_stdout_with_summary_on_stderr(capsys, cast_file):
    code, out, err = run(capsys, "scrub", str(cast_file))
    assert code == 0
    assert FAKE_GITHUB not in out
    assert "[REDACTED:github-token]" in out
    assert "1 secret found (cast)" in err


def test_scrub_writes_output_file_and_in_place(capsys, cast_file, tmp_path):
    dest = tmp_path / "clean.cast"
    code, out, _ = run(capsys, "scrub", str(cast_file), "-o", str(dest))
    assert code == 0
    assert out == ""  # nothing on stdout when -o is given
    assert FAKE_GITHUB not in dest.read_text(encoding="utf-8")
    code2, _, _ = run(capsys, "scrub", str(cast_file), "--in-place")
    assert code2 == 0
    assert FAKE_GITHUB not in cast_file.read_text(encoding="utf-8")


def test_scrub_in_place_misuse_is_a_usage_error(capsys, cast_file, tmp_path):
    code, _, err = run(capsys, "scrub", "-", "--in-place")
    assert code == 2 and "in-place" in err
    code2, _, err2 = run(
        capsys, "scrub", str(cast_file), "--in-place", "-o", str(tmp_path / "x")
    )
    assert code2 == 2 and "mutually exclusive" in err2


def test_scrub_stdin_to_stdout(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"password={FAKE_GITHUB}\n"))
    code, out, _ = run(capsys, "scrub", "-")
    assert code == 0
    assert FAKE_GITHUB not in out


def test_scrub_log_reports_line_numbers(capsys, log_file):
    code, _, err = run(capsys, "scrub", str(log_file))
    assert code == 0
    assert "line 1" in err
    assert "github-token" in err
    # -q silences the summary but still emits the scrubbed content.
    code2, out2, err2 = run(capsys, "scrub", str(log_file), "-q")
    assert code2 == 0 and err2 == "" and out2


def test_scrub_mask_style_keeps_colors(capsys, log_file):
    code, out, _ = run(capsys, "scrub", str(log_file), "--style", "mask")
    assert code == 0
    assert "*" * len(FAKE_GITHUB) in out
    assert "\x1b[32m" in out  # colors intact


def test_scrub_hash_style_stable_tag(capsys, tmp_path):
    path = tmp_path / "twice.log"
    path.write_text(f"{FAKE_GITHUB}\n{FAKE_GITHUB}\n", encoding="utf-8")
    code, out, _ = run(capsys, "scrub", str(path), "--style", "hash")
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == lines[1]
    assert lines[0].startswith("[REDACTED:github-token:")


def test_scrub_forced_format_overrides_sniffing(capsys, cast_file):
    # Forcing log format treats the JSON lines as text; content is still
    # scrubbed but no cast parsing happens.
    code, out, err = run(capsys, "scrub", str(cast_file), "--format", "log")
    assert code == 0
    assert "(log)" in err
    assert FAKE_GITHUB not in out


def test_scrub_summary_as_json(capsys, log_file):
    code, _, err = run(capsys, "scrub", str(log_file), "--json")
    assert code == 0
    payload = json.loads(err)
    assert payload["format"] == "log"
    assert payload["count"] == 1
    assert payload["findings"][0]["rule"] == "github-token"
    assert FAKE_GITHUB not in err


# --- scan ------------------------------------------------------------------


def test_scan_exit_codes_gate_ci(capsys, cast_file, tmp_path):
    code, out, _ = run(capsys, "scan", str(cast_file))
    assert code == 1
    assert "github-token" in out
    clean = tmp_path / "clean.log"
    clean.write_text("all quiet\n", encoding="utf-8")
    code2, out2, _ = run(capsys, "scan", str(clean))
    assert code2 == 0
    assert "clean" in out2


def test_scan_json_report(capsys, cast_file):
    code, out, _ = run(capsys, "scan", str(cast_file), "--json")
    assert code == 1
    payload = json.loads(out)
    assert payload["findings"][0]["location"]["stream"] == "o"


def test_scan_disable_allow_and_no_entropy_can_silence(capsys, cast_file):
    code, _, _ = run(
        capsys,
        "scan",
        str(cast_file),
        "--disable",
        "github-token",
        "--disable",
        "secret-assignment",
        "--no-entropy",
    )
    assert code == 0
    code2, _, _ = run(capsys, "scan", str(cast_file), "--allow", "^ghp_Ab3")
    assert code2 == 0


def test_scan_rules_file_flag(capsys, tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps({"rules": [{"name": "corp-id", "pattern": "CORP-[0-9]{10}"}]}),
        encoding="utf-8",
    )
    target = tmp_path / "x.log"
    target.write_text("id CORP-1234567890\n", encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(target), "--rules", str(rules))
    assert code == 1
    assert "corp-id" in out


def test_scan_entropy_flags_pass_through(capsys, tmp_path):
    target = tmp_path / "e.log"
    target.write_text("blob Zq3xVb9TkLm2Pw8RsYd4Jf6Hn1Cg5Wt7\n", encoding="utf-8")
    code, _, _ = run(capsys, "scan", str(target))
    assert code == 1  # flagged by default
    code2, _, _ = run(capsys, "scan", str(target), "--min-length", "40")
    assert code2 == 0  # candidate now too short to consider


# --- errors and misc -------------------------------------------------------


def test_input_and_config_errors_exit_2(capsys, tmp_path, cast_file):
    code, _, err = run(capsys, "scan", str(tmp_path / "ghost.log"))
    assert code == 2 and "error" in err
    broken = tmp_path / "broken.cast"
    broken.write_text('{"version": 2}\nnot json\n', encoding="utf-8")
    code2, _, err2 = run(capsys, "scrub", str(broken))
    assert code2 == 2 and "line 2" in err2
    rules = tmp_path / "bad.json"
    rules.write_text("{oops", encoding="utf-8")
    code3, _, err3 = run(capsys, "scan", str(cast_file), "--rules", str(rules))
    assert code3 == 2 and "not valid JSON" in err3


def test_rules_subcommand_lists_builtins(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    assert "github-token" in out
    assert "entropy" in out
    code2, out2, _ = run(capsys, "rules", "--json")
    assert code2 == 0
    names = [entry["name"] for entry in json.loads(out2)]
    assert "aws-access-key-id" in names


def test_downstream_closing_the_pipe_is_not_an_error(tmp_path):
    # `scrubcast scrub big.log | head -1` must exit 0 with no error output:
    # the consumer walking away is normal pipeline behavior, not a failure.
    # The input is made large enough that the output cannot fit the OS pipe
    # buffer, so EPIPE fires deterministically once the read end closes.
    big = tmp_path / "big.log"
    big.write_text("nothing secret on this line\n" * 10_000, encoding="utf-8")
    src = str(Path(__file__).resolve().parent.parent / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "scrubcast", "scrub", str(big), "-q"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": src},
    )
    proc.stdout.readline()
    proc.stdout.close()  # what `head` does after its first line
    assert proc.wait() == 0
    assert proc.stderr.read() == b""


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"scrubcast {__version__}"
