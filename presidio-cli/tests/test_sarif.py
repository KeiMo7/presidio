import io
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from jsonschema import Draft4Validator, FormatChecker
from presidio_analyzer import RecognizerResult

from presidio_cli import cli
from presidio_cli.analyzer import PIIProblem
from presidio_cli.sarif import (
    SARIF_LEVEL_BY_SEVERITY,
    SarifValidationError,
    SarifWriter,
    relative_artifact_uri,
)
from presidio_cli.cli import SarifOutputError

SCHEMA_PATH = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"


@pytest.fixture()
def problems():
    return [
        problem("CREDIT_CARD", 6, 25, 1.0),
        problem("PERSON", 16, 26, 0.85, line=2),
    ]


def problem(
    entity_type: str,
    start: int,
    end: int,
    score: float,
    line: int = 1,
) -> PIIProblem:
    return PIIProblem(line, RecognizerResult(entity_type, start, end, score))


def write_log(
    root: Path,
    findings,
    failures=(),
    exit_code: int = 0,
):
    stream = io.StringIO()
    writer = SarifWriter(stream, str(root), tool_version="test-version")
    for finding, filepath in findings:
        writer.write_result(finding, filepath)
    for failure in failures:
        writer.record_failure(failure)
    writer.finish(exit_code)
    return json.loads(stream.getvalue()), stream.getvalue()


def assert_schema_valid(log):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["id"] == (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
        "sarif-schema-2.1.0.json"
    )
    Draft4Validator(schema, format_checker=FormatChecker()).validate(log)


def test_sarif_emits_one_result_per_rule_and_location(tmp_path):
    log, _ = write_log(
        tmp_path,
        [
            (problem("CREDIT_CARD", 4, 19, 1.0, line=2), "src/accounts.txt"),
            (problem("CREDIT_CARD", 0, 16, 1.0, line=7), "src/accounts.txt"),
            (problem("PERSON", 2, 7, 0.85, line=9), "src/accounts.txt"),
        ],
        exit_code=1,
    )

    results = log["runs"][0]["results"]
    assert [result["ruleId"] for result in results] == [
        "PII.CREDIT_CARD",
        "PII.CREDIT_CARD",
        "PII.PERSON",
    ]
    assert [result["level"] for result in results] == [
        "error",
        "error",
        "warning",
    ]
    assert [
        result["locations"][0]["physicalLocation"]["region"] for result in results
    ] == [
        {"startLine": 2, "startColumn": 5, "endLine": 2, "endColumn": 20},
        {"startLine": 7, "startColumn": 1, "endLine": 7, "endColumn": 17},
        {"startLine": 9, "startColumn": 3, "endLine": 9, "endColumn": 8},
    ]
    assert all(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/accounts.txt"
        for result in results
    )
    assert results[2]["message"]["text"].startswith("PERSON detected")


def test_sarif_rule_id_is_stable_across_files(tmp_path):
    log, _ = write_log(
        tmp_path,
        [
            (problem("EMAIL_ADDRESS", 0, 5, 1.0), "a.txt"),
            (problem("EMAIL_ADDRESS", 0, 5, 1.0), "nested/b.txt"),
        ],
    )

    results = log["runs"][0]["results"]
    assert results[0]["ruleId"] == results[1]["ruleId"] == "PII.EMAIL_ADDRESS"
    assert results[0]["ruleIndex"] == results[1]["ruleIndex"] == 0


def test_sarif_zero_findings_is_valid_and_has_empty_results(tmp_path):
    log, raw = write_log(tmp_path, [], exit_code=0)

    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert log["runs"][0]["invocations"][0]["exitCode"] == 0
    assert raw.rstrip().endswith("}]}")
    assert_schema_valid(log)


def test_sarif_output_matches_official_schema(tmp_path):
    log, _ = write_log(
        tmp_path,
        [
            (problem("CREDIT_CARD", 0, 16, 1.0, line=1), "src/a.py"),
            (problem("PERSON", 5, 12, 0.85, line=3), "src/a.py"),
            (problem("PHONE_NUMBER", 2, 14, 0.3, line=8), "src/b.py"),
        ],
        exit_code=1,
    )
    assert_schema_valid(log)


def test_sarif_severity_mapping_is_explicit(tmp_path):
    log, _ = write_log(
        tmp_path,
        [
            (problem("PERSON", 0, 5, 1.0), "a.txt"),
            (problem("PERSON", 0, 5, 0.5), "a.txt"),
            (problem("PERSON", 0, 5, 0.49), "a.txt"),
        ],
    )

    assert SARIF_LEVEL_BY_SEVERITY == {
        "high": "error",
        "medium": "warning",
        "hint": "note",
    }
    assert [result["level"] for result in log["runs"][0]["results"]] == [
        "error",
        "warning",
        "note",
    ]


def test_sarif_failure_is_visible_and_does_not_include_exception_data(tmp_path):
    secret = "password=hunter2 /home/alice/private.txt"
    log, raw = write_log(
        tmp_path,
        [],
        failures=[RuntimeError(secret)],
        exit_code=0,
    )

    invocation = log["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"
    assert invocation["toolExecutionNotifications"][0]["properties"]["errorType"] == (
        "RuntimeError"
    )
    assert "hunter2" not in raw
    assert "/home/alice" not in raw
    assert_schema_valid(log)


def test_relative_artifact_uri_encodes_unicode_and_reserved_characters(tmp_path):
    path = tmp_path / "src" / "é space" / "a#b?.txt"

    assert relative_artifact_uri(str(path), str(tmp_path)) == (
        "src/%C3%A9%20space/a%23b%3F.txt"
    )


def test_relative_artifact_uri_rejects_non_text_paths(tmp_path):
    with pytest.raises(SarifValidationError):
        relative_artifact_uri(b"a.txt", str(tmp_path))
    with pytest.raises(SarifValidationError):
        relative_artifact_uri("a.txt", os.fsencode(str(tmp_path)))
    with pytest.raises(SarifValidationError):
        relative_artifact_uri("", str(tmp_path))
    with pytest.raises(SarifValidationError):
        relative_artifact_uri("\x00", str(tmp_path))


def test_relative_artifact_uri_rejects_root_and_unencodable_names(tmp_path):
    with pytest.raises(SarifValidationError):
        relative_artifact_uri(str(tmp_path), str(tmp_path))
    with pytest.raises(SarifValidationError):
        relative_artifact_uri("\ud800", str(tmp_path))
    with pytest.raises(SarifValidationError):
        relative_artifact_uri("/home/alice/file.txt", str(tmp_path))


def test_relative_artifact_uri_handles_non_utf8_path_bytes(tmp_path):
    path = os.fsdecode(os.fsencode(str(tmp_path)) + b"/bad-\xff.txt")

    uri = relative_artifact_uri(path, str(tmp_path))

    assert uri == "bad-%FF.txt"
    assert "%FF" in json.dumps(uri)


def test_relative_artifact_uri_keeps_symlink_name(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("mail me at person@example.com", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert relative_artifact_uri(str(link), str(tmp_path)) == "link.txt"


def test_relative_artifact_uri_handles_long_paths(tmp_path):
    long_name = "a" * 5000
    path = str(tmp_path / long_name)

    uri = relative_artifact_uri(path, str(tmp_path))

    assert uri == long_name
    assert not uri.startswith(("/", "\\"))


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        (r"C:\repo\src\a.txt", r"C:\repo", "src/a.txt"),
        (r"C:\repo\src\a.txt", "/tmp", "repo/src/a.txt"),
        ("/repo/src/a b.txt", "/repo", "src/a%20b.txt"),
        ("src/weird:name.txt", "/repo", "src/weird%3Aname.txt"),
    ],
)
def test_artifact_uri_never_emits_absolute_windows_or_scheme_paths(
    path, root, expected
):
    uri = relative_artifact_uri(path, root)

    assert uri == expected
    assert not uri.startswith("/")
    assert ":" not in uri


def test_writer_streams_results_before_finishing(tmp_path):
    stream = io.StringIO()
    writer = SarifWriter(stream, str(tmp_path))

    writer.write_result(problem("PERSON", 0, 5, 1.0), "a.txt")

    partial = stream.getvalue()
    assert '"ruleId":"PII.PERSON"' in partial
    assert '"tool"' not in partial

    writer.finish(1)
    assert len(json.loads(stream.getvalue())["runs"][0]["results"]) == 1


def test_writer_handles_ten_thousand_results_without_collecting_them(
    tmp_path,
):
    stream = io.StringIO()
    writer = SarifWriter(stream, str(tmp_path))

    for index in range(10_000):
        writer.write_result(
            problem("PERSON", index, index + 5, 1.0),
            f"src/{index % 10}.txt",
        )
    writer.finish(1)

    assert writer.result_count == 10_000
    assert len(json.loads(stream.getvalue())["runs"][0]["results"]) == 10_000


def test_writers_do_not_share_state_across_threads(tmp_path):
    def render(entity_type):
        stream = io.StringIO()
        writer = SarifWriter(stream, str(tmp_path))
        writer.write_result(problem(entity_type, 0, 5, 1.0), "a.txt")
        writer.finish(1)
        return json.loads(stream.getvalue())

    with ThreadPoolExecutor(max_workers=2) as executor:
        person, email = executor.map(render, ["PERSON", "EMAIL_ADDRESS"])

    assert person["runs"][0]["results"][0]["ruleId"] == "PII.PERSON"
    assert email["runs"][0]["results"][0]["ruleId"] == "PII.EMAIL_ADDRESS"


def test_build_result_reports_the_exact_invalid_field(tmp_path):
    stream = io.StringIO()
    writer = SarifWriter(stream, str(tmp_path))
    invalid = problem("PERSON", -1, 5, 1.0)

    with pytest.raises(SarifValidationError) as exc_info:
        writer.write_result(invalid, "a.txt")

    assert exc_info.value.field_path == (
        "/runs/0/results/0/locations/0/physicalLocation/region/startColumn"
    )
    assert exc_info.value.reason


@pytest.mark.parametrize(
    ("finding", "filepath", "expected_path"),
    [
        (
            problem("", 0, 5, 1.0),
            "a.txt",
            "/runs/0/results/0/ruleId",
        ),
        (
            problem("PERSON", 5, 5, 1.0),
            "a.txt",
            "/runs/0/results/0/locations/0/physicalLocation/region/endColumn",
        ),
        (
            problem("PERSON", 0, 5, float("nan")),
            "a.txt",
            "/runs/0/results/0/properties/score",
        ),
        (
            problem("PERSON", 0, 5, 1.0),
            "",
            "/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri",
        ),
    ],
)
def test_build_result_reports_invalid_boundary_fields(
    tmp_path, finding, filepath, expected_path
):
    writer = SarifWriter(io.StringIO(), str(tmp_path))

    with pytest.raises(SarifValidationError) as exc_info:
        writer.write_result(finding, filepath)

    assert exc_info.value.field_path == expected_path


def test_writer_caps_failure_notifications(tmp_path):
    stream = io.StringIO()
    writer = SarifWriter(stream, str(tmp_path))
    for _ in range(101):
        writer.record_failure(RuntimeError("hidden"))
    writer.finish(0)

    invocation = json.loads(stream.getvalue())["runs"][0]["invocations"][0]
    notifications = invocation["toolExecutionNotifications"]
    assert len(notifications) == 101
    assert notifications[-1]["level"] == "note"
    assert notifications[-1]["properties"]["omittedFailureCount"] == 1


def test_writer_rejects_use_after_finish(tmp_path):
    writer = SarifWriter(io.StringIO(), str(tmp_path))
    writer.finish(0)

    with pytest.raises(ValueError, match="already finished"):
        writer.write_result(problem("PERSON", 0, 5, 1.0), "a.txt")


def test_cli_sarif_output_writes_file_and_preserves_exit_code(
    mocker, tmp_path, problems
):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch("presidio_cli.cli.analyze", return_value=problems)
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    assert len(log["runs"][0]["results"]) == 2
    assert log["runs"][0]["invocations"][0]["exitCode"] == 1
    exit_mock.assert_called_once_with(1)


def test_cli_sarif_zero_findings_writes_empty_results_and_exits_zero(mocker, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("clean", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch("presidio_cli.cli.analyze", return_value=[])
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["invocations"][0]["exitCode"] == 0
    exit_mock.assert_called_once_with(0)


def test_cli_sarif_stdin_writes_relative_artifact(mocker, capsys):
    mocked_args = mocker.Mock(
        files=(),
        stdin=True,
        format="sarif",
        no_warnings=False,
        sarif_output=None,
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("EMAIL_ADDRESS", 0, 15, 1.0)],
    )
    mocker.patch("presidio_cli.cli.sys.stdin", io.StringIO("a@example.com"))
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(capsys.readouterr().out)
    artifact = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact == {"uri": "stdin"}
    exit_mock.assert_called_once_with(1)


def test_cli_sarif_stdin_failure_does_not_leak_exception(mocker, capsys, caplog):
    secret = "token=top-secret /home/alice/private.txt"
    mocked_args = mocker.Mock(
        files=(),
        stdin=True,
        format="sarif",
        no_warnings=False,
        sarif_output=None,
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[])
    mocker.patch("presidio_cli.cli.analyze", side_effect=RuntimeError(secret))
    mocker.patch("presidio_cli.cli.sys.stdin", io.StringIO("a@example.com"))
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    output = capsys.readouterr()
    log = json.loads(output.out)
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert secret not in output.out
    assert secret not in output.err
    assert secret not in caplog.text
    exit_mock.assert_called_once_with(0)


def test_cli_sarif_no_warnings_filters_results(mocker, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=True,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[
            problem("PERSON", 0, 5, 1.0),
            problem("PERSON", 6, 11, 0.85),
        ],
    )
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    assert len(log["runs"][0]["results"]) == 1
    assert log["runs"][0]["results"][0]["level"] == "error"
    exit_mock.assert_called_once_with(1)


def test_cli_sarif_no_warnings_filters_stdin_results(mocker, capsys):
    mocked_args = mocker.Mock(
        files=(),
        stdin=True,
        format="sarif",
        no_warnings=True,
        sarif_output=None,
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("PERSON", 0, 5, 0.85)],
    )
    mocker.patch("presidio_cli.cli.sys.stdin", io.StringIO("Alice"))
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(capsys.readouterr().out)
    assert log["runs"][0]["results"] == []
    exit_mock.assert_called_once_with(0)


def test_cli_sarif_uses_git_root_for_artifact_uri(mocker, tmp_path):
    repository = tmp_path / "repo"
    (repository / ".git").mkdir(parents=True)
    source = repository / "sub" / "a.txt"
    source.parent.mkdir()
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("PERSON", 0, 5, 1.0)],
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    artifact = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact == {"uri": "sub/a.txt"}


def test_cli_sarif_uses_cwd_for_root_when_no_git_root(mocker, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=("a.txt",),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=["a.txt"])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("PERSON", 0, 5, 1.0)],
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    artifact = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact == {"uri": "a.txt"}


def test_cli_sarif_enumerating_failure_is_visible_and_sanitized(
    mocker, tmp_path, capsys, caplog
):
    secret = "token=top-secret /home/alice/private.txt"
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=("missing",),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch(
        "presidio_cli.cli.find_files_recursively",
        side_effect=RuntimeError(secret),
    )
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert secret not in output.read_text(encoding="utf-8")
    assert secret not in caplog.text
    assert secret not in capsys.readouterr().err
    exit_mock.assert_called_once_with(0)


def test_cli_sarif_skips_preexisting_output_file(mocker, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    output.write_text("previous complete log", encoding="utf-8")
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch(
        "presidio_cli.cli.find_files_recursively",
        return_value=[str(source), str(output)],
    )
    analyze_mock = mocker.patch("presidio_cli.cli.analyze", return_value=[])
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    mocker.patch("sys.exit")

    cli.run()

    assert analyze_mock.call_count == 1
    assert json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"] == []


def test_cli_sarif_failure_is_valid_atomic_and_does_not_log_secret(
    mocker, tmp_path, caplog, capsys
):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    secret = "token=top-secret /home/alice/private.txt"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch(
        "presidio_cli.cli.analyze",
        side_effect=RuntimeError(secret),
    )
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(output.read_text(encoding="utf-8"))
    invocation = log["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["exitCode"] == 0
    assert "top-secret" not in output.read_text(encoding="utf-8")
    assert "top-secret" not in caplog.text
    assert "/home/alice" not in caplog.text
    assert "top-secret" not in capsys.readouterr().err
    exit_mock.assert_called_once_with(0)


def test_cli_sarif_validation_failure_does_not_publish_partial_file(
    mocker, tmp_path, capsys
):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    output.write_text("previous complete log", encoding="utf-8")
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch("presidio_cli.cli.analyze", return_value=[])
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch(
        "presidio_cli.sarif.SarifWriter.finish",
        side_effect=SarifValidationError("/runs/0/version", "value is invalid"),
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    assert output.read_text(encoding="utf-8") == "previous complete log"
    assert "/runs/0/version" in capsys.readouterr().err
    exit_mock.assert_called_once_with(1)


def test_cli_sarif_result_validation_reports_field_and_does_not_publish(
    mocker, tmp_path, capsys
):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    output = tmp_path / "results.sarif"
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(output),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("PERSON", -1, 5, 1.0)],
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    assert not output.exists()
    assert (
        "/runs/0/results/0/locations/0/physicalLocation/region/startColumn"
        in capsys.readouterr().err
    )
    exit_mock.assert_called_once_with(1)


def test_sarif_output_exception_does_not_expose_path_or_credentials(mocker, tmp_path):
    secret = "token=top-secret /home/alice/private.txt"
    mocker.patch(
        "presidio_cli.cli.tempfile.NamedTemporaryFile",
        side_effect=OSError(secret),
    )

    with pytest.raises(SarifOutputError) as exc_info:
        cli._write_sarif_file(str(tmp_path / "out.sarif"), None, None)

    assert secret not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "error",
    [
        SarifOutputError("Unable to create SARIF output file."),
        OSError("token=top-secret /home/alice/private.txt"),
    ],
)
def test_cli_sarif_publish_failure_is_sanitized(mocker, tmp_path, capsys, error):
    mocked_args = mocker.Mock(
        files=("a.txt",),
        stdin=False,
        format="standard",
        no_warnings=False,
        sarif_output=str(tmp_path / "results.sarif"),
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli._write_sarif_file", side_effect=error)
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    assert "top-secret" not in capsys.readouterr().err
    exit_mock.assert_called_once_with(1)


def test_cli_sarif_format_writes_complete_document_to_stdout(mocker, tmp_path, capsys):
    source = tmp_path / "a.txt"
    source.write_text("sensitive", encoding="utf-8")
    mocked_args = mocker.Mock(
        files=(str(source),),
        stdin=False,
        format="sarif",
        no_warnings=False,
        sarif_output=None,
        config_data=None,
        config_file=None,
        threshold=None,
    )
    mocker.patch("presidio_cli.cli.PresidioCLIConfig", return_value=make_conf(mocker))
    mocker.patch("presidio_cli.cli.find_files_recursively", return_value=[str(source)])
    mocker.patch(
        "presidio_cli.cli.analyze",
        return_value=[problem("PERSON", 0, 5, 1.0)],
    )
    mocker.patch(
        "presidio_cli.cli._repository_root_for_inputs", return_value=str(tmp_path)
    )
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=mocked_args)
    exit_mock = mocker.patch("sys.exit")

    cli.run()

    log = json.loads(capsys.readouterr().out)
    assert len(log["runs"][0]["results"]) == 1
    exit_mock.assert_called_once_with(1)


def make_conf(mocker, threshold=0.25):
    conf = mocker.Mock()
    conf.threshold = threshold
    conf.locale = None
    return conf
