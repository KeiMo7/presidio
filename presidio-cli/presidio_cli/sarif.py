"""Streaming SARIF 2.1.0 output for Presidio CLI findings."""

import json
import math
import ntpath
import os
import re
from typing import IO, Dict, List
from urllib.parse import quote_from_bytes

from presidio_cli import APP_VERSION
from presidio_cli.analyzer import PIIProblem

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

# Severity names are Presidio's public vocabulary. The SARIF values are
# intentionally kept in one table so integrations cannot drift.
SARIF_LEVEL_BY_SEVERITY = {
    "high": "error",
    "medium": "warning",
    "hint": "note",
}

HIGH_SEVERITY_MIN_SCORE = 1.0
MEDIUM_SEVERITY_MIN_SCORE = 0.5
MAX_RECORDED_FAILURES = 100

_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


class SarifValidationError(ValueError):
    """Raised when a generated SARIF value would violate the output contract."""

    def __init__(self, field_path: str, reason: str) -> None:
        """
        Create a validation error that identifies the offending field.

        :param field_path: JSON Pointer to the invalid field.
        :param reason: Static explanation that does not include user data.
        """
        self.field_path = field_path
        self.reason = reason
        super().__init__(f"Invalid SARIF field {field_path}: {reason}")


def severity_for_score(score: float) -> str:
    """
    Classify a finding by confidence.

    :param score: Presidio finding score.
    :return: One of ``high``, ``medium`` or ``hint``.
    """
    if score >= HIGH_SEVERITY_MIN_SCORE:
        return "high"
    if score >= MEDIUM_SEVERITY_MIN_SCORE:
        return "medium"
    return "hint"


def sarif_level_for_score(score: float) -> str:
    """
    Map a Presidio finding score to a SARIF result level.

    :param score: Presidio finding score.
    :return: One of ``error``, ``warning`` or ``note``.
    """
    return SARIF_LEVEL_BY_SEVERITY[severity_for_score(score)]


def rule_id_for_entity(entity_type: str) -> str:
    """
    Build a stable, path-independent SARIF rule identifier.

    :param entity_type: Presidio entity type.
    :return: Stable rule identifier.
    """
    return f"PII.{entity_type}"


def relative_artifact_uri(filepath: str, repository_root: str) -> str:
    """
    Convert a filesystem path to a percent-encoded artifact URI.

    The URI is relative to the repository root and never follows symlinks.
    Characters outside the URI unreserved set are UTF-8 percent-encoded,
    including non-UTF-8 path bytes exposed by Python's surrogate escapes.

    :param filepath: Path to the scanned artifact.
    :param repository_root: Root against which the artifact path is resolved.
    :return: Relative URI suitable for ``artifactLocation.uri``.
    :raises SarifValidationError: If the path cannot be represented as a
        relative URI.
    """
    path = os.fspath(filepath)
    root = os.fspath(repository_root)
    field_path = "/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri"

    if not isinstance(path, str):
        raise SarifValidationError(field_path, "artifact path must be text")
    if not isinstance(root, str):
        raise SarifValidationError(field_path, "repository root must be text")
    if not path or "\x00" in path:
        raise SarifValidationError(field_path, "artifact path must be non-empty text")

    try:
        relative = _relative_path(path, root)
    except (OSError, ValueError) as exc:
        raise SarifValidationError(
            field_path, "artifact path must share a root with the repository"
        ) from exc
    relative = relative.replace(os.sep, "/")
    if relative in ("", "."):
        raise SarifValidationError(field_path, "artifact path cannot be the root")
    if ".." in relative.split("/"):
        raise SarifValidationError(
            field_path, "artifact path must be inside the repository root"
        )
    if relative.startswith("/") or _DRIVE_PATH.match(relative):
        raise SarifValidationError(field_path, "artifact path must be relative")

    try:
        encoded = quote_from_bytes(os.fsencode(relative), safe="/-._~")
    except (UnicodeError, ValueError) as exc:
        raise SarifValidationError(
            field_path, "artifact path cannot be percent-encoded"
        ) from exc

    return encoded


def _relative_path(path: str, root: str) -> str:
    """Return a lexical relative path without resolving symlinks."""
    if _DRIVE_PATH.match(path):
        if _DRIVE_PATH.match(root):
            return ntpath.relpath(path, root).replace("\\", "/")
        return (
            path[3:].replace("\\", "/")
            if path[2:3] in ("/", "\\")
            else path[2:].replace("\\", "/")
        )

    if not os.path.isabs(path):
        path = os.path.join(root, path)
    absolute_path = os.path.abspath(path)
    absolute_root = os.path.abspath(root)
    return os.path.relpath(absolute_path, absolute_root)


def _validate_text(value: object, field_path: str) -> None:
    if not isinstance(value, str) or not value:
        raise SarifValidationError(field_path, "value must be a non-empty string")


def _validate_int(value: object, field_path: str, minimum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise SarifValidationError(
            field_path, f"value must be an integer greater than or equal to {minimum}"
        )


def build_result(
    problem: PIIProblem,
    filepath: str,
    repository_root: str,
    rule_index: int,
    result_index: int,
) -> Dict:
    """
    Build one SARIF result from a Presidio finding.

    :param problem: Finding produced by the existing CLI analyzer path.
    :param filepath: Scanned file path.
    :param repository_root: Root used for relative artifact URIs.
    :param rule_index: Index of the rule in ``tool.driver.rules``.
    :param result_index: Zero-based index of this result in the run.
    :return: SARIF result object.
    :raises SarifValidationError: If a generated field is invalid.
    """
    base_path = f"/runs/0/results/{result_index}"
    _validate_text(problem.type, f"{base_path}/ruleId")
    _validate_int(
        problem.line,
        f"{base_path}/locations/0/physicalLocation/region/startLine",
        1,
    )
    _validate_int(
        problem.column,
        f"{base_path}/locations/0/physicalLocation/region/startColumn",
        1,
    )

    end = problem.recognizer_result.get("end")
    _validate_int(end, f"{base_path}/locations/0/physicalLocation/region/endColumn", 1)
    if end <= problem.recognizer_result.get("start", -1):
        raise SarifValidationError(
            f"{base_path}/locations/0/physicalLocation/region/endColumn",
            "end column must be greater than start column",
        )

    score = problem.score
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not math.isfinite(score)
    ):
        raise SarifValidationError(
            f"{base_path}/properties/score", "score must be a finite number"
        )

    severity = severity_for_score(score)
    try:
        artifact_uri = relative_artifact_uri(filepath, repository_root)
    except SarifValidationError as exc:
        raise SarifValidationError(
            f"{base_path}/locations/0/physicalLocation/artifactLocation/uri",
            exc.reason,
        ) from exc

    return {
        "ruleId": rule_id_for_entity(problem.type),
        "ruleIndex": rule_index,
        "kind": "fail",
        "level": sarif_level_for_score(score),
        "message": {"text": f"{problem.type} detected with confidence {score:.2f}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {
                        "startLine": problem.line,
                        "startColumn": problem.column,
                        "endLine": problem.line,
                        "endColumn": end + 1,
                    },
                }
            }
        ],
        "properties": {"score": score, "severity": severity},
    }


class SarifWriter:
    """Write a single streaming SARIF run to a text stream."""

    def __init__(
        self,
        stream: IO[str],
        repository_root: str,
        tool_version: str = APP_VERSION,
    ) -> None:
        """
        Start a SARIF log.

        :param stream: Writable text stream. The caller owns closing it.
        :param repository_root: Root for relative artifact URIs.
        :param tool_version: Presidio CLI version reported in SARIF metadata.
        """
        self._stream = stream
        self._repository_root = repository_root
        self._tool_version = tool_version
        self._rules: Dict[str, str] = {}
        self._rule_indexes: Dict[str, int] = {}
        self._result_count = 0
        self._failures: List[Dict] = []
        self._failure_count = 0
        self._finished = False

        self._stream.write(
            '{"$schema":'
            + json.dumps(SARIF_SCHEMA_URI)
            + ',"version":"2.1.0","runs":[{"results":['
        )

    @property
    def result_count(self) -> int:
        """Return the number of results written so far."""
        return self._result_count

    @property
    def failure_count(self) -> int:
        """Return the number of failed input scans observed."""
        return self._failure_count

    def write_result(self, problem: PIIProblem, filepath: str) -> None:
        """
        Stream one finding as an independent SARIF result.

        :param problem: Finding produced by the existing CLI analyzer path.
        :param filepath: Scanned file path.
        :raises SarifValidationError: If a generated field is invalid.
        """
        self._ensure_open()
        entity_type = problem.type
        rule_id = rule_id_for_entity(entity_type)
        if rule_id not in self._rules:
            self._rules[rule_id] = entity_type
            self._rule_indexes[rule_id] = len(self._rule_indexes)
        rule_index = self._rule_indexes[rule_id]

        result = build_result(
            problem,
            filepath,
            self._repository_root,
            rule_index,
            self._result_count,
        )
        if self._result_count:
            self._stream.write(",")
        json.dump(result, self._stream, ensure_ascii=True, separators=(",", ":"))
        self._result_count += 1

    def record_failure(self, error: BaseException) -> None:
        """
        Record a scan failure without persisting exception details.

        :param error: Exception raised while scanning an input.
        """
        self._ensure_open()
        self._failure_count += 1
        if len(self._failures) >= MAX_RECORDED_FAILURES:
            return
        self._failures.append(
            {
                "level": "error",
                "message": {"text": "Scan failed while processing an input."},
                "properties": {"errorType": type(error).__name__},
            }
        )

    def finish(self, exit_code: int) -> None:
        """
        Finish the SARIF log with tool metadata and invocation status.

        :param exit_code: Process exit code that Presidio CLI will return.
        :raises SarifValidationError: If generated metadata is invalid.
        """
        self._ensure_open()
        self._finished = True

        notifications = list(self._failures)
        if self._failure_count > len(self._failures):
            notifications.append(
                {
                    "level": "note",
                    "message": {"text": "Additional scan failures were omitted."},
                    "properties": {
                        "omittedFailureCount": self._failure_count - len(self._failures)
                    },
                }
            )

        rules = self._build_rules()
        invocation = self._build_invocation(exit_code, notifications)
        self._validate_finish(rules, invocation)

        self._stream.write('],"tool":{"driver":')
        json.dump(
            {
                "name": "Presidio",
                "version": self._tool_version,
                "informationUri": "https://presidio.dataprivacystack.org/",
                "rules": rules,
            },
            self._stream,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        self._stream.write('},"invocations":')
        json.dump(
            [invocation],
            self._stream,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        self._stream.write("}]}\n")

    def _build_rules(self) -> List[Dict]:
        rules = []
        for ridex, (rule_id, entity_type) in enumerate(self._rules.items()):
            path = f"/runs/0/tool/driver/rules/{ridex}"
            _validate_text(rule_id, f"{path}/id")
            _validate_text(entity_type, f"{path}/name")
            rules.append(
                {
                    "id": rule_id,
                    "name": entity_type,
                    "shortDescription": {
                        "text": f"{entity_type} personally identifiable information."
                    },
                }
            )
        return rules

    def _build_invocation(self, exit_code: int, notifications: List[Dict]) -> Dict:
        return {
            "executionSuccessful": self._failure_count == 0,
            "exitCode": exit_code,
            "toolExecutionNotifications": notifications,
        }

    def _validate_finish(self, rules: List[Dict], invocation: Dict) -> None:
        if not isinstance(invocation.get("executionSuccessful"), bool):
            raise SarifValidationError(
                "/runs/0/invocations/0/executionSuccessful",
                "value must be a boolean",
            )
        _validate_int(
            invocation.get("exitCode"),
            "/runs/0/invocations/0/exitCode",
            0,
        )
        notifications = invocation.get("toolExecutionNotifications")
        if not isinstance(notifications, list):
            raise SarifValidationError(
                "/runs/0/invocations/0/toolExecutionNotifications",
                "value must be an array",
            )
        for index, notification in enumerate(notifications):
            path = f"/runs/0/invocations/0/toolExecutionNotifications/{index}"
            if notification.get("level") not in ("none", "note", "warning", "error"):
                raise SarifValidationError(
                    f"{path}/level", "value must be a valid SARIF notification level"
                )
            message = notification.get("message", {})
            _validate_text(message.get("text"), f"{path}/message/text")
        for index, rule in enumerate(rules):
            _validate_text(rule.get("id"), f"/runs/0/tool/driver/rules/{index}/id")
            _validate_text(rule.get("name"), f"/runs/0/tool/driver/rules/{index}/name")

    def _ensure_open(self) -> None:
        if self._finished:
            raise ValueError("SARIF writer is already finished")
