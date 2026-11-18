import argparse
import io
import json
import locale
import logging
import os
import platform
import shutil
import sys
import tempfile
import traceback
from typing import Generator, List

from presidio_cli import APP_DESCRIPTION, APP_VERSION, SHELL_NAME
from presidio_cli.analyzer import PIIProblem, analyze
from presidio_cli.config import PresidioCLIConfig, PresidioCLIConfigError
from presidio_cli.sarif import SarifValidationError, SarifWriter

logger = logging.getLogger("presidio-cli")


class SarifOutputError(Exception):
    """Represents a failure to write a complete SARIF log."""


class Format(object):
    """Class providing methods for formatting output, with information about discovered PII problems."""  # noqa: E501

    @staticmethod
    def parsable(problem: PIIProblem) -> str:
        """
        Format the problem as JSON.

        :param problem: PIIProblem to be formatted.
        :return: JSON representation of the problem.
        """
        return json.dumps(problem.recognizer_result)

    @staticmethod
    def standard(problem: PIIProblem) -> str:
        """
        Output the problem in standard format.

        :param problem: PIIProblem to be formatted.
        :return: Standard text representation of the problem.
        """
        line = "  %d:%d" % (problem.line, problem.column)
        line += max(12 - len(line), 0) * " "
        line += str(problem.score)
        line += max(21 - len(line), 0) * " "
        line += problem.type
        if problem.explanation:
            line += "  (%s)" % problem.explanation
        return line

    @staticmethod
    def standard_color(problem: PIIProblem) -> str:
        """
        Output the problem in standard, colored format.

        :param problem: PIIProblem to be formatted.
        :return: Standard, colored text representation of the problem.
        """
        line = "  \033[2m%d:%d\033[0m" % (problem.line, problem.column)
        line += max(20 - len(line), 0) * " "
        if problem.level == "warning":
            line += "\033[33m%s\033[0m" % problem.score
        else:
            line += "\033[31m%s\033[0m" % problem.score
        line += max(38 - len(line), 0) * " "
        line += problem.type
        if problem.explanation:
            line += "  \033[2m(%s)\033[0m" % problem.explanation
        return line

    @staticmethod
    def github(problem: PIIProblem, filename: str) -> str:
        """
        Output the problem as a GitHub Actions warning or error workflow command.

        :param problem: PIIProblem to be formatted.
        :param filename: Filename where the problem occurs.
        :return: Workflow command that creates an annotation for the problem.
        """
        message = f"{problem.line}:{problem.column} [{problem.type}]"
        message += f" score={problem.score}"
        if problem.explanation:
            message += f" ({problem.explanation})"
        # Drop the ./ that `presidio .` adds, as run() does before analyze()
        if filename.startswith(("./", ".\\")):
            filename = filename[2:]
        file = _escape_github_property(filename)
        return (
            f"::{problem.level} file={file},line={problem.line},col={problem.column}"
            f"::{_escape_github_data(message)}"
        )


def _escape_github_data(value: str) -> str:
    """Escape the message of a GitHub Actions workflow command."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_github_property(value: str) -> str:
    """Escape a property value of a GitHub Actions workflow command."""
    return _escape_github_data(value).replace(":", "%3A").replace(",", "%2C")


def threshold_value(value: str) -> float:
    """Parse a threshold value between 0.0 and 1.0."""
    try:
        threshold = float(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError("threshold must be a float") from e

    if not 0.0 <= threshold <= 1.0:
        raise argparse.ArgumentTypeError("threshold must be between 0.0 and 1.0")

    return threshold


def supports_color() -> bool:
    """Check whether the platform supports colored output."""
    supported_platform = not (
        platform.system() == "Windows"
        and not (
            "ANSICON" in os.environ
            or ("TERM" in os.environ and os.environ["TERM"] == "ANSI")
        )
    )
    return supported_platform and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def show_problems(
    problems: Generator["PIIProblem", None, None],
    file: str,
    args_format: str,
    no_warn: bool,
) -> int:
    """
    Show formatted output of discovered problems.

    :param problems: generator of PIIProblem objects
    :param file: processed filename for 'stdin'
    :param args_format: format in which to output discovered problems
    :param no_warn: whether to output only error level problems
    :return: number of problems that were output
    """
    prob_num = 0
    first = True

    if args_format == "auto":
        if "GITHUB_ACTIONS" in os.environ and "GITHUB_WORKFLOW" in os.environ:
            args_format = "github"
        elif supports_color():
            args_format = "colored"

    for problem in problems:
        if no_warn and (problem.level != "error"):
            continue
        prob_num += 1
        if args_format == "parsable":
            print(Format.parsable(problem))
        elif args_format == "github":
            if first:
                print("::group::%s" % _escape_github_data(file))
                first = False
            print(Format.github(problem, file))
        elif args_format == "colored":
            if first:
                print("\033[4m%s\033[0m" % file)
                first = False
            print(Format.standard_color(problem))
        else:
            if first:
                print(file)
                first = False
            print(Format.standard(problem))

    if not first and args_format == "github":
        print("::endgroup::")

    if not first and args_format != "parsable":
        print("")

    return prob_num


def find_files_recursively(
    items: List[str], conf: PresidioCLIConfig
) -> Generator[str, None, None]:
    """
    Generate all file names inside the directories.

    :param items: List of directories containing files to be analyzed.
    :param conf: PresidioCLIConfig object
    """
    for item in items:
        if os.path.isdir(item):
            for root, dirnames, filenames in os.walk(item):
                for f in filenames:
                    filepath = os.path.join(root, f)
                    if conf.is_text_file(filepath):
                        yield filepath
        else:
            if conf.is_text_file(item):
                yield item


def _find_git_root(start: str) -> str:
    """Return the nearest Git root, or an empty string when none exists."""
    current = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return ""
        current = parent


def _find_repository_root(start: str = None) -> str:
    """Find the nearest Git root, falling back to the current directory."""
    return _find_git_root(start or os.getcwd()) or os.path.abspath(os.getcwd())


def _repository_root_for_inputs(items: List[str]) -> str:
    """Choose one root that keeps every input artifact path relative."""
    existing = [
        os.path.abspath(os.fspath(item)) for item in items if os.path.exists(item)
    ]
    if not existing:
        return _find_repository_root()

    cwd = os.path.abspath(os.getcwd())
    bases = [
        item if os.path.isdir(item) else os.path.dirname(item) for item in existing
    ]
    git_roots = {_find_git_root(base) for base in bases} - {""}
    if len(git_roots) == 1:
        return git_roots.pop()

    try:
        if all(os.path.commonpath([cwd, base]) == cwd for base in bases):
            return cwd
        return os.path.commonpath(bases)
    except ValueError:
        return cwd


def _scan_sarif(
    conf: PresidioCLIConfig,
    args: argparse.Namespace,
    writer: SarifWriter,
    excluded_paths=frozenset(),
) -> int:
    """Scan inputs and stream findings into a SARIF writer."""
    prob_num = 0
    try:
        for file in find_files_recursively(args.files, conf):
            if os.path.abspath(file) in excluded_paths:
                continue
            filepath = (
                file[2:] if file.startswith("./") or file.startswith(".\\") else file
            )
            try:
                with io.open(file, newline="", encoding="utf-8") as f:
                    problems = analyze(f, conf, filepath)
                    for problem in problems:
                        if args.no_warnings and problem.level != "error":
                            continue
                        writer.write_result(problem, os.path.abspath(file))
                        prob_num += 1
            except SarifValidationError:
                raise
            except Exception as exc:
                logger.error(
                    "SARIF scan failed for an input: error_type=%s",
                    type(exc).__name__,
                )
                writer.record_failure(exc)
    except SarifValidationError:
        raise
    except Exception as exc:
        logger.error(
            "SARIF scan failed while enumerating inputs: error_type=%s",
            type(exc).__name__,
        )
        writer.record_failure(exc)

    if args.stdin:
        try:
            problems = analyze(sys.stdin, conf, "")
            for problem in problems:
                if args.no_warnings and problem.level != "error":
                    continue
                writer.write_result(problem, "stdin")
                prob_num += 1
        except SarifValidationError:
            raise
        except Exception as exc:
            logger.error(
                "SARIF scan failed for standard input: error_type=%s",
                type(exc).__name__,
            )
            writer.record_failure(exc)

    exit_code = 1 if prob_num > 0 else 0
    writer.finish(exit_code)
    logger.info(
        "SARIF scan completed: results=%d failures=%d",
        writer.result_count,
        writer.failure_count,
    )
    return prob_num


def _write_sarif_file(
    output_path: str, conf: PresidioCLIConfig, args: argparse.Namespace
) -> int:
    """Stream SARIF to a temporary file and atomically publish it."""
    target = os.path.abspath(os.fspath(output_path))
    directory = os.path.dirname(target) or os.curdir
    try:
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=directory,
            prefix=".presidio-sarif-",
            delete=False,
        )
    except OSError:
        raise SarifOutputError("Unable to create SARIF output file.") from None

    temp_name = temp_file.name
    published = False
    try:
        with temp_file:
            writer = SarifWriter(temp_file, _repository_root_for_inputs(args.files))
            prob_num = _scan_sarif(
                conf,
                args,
                writer,
                excluded_paths=frozenset({temp_name, target}),
            )
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, target)
        published = True
        return prob_num
    finally:
        if not published:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def _write_sarif_stdout(conf: PresidioCLIConfig, args: argparse.Namespace) -> int:
    """Stream SARIF to a temporary file, then emit it only when complete."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", newline="\n") as temp_file:
        writer = SarifWriter(temp_file, _repository_root_for_inputs(args.files))
        prob_num = _scan_sarif(conf, args, writer)
        temp_file.flush()
        temp_file.seek(0)
        shutil.copyfileobj(temp_file, sys.stdout)
        return prob_num


def run() -> None:
    """Entrypoint of Presidio CLI."""
    parser = argparse.ArgumentParser(prog=SHELL_NAME, description=APP_DESCRIPTION)

    parser.add_argument("-v", "--version", action="version", version=f"v{APP_VERSION}")

    files_group = parser.add_mutually_exclusive_group(required=True)
    files_group.add_argument(
        "files",
        metavar="FILE_OR_DIR",
        nargs="*",
        default=(),
        help="files to check",
    )
    files_group.add_argument(
        "-", action="store_true", dest="stdin", help="read from standard input"
    )

    config_group = parser.add_mutually_exclusive_group()
    config_group.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        action="store",
        help="path to a custom configuration",
    )

    config_group.add_argument(
        "-d",
        "--config-data",
        dest="config_data",
        action="store",
        help="custom configuration (as YAML source)",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=("standard", "github", "auto", "colored", "parsable", "sarif"),
        default="auto",
        help="format for parsing output",
    )

    parser.add_argument(
        "--sarif-output",
        metavar="PATH",
        default=None,
        help="write a SARIF 2.1.0 log to PATH instead of human-readable output",
    )

    parser.add_argument(
        "--no-warnings",
        action="store_true",
        help="output only error level problems",
    )
    parser.add_argument(
        "--threshold",
        type=threshold_value,
        default=None,
        help="override the config threshold for this run",
    )

    args = parser.parse_args()

    try:
        if args.config_data is not None:
            if args.config_data != "" and ":" not in args.config_data:
                args.config_data = "extends: " + args.config_data
            conf = PresidioCLIConfig(content=args.config_data)
        elif args.config_file is not None:
            conf = PresidioCLIConfig(file=args.config_file)
        elif os.path.isfile(".presidiocli"):
            conf = PresidioCLIConfig(file=".presidiocli")
        else:
            conf = PresidioCLIConfig(content="extends: default")
    except PresidioCLIConfigError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    if args.threshold is not None:
        conf.threshold = args.threshold

    if conf.locale is not None:
        locale.setlocale(locale.LC_ALL, conf.locale)

    sarif_output = getattr(args, "sarif_output", None)
    if not isinstance(sarif_output, (str, os.PathLike)):
        sarif_output = None

    if sarif_output is not None or args.format == "sarif":
        logger.info("Starting SARIF scan")
        try:
            if sarif_output is not None:
                prob_num = _write_sarif_file(sarif_output, conf, args)
            else:
                prob_num = _write_sarif_stdout(conf, args)
        except SarifValidationError as exc:
            logger.error("SARIF output validation failed")
            print(exc, file=sys.stderr)
            sys.exit(1)
            return
        except (SarifOutputError, OSError) as exc:
            logger.error("SARIF output failed: error_type=%s", type(exc).__name__)
            message = (
                str(exc)
                if isinstance(exc, SarifOutputError)
                else "Unable to write SARIF output."
            )
            print(message, file=sys.stderr)
            sys.exit(1)
            return
        sys.exit(1 if prob_num > 0 else 0)
        return

    prob_num = 0
    for file in find_files_recursively(args.files, conf):
        filepath = file[2:] if file.startswith("./") or file.startswith(".\\") else file
        try:
            with io.open(file, newline="", encoding="utf-8") as f:
                problems = analyze(f, conf, filepath)
        except Exception:
            traceback.print_exc()
            continue
        prob_num += show_problems(
            problems, file, args_format=args.format, no_warn=args.no_warnings
        )

    if args.stdin:
        try:
            problems = analyze(sys.stdin, conf, "")
        except EnvironmentError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        prob_num += show_problems(
            problems,
            "stdin",
            args_format=args.format,
            no_warn=args.no_warnings,
        )

    if prob_num > 0:
        return_code = 1
    else:
        return_code = 0
    sys.exit(return_code)
