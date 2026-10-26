"""Console output of regrtest, written by reporters.

ClassicConsoleReporter logs a line per test, with the time, the load and the
memory usage.

ModernConsoleReporter: at a terminal, the results of passing and skipped
tests collapse into a status line redrawn at the bottom of the output: only
the notable results (failures, environment changes, ...) and the test output
stay on screen. Elsewhere, one line is written per test file. A compact
summary lists what needs attention at the end.
"""

import os
import shutil
import sys
import threading
import time
from _colorize import decolor, get_colors  # type: ignore[import-not-found]
from typing import Any, TextIO

from test import support
from .logger import Logger
from .reporter import Reporter
from .result import State, TestResult
from .results import TestResults
from .runtests import RunTests
from .single import PROGRESS_MIN_TIME
from .utils import TestName, count, format_duration, printlist


# Classic console: log the running tests if nothing happened last N seconds
PROGRESS_UPDATE = 30.0   # seconds
assert PROGRESS_UPDATE >= PROGRESS_MIN_TIME

# Maximum number of failed test cases listed per test file in the summary
MAX_FAILED_CASES = 10

# State => (label, color name)
_LABELS = {
    State.PASSED: ("PASS", "GREEN"),
    State.FAILED: ("FAIL", "BOLD_RED"),
    State.UNCAUGHT_EXC: ("FAIL", "BOLD_RED"),
    State.REFLEAK: ("LEAK", "BOLD_RED"),
    State.ENV_CHANGED: ("ENV", "YELLOW"),
    State.SKIPPED: ("SKIP", "YELLOW"),
    State.RESOURCE_DENIED: ("SKIP", "YELLOW"),
    State.INTERRUPTED: ("INTR", "YELLOW"),
    State.WORKER_FAILED: ("CRASH", "BOLD_RED"),
    State.WORKER_BUG: ("BUG", "BOLD_RED"),
    State.DID_NOT_RUN: ("EMPTY", "YELLOW"),
    State.TIMEOUT: ("TIME", "BOLD_RED"),
}
_LABEL_WIDTH = max(len(label) for label, _ in _LABELS.values())

# Results which collapse into the status line at a terminal
_QUIET_STATES = {State.PASSED, State.SKIPPED, State.RESOURCE_DENIED}


def use_modern_console(console: str, stream: TextIO | None = None) -> bool:
    """Resolve the --console option: "auto" means at a terminal."""
    if console != "auto":
        return console == "modern"
    return is_terminal(stream or sys.stdout)


def is_terminal(stream: TextIO) -> bool:
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def format_short_duration(seconds: float) -> str:
    """Format a duration in a compact form: "0.3s", "4m05s", "1h02m"."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def describe_result(result: TestResult) -> str:
    """Describe a result without its test name: "(2 failures)"."""
    match result.state:
        case State.FAILED:
            parts = []
            if result.errors:
                parts.append(count(len(result.errors), "error"))
            if result.failures:
                parts.append(count(len(result.failures), "failure"))
            return f"({', '.join(parts)})" if parts else ""
        case State.UNCAUGHT_EXC:
            return "(uncaught exception)"
        case State.REFLEAK:
            return "(reference leak)"
        case State.ENV_CHANGED:
            return "(env changed)"
        case State.RESOURCE_DENIED:
            return "(resource denied)"
        case State.WORKER_FAILED:
            return "(worker non-zero exit code)"
        case State.WORKER_BUG:
            return "(worker bug)"
        case State.DID_NOT_RUN:
            return "(ran no tests)"
        case State.TIMEOUT:
            return "(timed out)"
    return ""


class ClassicConsoleReporter(Reporter):
    """Log a line per test, and the results after each run."""

    def __init__(self, logger: Logger, *, quiet: bool = False,
                 print_slowest: bool = False,
                 filtered: bool = False) -> None:
        self.logger = logger
        self.quiet = quiet
        self.print_slowest = print_slowest
        self.filtered = filtered
        self.runtests: RunTests | None = None
        self.first_runtests: RunTests | None = None
        self.test_index = 0
        # Test run by the main process
        self.main_test: TestName | None = None
        # (test name, seconds running) of the tests run by the workers
        self.running: list[tuple[TestName, float]] = []
        self.last_progress = time.monotonic()

    def run_started(self, runtests: RunTests) -> None:
        if runtests.rerun:
            print()
        if self.first_runtests is None:
            self.first_runtests = runtests
        self.runtests = runtests
        self.test_index = 0
        self.last_progress = time.monotonic()
        self.logger.set_tests(runtests)

    def log(self, message: str = "") -> None:
        self.logger.log(message)

    def test_started(self, test_name: TestName) -> None:
        self.test_index += 1
        self.main_test = test_name
        self.logger.display_progress(self.test_index, test_name)

    def tests_running(self, running: list[tuple[TestName, float]]) -> None:
        self.running = running
        assert self.runtests is not None
        now = time.monotonic()
        if self.runtests.pgo or now - self.last_progress < PROGRESS_UPDATE:
            return
        self.last_progress = now
        text = self.format_running()
        if text:
            self.log(text)

    def format_running(self) -> str | None:
        running = [f'{test_name} ({format_duration(dt)})'
                   for test_name, dt in self.running
                   if dt >= PROGRESS_MIN_TIME]
        if not running:
            return None
        return f"running ({len(running)}): {', '.join(running)}"

    def test_result(self, result: TestResult, output: str | None = None,
                    error: str | None = None) -> None:
        assert self.runtests is not None
        pgo = self.runtests.pgo
        self.last_progress = time.monotonic()
        text = str(result)
        duration = result.duration
        if result.test_name == self.main_test:
            self.main_test = None
            if duration is not None and duration >= PROGRESS_MIN_TIME:
                text = f"{text} in {format_duration(duration)}"
        else:
            self.test_index += 1
            if error:
                # WORKER_BUG
                text += ' (%s)' % error
            elif duration and duration >= PROGRESS_MIN_TIME and not pgo:
                text += ' (%s)' % format_duration(duration)
            if not pgo:
                running = self.format_running()
                if running:
                    text += f' -- {running}'
        self.logger.display_progress(self.test_index, text)
        if output:
            print(output, flush=True)

    def run_finished(self, results: TestResults, state: str) -> None:
        runtests = self.runtests
        assert runtests is not None
        # If running the test suite for PGO then no one cares about results.
        if runtests.pgo:
            return

        if runtests.rerun and results.bad:
            ansi = get_colors()
            print(f"{ansi.BOLD_RED}{count(len(results.bad), 'test')} "
                  f"failed again:{ansi.RESET}")
            printlist(results.bad)

        print()
        print(f"== Tests result: {state} ==")
        results.display_result(runtests.tests, self.quiet, self.print_slowest)

    def summary(self, results: TestResults, state: str) -> None:
        assert self.first_runtests is not None
        duration = time.perf_counter() - self.logger.start_time

        # Total duration
        print()
        print("Total duration: %s" % format_duration(duration))

        results.display_summary(self.first_runtests, self.filtered)

        # Result
        print(f"Result: {state}")


class _StatusClearingStream:
    """Clear the status line before anything is written to the terminal.

    Wrap sys.stdout and sys.stderr while tests run, so that the output of
    tests running in the main process doesn't end up on the status line.
    """

    def __init__(self, stream: TextIO,
                 console: 'ModernConsoleReporter') -> None:
        self._stream = stream
        self._console = console

    def write(self, text: str) -> int:
        self._console.clear_status()
        return self._stream.write(text)

    def writelines(self, lines: Any) -> None:
        self._console.clear_status()
        self._stream.writelines(lines)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class ModernConsoleReporter(Reporter):
    """Write a status line, the notable results and a summary."""

    def __init__(self, stream: TextIO | None = None, *,
                 live: bool | None = None,
                 fail_env_changed: bool = False,
                 print_slowest: bool = False,
                 filtered: bool = False) -> None:
        self.stream = stream if stream is not None else sys.stdout
        # Collapse quiet results into a status line redrawn in place
        self.live = is_terminal(self.stream) if live is None else live
        self.fail_env_changed = fail_env_changed
        self.print_slowest = print_slowest
        self.filtered = filtered
        self.colors = get_colors(file=self.stream)
        self.start_time = time.perf_counter()

        self.first_runtests: RunTests | None = None
        self.rerun = False
        self.verbose = 0
        self.total: int | None = None
        self.done = 0
        self.failed = 0
        self.env_changed = 0
        # Last result of each test which needs attention
        self.notable: dict[TestName, TestResult] = {}
        # (test name, seconds running) of the tests currently running
        self.running: list[tuple[TestName, float]] = []

        self._lock = threading.RLock()
        self._status_visible = False
        self._saved_streams: tuple[Any, Any, Any] | None = None
        # Fall back to ASCII if the terminal cannot encode the progress bar
        bar_chars = ("\u2501", "\u2500")
        try:
            "".join(bar_chars).encode(getattr(self.stream, "encoding", None)
                                      or "ascii")
            self._bar_chars = bar_chars
        except (LookupError, UnicodeEncodeError):
            self._bar_chars = ("#", "-")

    # Writing

    def _write(self, text: str) -> None:
        with self._lock:
            self.clear_status()
            self.stream.write(text)
            self.stream.flush()

    def write(self, text: str) -> None:
        """Write test output above the status line."""
        if not text.endswith("\n"):
            text += "\n"
        self._write(text)

    def log(self, message: str = "") -> None:
        """Write a message of regrtest above the status line."""
        ansi = self.colors
        if message:
            message = f"{ansi.GREY}{message}{ansi.RESET}"
        self._write(f"{message}\n")

    def clear_status(self) -> None:
        with self._lock:
            if not self._status_visible:
                return
            self._status_visible = False
            self.stream.write("\r\x1b[K")
            self.stream.flush()

    def _format_status(self, width: int) -> str:
        ansi = self.colors
        elapsed = format_short_duration(time.perf_counter() - self.start_time)
        segments: list[tuple[str, str]] = []
        if self.total:
            bar_width = 20 if width >= 80 else 0
            if bar_width:
                filled = bar_width * self.done // self.total
                full, empty = self._bar_chars
                color = ansi.RED if self.failed else ansi.GREEN
                segments.append((f"{color}{full * filled}{ansi.GREY}"
                                 f"{empty * (bar_width - filled)}{ansi.RESET}",
                                 " "))
            segments.append((f"{ansi.BOLD}{self.done}/{self.total}"
                             f"{ansi.RESET}", " "))
        else:
            segments.append((f"{ansi.BOLD}{self.done}{ansi.RESET}", " "))
        if self.failed:
            segments.append((f"{ansi.BOLD_RED}{self.failed} failed"
                             f"{ansi.RESET}", " \u00b7 "))
        if self.env_changed:
            segments.append((f"{ansi.YELLOW}{self.env_changed} env changed"
                             f"{ansi.RESET}", " \u00b7 "))
        segments.append((f"{ansi.GREY}{elapsed}{ansi.RESET}", " \u00b7 "))
        if self.running:
            running = sorted(self.running, key=lambda item: -item[1])
            names = ", ".join(
                f"{name} ({format_short_duration(dt)})" if dt >= 1 else name
                for name, dt in running)
            segments.append((names, " \u00b7 "))

        line = ""
        for index, (text, sep) in enumerate(segments):
            if index:
                text = sep + text
            line += text
        return self._truncate(line, width)

    def _truncate(self, line: str, width: int) -> str:
        if len(decolor(line)) <= width:
            return line
        # Cut the visible characters, keep the color codes
        result = []
        visible = 0
        i = 0
        while i < len(line) and visible < width - 1:
            if line[i] == "\x1b" and (end := line.find("m", i)) != -1:
                result.append(line[i:end + 1])
                i = end + 1
                continue
            result.append(line[i])
            visible += 1
            i += 1
        return "".join(result) + "\u2026" + self.colors.RESET

    def draw_status(self) -> None:
        if not self.live:
            return
        with self._lock:
            # Keep the output written before the status line in order
            support.flush_std_streams()
            width = shutil.get_terminal_size().columns - 1
            self.stream.write(f"\r\x1b[K{self._format_status(width)}")
            self.stream.flush()
            self._status_visible = True

    # Progress

    def run_started(self, runtests: RunTests) -> None:
        self.rerun = runtests.rerun
        self.verbose = runtests.verbose
        if self.first_runtests is None:
            self.first_runtests = runtests
        self.total = None if runtests.forever else len(runtests.tests)
        self.done = 0
        self.failed = 0
        self.env_changed = 0
        self.running = []
        if self.rerun:
            self._write("\n")
        if self.live and self._saved_streams is None:
            self._saved_streams = (sys.stdout, sys.stderr,
                                   support.print_warning.orig_stderr)
            sys.stdout = _StatusClearingStream(sys.stdout, self)
            sys.stderr = _StatusClearingStream(sys.stderr, self)
            support.print_warning.orig_stderr = sys.stderr
        self.draw_status()

    def run_finished(self, results: TestResults, state: str) -> None:
        self.clear_status()
        if self._saved_streams is not None:
            (sys.stdout, sys.stderr,
             support.print_warning.orig_stderr) = self._saved_streams
            self._saved_streams = None

    def test_started(self, test_name: TestName) -> None:
        self.tests_running([(test_name, 0.0)])

    def tests_running(self, running: list[tuple[TestName, float]]) -> None:
        self.running = running
        self.draw_status()

    def test_result(self, result: TestResult, output: str | None = None,
                    error: str | None = None) -> None:
        # The output of a collapsed result is only shown in verbose mode
        if output and (self.verbose or not self.collapses(result)):
            self.write(output)

        self.done += 1
        self.running = [item for item in self.running
                        if item[0] != result.test_name]
        if result.is_failed(self.fail_env_changed):
            self.failed += 1
        elif result.state == State.ENV_CHANGED:
            self.env_changed += 1

        if result.state in _QUIET_STATES:
            self.notable.pop(result.test_name, None)
        else:
            self.notable[result.test_name] = result

        if not self.collapses(result):
            self._write(self.format_result(result, error) + "\n")
        self.draw_status()

    def collapses(self, result: TestResult) -> bool:
        """Whether the result is only shown in the status line."""
        return (self.live and not self.rerun
                and result.state in _QUIET_STATES)

    def format_label(self, state: str | None) -> str:
        label, color = _LABELS.get(state or "", ("????", "BOLD_RED"))
        if state == State.ENV_CHANGED and self.fail_env_changed:
            color = "BOLD_RED"
        ansi = self.colors
        return f"{getattr(ansi, color)}{label:>{_LABEL_WIDTH}}{ansi.RESET}"

    def format_result(self, result: TestResult,
                      error: str | None = None) -> str:
        ansi = self.colors
        line = f"{self.format_label(result.state)} "
        if result.duration is not None and result.has_meaningful_duration():
            duration = format_short_duration(result.duration)
            line += f"{ansi.GREY}[{duration:>6}]{ansi.RESET} "
        else:
            line += " " * 9
        line += f"{ansi.BOLD}{result.test_name}{ansi.RESET}"
        description = describe_result(result)
        if description:
            line += f" {description}"
        if error:
            line += f" {ansi.GREY}{error}{ansi.RESET}"
        for reason in result.env_changed_reasons or ():
            line += (f"\n{'':{_LABEL_WIDTH + 10}}"
                     f"{ansi.GREY}{reason}{ansi.RESET}")
        return line

    # Summary

    def summary(self, results: TestResults, state: str) -> None:
        if self.first_runtests is None or self.first_runtests.pgo:
            return
        ansi = self.colors
        lines: list[str] = []
        width = min(shutil.get_terminal_size().columns, 80)
        title = " Summary "
        rule = self._bar_chars[1]
        lines.append(f"\n{ansi.BOLD}{rule * 2}{title}"
                     f"{rule * (width - len(title) - 2)}{ansi.RESET}")

        # What needs attention first
        indent = " " * (_LABEL_WIDTH + 1)
        for result in self.notable.values():
            line = f"{self.format_label(result.state)} {ansi.BOLD}"
            line += f"{result.test_name}{ansi.RESET}"
            description = describe_result(result)
            if description:
                line += f" {description}"
            lines.append(line)
            cases = [name for name, _ in result.failed_test_cases]
            for name in cases[:MAX_FAILED_CASES]:
                lines.append(f"{indent}{ansi.RED}{name}{ansi.RESET}")
            if len(cases) > MAX_FAILED_CASES:
                lines.append(f"{indent}{ansi.GREY}... and "
                             f"{len(cases) - MAX_FAILED_CASES} more"
                             f"{ansi.RESET}")
            for reason in result.env_changed_reasons or ():
                lines.append(f"{indent}{ansi.GREY}{reason}{ansi.RESET}")
        if self.notable:
            lines.append("")

        if self.print_slowest and results.test_times:
            lines.append(f"{ansi.BOLD}Slowest tests{ansi.RESET}")
            for test_time, test in sorted(results.test_times,
                                          reverse=True)[:10]:
                lines.append(f"{format_short_duration(test_time):>9} {test}")
            lines.append("")

        lines.extend(self.format_totals(results, state))
        self._write("\n".join(lines) + "\n")

    def format_totals(self, results: TestResults, state: str) -> list[str]:
        ansi = self.colors
        first_runtests = self.first_runtests
        assert first_runtests is not None
        filtered = ""
        if self.filtered:
            filtered = f" {ansi.GREY}(filtered){ansi.RESET}"

        def part(tests: Any, text: str, color: str = "") -> str | None:
            number = tests if isinstance(tests, int) else len(tests)
            if not number:
                return None
            reset = ansi.RESET if color else ""
            return f"{color}{number} {text}{reset}"

        omitted = len(set(first_runtests.tests) - results.get_executed())
        if first_runtests.forever:
            omitted = 0
        files = [
            part(results.good, "passed", ansi.GREEN),
            part(results.bad, "failed", ansi.BOLD_RED),
            part(results.env_changed, "env changed",
                 ansi.BOLD_RED if self.fail_env_changed else ansi.YELLOW),
            part(results.skipped, "skipped", ansi.YELLOW),
            part(results.resource_denied, "resource denied", ansi.YELLOW),
            part(results.run_no_tests, "ran no tests", ansi.YELLOW),
            part(omitted, "omitted", ansi.YELLOW),
        ]
        stats = results.stats
        tests = [
            f"{stats.tests_run:,} run",
            part(stats.failures, "failed", ansi.BOLD_RED),
            part(stats.skipped, "skipped", ansi.YELLOW),
        ]
        lines = [
            ("Files", ", ".join(filter(None, files)) or "none run"),
            ("Tests", ", ".join(filter(None, tests)) + filtered),
        ]
        if results.rerun:
            lines.append(("Re-run", ", ".join(results.rerun)))
        duration = time.perf_counter() - self.start_time
        lines.append(("Time", format_short_duration(duration)))
        lines.append(("Result", f"{ansi.BOLD}{state}{ansi.RESET}"))
        return [f"{ansi.BOLD}{name:>6}{ansi.RESET}  {text}"
                for name, text in lines]
