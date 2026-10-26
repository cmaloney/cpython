import html
import inspect
import os
import pathlib
import re
import sys
import time
import traceback as traceback_module
import unittest
from _colorize import decolor  # type: ignore[import-not-found]
from typing import Any, Callable, Iterable, TextIO

from test import support
from .findtests import findtestdir
from .result import TestResult
from .results import TestResults
from .runtests import RunTests
from .utils import StrPath, count, sanitize_xml

lazy import xml.etree.ElementTree as ET
lazy from xml.etree.ElementTree import Element


class Reporter:
    """Report test failures, for example to a CI service. A no-op here."""

    def run_started(self, runtests: RunTests) -> None:
        """Called at the start of each run, and in the test process."""

    def test_run_started(self) -> None:
        """Called in the test process before running a test suite."""

    def test_case_started(self, test: unittest.TestCase) -> None:
        """Called in the test process before a test case runs."""

    def test_case_finished(self, test: unittest.TestCase, outcome: str,
                           details: Any = None,
                           output: tuple[str, str] | None = None) -> None:
        """Called in the test process after a test case ran.

        outcome is "success", "error", "failure", "skipped",
        "expected_failure" or "unexpected_success". details is the
        exc_info of an error, failure or expected failure, or the reason of
        a skip. output is the captured (stdout, stderr), if captured.
        """

    def test_run_finished(self, result: unittest.TestResult) -> None:
        """Called in the test process after running a test suite."""

    def test_case_failed(self, test_case: str, traceback: str,
                         stream: TextIO) -> None:
        """Called in the test process after a test case failed."""

    def test_result(self, result: TestResult) -> None:
        """Called in the main process after a test file completed."""

    def summary(self, results: TestResults, state: str) -> None:
        """Called in the main process after all runs."""

    @staticmethod
    def parse_traceback(traceback: str) -> tuple[str | None, str | None, str]:
        """Return (filename, line, exception) of a failure."""
        # A frame is its "File" line and its source lines
        frames = list(re.finditer(
            r'^ *File "(.*)", line (\d+).*\n(?:    .*\n)*', traceback,
            re.MULTILINE))
        filename = line = None
        exception = traceback
        if frames:
            filename, line = frames[0].groups()
            exception = traceback[frames[-1].end():]
        # Prefer the last frame in a test file, the assertion
        for frame in frames:
            if pathlib.Path(frame[1]).name.startswith("test_"):
                filename, line = frame.groups()
        return filename, line, exception.strip()


class MultiReporter(Reporter):
    """Forward every Reporter call to each added reporter."""

    def __init__(self, reporters: Iterable[Reporter] = ()) -> None:
        self.reporters: list[Reporter] = list(reporters)

    def add(self, reporter: Reporter) -> None:
        self.reporters.append(reporter)


def _forward(name: str) -> Callable[..., None]:
    def forward(self: MultiReporter, *args: Any, **kwargs: Any) -> None:
        for reporter in self.reporters:
            getattr(reporter, name)(*args, **kwargs)
    forward.__name__ = forward.__qualname__ = name
    return forward


# Define a forwarding method for each hook (plain function) of Reporter
for _name, _value in vars(Reporter).items():
    if inspect.isfunction(_value) and not _name.startswith('_'):
        setattr(MultiReporter, _name, _forward(_name))
del _name, _value


def get_reporter(*, use_junit: bool = False,
                 junit_filename: StrPath | None = None) -> MultiReporter:
    """Create the reporters of a process.

    The test process only needs use_junit to record the JUnit XML results,
    the main process writes them to junit_filename.
    """
    reporter = MultiReporter()
    if use_junit or junit_filename:
        reporter.add(JUnitReporter(junit_filename))
    if GitHubActionsReporter.enabled():
        reporter.add(GitHubActionsReporter())
    return reporter


class JUnitReporter(Reporter):
    """Write the results of the test cases to a JUnit XML file.

    The test process records a testsuite element per test suite run in
    support.junit_xml_list, which is sent to the main process in
    TestResult.xml_data. The main process writes them all in summary().
    """

    def __init__(self, filename: StrPath | None = None) -> None:
        # Resolve the filename before the tests change the current directory
        self.filename = os.path.abspath(filename) if filename else None
        self.testsuites: list[Element] = []
        self._suite: Element | None = None
        self._case: Element | None = None
        self._start_time: float | None = None

    # Test process

    def test_run_started(self) -> None:
        from datetime import datetime, UTC
        self._suite = ET.Element('testsuite')
        self._suite.set('start',
                        datetime.now(UTC).replace(tzinfo=None).isoformat(' '))
        self._case = None
        self._start_time = None

    def test_case_started(self, test: unittest.TestCase) -> None:
        if self._suite is None:
            return
        self._case = ET.SubElement(self._suite, 'testcase')
        self._start_time = time.perf_counter()

    def test_case_finished(self, test: unittest.TestCase, outcome: str,
                           details: Any = None,
                           output: tuple[str, str] | None = None) -> None:
        e = self._case
        self._case = None
        if e is None:
            return

        e.set('name', self.get_test_id(test))
        e.set('status', 'run')
        e.set('result', 'completed')
        if self._start_time:
            e.set('time', f'{time.perf_counter() - self._start_time:0.6f}')

        children: dict[str, Any] = {}
        match outcome:
            case 'error' | 'failure' | 'expected_failure':
                if output is not None:
                    stdout, stderr = output
                    ET.SubElement(e, 'system-out').text = \
                        sanitize_xml(stdout.rstrip())
                    ET.SubElement(e, 'system-err').text = \
                        sanitize_xml(stderr.rstrip())
                tag = 'output' if outcome == 'expected_failure' else outcome
                children[tag] = self.make_error_dict(*details)
            case 'skipped':
                children['skipped'] = details
            case 'unexpected_success':
                children['outcome'] = 'UNEXPECTED_SUCCESS'

        for k, v in children.items():
            if not v:
                continue
            e2 = ET.SubElement(e, k)
            if hasattr(v, 'items'):
                for k2, v2 in v.items():
                    if k2:
                        e2.set(k2, sanitize_xml(str(v2)))
                    else:
                        e2.text = sanitize_xml(str(v2))
            else:
                e2.text = sanitize_xml(str(v))

    def test_run_finished(self, result: unittest.TestResult) -> None:
        e = self._suite
        self._suite = None
        if e is None or support.junit_xml_list is None:
            return
        e.set('tests', str(result.testsRun))
        e.set('errors', str(len(result.errors)))
        e.set('failures', str(len(result.failures)))
        support.junit_xml_list.append(ET.tostring(e).decode('ascii'))

    @staticmethod
    def get_test_id(test: unittest.TestCase) -> str:
        try:
            test_id = test.id
        except AttributeError:
            return str(test)
        try:
            return test_id()
        except TypeError:
            return str(test_id)

    @staticmethod
    def make_error_dict(err_type, err_value, err_tb) -> dict[str, str]:
        if isinstance(err_type, type):
            if err_type.__module__ == 'builtins':
                typename = err_type.__name__
            else:
                typename = f'{err_type.__module__}.{err_type.__name__}'
        else:
            typename = repr(err_type)

        msg = traceback_module.format_exception(err_type, err_value, None)
        tb = traceback_module.format_exception(err_type, err_value, err_tb)

        return {
            'type': typename,
            'message': ''.join(msg),
            '': ''.join(tb),
        }

    # Main process

    def test_result(self, result: TestResult) -> None:
        for e in result.xml_data or ():
            try:
                self.testsuites.append(ET.fromstring(e))
            except ET.ParseError:
                print(result.xml_data, file=sys.__stderr__)
                raise

    def summary(self, results: TestResults, state: str) -> None:
        if self.filename is None or not self.testsuites:
            # Don't create empty XML file
            return

        root = ET.Element("testsuites")

        # Manually count the totals for the overall summary
        totals = {'tests': 0, 'errors': 0, 'failures': 0}
        for suite in self.testsuites:
            root.append(suite)
            for k in totals:
                try:
                    totals[k] += int(suite.get(k, 0))
                except ValueError:
                    pass

        for k, v in totals.items():
            root.set(k, str(v))

        with open(self.filename, 'wb') as f:
            for s in ET.tostringlist(root):
                f.write(s)


class GitHubActionsReporter(Reporter):
    """Annotate failures in the job log and list them in the job summary."""

    ESCAPE_DATA = str.maketrans({"%": "%25", "\r": "%0D", "\n": "%0A"})
    ESCAPE_PROPERTY = ESCAPE_DATA | str.maketrans({":": "%3A", ",": "%2C"})

    @staticmethod
    def enabled() -> bool:
        return bool(os.environ.get("GITHUB_STEP_SUMMARY"))

    def run_started(self, runtests: RunTests) -> None:
        self.runtests = runtests

    def test_case_failed(self, test_case: str, traceback: str,
                         stream: TextIO) -> None:
        if not self.runtests.final_run:
            return
        filename, line, exception = self.parse_traceback(decolor(traceback))
        self.annotate(test_case, exception, filename, line, stream)

    def test_result(self, result: TestResult) -> None:
        if not self.runtests.final_run:
            return
        if not result.is_failed(self.runtests.fail_env_changed):
            return
        # Already annotated by test_case_failed()
        if result.failed_test_cases:
            return
        # "test.test_x.test_y" is test_x/test_y.py or test_x/test_y/__init__.py
        name = result.test_name.removeprefix("test.")
        path = pathlib.Path(findtestdir(self.runtests.test_dir),
                            *name.split("."))
        filename = None
        for candidate in (path.with_suffix(".py"), path / "__init__.py"):
            if candidate.exists():
                filename = str(candidate)
        message = "\n".join([str(result), *(result.env_changed_reasons or ())])
        self.annotate(result.test_name, decolor(message), filename)

    def annotate(self, title: str, message: str, filename: str | None,
                 line: str | None = None,
                 stream: TextIO | None = None) -> None:
        if filename:
            # Make installed stdlib paths relative to the checkout
            path = pathlib.Path(filename)
            stdlib_dir = pathlib.Path(os.__file__).parent
            if path.is_relative_to(stdlib_dir):
                filename = ("Lib" / path.relative_to(stdlib_dir)).as_posix()
            # GitHub needs a line to show the annotation on the file
            line = line or "1"
        props = {"file": filename, "line": line, "title": title}
        props_text = ",".join(f"{key}={value.translate(self.ESCAPE_PROPERTY)}"
                              for key, value in props.items() if value)
        print(f"::error {props_text}::{message.translate(self.ESCAPE_DATA)}",
              file=stream, flush=True)

    def summary(self, results: TestResults, state: str) -> None:
        failed = [result for result in results.rerun_results
                  if result.is_failed(self.runtests.fail_env_changed)]
        if not failed:
            return
        ncases = sum(len(result.failed_test_cases) for result in failed)
        blocks = [f"## {decolor(state)}: "
                  f"{count(len(failed), 'test file')} and "
                  f"{count(ncases, 'test case')} failed"]
        for result in failed:
            blocks.append(f"### {decolor(str(result))}")
            if result.env_changed_reasons:
                blocks.append("\n".join(
                    f"- {reason}" for reason in result.env_changed_reasons))
            for name, traceback in result.failed_test_cases:
                # Expand short tracebacks if there are only a few
                if ncases <= 5 and traceback.count("\n") < 30:
                    details = "<details open>"
                else:
                    details = "<details>"
                blocks += [f"{details}<summary>{html.escape(name)}</summary>",
                           f"```pytb\n{decolor(traceback).rstrip()}\n```",
                           "</details>"]
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a",
                  encoding="utf-8") as fp:
            fp.write("".join(f"{block}\n\n" for block in blocks))
