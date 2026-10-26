'''Test runner and result class for the regression test suite.

'''

import functools
import io
import sys
import time
import unittest
from test import support
from test.libregrtest.reporter import Reporter

class RegressionTestResult(unittest.TextTestResult):
    reporter = Reporter()

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream=stream, descriptions=descriptions,
                         verbosity=verbosity)
        self.buffer = True

    def startTestRun(self):
        super().startTestRun()
        self.reporter.test_run_started()

    def stopTestRun(self):
        self.reporter.test_run_finished(self)
        super().stopTestRun()

    def startTest(self, test):
        super().startTest(test)
        self.reporter.test_case_started(test)

    def _add_result(self, test, outcome, details=None):
        if self._stdout_buffer is not None:
            output = (self._stdout_buffer.getvalue(),
                      self._stderr_buffer.getvalue())
        else:
            output = None
        self.reporter.test_case_finished(test, outcome, details, output)

    def addError(self, test, err):
        self._add_result(test, 'error', err)
        super().addError(test, err)

    def addExpectedFailure(self, test, err):
        self._add_result(test, 'expected_failure', err)
        super().addExpectedFailure(test, err)

    def addFailure(self, test, err):
        self._add_result(test, 'failure', err)
        super().addFailure(test, err)
        if support.failfast:
            self.stop()

    def addSkip(self, test, reason):
        self._add_result(test, 'skipped', reason)
        super().addSkip(test, reason)

    def addSuccess(self, test):
        self._add_result(test, 'success')
        super().addSuccess(test)

    def addUnexpectedSuccess(self, test):
        self._add_result(test, 'unexpected_success')
        super().addUnexpectedSuccess(test)

    def printErrorList(self, flavour, errors):
        for test, err in errors:
            super().printErrorList(flavour, [(test, err)])
            self.report_failure(test, err)

    def report_failure(self, test, err):
        self.reporter.test_case_failed(str(test), err, self.stream)

class QuietRegressionTestRunner:
    def __init__(self, stream, buffer=False):
        self.result = RegressionTestResult(stream, None, 0)
        self.result.buffer = buffer

    def run(self, test):
        self.result.startTestRun()
        try:
            test(self.result)
        finally:
            self.result.stopTestRun()
        # Failures are not printed in quiet mode
        for test, err in self.result.errors + self.result.failures:
            self.result.report_failure(test, err)
        return self.result

def get_test_runner_class(verbosity, buffer=False):
    if verbosity:
        # The verbosity of regrtest is one less than the verbosity of
        # unittest: -v reports the test names, -vv also the doctest examples.
        return functools.partial(unittest.TextTestRunner,
                                 resultclass=RegressionTestResult,
                                 buffer=buffer,
                                 verbosity=verbosity + 1)
    return functools.partial(QuietRegressionTestRunner, buffer=buffer)

def get_test_runner(stream, verbosity, capture_output=False):
    return get_test_runner_class(verbosity, capture_output)(stream)

if __name__ == '__main__':
    from test.libregrtest.reporter import JUnitReporter
    support.junit_xml_list = []
    RegressionTestResult.reporter = JUnitReporter()

    class TestTests(unittest.TestCase):
        def test_pass(self):
            pass

        def test_pass_slow(self):
            time.sleep(1.0)

        def test_fail(self):
            print('stdout', file=sys.stdout)
            print('stderr', file=sys.stderr)
            self.fail('failure message')

        def test_error(self):
            print('stdout', file=sys.stdout)
            print('stderr', file=sys.stderr)
            raise RuntimeError('error message')

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestTests))
    stream = io.StringIO()
    runner_cls = get_test_runner_class(sum(a == '-v' for a in sys.argv))
    runner = runner_cls(sys.stdout)
    result = runner.run(suite)
    print('Output:', stream.getvalue())
    print('XML:', *support.junit_xml_list)
