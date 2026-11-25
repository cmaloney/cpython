"""Run a regrtest invocation N times and classify each run.

Experiment harness for gh-162364 (not for upstream).  Usage:

    python repeat.py --runs 20 --expect pass|catch --label NAME -- REGRTEST ARGS

A run is "caught" only if it crashed, failed a C assertion, or hit the
regrtest --timeout (hang).  Ordinary test failures are reported separately.
With --expect pass, any non-passing run fails the job; with --expect catch,
any passing (missed) run fails the job.
"""
import argparse
import os
import re
import subprocess
import sys
import time

CRASH_RE = re.compile(
    r"Fatal Python error|Assertion .* failed|Segmentation fault|"
    r"Windows fatal exception|access violation|Timeout \(\d+:\d\d:\d\d\)!|"
    r"crashed \(Exit code|ThreadSanitizer"
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--runs", type=int, default=20)
    p.add_argument("--expect", choices=("pass", "catch"), required=True)
    p.add_argument("--label", required=True)
    p.add_argument("args", nargs=argparse.REMAINDER)
    ns = p.parse_args()
    args = ns.args[1:] if ns.args[:1] == ["--"] else ns.args

    cmd = [sys.executable, "-X", "faulthandler", "-m", "test", *args]
    print("command:", " ".join(cmd), flush=True)
    counts = {"pass": 0, "caught": 0, "fail": 0}
    times = []
    for i in range(1, ns.runs + 1):
        t0 = time.monotonic()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              errors="replace")
        dt = time.monotonic() - t0
        times.append(dt)
        out = proc.stdout
        if proc.returncode == 0 and not CRASH_RE.search(out):
            kind = "pass"
        elif CRASH_RE.search(out) or proc.returncode < 0:
            kind = "caught"
        else:
            kind = "fail"
        counts[kind] += 1
        print(f"run {i:2}: {kind:6} rc={proc.returncode} {dt:7.2f}s",
              flush=True)
        unexpected = (kind != "pass") if ns.expect == "pass" else (kind != "caught")
        if unexpected or (kind == "caught" and counts["caught"] == 1):
            print("::group::output of run", i)
            print(out[-6000:])
            print("::endgroup::", flush=True)

    times.sort()
    med = times[len(times) // 2]
    line = (f"| {ns.label} | {ns.expect} | {counts['pass']} | "
            f"{counts['caught']} | {counts['fail']} | {ns.runs} | "
            f"{med:.1f}s | {times[-1]:.1f}s |")
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("| job | expect | pass | caught | other fail | runs "
                    "| median | max |\n|---|---|---|---|---|---|---|---|\n")
            f.write(line + "\n\n")
    if ns.expect == "pass":
        return 0 if counts["pass"] == ns.runs else 1
    return 0 if counts["caught"] == ns.runs else 1


if __name__ == "__main__":
    sys.exit(main())
