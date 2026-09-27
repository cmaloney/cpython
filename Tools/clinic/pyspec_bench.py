"""Instructions per iteration of statements, on several interpreters.

    python Tools/clinic/pyspec_bench.py -p before=../b1/python \\
        -p after=../b2/python -s "b = b'abc' * 5" "b.removeprefix(b'ab')"

Each statement runs in a loop in a fresh process of each interpreter,
with the JIT on and off (PYTHON_JIT).  The setup runs in the same
function, so its names are fast locals.  Under ``perf stat`` the loop
runs N1 and N2 times; (instructions at N2 - instructions at N1) /
(N2 - N1), each the minimum of --repeat runs, is the cost of one
iteration, statement plus loop: startup, warm-up and JIT compilation
cancel out.  Measure ``pass`` to see the loop alone.  --cycles adds
cycles, which are only meaningful on a quiet machine with a fixed CPU
(--cpu).  Without a working ``perf``, the times of the two loop counts
are differenced instead (time.perf_counter, minimum of --repeat runs):
much noisier, and said so.  See Objects/pyspec/MIGRATING.rst.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

KERNEL = '--kernel'


def kernel(stmt, setup, n, timed):
    """Run in the child: define run(n) and run it once."""
    body = '\n'.join('    ' + line for line in setup.splitlines())
    src = (f'def run(n):\n{body}\n    for _ in range(n):\n'
           + '\n'.join('        ' + line for line in stmt.splitlines()))
    ns = {}
    exec(src, ns)
    t0 = time.perf_counter()
    ns['run'](n)
    if timed:
        print(time.perf_counter() - t0)


def perf_works():
    if shutil.which('perf') is None:
        return False
    proc = subprocess.run(['perf', 'stat', '-x,', '-e', 'instructions:u',
                           'true'], capture_output=True, text=True)
    return proc.returncode == 0 and '<not' not in proc.stderr


def query(python, code):
    out = subprocess.run([python, '-c', code], capture_output=True, text=True)
    return out.stdout.strip()


def jit_available(python):
    return query(python, 'import sys; print(getattr(sys, "_jit", None) '
                         'is not None and sys._jit.is_available())') == 'True'


def run_once(python, stmt, setup, n, jit, events, cpu):
    """{event: count} of one run, or {'time': seconds} without events."""
    env = dict(os.environ, PYTHON_JIT='1' if jit else '0')
    cmd = [python, __file__, KERNEL, stmt, setup, str(n), str(not events)]
    if cpu is not None and shutil.which('taskset'):
        cmd = ['taskset', '-c', str(cpu)] + cmd
    if events:
        cmd = ['perf', 'stat', '-x,', '-e', ','.join(events)] + cmd
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode:
        raise SystemExit(f'{python} failed:\n{proc.stderr}')
    if not events:
        return {'time': float(proc.stdout.split()[-1])}
    counts = {}
    for line in proc.stderr.splitlines():
        fields = line.split(',')
        if len(fields) > 2 and fields[2] in events:
            counts[fields[2]] = int(fields[0])
    return counts


def per_iteration(python, stmt, setup, jit, args, events):
    """{event: count per iteration}: the difference of the minimums."""
    lo, hi = args.loops
    runs = {n: [run_once(python, stmt, setup, n, jit, events, args.cpu)
                for _ in range(args.repeat)] for n in (lo, hi)}
    keys = events or ['time']
    return {k: (min(r[k] for r in runs[hi]) - min(r[k] for r in runs[lo]))
            / (hi - lo) for k in keys}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('stmt', nargs='+', help='statements to measure')
    p.add_argument('-s', '--setup', default='pass')
    p.add_argument('-p', '--python', action='append', metavar='LABEL=PATH',
                   help='interpreter (repeatable; default: this one)')
    p.add_argument('--jit', default='on,off',
                   help='on, off or on,off (default)')
    p.add_argument('--loops', default='100000,1100000',
                   help='the two loop counts N1,N2')
    p.add_argument('--repeat', type=int, default=5)
    p.add_argument('--cycles', action='store_true')
    p.add_argument('--cpu', type=int, help='pin to this CPU (taskset)')
    p.add_argument('--timing', action='store_true',
                   help='difference times even if perf works')
    args = p.parse_args(argv)
    args.loops = tuple(int(n) for n in args.loops.split(','))
    pythons = [tuple(s.split('=', 1)) if '=' in s else (s, s)
               for s in args.python or [sys.executable]]
    if not args.timing and perf_works():
        events = ['instructions:u'] + (['cycles:u'] * args.cycles)
        unit = [e.split(':')[0][:5] for e in events]
    else:
        if not args.timing:
            print('perf stat is not available: timing with '
                  'time.perf_counter instead (noisy; ns per iteration)')
        events, unit = [], ['ns']
    scale = 1e9 if not events else 1
    jits = {m: m == 'on' for m in args.jit.split(',')}
    avail = {label: jit_available(py) for label, py in pythons}
    configs = {query(py, 'import sysconfig; '
                         'print(sysconfig.get_config_var("CONFIG_ARGS"))')
               for _, py in pythons}
    if len(configs) > 1:
        print('warning: the interpreters were configured differently: '
              'their counts are not comparable')
    head = ['statement', 'jit'] + [f'{label} {u}' for label, _ in pythons
                                   for u in unit]
    if len(pythons) > 1:
        head.append(f'{pythons[-1][0]}/{pythons[0][0]}')
    print(' | '.join(head))
    for stmt in args.stmt:
        for mode, jit in jits.items():
            row, firsts = [stmt.replace('\n', '; '), mode], []
            for label, py in pythons:
                if jit and not avail[label]:
                    row += ['no jit'] * len(unit)
                    firsts.append(None)
                    continue
                res = per_iteration(py, stmt, args.setup, jit, args, events)
                vals = [v * scale for v in res.values()]
                row += [f'{v:.0f}' if events else f'{v:.1f}' for v in vals]
                firsts.append(vals[0])
            if len(pythons) > 1:
                a, b = firsts[0], firsts[-1]
                row.append(f'{100 * (b / a - 1):+.1f} %' if a and b else '-')
            print(' | '.join(row), flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == KERNEL:
        kernel(sys.argv[2], sys.argv[3], int(sys.argv[4]),
               sys.argv[5] == 'True')
    else:
        main()
