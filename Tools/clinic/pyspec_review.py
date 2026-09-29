#!/usr/bin/env python3
"""Answer a reviewer's questions about a pyspec change, in one summary.

    ./python Tools/clinic/pyspec_review.py [--baseline ../build-main/python]
                                           [--base main]

prints, ready to paste into a PR description:

1. Behaviour: did anything observable about the spec'd types change?
   Their capture against the committed record
   (Tools/clinic/pyspec-baseline/parity.txt), which sections of the record
   changed since the base, the differences made on purpose (PARITY
   "known" of each <stem>_cases.py), and with --baseline every line
   against a build of the base (Tools/clinic/pyspec_parity.py).
2. Generated code: is clinic's output up to date (clinic --dry-run on
   the C file of every spec), and which clinic outputs differ from the
   base, in which C functions, and whether that is on purpose (PARITY
   "generated").
3. Specs vs interpreter (test_clinic), facts (test_pyspec_facts; a debug
   build also asserts the facts at run time) and the disconnect ratchet
   (test_pyspec_catalog; its baseline may only shrink): pass or fail,
   with the ratchet counts.  --no-tests skips them.

Each answer is also one command of its own, printed with it.  The exit
status is 0 when every answer is fine.
"""

import argparse
import difflib
import glob
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pyspec_parity

SRCDIR = pyspec_parity.SRCDIR
TESTS = [
    ('Specs vs interpreter', 'test_clinic',
     'generated files up to date, spec run as Python vs the interpreter, '
     'slots vs dunders'),
    ('Facts', 'test_pyspec_facts',
     'call table and helpers vs the interpreter and their references'),
    ('Ratchet', 'test_pyspec_catalog',
     'disconnects vs Tools/clinic/pyspec-baseline/*.txt'),
]
# A line of a clinic output that starts what belongs to one C name.
ANCHOR = re.compile(r'PyDoc_STRVAR\((\w+?)(?:__doc__)?,'
                    r'|#define (\w+?)_METHODDEF\b'
                    r'|static [^=;(]*?\b(\w+)(?:\[\])? ='
                    r'|(\w+)\(')


def git(*args, check=True):
    proc = subprocess.run(['git', *args], cwd=SRCDIR, capture_output=True,
                          text=True, encoding='utf-8')
    if check and proc.returncode:
        raise RuntimeError(f'git {" ".join(args)}: {proc.stderr.strip()}')
    return proc.stdout


def merge_base(ref):
    for candidate in ([ref] if ref else ['main', 'upstream/main',
                                         'origin/main']):
        proc = subprocess.run(['git', 'merge-base', 'HEAD', candidate],
                              cwd=SRCDIR, capture_output=True, text=True)
        if proc.returncode == 0:
            return candidate, proc.stdout.strip()
    raise RuntimeError(f'no merge base with {ref or "main"}: pass --base')


def at_base(base, path):
    """The text of path at the base commit, or None."""
    proc = subprocess.run(['git', 'show', f'{base}:{path}'], cwd=SRCDIR,
                          capture_output=True, text=True, encoding='utf-8')
    return proc.stdout if proc.returncode == 0 else None


# -- 1. behaviour --------------------------------------------------------------

def behaviour(base, baseline):
    """(lines of the summary, ok)."""
    out, ok = [], True
    head, messages, current = pyspec_parity.check_against_record()
    names = pyspec_parity.type_names(current)
    nlines = sum(count for count, _ in current.values())
    what = (f'{", ".join(names)} ({nlines:,} lines in {len(current)} '
            'sections)')
    record = pyspec_parity.RECORD
    if messages is None:
        out.append(f'- Behaviour: {record} has no block for this '
                   f'configuration; {what} not checked against it')
    elif messages:
        ok = False
        out.append(f'- Behaviour: DIFFERS from {record} in '
                   f'{len(messages)} sections of {what}:')
        out += [f'  - {m}' for m in messages]
    else:
        out.append(f'- Behaviour: same as {record} for {what}')
    # What the change did to the record.
    old = at_base(base, record)
    if old is None:
        out.append(f'  - {record}: new since the base')
    else:
        before = pyspec_parity.parse_record(old).get(head)
        after = pyspec_parity.read_record().get(head)
        if before == after:
            out.append(f'  - {record}: unchanged since the base for this '
                       'configuration')
        elif before is None:
            out.append(f'  - {record}: block of this configuration new '
                       'since the base')
        else:
            changed = [f'{n} {s}' for n, s in {**before, **after}
                       if before.get((n, s)) != after.get((n, s))]
            out.append(f'  - {record}: {len(changed)} sections changed '
                       f'since the base (say why): {", ".join(changed)}')
    seen = None
    if baseline:
        before = pyspec_parity.run_capture(baseline, names)
        after = pyspec_parity.run_capture(sys.executable, names)
        comparison = pyspec_parity.Comparison(
            before, after, [pyspec_parity.resolve(n) for n in names])
        total = sum(comparison.probes.values())
        if comparison:
            ok = False
            out.append(f'  - vs {baseline}: DIFFERS:')
            out += ['    ' + line for line in
                    comparison.text(limit=3).splitlines()]
        else:
            out.append(f'  - vs {baseline}: no difference in {total:,} '
                       'lines')
        seen = comparison.known_seen()
    for data in pyspec_parity.spec_types().values():
        for pattern, (_, reason) in data.known.items():
            if seen is None:
                note = ''
            elif (data.name, pattern) in seen:
                note = ' (differs from the baseline: '
                note += ', '.join(seen[data.name, pattern]) + ')'
            else:
                note = ' (NOT SEEN vs the baseline: delete it?)'
                ok = False
            out.append(f'  - on purpose: {data.name} /{pattern}/: {reason}'
                       f'{note}')
    out.append('  - (`python Tools/clinic/pyspec_parity.py check`'
               + (f'; `... compare {baseline}`' if baseline else '') + ')')
    return out, ok


# -- 2. generated code -----------------------------------------------------------

def spec_c_files():
    """The C file of every spec (Objects/pyspec/foo.py: Objects/foo.c)."""
    files = []
    for top in ('Objects', 'Modules', 'Python', 'Include'):
        pattern = os.path.join(SRCDIR, top, '**', 'pyspec', '*.py')
        for spec in sorted(glob.glob(pattern, recursive=True)):
            if spec.endswith('_cases.py'):
                continue
            stem = os.path.basename(spec).removesuffix('.py')
            parent = os.path.dirname(os.path.dirname(spec))
            for ext in ('.c', '.h'):
                path = os.path.join(parent, stem + ext)
                if os.path.exists(path):
                    files.append(os.path.relpath(path, SRCDIR))
                    break
    return files


def stale_files(c_files):
    """The clinic outputs that clinic would rewrite."""
    proc = subprocess.run(
        [sys.executable, os.path.join('Tools', 'clinic', 'clinic.py'),
         '--dry-run', *c_files],
        cwd=SRCDIR, capture_output=True, text=True, encoding='utf-8')
    if proc.returncode:
        return None, proc.stderr.strip().splitlines()[-1:]
    return [line.split(' ', 2)[2] for line in proc.stdout.splitlines()
            if line.startswith('would ')], None


def anchors(lines):
    """For each line of a clinic output, the C name it belongs to."""
    names, current = [], None
    for line in lines:
        m = ANCHOR.match(line)
        if m:
            name = next(g for g in m.groups() if g)
            current = name.lower() if m.group(2) else name
        names.append(current)
    return names


def changed_names(old, new):
    """The C names whose part of a clinic output changed, and the number
    of lines added and removed."""
    old, new = old.splitlines(), new.splitlines()
    old_names, new_names = anchors(old), anchors(new)
    names, added, removed = [], 0, 0
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            continue
        removed += i2 - i1
        added += j2 - j1
        touched = old_names[i1:i2] + new_names[j1:j2]
        if not touched:
            # An insertion: it belongs to the name before it.
            touched = new_names[max(j1 - 1, 0):j1]
        for name in touched:
            if name and name not in names:
                names.append(name)
    return names, added, removed


def explain(names):
    """Which names a PARITY "generated" explains: {reason: [names]}, and
    the names none does."""
    rules = [(re.compile(pattern), reason)
             for data in pyspec_parity.spec_types().values()
             for pattern, reason in data.generated.items()]
    reasons, unexplained = {}, []
    for name in names:
        for pattern, reason in rules:
            if pattern.match(name):
                reasons.setdefault(reason, []).append(name)
                break
        else:
            unexplained.append(name)
    return reasons, unexplained


def spec_of_output(path):
    """The spec a new foo_pyspec.c.h is generated from, or None."""
    stem = os.path.basename(path).removesuffix('.c.h').removesuffix('.h.h')
    stem = stem.removesuffix('_pyspec')
    for top in ('Objects', 'Modules', 'Python', 'Include'):
        found = glob.glob(os.path.join(SRCDIR, top, '**', 'pyspec',
                                       stem + '.py'), recursive=True)
        if found:
            return os.path.relpath(found[0], SRCDIR)
    return None


def shorten(names, n=6):
    if len(names) <= n:
        return ', '.join(names)
    return ', '.join(names[:n]) + f', ... ({len(names)} names)'


def generated(base):
    out, ok = [], True
    c_files = spec_c_files()
    stale, error = stale_files(c_files)
    if error:
        ok = False
        out.append(f'- Generated code: clinic FAILED: {" ".join(error)}')
    elif stale:
        ok = False
        out.append(f'- Generated code: OUT OF DATE: {", ".join(stale)} '
                   f'(run `python Tools/clinic/clinic.py {" ".join(c_files)}`)')
    else:
        out.append(f'- Generated code: up to date (clinic --dry-run on '
                   f'{len(c_files)} C files of specs)')
    status = git('diff', '--name-status', base, '--', '*/clinic/*.h')
    differ = [line.split('\t') for line in status.splitlines()]
    for kind, path, *_ in differ:
        if kind == 'D':
            out.append(f'  - {path}: deleted')
            continue
        with open(os.path.join(SRCDIR, path), encoding='utf-8') as f:
            new = f.read()
        if kind == 'A':
            spec = spec_of_output(path)
            source = f', generated from {spec}' if spec else ''
            out.append(f'  - {path}: new ({len(new.splitlines())} lines'
                       f'{source})')
            continue
        names, added, removed = changed_names(at_base(base, path), new)
        reasons, unexplained = explain(names)
        out.append(f'  - {path}: +{added}/-{removed} lines, in '
                   f'{shorten(names)}')
        for reason, which in reasons.items():
            out.append(f'    - on purpose ({shorten(which, 3)}): {reason}')
        if unexplained:
            out.append(f'    - NOT EXPLAINED: {shorten(unexplained)} (say '
                       'why, or add it to the "generated" of the PARITY of '
                       'the type)')
    other = 'every other' if differ else 'every'
    out.append(f'  - {other} clinic output: identical to the base')
    return out, ok


# -- 3. tests ------------------------------------------------------------------

def run_test(module):
    """(passed, summary, output) of one test module."""
    args = [sys.executable, '-m', 'test', module]
    if module == 'test_pyspec_catalog':
        args.append('-v')       # prints the counts per dimension
    proc = subprocess.run(args, cwd=SRCDIR, capture_output=True, text=True,
                          encoding='utf-8', errors='replace')
    output = proc.stdout + proc.stderr
    run = re.search(r'Total tests: run=([\d,]+)(.*)', output)
    summary = f'{run.group(1)} tests' if run else 'no test ran'
    if run and run.group(2).strip():
        summary += f' ({run.group(2).strip()})'
    return proc.returncode == 0, summary, output


def tests():
    out, ok = [], True
    debug = hasattr(sys, 'gettotalrefcount')
    for title, module, what in TESTS:
        passed, summary, output = run_test(module)
        ok &= passed
        extra = ''
        if module == 'test_pyspec_facts':
            extra = ('; debug build: facts also asserted at run time'
                     if debug else '; release build: no run-time fact '
                     'assertions (use a debug build)')
        if module == 'test_pyspec_catalog':
            counts = re.findall(r'^ {4}(\w+) +(\d+)$', output, re.M)
            extra = '; ' + ', '.join(f'{d} {n}' for d, n in counts)
        verdict = 'passed' if passed else 'FAILED'
        out.append(f'- {title}: {verdict}, {summary}{extra} '
                   f'(`python -m test {module}`: {what})')
        if not passed:
            fails = [line for line in output.splitlines()
                     if line.startswith(('FAIL:', 'ERROR:'))]
            out += [f'  - {line}' for line in fails[:10]]
    return out, ok


def ratchet_baseline(base):
    """How the ratchet's baseline files changed since the base."""
    stat = git('diff', '--numstat', base, '--',
               'Tools/clinic/pyspec-baseline/*.txt',
               ':!Tools/clinic/pyspec-baseline/parity.txt')
    added = removed = 0
    for line in stat.splitlines():
        a, r, _ = line.split('\t')
        added, removed = added + int(a), removed + int(r)
    if not stat:
        return '  - ratchet baseline: unchanged since the base'
    note = (' (added lines are new disconnects: say why)'
            if added else '')
    return (f'  - ratchet baseline: +{added}/-{removed} lines since the '
            f'base{note}')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n\n')[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--baseline', metavar='PYTHON',
                        help='a build of the base, same configuration: '
                             'compare every probed line with it')
    parser.add_argument('--base', metavar='REF',
                        help='the branch the change goes into (default: '
                             'main, upstream/main or origin/main)')
    parser.add_argument('--no-tests', action='store_true',
                        help='skip the test modules')
    args = parser.parse_args(argv)
    ref, base = merge_base(args.base)
    head = git('rev-parse', '--short', 'HEAD').strip()
    dirty = ' + uncommitted changes' if git('status', '--porcelain',
                                             '--untracked-files=no') else ''
    config = pyspec_parity.header().removeprefix('# ')
    lines = [f'pyspec review of {head}{dirty} against {ref} (merge base '
             f'{base[:11]}), {config}', '']
    ok = True
    parts = [behaviour(base, args.baseline), generated(base)]
    if not args.no_tests:
        test_lines, test_ok = tests()
        test_lines.append(ratchet_baseline(base))
        parts.append((test_lines, test_ok))
    for part, part_ok in parts:
        lines += part
        ok &= part_ok
    lines += ['', 'Result: ' + ('OK' if ok else 'PROBLEMS (see above)')]
    print('\n'.join(lines))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
