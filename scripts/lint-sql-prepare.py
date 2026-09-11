#!/usr/bin/env python3
"""Check 88 — every STATIC sqlx statement must PREPARE against the real schema.

`sqlx::query("…")` (the FUNCTION form) takes a runtime `&str`. Nothing checks it
against the schema: not rustc, not clippy, and not CI's "sqlx offline cache"
job, which covers only the `query!` MACRO forms. So a statement naming a
renamed column, a dropped table or a relation that never existed compiles
cleanly, ships, and fails at request time — where a caller's
`.unwrap_or_default()` renders it as an empty list and an operator reads a
determinate negative over SQL that has never once executed.

This extracts every static statement and PREPAREs it. See CLAUDE.md check 88 for
the measured numbers, the two false-positive classes and the stated limits.

Usage:  lint-sql-prepare.py <database-url> <root>...
Exit:   0 clean, 1 findings, 2 harness failure (never a silent skip).
"""
import json, os, re, subprocess, sys, tempfile

# `query_file` reads a .sql file at compile time; its argument is a PATH, not a
# statement, so it is deliberately NOT in this alternation.
CALL = re.compile(r'\bsqlx::(query_as|query_scalar|query)\b\s*(::\s*<[^>]*(?:<[^>]*>)?[^>]*>\s*)?\(')
PREPARABLE = ('select', 'insert', 'update', 'delete', 'values', 'with', 'merge', 'table')
MARKER = 'allow-unpreparable-sql'
MARKER_WINDOW = 8

# A parameter type the server cannot infer is NOT a schema finding: sqlx sends
# the type OIDs derived from the Rust bindings at runtime, so these statements
# work. Proven rather than assumed — re-preparing them with an explicit type
# list succeeds. Counted and reported, never failed on.
INDETERMINATE = ('42P08', '42P18')
# A DEALLOCATE of a statement that failed to PREPARE. Cascade noise.
CASCADE = '26000'


def read_literal(src, i):
    """Read one Rust string literal at src[i], resolving escapes and
    `\\`-continuations the way rustc does. Returns (text, end) or (None, why)."""
    n = len(src)
    while i < n:
        if src[i] in ' \t\r\n':
            i += 1; continue
        if src.startswith('//', i):
            j = src.find('\n', i); i = n if j < 0 else j + 1; continue
        if src.startswith('/*', i):
            j = src.find('*/', i); i = n if j < 0 else j + 2; continue
        break
    if i >= n:
        return None, 'eof'
    m = re.match(r'r(#*)"', src[i:])
    if m:
        term = '"' + m.group(1)
        start = i + len(m.group(0))
        j = src.find(term, start)
        return (src[start:j], j + len(term)) if j >= 0 else (None, 'unterminated-raw')
    if src[i] != '"':
        tail = src[i:i + 40].replace('\n', ' ').strip()
        if tail.startswith(('&format!', 'format!')):
            return None, 'format!'
        return None, ('ref-expr' if tail.startswith('&') else 'ident-or-expr')
    j, out = i + 1, []
    esc = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\', "'": "'", '0': '\0'}
    while j < n:
        c = src[j]
        if c == '\\':
            nxt = src[j + 1] if j + 1 < n else ''
            if nxt == '\n':
                j += 2
                while j < n and src[j] in ' \t':
                    j += 1
                continue
            out.append(esc.get(nxt, nxt)); j += 2; continue
        if c == '"':
            return ''.join(out), j + 1
        out.append(c); j += 1
    return None, 'unterminated'


def scan(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    lines = src.split('\n')
    for m in CALL.finditer(src):
        line = src.count('\n', 0, m.start()) + 1
        lo = max(0, line - 1 - MARKER_WINDOW)
        if any(MARKER in l for l in lines[lo:line]):
            yield {'file': path, 'line': line, 'marked': True}
            continue
        lit, why = read_literal(src, m.end())
        rec = {'file': path, 'line': line}
        if lit is None:
            rec['dynamic'] = why
        else:
            rec['sql'] = lit
        yield rec


def collect(roots):
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            # `.claude` holds OTHER BRANCHES' source (check 75); `target` is
            # build output. `tests` is excluded because an integration binary
            # legitimately CREATEs its own tables at runtime (`rls_probe`,
            # `rpcwc_probe`) — measured at 11 of the 11 test-file failures.
            dirnames[:] = [d for d in dirnames
                           if d not in ('target', '.git', 'node_modules', '.claude', 'tests')]
            for f in filenames:
                if f.endswith('.rs'):
                    yield from scan(os.path.join(dirpath, f))


def main():
    if len(sys.argv) < 3:
        print('usage: lint-sql-prepare.py <database-url> <root>...', file=sys.stderr)
        return 2
    url, roots = sys.argv[1], sys.argv[2:]
    recs = list(collect(roots))
    static = [r for r in recs if 'sql' in r]
    dynamic = [r for r in recs if 'dynamic' in r]
    marked = [r for r in recs if r.get('marked')]

    # A check that matches nothing is a green tick over zero statements
    # (checks 64/65). Refuse rather than pass.
    if not static:
        print('  harness failure: extracted 0 static statements from '
              f'{roots} — the scan shape or the roots are wrong, not the code',
              file=sys.stderr)
        return 2

    # Do not churn the operator's `pg_stat_statements` (2026-09-10). Every
    # probe below is TWO utility statements (`PREPARE sN AS …`, `DEALLOCATE
    # sN`) carrying a unique name, so neither normalises: measured on the
    # reference stack, ONE run of this check mints ~1900 entries against a
    # default `pg_stat_statements.max = 5000`. That was invisible until #786's
    # preload went live on 2026-09-10 and this package gave the view a reader;
    # the first lint run after it pushed the cluster over the cap and evicted
    # 9 of the operator's real entries.
    #
    # `track_utility` is a `superuser`-context GUC. A non-superuser lint role
    # gets `42501`, and a server without the extension gets `42704
    # unrecognized configuration parameter` — both harmless here: psql runs
    # with ON_ERROR_STOP=0, and the attribution loop below ignores every ERROR
    # that arrives before the first `@@@` marker (`cur` is still None), so a
    # refused SET cannot be blamed on a statement.
    probes, script = {}, [
        '\\set VERBOSITY verbose',
        'SET pg_stat_statements.track_utility = off;',
    ]
    skipped_kind = 0
    for n, r in enumerate(static, 1):
        sql = r['sql'].strip().rstrip(';').strip()
        head = re.sub(r'^\(*\s*', '', sql).split(None, 1)
        if not head or head[0].lower() not in PREPARABLE:
            skipped_kind += 1
            continue
        name = f's{n}'
        probes[name] = (r, sql)
        script += [f'\\echo @@@{name}', f'PREPARE {name} AS {sql};', f'DEALLOCATE {name};']

    with tempfile.NamedTemporaryFile('w', suffix='.sql', delete=False) as fh:
        fh.write('\n'.join(script) + '\n')
        path = fh.name
    try:
        # stderr MUST be merged into stdout, not captured separately. psql
        # writes `\echo` markers to stdout and `ERROR:` lines to stderr, so
        # two separate streams put every error AFTER every marker and the
        # attribution loop below blames the LAST statement for all of them —
        # a check that reports real findings against innocent lines. Found by
        # running this against the pre-fix tree and getting one finding where
        # the shell pipeline (`> out 2>&1`) had found sixteen.
        proc = subprocess.run(['psql', url, '-X', '-q', '-v', 'ON_ERROR_STOP=0', '-f', path],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        print('  harness failure: psql not on PATH', file=sys.stderr)
        return 2
    finally:
        os.unlink(path)
    if proc.returncode != 0 and not proc.stdout:
        print(f'  harness failure: psql exited {proc.returncode}: '
              f'{proc.stdout.strip()[:400]}', file=sys.stderr)
        return 2

    cur, findings, indeterminate = None, [], []
    for line in proc.stdout.split('\n'):
        m = re.match(r'^@@@(s\d+)$', line.strip())
        if m:
            cur = m.group(1); continue
        m = re.search(r'ERROR:\s+([0-9A-Z]{5}):\s*(.*)$', line)
        if not (m and cur and cur in probes):
            continue
        code, msg = m.group(1), m.group(2).strip()
        if code == CASCADE:
            continue
        r, _sql = probes.pop(cur)
        (indeterminate if code in INDETERMINATE else findings).append((r, code, msg))

    print(f'  scanned {len(static)} static statement(s) in {len(roots)} root(s); '
          f'{len(dynamic)} dynamic (format!/expr — OUT OF RANGE), '
          f'{len(marked)} marked, {skipped_kind} non-preparable kind, '
          f'{len(indeterminate)} indeterminate parameter type')
    for r, code, msg in sorted(findings, key=lambda t: (t[0]['file'], t[0]['line'])):
        print(f"  {r['file']}:{r['line']}: [{code}] {msg}")
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
