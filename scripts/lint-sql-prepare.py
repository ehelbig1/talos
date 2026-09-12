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
        lint-sql-prepare.py --self-test     (resolver fixture, no database)
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


# ---------------------------------------------------------------------------
# Same-file RESOLVER (2026-09-12). Until this landed the probe read only a
# string LITERAL at the call site; a statement reached through a `const`, a
# `concat!`, a same-file `macro_rules!` fragment or a `format!` whose only
# placeholders are constants was "dynamic — OUT OF RANGE": 73 sites on the
# widened roots, and one of them — `talos-registry`'s eviction exemption —
# was mutation-tested the same day with a leg over a DROPPED table and the
# probe did not see it. These shapes are all resolvable at read time from the
# file alone, and that is the scope: no cross-file lookups, no function calls,
# no positional `format!` arguments — anything else stays dynamic and is
# COUNTED, exactly as before.
# ---------------------------------------------------------------------------
CONST_DEF = re.compile(r"\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*&\s*(?:'static\s+)?str\s*=\s*")
MACRO_DEF = re.compile(r'\bmacro_rules!\s+([a-z_][a-z0-9_]*)\s*\{')
IDENT_EXPR = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z_][A-Z0-9_]*)$')
MAX_DEPTH = 12


def skip_ws_comments(src, i):
    n = len(src)
    while i < n:
        if src[i] in ' \t\r\n':
            i += 1
        elif src.startswith('//', i):
            j = src.find('\n', i); i = n if j < 0 else j + 1
        elif src.startswith('/*', i):
            j = src.find('*/', i); i = n if j < 0 else j + 2
        else:
            break
    return i


def span_balanced(src, i, closer_for):
    """src[i] is an opener; return the index just past its matching closer,
    skipping string literals and comments. None if unbalanced."""
    opener = src[i]
    closer = closer_for[opener]
    depth, j, n = 0, i, len(src)
    while j < n:
        c = src[j]
        if c == '"' or (c == 'r' and re.match(r'r#*"', src[j:])):
            lit, end = read_literal(src, j)
            if lit is None:
                return None
            j = end; continue
        if src.startswith('//', j):
            k = src.find('\n', j); j = n if k < 0 else k + 1; continue
        if src.startswith('/*', j):
            k = src.find('*/', j); j = n if k < 0 else k + 2; continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return None


PAIRS = {'(': ')', '[': ']', '{': '}'}


def split_top(text):
    """Split on top-level commas, respecting strings and brackets."""
    parts, depth, cur, j, n = [], 0, [], 0, len(text)
    while j < n:
        c = text[j]
        if c == '"' or (c == 'r' and re.match(r'r#*"', text[j:])):
            lit, end = read_literal(text, j)
            if lit is None:
                cur.append(text[j:]); break
            cur.append(text[j:end]); j = end; continue
        if c in PAIRS:
            depth += 1
        elif c in PAIRS.values():
            depth -= 1
        if c == ',' and depth == 0:
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(c)
        j += 1
    tail = ''.join(cur)
    if tail.strip():
        parts.append(tail)
    return [p.strip() for p in parts]


def first_argument(src, i):
    """The text of the first argument starting at src[i] (just past the call's
    `(`), up to the top-level `,` or the closing `)`."""
    depth, j, n, start = 0, skip_ws_comments(src, i), len(src), None
    start = j
    while j < n:
        c = src[j]
        if c == '"' or (c == 'r' and re.match(r'r#*"', src[j:])):
            lit, end = read_literal(src, j)
            if lit is None:
                return None
            j = end; continue
        if src.startswith('//', j):
            k = src.find('\n', j); j = n if k < 0 else k + 1; continue
        if c in PAIRS:
            depth += 1
        elif c in PAIRS.values():
            if depth == 0:
                return src[start:j]
            depth -= 1
        elif c == ',' and depth == 0:
            return src[start:j]
        j += 1
    return None


class Resolver:
    """Same-file constant / macro / concat! / const-only-format! resolution."""

    def __init__(self, src):
        self.consts, self.macros = {}, {}
        for m in CONST_DEF.finditer(src):
            end = self._expr_end(src, m.end())
            if end is not None:
                self.consts[m.group(1)] = src[m.end():end]
        for m in MACRO_DEF.finditer(src):
            close = span_balanced(src, m.end() - 1, PAIRS)
            if close is None:
                continue
            self.macros[m.group(1)] = self._rules(src[m.end():close - 1])

    @staticmethod
    def _expr_end(src, i):
        depth, j, n = 0, i, len(src)
        while j < n:
            c = src[j]
            if c == '"' or (c == 'r' and re.match(r'r#*"', src[j:])):
                lit, end = read_literal(src, j)
                if lit is None:
                    return None
                j = end; continue
            if src.startswith('//', j):
                k = src.find('\n', j); j = n if k < 0 else k + 1; continue
            if c in PAIRS:
                depth += 1
            elif c in PAIRS.values():
                depth -= 1
            elif c == ';' and depth == 0:
                return j
            j += 1
        return None

    @staticmethod
    def _rules(body):
        """`( $a:literal ) => { … }` arms → [(param_names, arm_body)]."""
        rules, j, n = [], 0, len(body)
        while j < n:
            j = skip_ws_comments(body, j)
            if j >= n or body[j] != '(':
                break
            pend = span_balanced(body, j, PAIRS)
            if pend is None:
                break
            params = re.findall(r'\$([a-z_][a-z0-9_]*)\s*:\s*(?:literal|expr|tt|ident)', body[j + 1:pend - 1])
            k = skip_ws_comments(body, pend)
            if not body.startswith('=>', k):
                break
            k = skip_ws_comments(body, k + 2)
            if k >= n or body[k] not in PAIRS:
                break
            bend = span_balanced(body, k, PAIRS)
            if bend is None:
                break
            rules.append((params, body[k + 1:bend - 1]))
            j = skip_ws_comments(body, bend)
            if j < n and body[j] == ';':
                j += 1
        return rules

    def resolve(self, expr, depth=0):
        """Returns (sql, kind) or (None, why)."""
        if depth > MAX_DEPTH:
            return None, 'depth'
        e = expr.strip()
        while e.startswith('&'):
            e = e[1:].lstrip()
        if e.startswith('(') and span_balanced(e, 0, PAIRS) == len(e):
            e = e[1:-1].strip()
        if not e:
            return None, 'empty'
        if e[0] == '"' or re.match(r'r#*"', e):
            lit, end = read_literal(e, 0)
            if lit is None or e[end:].strip():
                return None, 'literal-tail'
            return lit, 'literal'
        m = re.match(r'^(concat|format)!\s*\(', e)
        if m:
            close = span_balanced(e, m.end() - 1, PAIRS)
            if close is None or e[close:].strip():
                return None, f'{m.group(1)}!-shape'
            args = split_top(e[m.end():close - 1])
            if m.group(1) == 'concat':
                out = []
                for a in args:
                    v, why = self.resolve(a, depth + 1)
                    if v is None:
                        return None, f'concat!:{why}'
                    out.append(v)
                return ''.join(out), 'concat!'
            if not args:
                return None, 'format!-empty'
            if len(args) > 1:
                return None, 'format!-args'
            fmt, why = self.resolve(args[0], depth + 1)
            if fmt is None:
                return None, f'format!:{why}'
            out, j, n = [], 0, len(fmt)
            while j < n:
                c = fmt[j]
                if c == '{':
                    if fmt.startswith('{{', j):
                        out.append('{'); j += 2; continue
                    k = fmt.find('}', j)
                    if k < 0:
                        return None, 'format!-brace'
                    name = fmt[j + 1:k]
                    if not re.match(r'^[A-Z_][A-Z0-9_]*$', name):
                        return None, 'format!-placeholder'
                    v, why = self.resolve(name, depth + 1)
                    if v is None:
                        return None, f'format!:{why}'
                    out.append(v); j = k + 1; continue
                if c == '}':
                    if fmt.startswith('}}', j):
                        out.append('}'); j += 2; continue
                    return None, 'format!-brace'
                out.append(c); j += 1
            return ''.join(out), 'format!'
        m = re.match(r'^([a-z_][a-z0-9_]*)!\s*\(', e)
        if m:
            close = span_balanced(e, m.end() - 1, PAIRS)
            if close is None or e[close:].strip():
                return None, 'macro!-shape'
            args = split_top(e[m.end():close - 1])
            rules = self.macros.get(m.group(1))
            if not rules:
                return None, 'macro!-unknown'
            for params, body in rules:
                if len(params) != len(args):
                    continue
                for pname, arg in zip(params, args):
                    body = re.sub(r'\$' + re.escape(pname) + r'\b', lambda _m, a=arg: a, body)
                v, why = self.resolve(body, depth + 1)
                return (v, 'macro!') if v is not None else (None, f'macro!:{why}')
            return None, 'macro!-arity'
        m = IDENT_EXPR.match(e)
        if m:
            body = self.consts.get(m.group(1))
            if body is None:
                return None, 'const-unknown'
            v, why = self.resolve(body, depth + 1)
            return (v, 'const') if v is not None else (None, f'const:{why}')
        return None, 'expr'


def scan(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    lines = src.split('\n')
    resolver = Resolver(src)
    for m in CALL.finditer(src):
        line = src.count('\n', 0, m.start()) + 1
        lo = max(0, line - 1 - MARKER_WINDOW)
        if any(MARKER in l for l in lines[lo:line]):
            yield {'file': path, 'line': line, 'marked': True}
            continue
        lit, why = read_literal(src, m.end())
        rec = {'file': path, 'line': line}
        if lit is not None:
            rec['sql'] = lit
        else:
            arg = first_argument(src, m.end())
            val, kind = (resolver.resolve(arg) if arg is not None else (None, why))
            if val is not None:
                rec['sql'] = val
                rec['resolved'] = kind
            else:
                rec['dynamic'] = kind if arg is not None else why
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


FIXTURE = r"""
const COLS: &str = "id, name";
pub const NESTED: &'static str = concat!("SELECT ", COLS, " FROM t1");
macro_rules! cols { () => { "a, b" }; }
macro_rules! wrap { ($select:expr) => { concat!("UPDATE t2 SET x = 1 WHERE id IN ( ", $select, " )") }; }
macro_rules! win { ($w:literal) => { concat!(" WHERE recorded_at > NOW() - INTERVAL '1 day' * ", $w) }; }
pub const SWEEP: &str = wrap!(concat!("SELECT id FROM t3", win!("$1")));
struct S;
impl S { pub const ASSOC: &'static str = "SELECT 1 FROM t4"; }
fn f(live: &str) {
    sqlx::query("SELECT plain FROM t0");
    sqlx::query(NESTED);
    sqlx::query_as::<_, (i32,)>(SWEEP);
    sqlx::query(Self::ASSOC);
    sqlx::query(&concat!("SELECT ", cols!(), " FROM t5"));
    sqlx::query(&format!("SELECT {COLS} FROM t6 WHERE a = $1"));
    sqlx::query(&format!("SELECT {} FROM t7", live));
    sqlx::query(&format!("SELECT x FROM t8 {live}"));
    sqlx::query(&sql);
}
"""

EXPECT = {
    'SELECT plain FROM t0': None,
    'SELECT id, name FROM t1': 'const',
    "UPDATE t2 SET x = 1 WHERE id IN ( SELECT id FROM t3 WHERE recorded_at > NOW() - INTERVAL '1 day' * $1 )": 'const',
    'SELECT 1 FROM t4': 'const',
    'SELECT a, b FROM t5': 'concat!',
    'SELECT id, name FROM t6 WHERE a = $1': 'format!',
}
# `&sql` is a lower-case local: not a const, not a macro — `expr`, as before.
EXPECT_DYNAMIC = ['format!-args', 'format!-placeholder', 'expr']


def self_test():
    with tempfile.NamedTemporaryFile('w', suffix='.rs', delete=False) as fh:
        fh.write(FIXTURE); path = fh.name
    try:
        recs = list(scan(path))
    finally:
        os.unlink(path)
    got = {r['sql']: r.get('resolved') for r in recs if 'sql' in r}
    dyn = [r['dynamic'] for r in recs if 'dynamic' in r]
    ok = got == EXPECT and dyn == EXPECT_DYNAMIC
    if not ok:
        print('  self-test FAILED', file=sys.stderr)
        print(f'   resolved: {json.dumps(got, indent=1)}', file=sys.stderr)
        print(f'   dynamic:  {dyn}', file=sys.stderr)
        return 1
    print(f'  self-test ok: {len(EXPECT)} statements resolved as expected, '
          f'{len(EXPECT_DYNAMIC)} correctly left dynamic')
    return 0


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':
        return self_test()
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

    resolved = [r for r in static if r.get('resolved')]
    print(f'  scanned {len(static)} static statement(s) in {len(roots)} root(s) '
          f'({len(resolved)} resolved through const/concat!/macro!/format!); '
          f'{len(dynamic)} dynamic (format!/expr — OUT OF RANGE), '
          f'{len(marked)} marked, {skipped_kind} non-preparable kind, '
          f'{len(indeterminate)} indeterminate parameter type')
    for r, code, msg in sorted(findings, key=lambda t: (t[0]['file'], t[0]['line'])):
        print(f"  {r['file']}:{r['line']}: [{code}] {msg}")
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
