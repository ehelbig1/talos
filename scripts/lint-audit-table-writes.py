#!/usr/bin/env python3
"""Check 105: a migration must not UPDATE, DELETE or TRUNCATE a table that
`prevent_audit_modification()` guards.

`20260408000001_audit_log_immutability.sql` made the audit tables append-only
with a `BEFORE UPDATE OR DELETE … FOR EACH ROW` trigger, and package CG
(`20260917130000`) added `BEFORE TRUNCATE … FOR EACH STATEMENT` and four more
tables. A ROW trigger does not fire on zero rows, and a test database holds no
audit rows, so a migration that rewrites one passes every test and CI. On a
deployment with history it fails at migrate and stops the rollout: on
2026-10-15 `20261014191000` (#1301) backfilled `secret_audit_log.key_hash` with
an UPDATE and stopped the reference deployment's migrate on 35,900 rows. It was
replaced by `20261015120000` with no backfill (#1314,
`docs/engineering-log/packages/2026-10-15-audit-key-hash-no-backfill.md`).

Rule: a statement in `migrations/*.sql` (`migrations/.baseline/` is not read)
that would modify a row of a guarded table, at the point it runs, is refused:
`UPDATE t`, `DELETE FROM t`, `TRUNCATE … t`, `MERGE INTO t`, and
`INSERT INTO t … ON CONFLICT … DO UPDATE`.

"Guarded at the point it runs" is derived, not listed: the migrations are read
in the order sqlx applies them (by file name), and each
`CREATE [OR REPLACE] TRIGGER … ON t … EXECUTE FUNCTION
prevent_audit_modification()` guards `t` for the events it names from that
statement on, until a `DROP TRIGGER … ON t` or `DROP TABLE t` removes it. So a
write that predates its table's trigger (`20260408000001` for the first four,
`20260917130000` for package CG's four) is out of scope, and a NEW guarded table
is in scope from the migration that guards it without anyone editing a list.

The derived set of tables guarded against UPDATE/DELETE at the newest migration
must also equal check 47's `AUDIT_TABLES` (passed with `--audit-tables`), so a
new append-only table cannot be guarded without check 47 learning about it.

Lexing: `--` and `/* */` comments are dropped; a statement ends at a `;`
outside a single-quoted string (a dollar-quoted body is read as code, so each
statement inside a `DO $$ … $$` block is a statement here). Strings are kept,
except in `COMMENT ON`, whose text is prose.

No opt-out marker. Rewriting audit history is what the append-only policy
forbids, and disabling the trigger around a backfill was considered and
rejected in #1314. An already-APPLIED migration that predates the rule is named
in ALLOWED below with its reason; an entry that no longer matches anything is
itself a finding.

Measured 2026-10-15 over the 381 migrations: 1 statement found — the allowed
`20260529130000_org_id_columns.sql` backfill (applied when its table held few
rows). On main before #1314 the scan also finds `20261014191000` (the incident).
Statement-shaped false positives: 0 (the 15 trigger definitions, the GRANT /
REVOKE and `ON DELETE` clauses that name these tables do not match).

Stated limits: dynamic SQL is not resolved (`EXECUTE format('UPDATE %I …', t)`
with a table name supplied at run time is not seen); a write reached through a
function called from a migration is not followed; other final-row triggers
(`execution_approval_decision_is_final`) are a different rule and out of scope.

Exit 0 clean / 1 findings / 2 the scan derived no guarded table (a gate that
sees nothing is not a gate).
"""
import re
import sys
from pathlib import Path

GUARD_FN = "prevent_audit_modification"

# Already applied; editing an applied migration changes its checksum and breaks
# sqlx. Each entry is a file name and the reason it stands.
ALLOWED = {
    "20260529130000_org_id_columns.sql": (
        "applied 2026-05-29, before an audit-table backfill was known to stop "
        "a migrate; it set secret_audit_log.org_id on the rows of that day"
    ),
}

IDENT = r'(?:"?public"?\s*\.\s*)?"?(?P<t>[A-Za-z_][A-Za-z0-9_]*)"?'
WRITE_PATTERNS = [
    ("UPDATE", re.compile(r"\bUPDATE\s+(?:ONLY\s+)?" + IDENT, re.I)),
    ("DELETE", re.compile(r"\bDELETE\s+FROM\s+(?:ONLY\s+)?" + IDENT, re.I)),
    ("MERGE", re.compile(r"\bMERGE\s+INTO\s+(?:ONLY\s+)?" + IDENT, re.I)),
]
UPSERT = re.compile(
    r"\bINSERT\s+INTO\s+" + IDENT + r".*\bON\s+CONFLICT\b.*\bDO\s+UPDATE\b",
    re.I | re.S,
)
TRUNCATE = re.compile(
    r"(?P<prev>\b\w+\s+)?\bTRUNCATE\b(?:\s+TABLE)?(?:\s+ONLY)?\s+(?P<list>[^;]*)",
    re.I,
)
TRIGGER = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+\"?(?P<name>\w+)\"?"
    r"\s+(?:BEFORE|AFTER|INSTEAD\s+OF)\s+(?P<events>.*?)\s+ON\s+(?:ONLY\s+)?"
    + IDENT
    + r".*\bEXECUTE\s+(?:FUNCTION|PROCEDURE)\s+(?:\w+\.)?(?P<fn>\w+)",
    re.I | re.S,
)
DROP_TRIGGER = re.compile(
    r"\bDROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?\"?(?P<name>\w+)\"?\s+ON\s+(?:ONLY\s+)?" + IDENT,
    re.I,
)
DROP_TABLE = re.compile(r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<list>[^;]*)", re.I)
ALTERED = re.compile(
    r"^\s*(?:CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"|ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?)" + IDENT,
    re.I,
)
# An enforced action on the PARENT's delete or key update that writes the
# child row: DELETE for CASCADE on delete, UPDATE for every other one.
FK_ACTION = re.compile(
    r"\bON\s+(?P<on>DELETE|UPDATE)\s+(?P<act>CASCADE|SET\s+NULL|SET\s+DEFAULT)\b", re.I
)


def statements(sql: str):
    """Yield (line, text) per statement: comments dropped, split on `;`
    outside single-quoted strings, dollar quotes read through as code."""
    out, buf, line, start = [], [], 1, None
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += sql.count("\n", i, j)
            buf.append(" ")
            i = j
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'" and j + 1 < n and sql[j + 1] == "'":
                    j += 2
                    continue
                if sql[j] == "'":
                    break
                j += 1
            if start is None:
                start = line
            buf.append(sql[i : j + 1])
            line += sql.count("\n", i, j + 1)
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                buf.append(" ")
                i += len(m.group(0))
                continue
        if c == ";":
            text = "".join(buf).strip()
            if text:
                out.append((start or line, text))
            buf, start = [], None
            i += 1
            continue
        if c == "\n":
            line += 1
        elif start is None and not c.isspace():
            start = line
        buf.append(c)
        i += 1
    text = "".join(buf).strip()
    if text:
        out.append((start or line, text))
    return out


def scrub(stmt: str) -> str:
    """A COMMENT ON statement's text is prose: blank its strings."""
    if re.match(r"\s*COMMENT\s+ON\b", stmt, re.I):
        return re.sub(r"'(?:[^']|'')*'", "''", stmt)
    return stmt


def names(lst: str):
    for part in lst.split(","):
        m = re.match(r"\s*" + IDENT, part)
        if m:
            yield m.group("t").lower()


def writes(stmt: str):
    """Yield (op, table) for each row-modifying write the statement makes."""
    for op, pat in WRITE_PATTERNS:
        for m in pat.finditer(stmt):
            yield op, m.group("t").lower()
    m = UPSERT.search(stmt)
    if m:
        yield "UPDATE", m.group("t").lower()
    for m in TRUNCATE.finditer(stmt):
        prev = (m.group("prev") or "").strip().upper()
        # `BEFORE TRUNCATE ON t` (a trigger), `GRANT TRUNCATE ON t`.
        if prev in {"BEFORE", "AFTER", "OR", "GRANT", "REVOKE"}:
            continue
        lst = m.group("list")
        if re.match(r"\s*ON\b", lst, re.I):
            continue
        lst = re.split(r"\b(?:RESTART|CONTINUE|CASCADE|RESTRICT)\b", lst, flags=re.I)[0]
        for t in names(lst):
            yield "TRUNCATE", t


def fk_actions(stmt: str):
    """Yield (table, action, op) for each enforced FK action a CREATE/ALTER
    TABLE statement gives the table it creates or alters."""
    m = ALTERED.match(stmt)
    if not m or not re.search(r"\bREFERENCES\b", stmt, re.I):
        return
    for a in FK_ACTION.finditer(stmt):
        act = " ".join(a.group("act").upper().split())
        on = a.group("on").upper()
        op = "DELETE" if (on, act) == ("DELETE", "CASCADE") else "UPDATE"
        yield m.group("t").lower(), f"ON {on} {act}", op


def scan(files):
    """files: [(name, text)] in apply order.
    Returns (findings, fks, guarded): findings are (name, line, op, table)
    writes, fks are (name, line, action, table) foreign keys whose action
    would write a guarded row, and guarded maps table -> refused ops at the
    end."""
    guards = {}  # table -> {trigger name: set(ops)}
    findings, fks = [], []

    def refused(t):
        ops = set()
        for s in guards.get(t, {}).values():
            ops |= s
        return ops

    for name, text in files:
        for line, raw in statements(text):
            stmt = scrub(raw)
            for op, t in writes(stmt):
                ref = refused(t)
                if op in ref or (op == "MERGE" and ref & {"UPDATE", "DELETE"}):
                    findings.append((name, line, op, t))
            for t, action, op in fk_actions(stmt):
                if op in refused(t):
                    fks.append((name, line, action, t))
            m = TRIGGER.search(stmt)
            if m and m.group("fn").lower() == GUARD_FN:
                ev = {e.upper() for e in re.findall(r"UPDATE|DELETE|TRUNCATE|INSERT", m.group("events"), re.I)}
                guards.setdefault(m.group("t").lower(), {})[m.group("name").lower()] = ev
            m = DROP_TRIGGER.search(stmt)
            if m:
                guards.get(m.group("t").lower(), {}).pop(m.group("name").lower(), None)
            m = DROP_TABLE.search(stmt)
            if m:
                for t in names(m.group("list")):
                    guards.pop(t, None)
    guarded = {t: refused(t) for t in guards if refused(t)}
    return findings, fks, guarded


def apply_order(paths):
    return sorted(paths, key=lambda p: p.name)


def run(root: Path, leg: str):
    paths = apply_order(p for p in (root / "migrations").glob("*.sql") if p.is_file())
    files = [(p.name, p.read_text(encoding="utf-8")) for p in paths]
    findings, fks, guarded = scan(files)
    if not guarded:
        print("✗ no table guarded by prevent_audit_modification() was found — has the trigger moved?")
        return 2
    rc = 0
    if leg == "fks":
        for name, line, action, t in fks:
            print(f"  migrations/{name}:{line}  {t} gains a foreign key {action}")
            rc = 1
        print(f"{len(paths)} migrations, {len(guarded)} guarded tables, {len(fks)} enforced FK action(s) found")
        return rc
    hit_allowed = set()
    for name, line, op, t in findings:
        if name in ALLOWED:
            hit_allowed.add(name)
            continue
        print(f"  migrations/{name}:{line}  {op} on {t} (refuses {', '.join(sorted(guarded.get(t, {op})))})")
        rc = 1
    for name in sorted(set(ALLOWED) - hit_allowed):
        print(f"  ALLOWED names {name}, which no longer writes a guarded table — remove the entry")
        rc = 1
    print(
        f"{len(paths)} migrations, {len(guarded)} guarded tables, "
        f"{len(findings)} write(s) found, {len(hit_allowed)} allowed by name"
    )
    return rc


TRIG = (
    "CREATE OR REPLACE FUNCTION prevent_audit_modification() RETURNS TRIGGER AS $$\n"
    "BEGIN RAISE EXCEPTION 'no UPDATE secret_audit_log'; END; $$ LANGUAGE plpgsql;\n"
    "CREATE TRIGGER trg_a BEFORE UPDATE OR DELETE ON secret_audit_log\n"
    "    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();\n"
)
BEFORE = ("001_x.sql", "UPDATE secret_audit_log SET a = 1;\nDELETE FROM secret_audit_log;\n"
          "ALTER TABLE secret_audit_log ADD COLUMN u UUID REFERENCES users(id) ON DELETE CASCADE;\n")
WRITE_CASES = [
    # (migration text after the trigger, expected [(op, table)])
    ("UPDATE secret_audit_log l\nSET key_hash = 'x'\nFROM secrets s WHERE s.id = l.secret_id;", [("UPDATE", "secret_audit_log")]),
    ('UPDATE ONLY public."secret_audit_log" SET a = 1;', [("UPDATE", "secret_audit_log")]),
    ("DELETE FROM secret_audit_log WHERE ts < now();", [("DELETE", "secret_audit_log")]),
    ("MERGE INTO secret_audit_log USING x ON true WHEN MATCHED THEN DELETE;", [("MERGE", "secret_audit_log")]),
    ("INSERT INTO secret_audit_log (id) VALUES (1)\nON CONFLICT (id) DO UPDATE SET a = 1;", [("UPDATE", "secret_audit_log")]),
    ("INSERT INTO secret_audit_log (id) VALUES (1) ON CONFLICT DO NOTHING;", []),
    ("DO $$ BEGIN\n  UPDATE secret_audit_log SET a = 1;\nEND $$;", [("UPDATE", "secret_audit_log")]),
    ("UPDATE secret_audit_log_archive SET a = 1;", []),
    ("-- UPDATE secret_audit_log SET a = 1;\n/* DELETE FROM secret_audit_log; */ SELECT 1;", []),
    ("COMMENT ON TABLE secret_audit_log IS 'never UPDATE secret_audit_log';", []),
    ("GRANT UPDATE, DELETE ON secret_audit_log TO x; REVOKE TRUNCATE ON secret_audit_log FROM x;", []),
    ("ALTER TABLE secret_audit_log ADD COLUMN k TEXT;", []),
    ("CREATE TRIGGER trg_b BEFORE UPDATE OR DELETE ON secret_audit_log FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();", []),
    # Known limit: a table name supplied at run time is not resolved.
    ("DO $$ BEGIN EXECUTE format('UPDATE %I SET a = 1', 'secret_audit_log'); END $$;", []),
    # Without a TRUNCATE trigger, TRUNCATE is not refused by this table.
    ("TRUNCATE secret_audit_log;", []),
    ("DROP TABLE IF EXISTS secret_audit_log; UPDATE secret_audit_log SET a = 1;", []),
    ("DROP TRIGGER IF EXISTS trg_a ON secret_audit_log; DELETE FROM secret_audit_log;", []),
]
FK_CASES = [
    # (migration text after the trigger, expected [(action, table)])
    ("ALTER TABLE secret_audit_log ADD COLUMN u UUID REFERENCES users(id) ON DELETE SET NULL;", [("ON DELETE SET NULL", "secret_audit_log")]),
    ("ALTER TABLE\n    secret_audit_log\n  ADD CONSTRAINT f FOREIGN KEY (s) REFERENCES secrets(id)\n  ON DELETE CASCADE;", [("ON DELETE CASCADE", "secret_audit_log")]),
    ("ALTER TABLE ONLY public.secret_audit_log ADD FOREIGN KEY (o) REFERENCES orgs(id) ON UPDATE CASCADE;", [("ON UPDATE CASCADE", "secret_audit_log")]),
    ("ALTER TABLE secret_audit_log ADD COLUMN o UUID REFERENCES orgs(id) ON DELETE  SET  DEFAULT;", [("ON DELETE SET DEFAULT", "secret_audit_log")]),
    ("ALTER TABLE secret_audit_log ADD COLUMN o UUID REFERENCES orgs(id);", []),
    ("ALTER TABLE secret_audit_log ADD COLUMN o UUID REFERENCES orgs(id) ON DELETE RESTRICT;", []),
    ("ALTER TABLE secret_audit_log_archive ADD COLUMN u UUID REFERENCES users(id) ON DELETE CASCADE;", []),
    # A table that REFERENCES the audit table is not the audit table.
    ("CREATE TABLE notes (a UUID REFERENCES secret_audit_log(id) ON DELETE CASCADE);", []),
    ("-- ALTER TABLE secret_audit_log ... REFERENCES users(id) ON DELETE CASCADE\nSELECT 1;", []),
]


def self_test():
    fails = 0
    for i, (body, want) in enumerate(WRITE_CASES):
        got, _, _ = scan([BEFORE, ("002_trig.sql", TRIG), ("003_case.sql", body)])
        got = [(op, t) for (_n, _l, op, t) in got]
        if got != want:
            print(f"write case {i}: want {want}, got {got}\n  {body!r}")
            fails += 1
    for i, (body, want) in enumerate(FK_CASES):
        _, got, _ = scan([BEFORE, ("002_trig.sql", TRIG), ("003_case.sql", body)])
        got = [(a, t) for (_n, _l, a, t) in got]
        if got != want:
            print(f"fk case {i}: want {want}, got {got}\n  {body!r}")
            fails += 1
    extra = 0
    # A write or FK in a migration before the trigger is out of scope.
    extra += 1
    got, fks, guarded = scan([BEFORE, ("002_trig.sql", TRIG)])
    if got or fks or guarded != {"secret_audit_log": {"UPDATE", "DELETE"}}:
        print(f"pre-trigger case: got {got} {fks}, guarded {guarded}")
        fails += 1
    # TRUNCATE trigger: a TRUNCATE list naming the table is refused, the
    # trigger definition itself is not.
    extra += 1
    trunc = "CREATE OR REPLACE TRIGGER trg_t BEFORE TRUNCATE ON secret_audit_log FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();"
    got, _, _ = scan([("002_trig.sql", TRIG), ("003_t.sql", trunc), ("004.sql", "TRUNCATE TABLE a, secret_audit_log RESTART IDENTITY;")])
    if [(op, t) for (_n, _l, op, t) in got] != [("TRUNCATE", "secret_audit_log")]:
        print(f"truncate case: got {got}")
        fails += 1
    # Line numbers point at the statement's first line.
    extra += 1
    got, _, _ = scan([("002_trig.sql", TRIG), ("003.sql", "SELECT 1;\n\n-- note\nUPDATE secret_audit_log\n SET a = 1;")])
    if [l for (_n, l, _o, _t) in got] != [4]:
        print(f"line case: got {got}")
        fails += 1
    if fails:
        print(f"✗ {fails} self-test case(s) failed")
        return 1
    print(f"✓ self-test: {len(WRITE_CASES) + len(FK_CASES) + extra} cases")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if argv[:1] != ["--leg"] or len(argv) < 2 or argv[1] not in ("writes", "fks"):
        print("usage: lint-audit-table-writes.py --leg writes|fks | --self-test")
        return 2
    root = Path(__file__).resolve().parent.parent
    return run(root, argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
