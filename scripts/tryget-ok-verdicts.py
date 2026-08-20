#!/usr/bin/env python3
"""Per-site verdicts for the `.try_get(...).ok()` class (Part 3 of
docs/swallowed-results-inventory.md).

Keyed by (file, PRE-FIX line) against `origin/main` @ 248d690, enumerated by
scripts/lint-tryget-ok-inventory.py. Line numbers are the `.try_get` line and
will NOT match the post-fix tree — that is deliberate: the inventory records the
population as found, the way #660/#661 did.

Buckets:
  a  drift-hiding that CHANGES BEHAVIOUR or defeats a check — encryption,
     tenancy, security-report and assertion columns. Ranked first.
  b  genuinely NULLable column, `None` is a real value. Correct form is
     `.try_get::<Option<_>, _>("col")?` — NULL still yields None, drift errors.
  c  not a DB column read.

Run:  python3 scripts/tryget-ok-verdicts.py            # print the markdown body
      python3 scripts/tryget-ok-verdicts.py --check S  # cross-check S=sites.json
"""
import sys
import json
import collections

V = {}


def add(f, lines, bucket, what, ev):
    for l in lines:
        assert (f, l) not in V, f"duplicate verdict {f}:{l}"
        V[(f, l)] = (bucket, what, ev)


# ────────────────────────────── (a) ──────────────────────────────────────────

add("talos-memory/src/lib.rs", [432, 433, 1076, 1077, 1959, 1960, 2233, 2234],
    "a", "actor_memory.value_enc / value_key_id — the ciphertext itself",
    "Both columns are NOT NULL in the live schema, so a None can ONLY mean "
    "SELECT-projection drift or a decode change. resolve_stored_value falls "
    "through `if let (Some(enc), Some(key_id))` to "
    "`Ok(value_plain.unwrap_or(Null))`, and value_plain is ALWAYS None because "
    "Phase B dropped the `value` column — so the drift resolves to an EMPTY "
    "MEMORY returned as success, with no decrypt attempted and no error. In "
    "each of the four functions the very next line reads `value_format` with "
    "`.context(...)?` under a comment explaining that exact risk; the argument "
    "was not applied to the two lines above it. clone_memories l.3176-3177 "
    "already does it right (`let value_enc: Vec<u8> = r.try_get(\"value_enc\")?`). "
    "LATENT, not live: every in-repo SELECT feeding these four projects both "
    "columns today.")

add("talos-memory/src/lib.rs", [431], "a",
    "actor_memory.value — a read of a DROPPED column; the `.ok()` is load-bearing",
    "Phase B dropped `value`, so try_get returns Err(ColumnNotFound) on EVERY "
    "call and `.ok()` is what makes decrypt work at all (the doc comment at "
    "l.411-413 says so). Converting this one to `?` breaks every memory "
    "decrypt. Fixed by DELETING the read: resolve_stored_value is already "
    "called with a literal None at all five other call sites. The one site in "
    "the population where the mechanical conversion is actively wrong.")

add("controller/examples/verify_module_payload_encryption.rs", [93, 94, 95, 96, 97],
    "a", "the encryption verifier's own assertions read through a swallow",
    "Every one of the five feeds an assert!: `assert!(pt_input.is_none(), "
    "\"PLAINTEXT LEAK: input_data is non-NULL\")` and the ciphertext-present "
    "asserts. A drifted/renamed column reads as None, so the plaintext-leak "
    "assertion PASSES VACUOUSLY and the ciphertext asserts fail for the wrong "
    "reason. A gate that cannot fail on the condition it checks (#624 class), "
    "inside the tool that certifies payload encryption.")

add("controller/examples/backfill_module_payload_encryption.rs", [85, 86, 87],
    "a", "swallowed read feeding a DESTRUCTIVE update",
    "The three plaintext columns are read with `.ok()`, encrypted, and then the "
    "row is UPDATEd with `input_data = NULL, output_data = NULL, "
    "trigger_metadata = NULL` plus the ciphertext. A silent None means empty "
    "ciphertext is written AND the plaintext is nulled — irreversible loss. "
    "One-shot operator migration, but the shape is the sharpest in the set.")

add("talos-module-executions/src/lib.rs",
    [364, 365, 367, 368, 369, 991, 992, 993, 994, 1104, 1105, 1106, 1107],
    "a", "module_executions ciphertext + payload_enc_key_id",
    "`input_data_enc` / `output_data_enc` / `trigger_metadata_enc` / "
    "`payload_enc_key_id` / `workflow_execution_id` are all genuinely NULLABLE, "
    "so the Option is right and the fix is purely `.ok().flatten()` -> `?`. "
    "Ranked (a) because they are the payload-encryption path and because the "
    "SAME functions harden `payload_format` with an explicit match-and-fail "
    "arm three lines below — identical asymmetry to talos-memory.")

add("talos-module-executions/src/lib.rs", [988, 989, 990, 1101, 1102, 1103],
    "a", "module_executions legacy plaintext payload columns",
    "Nullable (post-backfill they are NULL). Read alongside the ciphertext to "
    "pick the decrypt-vs-plaintext branch, so a swallowed drift here silently "
    "picks the wrong branch. Same functions, same fix.")

add("talos-analytics-repository/src/lib.rs", [2096], "a",
    "workflow_schedules.timezone — #661's own defect in a spelling its fix did not cover",
    "NOT NULL in the schema. #661 fixed exactly this column at "
    "talos-workflow-repository/src/workflows.rs:1881, where a silent default "
    "ran every exported cron in UTC. Here the None surfaces at "
    "talos-mcp-handlers/src/analytics.rs:4776 as "
    "`r.timezone.as_deref().unwrap_or(\"UTC\")` — a schedule in "
    "America/Vancouver would be REPORTED as UTC. Display path, not the "
    "executor, so it misinforms rather than misfires.")

add("talos-analytics-repository/src/lib.rs", [4332], "a",
    "security-hygiene report silently under-reports",
    "`filter_map(|r| r.try_get::<String, _>(\"name\").ok())` over `SELECT "
    "DISTINCT name FROM modules WHERE '*' = ANY(allowed_secrets)` — the "
    "wildcard-secret-grant check in the platform hygiene report. Drift drops "
    "rows silently, so the report says 'no wildcard modules' for a reason "
    "unrelated to there being none. (The whole query is additionally "
    "`.unwrap_or_default()`-ed, which is #661's class, not this one.)")

add("talos-totp-2fa/src/lib.rs", [854], "a",
    "users.backup_codes on the 2FA backup-code verification path",
    "Nullable column, so the Option is right. Drift => None => rollback + "
    "record_2fa_failure + Ok(false): fail-CLOSED, so not an auth bypass, but "
    "every backup code is rejected and the operator sees a wrong password, not "
    "a schema error.")

add("talos-module-repository/src/lib.rs", [1445, 1448], "a",
    "silent row-SKIP on NOT NULL columns",
    "`let Some(id) = r.try_get::<Uuid, _>(\"id\").ok() else { continue };` — "
    "the in-place comment says 'skip a malformed row rather than abort the "
    "batch (preserves the prior filter_map behaviour)'. Both columns are NOT "
    "NULL projections, so the only reachable skip IS drift, and the batch "
    "silently shortens. This shape was introduced BY the check-52 burn-down: "
    "the swallow moved into the spelling the check cannot see.")

add("talos-module-repository/src/lib.rs", [458, 3318, 3319], "a",
    "silent row-SKIP, filter_map form", "Same shape as l.1445/1448.")
add("talos-workflow-repository/src/templates.rs", [169], "a",
    "silent row-SKIP, filter_map form", "Same shape.")
add("talos-registry/src/reconcile.rs", [391], "a",
    "silent row-SKIP, filter_map form",
    "Operator-visibility warning listing workflows that still reference a "
    "stale catalog twin. Under-reporting is the whole failure mode of that log "
    "line.")
add("controller/examples/verify_restore.rs", [446], "a",
    "silent row-SKIP, filter_map form",
    "Org id list driving the restore verifier's per-org DEK decrypt sweep. A "
    "dropped org is an org whose secrets were never verified.")

add("talos-workflow-repository/src/workflows.rs", [151, 152], "a",
    "the `.ok()` is masking a MISSING PROJECTION",
    "`list_workflows`' two SELECT branches (l.104, l.122) do not project "
    "`w.status` or `w.workflow_type` at all, so both reads return None on "
    "every call. Its sibling `list_workflows_paginated` (l.170) does project "
    "them. Fixed by adding the two columns to both branches, then `?`. LATENT: "
    "`WorkflowRepository::list_workflows` has ZERO callers workspace-wide, so "
    "no live surface is wrong today — the MCP handler uses the paginated twin.")

# ────────────────────────────── (b) ──────────────────────────────────────────

add("talos-actor-repository/src/lib.rs", [3484, 3495], "b",
    "actors.description (NULL), actors.updated_at (NOT NULL, Option field)", "")
add("talos-actor-repository/src/lib.rs", [3486, 3491], "b",
    "actors.status / max_capability_world — NOT NULL, defaulted after flatten",
    "`.ok().flatten().unwrap_or_else(default)`. NOT NULL, so the Option can "
    "only be drift; the default is kept because the caller's contract is a "
    "String. Fix drops `.flatten()` and propagates.")
add("talos-actor-repository/src/lib.rs", [3667], "b",
    "computed `(1.0 - (embedding <=> $2::vector)) AS score`", "")
add("talos-advanced-repository/src/lib.rs", [1476], "b",
    "workflow_schedules.next_trigger_at (NULL)", "")
add("talos-advanced-repository/src/lib.rs", [2667, 2672], "b",
    "actors.status / max_capability_world — as above", "")
add("talos-advanced-repository/src/lib.rs", [2743, 2744, 2745], "b",
    "workflow_executions.started_at (NOT NULL, Option field) / completed_at "
    "(NULL) / computed duration_ms", "")
add("talos-analytics-repository/src/lib.rs", [2097, 2098], "b",
    "workflow_schedules.last_triggered_at / next_trigger_at (NULL)", "")
add("talos-execution-repository/src/lib.rs", [2965, 2967, 2968, 2969], "b",
    "LEFT JOIN w.name AS workflow_name (NULL), started_at, completed_at, "
    "error_message", "")
add("talos-memory/src/lib.rs", [1601, 3180], "b", "actor_memory.metadata (NULL jsonb)", "")
add("talos-module-repository/src/lib.rs", [283, 284], "b",
    "computed similarity() score / same_category", "")
add("talos-module-repository/src/lib.rs", [609], "b", "modules.config (NULL jsonb)", "")
add("talos-module-repository/src/lib.rs", [626], "b",
    "modules.max_fuel — the in-place comment already calls the Option "
    "'defensive against schema drift'; the `.filter(|v| *v > 0)` is kept", "")
add("talos-module-repository/src/lib.rs", [785, 787], "b",
    "modules.capability_world / usage_count — NOT NULL, Option-typed field "
    "(the comment says so)", "")
add("talos-module-repository/src/lib.rs", [936], "b", "modules.template_id-as-id (NULL)", "")
add("talos-webhook-repository/src/lib.rs", [467], "b",
    "LEFT JOIN wt.name AS trigger_name (NULL)", "")
add("talos-webhooks/src/dlq.rs", [214, 223, 224], "b",
    "LEFT JOIN workflows w — workflow_id / user_id / org_id all legitimately NULL",
    "The enclosing `flush_batch` returns `()`, so `?` is unavailable: converted "
    "to an explicit match that logs the drift at error! and keeps the "
    "fire-and-forget event flowing. Loud, not silent.")
add("talos-workflow-repository/src/search.rs", [752], "b",
    "computed match_score (real)", "")
add("talos-workflow-repository/src/workflows.rs", [144, 146, 147, 148, 254, 256, 257, 258],
    "b",
    "workflows.description (NULL) / tags (NOT NULL array, defaulted) / "
    "LATERAL latest.status + latest.started_at (NULL by LEFT JOIN)", "")
add("talos-workflow-repository/src/workflows.rs", [261, 262], "b",
    "workflows.status / workflow_type in the PAGINATED twin — projected, "
    "NOT NULL, Option-typed field", "")

# ────────────────────────────── (c) ──────────────────────────────────────────
# none: every site in the population is a real `sqlx::Row` column read.


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        sites = json.load(open(sys.argv[2]))
        keys = {(s["file"], s["line"]) for s in sites}
        missing = sorted(keys - set(V))
        extra = sorted(set(V) - keys)
        print(f"sites={len(keys)} verdicts={len(V)}")
        print(f"unclassified={len(missing)} {missing}")
        print(f"stale_verdicts={len(extra)} {extra}")
        c = collections.Counter(v[0] for v in V.values())
        print("buckets:", dict(sorted(c.items())))
        return 0 if not missing and not extra else 1
    c = collections.Counter(v[0] for v in V.values())
    print(f"total {len(V)}  " + "  ".join(f"({k}) {n}" for k, n in sorted(c.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
