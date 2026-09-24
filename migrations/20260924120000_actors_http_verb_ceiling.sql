-- Split the write ceiling's VERB-INFERRED half onto its own axis.
--
-- `actors.max_write_ceiling` governs fifteen gated ops. Three of them —
-- `http::fetch`, `http::fetch_all`, `graphql::execute` — decide "is this a
-- mutation?" by INFERRING it from the HTTP verb, and that inference
-- over-refuses by design: a POST that is a READ on the target API (Plaid's
-- `/accounts/balance/get`, Elasticsearch's `_search`) is refused anyway,
-- because GET is the only verb the gate can call a read.
--
-- Today the only way to clear that refusal is `max_write_ceiling = 'write'`,
-- which also grants the twelve CATEGORICAL ops the actor never needed —
-- agent-memory writes, database DML, email, NATS publish, object storage,
-- integration state. Measured on the reference fleet 2026-09-24: the Plaid
-- reader actor holds `write` for exactly this reason and its module calls
-- `http::fetch` and nothing else.
--
-- `http_verb_ceiling` is that override, and ONLY that:
--   NULL      -> inherit `max_write_ceiling` (every existing row; byte-identical
--                behaviour, which is why there is no backfill and no default)
--   'write'   -> the three inferring gates permit any verb
--   'readonly'-> the three inferring gates refuse non-GET even when
--                `max_write_ceiling` is 'write' (a TIGHTENING direction: an
--                actor that may keep notes but must not POST anywhere)
--
-- NULLABLE with no DEFAULT deliberately. A DEFAULT would make "inherit"
-- indistinguishable from "explicitly set to the inherited value", and the
-- three-valued read is what lets the signed wire field stay a conditional
-- append (`:hvc=`), so a default-shaped job is byte-identical and no
-- coordinated controller+worker restart is required.
ALTER TABLE actors ADD COLUMN IF NOT EXISTS http_verb_ceiling TEXT;

-- Only the two canonical tokens, or NULL. Mirrors the fail-closed
-- `WriteCeiling::from_db_str`, but a CHECK is cheaper than discovering a typo
-- at dispatch time — and unlike `max_write_ceiling` (whose column predates
-- this discipline) there are no legacy values to grandfather.
ALTER TABLE actors DROP CONSTRAINT IF EXISTS actors_http_verb_ceiling_check;
ALTER TABLE actors ADD CONSTRAINT actors_http_verb_ceiling_check
    CHECK (http_verb_ceiling IS NULL OR http_verb_ceiling IN ('readonly', 'write'));

-- The SAME escalation guard `max_write_ceiling` has carried since
-- 20260709180000. Without it this column is a bypass: an operator (or a
-- migration re-run, or a fat-fingered bulk UPDATE) could grant POST-shaped
-- egress to every actor at once while the guard on the sibling column looked
-- on. A guard that covers one of two escalation paths is not a guard.
--
-- Escalation here means NULL/'readonly' -> 'write'. Locking down
-- ('write' -> 'readonly'/NULL) is always permitted, as on the sibling column.
CREATE OR REPLACE FUNCTION talos_guard_actor_http_verb_ceiling()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.http_verb_ceiling = 'write'
       AND OLD.http_verb_ceiling IS DISTINCT FROM 'write'
       AND current_setting('talos.allow_ceiling_grant', true) IS DISTINCT FROM 'on'
    THEN
        RAISE EXCEPTION
            'refusing to grant the http-verb ceiling to actor % outside the '
            'sanctioned set_actor_http_verb_ceiling path (guards against a bulk / '
            'migration re-run clobber of operator intent)', NEW.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER actors_http_verb_ceiling_grant_guard
    BEFORE UPDATE OF http_verb_ceiling ON actors
    FOR EACH ROW
    EXECUTE FUNCTION talos_guard_actor_http_verb_ceiling();

COMMENT ON COLUMN actors.http_verb_ceiling IS
    'Override for the VERB-INFERRED half of the write ceiling (http fetch / '
    'fetch_all / graphql execute). NULL inherits max_write_ceiling. Set via '
    'set_actor_http_verb_ceiling, which holds the talos.allow_ceiling_grant GUC.';
