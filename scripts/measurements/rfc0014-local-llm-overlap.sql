-- RFC 0014 P2c: how often local LLM calls overlap, and with which models.
-- Read-only. Run: docker exec -i talos-postgres psql -U talos talos -At -F' | ' < this-file
-- Upper bounds: a module execution's interval contains its LLM call and its other work.

-- 1. Same-run vs cross-run overlap.
with llm_mods as (
  select id from modules where source_code ~ 'llm::(complete|chat|llm_tools|complete_with)' or source_code ~ 'complete_with_tools'
), calls as (
  select me.id, me.workflow_execution_id as run, me.started_at s, me.completed_at e
  from module_executions me join llm_mods m on m.id = me.module_id
  where me.started_at > now() - interval '30 days' and me.completed_at is not null
), ov as (
  select a.id, a.run,
    count(b.id) filter (where b.run is not distinct from a.run and b.id <> a.id) as same_run_overlap,
    count(b.id) filter (where b.run is distinct from a.run) as other_run_overlap
  from calls a left join calls b on b.s < a.e and b.e > a.s and b.id <> a.id
  group by a.id, a.run
)
select count(*) total_llm_calls,
  count(*) filter (where same_run_overlap > 0) with_same_run_sibling_in_flight,
  count(*) filter (where other_run_overlap > 0) with_other_run_in_flight,
  count(*) filter (where same_run_overlap > 0 and other_run_overlap > 0) both,
  max(same_run_overlap) max_same_run_siblings
from ov;

-- 2. Model pairs among overlapping cross-run calls.
with llm_mods as (
  select id from modules where source_code ~ 'llm::(complete|chat|llm_tools|complete_with)' or source_code ~ 'complete_with_tools'
), node_models as (
  select w.id wf, (n->>'type')::text mod, coalesce(n->'data'->>'MODEL', n->'data'->'config'->>'MODEL') model
  from workflows w, jsonb_array_elements(w.graph_json::jsonb->'nodes') n
), calls as (
  select me.id, me.workflow_execution_id run, me.started_at s, me.completed_at e,
    (select string_agg(distinct nm.model, ',') from node_models nm where nm.wf = we.workflow_id and nm.mod = me.module_id::text) model
  from module_executions me join llm_mods m on m.id = me.module_id
  left join workflow_executions we on we.id = me.workflow_execution_id
  where me.started_at > now() - interval '30 days' and me.completed_at is not null
)
select coalesce(a.model,'?') ma, coalesce(b.model,'?') mb, count(*)
from calls a join calls b on b.s < a.e and b.e > a.s and b.id < a.id and b.run is distinct from a.run
group by 1,2 order by 3 desc limit 20;

-- 3. Calls with 2+ others in flight, and how many involve a known different model.
with llm_mods as (
  select id from modules where source_code ~ 'llm::(complete|chat|llm_tools|complete_with)' or source_code ~ 'complete_with_tools'
), node_models as (
  select w.id wf, (n->>'type')::text mod, coalesce(n->'data'->>'MODEL', n->'data'->'config'->>'MODEL') model
  from workflows w, jsonb_array_elements(w.graph_json::jsonb->'nodes') n
), calls as (
  select me.id, me.workflow_execution_id run, me.started_at s, me.completed_at e,
    (select string_agg(distinct nm.model, ',') from node_models nm where nm.wf = we.workflow_id and nm.mod = me.module_id::text) model
  from module_executions me join llm_mods m on m.id = me.module_id
  left join workflow_executions we on we.id = me.workflow_execution_id
  where me.started_at > now() - interval '30 days' and me.completed_at is not null
), ov as (
  select a.id, a.model, count(b.id) others, count(distinct b.model) filter (where a.model is not null and b.model is not null and b.model <> a.model) other_models
  from calls a join calls b on b.s < a.e and b.e > a.s and b.id <> a.id
  group by a.id, a.model
)
select count(*) filter (where others >= 2) calls_with_2plus_concurrent,
       count(*) filter (where others >= 2 and other_models >= 1) of_which_mixed_models,
       count(distinct date_trunc('day', c.s)) filter (where others >= 2 and other_models >= 1) days
from ov join calls c on c.id = ov.id;
