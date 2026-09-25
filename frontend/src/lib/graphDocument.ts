/**
 * The stored `graph_json` ⇄ editor round trip — ONE home for which keys the
 * editor models and where every other key goes.
 *
 * The editor used to load only `id` / `type` / `position` / `data` from each
 * stored node and rebuild the graph as `{priority, nodes, edges}` on save, so
 * a load → save of a graph written by the MCP tools silently deleted:
 *   - `skip_condition` / `continue_on_error` / `timeout_secs` stored in `data`
 *     (the saver spread the editor's EMPTY typed fields AFTER the config, and
 *     an explicit `undefined` both overwrote the key and was then dropped by
 *     `JSON.stringify`);
 *   - `retry_count` / `retry_backoff_ms` / `retry_condition` /
 *     `retry_delay_expression`, which MCP stores at the node's TOP LEVEL;
 *   - every other top-level node key (`kind`, `description`, …), every
 *     top-level edge key the editor does not model (`id`, `logic`, …), and the
 *     graph's own top-level keys (`execution_timeout_secs`, …).
 *
 * The rule now: an engine control the editor has a field for is read from
 * wherever the ENGINE reads it (same precedence), removed from the config /
 * extras so the typed field is its single source, and written back only when
 * defined. Everything the editor does not model is carried through verbatim.
 */

import type { RetryPolicy } from "@/store/workflowStore";

type Json = Record<string, unknown>;

/** Node keys the engine reads as execution controls (see engine_graph_load.rs /
 *  graph_parser.rs). The editor models each of these as a typed field. */
export const NODE_ENGINE_CONTROL_KEYS = [
  "skip_condition",
  "continue_on_error",
  "timeout_secs",
  "retry_count",
  "retry_backoff_ms",
  "retry_condition",
  "retry_delay_expression",
] as const;

/** Node keys the editor rebuilds itself on save (never carried as extras). */
const NODE_STRUCTURAL_KEYS = ["id", "type", "position", "data"];

/** Edge keys the editor rebuilds itself on save. */
const EDGE_MODELLED_KEYS = [
  "source",
  "target",
  "sourceHandle",
  "targetHandle",
  "condition",
  "edge_type",
  "data",
];

/** Graph keys the editor rebuilds itself on save. */
const GRAPH_MODELLED_KEYS = ["nodes", "edges", "priority"];

export interface NodeEngineControls {
  skipCondition?: string;
  continueOnError?: boolean;
  timeoutSecs?: number;
  retryPolicy?: RetryPolicy;
}

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function nonNegInt(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : undefined;
}

/**
 * Read a stored node's execution controls with the ENGINE's precedence:
 * `skip_condition` / `timeout_secs` — `data` first, then top level;
 * `continue_on_error` — true if EITHER location says true;
 * `retry_*` — top level first, then `data`.
 * A key whose value has the wrong type is not read (the engine ignores it
 * too) and is left where it is, so it still round-trips unchanged.
 */
export function readNodeEngineControls(node: Json): NodeEngineControls {
  const data = isObject(node.data) ? node.data : {};
  const out: NodeEngineControls = {};

  const skip = str(data.skip_condition) ?? str(node.skip_condition);
  if (skip !== undefined) out.skipCondition = skip;

  const coeData = data.continue_on_error;
  const coeTop = node.continue_on_error;
  if (coeData === true || coeTop === true) out.continueOnError = true;
  else if (coeData === false || coeTop === false) out.continueOnError = false;

  const timeout = nonNegInt(data.timeout_secs) ?? nonNegInt(node.timeout_secs);
  if (timeout !== undefined) out.timeoutSecs = timeout;

  const retryCount = nonNegInt(node.retry_count) ?? nonNegInt(data.retry_count);
  const backoff =
    nonNegInt(node.retry_backoff_ms) ?? nonNegInt(data.retry_backoff_ms);
  const condition = str(node.retry_condition) ?? str(data.retry_condition);
  const delayExpr =
    str(node.retry_delay_expression) ?? str(data.retry_delay_expression);
  if (
    retryCount !== undefined ||
    backoff !== undefined ||
    condition !== undefined ||
    delayExpr !== undefined
  ) {
    // `maxRetries` stays ABSENT when the graph declared no count: absent means
    // "the engine's method-aware default", and inventing a number here would
    // change what the node does.
    const policy: RetryPolicy = {};
    if (retryCount !== undefined) policy.maxRetries = retryCount;
    if (backoff !== undefined) policy.backoffMs = backoff;
    if (condition !== undefined) policy.retryCondition = condition;
    if (delayExpr !== undefined) policy.retryDelayExpression = delayExpr;
    out.retryPolicy = policy;
  }
  return out;
}

/** True when `obj[key]` holds a value `readNodeEngineControls` would read. */
function isReadableControl(key: string, value: unknown): boolean {
  switch (key) {
    case "skip_condition":
    case "retry_condition":
    case "retry_delay_expression":
      return typeof value === "string";
    case "continue_on_error":
      return typeof value === "boolean";
    default:
      return nonNegInt(value) !== undefined;
  }
}

/**
 * A copy of `obj` without the engine-control keys the typed fields now own,
 * so clearing a field in the editor actually clears it (a stale copy in the
 * config would otherwise survive the save).
 */
export function withoutEngineControls(obj: Json): Json {
  const out: Json = {};
  for (const [k, v] of Object.entries(obj)) {
    if (
      (NODE_ENGINE_CONTROL_KEYS as readonly string[]).includes(k) &&
      isReadableControl(k, v)
    ) {
      continue;
    }
    out[k] = v;
  }
  return out;
}

/** A stored node's top-level keys the editor does not model (`kind`,
 *  `description`, …), to be written back verbatim. */
export function nodeTopLevelExtras(node: Json): Json {
  const out: Json = {};
  for (const [k, v] of Object.entries(withoutEngineControls(node))) {
    if (!NODE_STRUCTURAL_KEYS.includes(k)) out[k] = v;
  }
  return out;
}

/** A stored edge's top-level keys the editor does not model (`id`, `logic`, …). */
export function edgeTopLevelExtras(edge: Json): Json {
  const out: Json = {};
  for (const [k, v] of Object.entries(edge)) {
    if (!EDGE_MODELLED_KEYS.includes(k)) out[k] = v;
  }
  return out;
}

/** The graph's top-level keys the editor does not model
 *  (`execution_timeout_secs`, …). */
export function graphTopLevelExtras(graph: Json): Json {
  const out: Json = {};
  for (const [k, v] of Object.entries(graph)) {
    if (!GRAPH_MODELLED_KEYS.includes(k)) out[k] = v;
  }
  return out;
}

/**
 * `obj` without its `undefined`-valued keys. Spread THIS, never a literal with
 * possibly-undefined members: `{...config, ...{k: undefined}}` overwrites
 * `config.k` and `JSON.stringify` then drops it — which is how the editor used
 * to delete MCP-authored `skip_condition` / `continue_on_error` on every save.
 */
export function definedOnly<T extends Json>(obj: T): Partial<T> {
  const out: Json = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v;
  }
  return out as Partial<T>;
}

/** The stored spelling of a node's engine controls. */
export interface EngineControlKeys {
  [key: string]: unknown;
  skip_condition?: string;
  continue_on_error?: boolean;
  timeout_secs?: number;
  retry_count?: number;
  retry_backoff_ms?: number;
  retry_condition?: string;
  retry_delay_expression?: string;
}

/** The engine-control keys to write for a node, from its typed fields. Only
 *  defined values — an unset field writes nothing. */
export function engineControlKeys(c: NodeEngineControls): EngineControlKeys {
  return definedOnly<EngineControlKeys>({
    skip_condition: c.skipCondition,
    continue_on_error: c.continueOnError,
    timeout_secs: c.timeoutSecs,
    retry_count: c.retryPolicy?.maxRetries,
    retry_backoff_ms: c.retryPolicy?.backoffMs,
    retry_condition: c.retryPolicy?.retryCondition,
    retry_delay_expression: c.retryPolicy?.retryDelayExpression,
  });
}
