import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  listActors,
  listActorsMemories,
  type ActorMemoryGroup,
} from "@/lib/graphqlApi";
import { cn } from "@/lib/utils";
import { Button, PageContainer, PageHeader } from "@/components/ui";
import {
  Sparkles,
  Clock,
  RefreshCw,
  Inbox,
  CalendarDays,
  Briefcase,
  FileText,
  ChevronDown,
} from "lucide-react";

// ── Data ────────────────────────────────────────────────────────────────────
//
// "Results" are the curated outputs workflows persist to actor memory under a
// `<name>/latest` key (the __memory_write__ convention). We fan out across the
// user's actors, read their episodic `*/latest` memories (filtered by the
// server), and surface every one — so any workflow that follows the
// convention shows up here with no per-workflow wiring.

interface Briefing {
  actorId: string;
  actorName: string;
  key: string;
  /** kind = the key prefix before `/`, e.g. "daily_brief". */
  kind: string;
  updatedAt: string;
  value: unknown;
}

/** Parse a memory `value` string, transparently unwrapping the double-encoded
 *  case (a stored JSON *string* whose contents are themselves JSON — how
 *  LLM-node outputs land in memory). Falls back to the raw string. */
function parseMemoryValue(raw: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return raw;
  }
  if (typeof parsed === "string") {
    const trimmed = parsed.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        return JSON.parse(trimmed);
      } catch {
        return parsed;
      }
    }
  }
  return parsed;
}

/** The server's per-actor row cap on `actorsMemories` (default = max). */
export const MEMORIES_PER_ACTOR_CAP = 1000;
const ACTOR_CHUNK = 100;
/** The briefing key convention; the server filters on it. */
export const BRIEFING_KEY_SUFFIX = "/latest";

export interface BriefingsLoad {
  briefings: Briefing[];
  /** Actors whose memories could not be read (their chunk failed). */
  unreadableActors: string[];
  /** Actors that returned the per-actor cap. The read is already limited
   *  to `/latest` keys and windowed by last write, so this needs more than
   *  1000 distinct briefing keys on one actor — reported, not assumed away. */
  possiblyTruncatedActors: string[];
}

/** Pure fold of the per-chunk reads; a failed chunk is reported, never
 *  rendered as "no briefings". */
export function summarizeBriefings(
  actors: ReadonlyArray<{ id: string; name: string }>,
  chunks: ReadonlyArray<{
    ids: string[];
    result: PromiseSettledResult<ActorMemoryGroup[]>;
  }>,
): BriefingsLoad {
  const nameById = new Map(actors.map((a) => [a.id, a.name]));
  const name = (id: string) => nameById.get(id) ?? id;
  const unreadableActors: string[] = [];
  const possiblyTruncatedActors: string[] = [];
  const groups: ActorMemoryGroup[] = [];
  for (const { ids, result } of chunks) {
    if (result.status === "rejected") {
      unreadableActors.push(...ids.map(name));
      continue;
    }
    for (const group of result.value) {
      groups.push(group);
      if (group.memories.length >= MEMORIES_PER_ACTOR_CAP) {
        possiblyTruncatedActors.push(name(group.actorId));
      }
    }
  }
  const briefings = groups
    .flatMap((group) =>
      group.memories
        // The server already filtered on the suffix; kept as a cheap guard.
        .filter((e) => e.key.endsWith(BRIEFING_KEY_SUFFIX))
        .map<Briefing>((e) => ({
          actorId: group.actorId,
          actorName: name(group.actorId),
          key: e.key,
          kind: e.key.split("/")[0] ?? e.key,
          updatedAt: e.updatedAt,
          value: parseMemoryValue(e.value),
        })),
    )
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  return { briefings, unreadableActors, possiblyTruncatedActors };
}

export async function loadBriefings(): Promise<BriefingsLoad> {
  const actors = await listActors();
  // Batched read, chunked at the server's 100-id cap, restricted in SQL to
  // `*/latest` keys so an actor's other memories cannot window them out.
  const chunks: string[][] = [];
  for (let i = 0; i < actors.length; i += ACTOR_CHUNK) {
    chunks.push(actors.slice(i, i + ACTOR_CHUNK).map((a) => a.id));
  }
  const results = await Promise.allSettled(
    chunks.map((ids) =>
      listActorsMemories(ids, "episodic", BRIEFING_KEY_SUFFIX),
    ),
  );
  // Nothing readable at all is the page's error state, not "no results".
  const firstFailure = results.find((r) => r.status === "rejected");
  if (firstFailure && results.every((r) => r.status === "rejected")) {
    throw firstFailure.reason;
  }
  return summarizeBriefings(
    actors,
    chunks.map((ids, i) => ({ ids, result: results[i] })),
  );
}

// ── Presentation helpers ─────────────────────────────────────────────────────

const KIND_META: Record<
  string,
  { title: string; icon: React.ComponentType<{ className?: string }> }
> = {
  daily_brief: { title: "Daily Brief", icon: CalendarDays },
  crm: { title: "Opportunity CRM", icon: Briefcase },
  inbox_triage: { title: "Inbox Triage", icon: Inbox },
  meeting_prep: { title: "Meeting Prep", icon: FileText },
  recall: { title: "Recall", icon: FileText },
};

function kindMeta(kind: string) {
  return (
    KIND_META[kind] ?? {
      title: kind
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase()),
      icon: FileText,
    }
  );
}

function titleize(key: string): string {
  return key.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

/** Recursive, readable renderer for arbitrary workflow-result JSON. Objects
 *  become labelled sections, arrays become lists, primitives become text —
 *  so every workflow's output is legible without a bespoke component. */
function PrettyValue({
  value,
  depth = 0,
}: {
  value: unknown;
  depth?: number;
}): React.ReactElement {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground/70 italic">—</span>;
  }

  if (typeof value === "string") {
    if (value.trim() === "")
      return <span className="text-muted-foreground/70 italic">—</span>;
    return (
      <span className="text-foreground/80 whitespace-pre-wrap break-words">
        {value}
      </span>
    );
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return <span className="text-foreground/80">{String(value)}</span>;
  }

  if (Array.isArray(value)) {
    if (value.length === 0)
      return <span className="text-muted-foreground/70 italic">none</span>;
    return (
      <ul className="space-y-2">
        {value.map((item, i) => (
          <li
            key={i}
            className={cn(
              "text-sm",
              typeof item === "object" && item !== null
                ? "rounded-xl border border-white/5 bg-black/20 p-3"
                : "flex gap-2",
            )}
          >
            {typeof item === "object" && item !== null ? (
              <PrettyValue value={item} depth={depth + 1} />
            ) : (
              <>
                <span className="text-primary/50 select-none">•</span>
                <PrettyValue value={item} depth={depth + 1} />
              </>
            )}
          </li>
        ))}
      </ul>
    );
  }

  // Object → labelled fields.
  const entries = Object.entries(value as Record<string, unknown>).filter(
    ([k]) => !k.startsWith("__"),
  );
  if (entries.length === 0)
    return <span className="text-muted-foreground/70 italic">—</span>;

  return (
    <div className={cn("space-y-2", depth > 0 && "space-y-1.5")}>
      {entries.map(([k, v]) => {
        const isPrimitive = typeof v !== "object" || v === null;
        return (
          <div
            key={k}
            className={cn(isPrimitive ? "flex flex-wrap gap-x-2" : "space-y-1")}
          >
            <span className="text-xs font-bold text-primary/60 shrink-0">
              {titleize(k)}
            </span>
            <div className={cn(isPrimitive ? "" : "pl-1")}>
              <PrettyValue value={v} depth={depth + 1} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Card ─────────────────────────────────────────────────────────────────────

function BriefingCard({ briefing }: { briefing: Briefing }) {
  const [showRaw, setShowRaw] = useState(false);
  const meta = kindMeta(briefing.kind);
  const Icon = meta.icon;

  return (
    <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-6 flex flex-col gap-4 transition-premium hover:border-white/10 hover:shadow-2xl group relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white tracking-tight">
              {meta.title}
            </h3>
            <p className="text-xs text-muted-foreground/50 font-bold mt-0.5">
              {briefing.actorName}
            </p>
          </div>
        </div>
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground/50 font-bold shrink-0">
          <Clock className="w-3 h-3" />
          {timeAgo(briefing.updatedAt)}
        </span>
      </div>

      <div className="relative z-10 text-sm leading-relaxed">
        <PrettyValue value={briefing.value} />
      </div>

      <button
        onClick={() => setShowRaw((s) => !s)}
        className="relative z-10 self-start flex items-center gap-1.5 text-xs font-bold text-muted-foreground/60 hover:text-muted-foreground/70 transition-premium"
      >
        <ChevronDown
          className={cn(
            "w-3 h-3 transition-transform",
            showRaw && "rotate-180",
          )}
        />
        {showRaw ? "Hide" : "Raw"} JSON
      </button>
      {showRaw && (
        <pre className="relative z-10 text-xs text-foreground/60 font-mono bg-black/40 rounded-xl p-3 border border-white/5 overflow-x-auto max-h-64 thin-scrollbar">
          {JSON.stringify(briefing.value, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Briefings() {
  const { data, isLoading, isError, refetch, isRefetching } = useQuery({
    queryKey: ["briefings"],
    queryFn: loadBriefings,
    refetchOnWindowFocus: true,
  });

  const briefings = useMemo(() => data?.briefings ?? [], [data]);
  const unreadable = data?.unreadableActors ?? [];
  const truncated = data?.possiblyTruncatedActors ?? [];
  const hasResults = briefings.length > 0;
  const lastUpdated = useMemo(
    () => (hasResults ? briefings[0].updatedAt : null),
    [briefings, hasResults],
  );

  return (
    <div className="h-full overflow-y-auto thin-scrollbar">
      <PageContainer className="space-y-8">
        <PageHeader
          title="Briefings"
          description={
            <>
              The latest result from each of your workflows, in one place.
              {lastUpdated && <> Updated {timeAgo(lastUpdated)}.</>}
            </>
          }
          actions={
            <Button
              variant="outline"
              onClick={() => refetch()}
              disabled={isRefetching}
            >
              <RefreshCw
                className={cn("w-4 h-4", isRefetching && "animate-spin")}
              />
              Refresh
            </Button>
          }
          className="mb-0"
        />
        {!isLoading && !isError && unreadable.length > 0 && (
          <div
            role="alert"
            className="rounded-2xl border border-destructive/20 bg-destructive/5 px-5 py-3 text-xs text-destructive"
          >
            Couldn&apos;t read results for {unreadable.join(", ")}. What is
            shown below may be incomplete.
          </div>
        )}
        {!isLoading && !isError && truncated.length > 0 && (
          <div className="rounded-2xl border border-warning/20 bg-warning/5 px-5 py-3 text-xs text-warning">
            {truncated.join(", ")} returned the maximum of{" "}
            {MEMORIES_PER_ACTOR_CAP} memories; some older results may be
            missing.
          </div>
        )}

        {/* Content */}
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[0, 1].map((i) => (
              <div
                key={i}
                className="h-64 rounded-2xl border border-white/5 bg-surface-3/20 animate-pulse"
              />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-2xl border border-destructive/20 bg-destructive/5 p-10 text-center">
            <p className="text-sm text-destructive font-bold">
              Couldn&apos;t load your results.
            </p>
            <button
              onClick={() => refetch()}
              className="mt-4 text-xs font-semibold text-muted-foreground hover:text-white"
            >
              Try again
            </button>
          </div>
        ) : !hasResults && unreadable.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-white/10 bg-black/10 p-16 text-center space-y-3">
            <Sparkles className="w-8 h-8 text-muted-foreground/60 mx-auto" />
            <p className="text-sm text-muted-foreground/60 font-medium max-w-md mx-auto">
              No results yet. When a scheduled workflow runs and writes its
              output to memory (a{" "}
              <code className="text-primary/70">/latest</code> key), it&apos;ll
              appear here.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {briefings.map((b) => (
              <BriefingCard key={`${b.actorId}:${b.key}`} briefing={b} />
            ))}
          </div>
        )}
      </PageContainer>
    </div>
  );
}
