import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  listActors,
  listActorMemories,
  type ActorMemoryEntry,
} from "@/lib/graphqlApi";
import { cn } from "@/lib/utils";
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
// user's actors, pull their episodic memories, and surface every `*/latest`
// entry — so any workflow that follows the convention shows up here with no
// per-workflow wiring.

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

async function loadBriefings(): Promise<Briefing[]> {
  const actors = await listActors();
  const perActor = await Promise.all(
    actors.map(async (a) => {
      // One actor's memory read failing must not sink the whole page.
      const entries = await listActorMemories(a.id, "episodic").catch(
        () => [] as ActorMemoryEntry[],
      );
      return entries
        .filter((e) => e.key.endsWith("/latest"))
        .map<Briefing>((e) => ({
          actorId: a.id,
          actorName: a.name,
          key: e.key,
          kind: e.key.split("/")[0] ?? e.key,
          updatedAt: e.updatedAt,
          value: parseMemoryValue(e.value),
        }));
    }),
  );
  return perActor.flat().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
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
    return <span className="text-muted-foreground/40 italic">—</span>;
  }

  if (typeof value === "string") {
    if (value.trim() === "")
      return <span className="text-muted-foreground/40 italic">—</span>;
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
      return <span className="text-muted-foreground/40 italic">none</span>;
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
    return <span className="text-muted-foreground/40 italic">—</span>;

  return (
    <div className={cn("space-y-2", depth > 0 && "space-y-1.5")}>
      {entries.map(([k, v]) => {
        const isPrimitive = typeof v !== "object" || v === null;
        return (
          <div
            key={k}
            className={cn(isPrimitive ? "flex flex-wrap gap-x-2" : "space-y-1")}
          >
            <span className="text-[11px] font-bold uppercase tracking-wider text-primary/60 shrink-0">
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
    <div className="bg-surface-3/30 border border-white/5 rounded-[2rem] p-6 flex flex-col gap-4 transition-premium hover:border-white/10 hover:shadow-2xl hover:shadow-primary/5 group relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-black text-white tracking-tight">
              {meta.title}
            </h3>
            <p className="text-[10px] text-muted-foreground/50 font-bold uppercase tracking-widest mt-0.5">
              {briefing.actorName}
            </p>
          </div>
        </div>
        <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground/50 font-bold uppercase tracking-widest shrink-0">
          <Clock className="w-3 h-3" />
          {timeAgo(briefing.updatedAt)}
        </span>
      </div>

      <div className="relative z-10 text-sm leading-relaxed">
        <PrettyValue value={briefing.value} />
      </div>

      <button
        onClick={() => setShowRaw((s) => !s)}
        className="relative z-10 self-start flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground/30 hover:text-muted-foreground/70 transition-premium"
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
        <pre className="relative z-10 text-[10px] text-foreground/60 font-mono bg-black/40 rounded-xl p-3 border border-white/5 overflow-x-auto max-h-64 thin-scrollbar">
          {JSON.stringify(briefing.value, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Briefings() {
  const {
    data: briefings = [],
    isLoading,
    isError,
    refetch,
    isRefetching,
  } = useQuery({
    queryKey: ["briefings"],
    queryFn: loadBriefings,
    refetchOnWindowFocus: true,
  });

  const hasResults = briefings.length > 0;
  const lastUpdated = useMemo(
    () => (hasResults ? briefings[0].updatedAt : null),
    [briefings, hasResults],
  );

  return (
    <div className="h-full overflow-y-auto thin-scrollbar">
      <div className="max-w-6xl mx-auto px-8 py-10 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-5">
            <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[1.5rem] flex items-center justify-center text-primary shadow-[0_0_30px_hsla(var(--primary),0.1)]">
              <Sparkles className="w-7 h-7" />
            </div>
            <div>
              <h1 className="text-3xl md:text-4xl font-black text-white tracking-tighter uppercase">
                Briefings
              </h1>
              <p className="text-sm text-muted-foreground/60 font-medium mt-1">
                The latest result from each of your workflows, in one place.
                {lastUpdated && (
                  <span className="text-muted-foreground/40">
                    {" "}
                    Updated {timeAgo(lastUpdated)}.
                  </span>
                )}
              </p>
            </div>
          </div>
          <button
            onClick={() => refetch()}
            disabled={isRefetching}
            className="self-start flex items-center gap-2 px-4 py-2.5 rounded-2xl border border-white/5 bg-white/5 hover:bg-primary/10 hover:border-primary/20 hover:text-primary text-muted-foreground text-[10px] font-black uppercase tracking-widest transition-premium active:scale-95 disabled:opacity-50"
          >
            <RefreshCw
              className={cn("w-3.5 h-3.5", isRefetching && "animate-spin")}
            />
            Refresh
          </button>
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[0, 1].map((i) => (
              <div
                key={i}
                className="h-64 rounded-[2rem] border border-white/5 bg-surface-3/20 animate-pulse"
              />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-[2rem] border border-destructive/20 bg-destructive/5 p-10 text-center">
            <p className="text-sm text-destructive font-bold">
              Couldn&apos;t load your results.
            </p>
            <button
              onClick={() => refetch()}
              className="mt-4 text-[10px] font-black uppercase tracking-widest text-muted-foreground hover:text-white"
            >
              Try again
            </button>
          </div>
        ) : !hasResults ? (
          <div className="rounded-[2rem] border border-dashed border-white/10 bg-black/10 p-16 text-center space-y-3">
            <Sparkles className="w-8 h-8 text-muted-foreground/30 mx-auto" />
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
      </div>
    </div>
  );
}
