import React, { useState, useMemo } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useQuery } from "@tanstack/react-query";
import { ClipboardList, Download, Filter, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { getActorActionLog, type ActorActionLogEntry } from "@/lib/graphqlApi";
import { SkeletonTimeline } from "@/components/ui";
import { LocalEmptyState, LogEntryRow, downloadLogCsv } from "./shared";

const LOG_FILTER_OPTIONS = [
  { id: "all", label: "All" },
  { id: "created", label: "created" },
  { id: "workflow_executed", label: "workflow_executed" },
  { id: "handoff", label: "handoff" },
  { id: "lifecycle", label: "suspended/activated" },
] as const;

type LogFilter = (typeof LOG_FILTER_OPTIONS)[number]["id"];

const VISIBLE_PAGE_SIZE = 50;

export function LogPanel({ actorId }: { actorId: string }) {
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState<LogFilter>("all");
  const [search, setSearch] = useState("");
  const [visibleCount, setVisibleCount] = useState(VISIBLE_PAGE_SIZE);

  const { data: entries = [], isLoading } = useQuery<ActorActionLogEntry[]>({
    queryKey: ["actorActionLog", actorId, limit],
    queryFn: () => getActorActionLog(actorId, limit),
  });

  const filtered = useMemo(() => {
    let result = entries;
    if (filter !== "all") {
      result = result.filter((e) => {
        const t = e.actionType.toLowerCase();
        if (filter === "handoff") return t.includes("handoff");
        if (filter === "lifecycle")
          return t === "suspended" || t === "activated";
        return t === filter;
      });
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.summary.toLowerCase().includes(q) ||
          e.actionType.toLowerCase().includes(q) ||
          (e.workflowId ?? "").toLowerCase().includes(q),
      );
    }
    return result;
  }, [entries, filter, search]);

  if (isLoading) return <SkeletonTimeline className="mt-4" />;

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex items-center gap-1.5 flex-wrap">
          {LOG_FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              onClick={() => setFilter(opt.id)}
              className={cn(
                "px-2.5 py-1 text-xs rounded-lg border transition-ui",
                filter === opt.id
                  ? "bg-primary/20 border-primary/30 text-primary"
                  : "border-white/5 text-muted-foreground hover:text-white hover:bg-surface-3/60",
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Filter className="w-3.5 h-3.5 text-muted-foreground/70 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search…"
              className="pl-7 pr-3 text-xs w-40"
            />
          </div>
          {entries.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => downloadLogCsv(entries)}
            >
              <Download className="w-3.5 h-3.5" />
              CSV
            </Button>
          )}
        </div>
      </div>

      {filtered.length === 0 ? (
        <LocalEmptyState
          icon={<ClipboardList size={40} />}
          message="No matching entries"
        />
      ) : (
        <div className="bg-surface-3/60 border border-white/5 rounded-2xl overflow-hidden">
          <div className="divide-y divide-[rgba(255,255,255,0.04)]">
            {filtered.slice(0, visibleCount).map((entry) => (
              <LogEntryRow key={entry.id} entry={entry} />
            ))}
          </div>
          {filtered.length > visibleCount && (
            <button
              onClick={() => setVisibleCount((v) => v + VISIBLE_PAGE_SIZE)}
              className="w-full py-2.5 text-xs text-muted-foreground hover:text-white hover:bg-[rgba(255,255,255,0.03)] transition-ui border-t border-[rgba(255,255,255,0.04)]"
            >
              Show more ({filtered.length - visibleCount} remaining)
            </button>
          )}
        </div>
      )}

      {entries.length >= limit && (
        <div className="text-center">
          <Button
            variant="ghost"
            size="sm"
            className="mx-auto"
            onClick={() => setLimit((l) => l + 50)}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
