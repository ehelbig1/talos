import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Brain,
  Plus,
  Download,
  Upload,
  Filter,
  X,
  Save,
  Pencil,
  Trash2,
  ChevronDown,
  ChevronUp,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  listActorMemories,
  writeActorMemory,
  deleteActorMemory,
  type ActorMemoryEntry,
} from "@/lib/graphqlApi";
import { SkeletonBlock } from "@/components/ui";

// ── Memory type metadata ──────────────────────────────────────────────────────

const MEMORY_TYPES = ["semantic", "episodic", "working", "scratchpad"] as const;
type MemoryType = (typeof MEMORY_TYPES)[number];

const MEMORY_TYPE_META: Record<
  MemoryType,
  { label: string; ttl: string; color: string; bg: string }
> = {
  semantic: {
    label: "Semantic",
    ttl: "Permanent",
    color: "text-violet-400",
    bg: "bg-violet-500/10",
  },
  episodic: {
    label: "Episodic",
    ttl: "7 days",
    color: "text-sky-400",
    bg: "bg-sky-500/10",
  },
  working: {
    label: "Working",
    ttl: "1 hour",
    color: "text-amber-400",
    bg: "bg-amber-500/10",
  },
  scratchpad: {
    label: "Scratchpad",
    ttl: "24 hours",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
  },
};

// ── TTL status ────────────────────────────────────────────────────────────────

function ttlStatus(expiresAt: string | null): {
  label: string;
  urgency: 0 | 1 | 2 | 3;
} {
  if (!expiresAt) return { label: "", urgency: 0 };
  const msLeft = new Date(expiresAt).getTime() - Date.now();
  if (msLeft <= 0) return { label: "Expired", urgency: 3 };
  const mins = msLeft / 60_000;
  const hours = mins / 60;
  const days = hours / 24;
  if (mins < 60) return { label: `${Math.ceil(mins)}m left`, urgency: 3 };
  if (hours < 6) return { label: `${Math.ceil(hours)}h left`, urgency: 2 };
  if (days < 2) return { label: `${Math.ceil(hours)}h left`, urgency: 1 };
  return { label: `${Math.ceil(days)}d left`, urgency: 1 };
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MemoryTypeBadge({ type }: { type: string }) {
  const meta = MEMORY_TYPE_META[type as MemoryType] ?? {
    label: type,
    ttl: "",
    color: "text-muted-foreground",
    bg: "bg-surface-4/60",
  };
  return (
    <span
      className={cn(
        "text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full",
        meta.color,
        meta.bg,
      )}
    >
      {meta.label}
    </span>
  );
}

function MemoryEntryRow({
  actorId,
  entry,
  onEdit,
  onDelete,
  deleting,
}: {
  actorId: string;
  entry: ActorMemoryEntry;
  onEdit: (e: ActorMemoryEntry) => void;
  onDelete: (key: string) => void;
  deleting: boolean;
}) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [extending, setExtending] = useState(false);

  let prettyValue = entry.value;
  try {
    prettyValue = JSON.stringify(JSON.parse(entry.value), null, 2);
  } catch {
    /* raw string */
  }
  const isMultiline = prettyValue.includes("\n");

  const { label: ttlLabel, urgency } = ttlStatus(entry.expiresAt);
  const ttlColor =
    urgency === 3
      ? "text-red-400 bg-red-500/10"
      : urgency === 2
        ? "text-amber-400 bg-amber-500/10"
        : "text-muted-foreground/40 bg-surface-3/60";

  const handleExtend = async () => {
    setExtending(true);
    try {
      await writeActorMemory({
        actorId,
        key: entry.key,
        value: entry.value,
        memoryType: entry.memoryType,
      });
      queryClient.invalidateQueries({ queryKey: ["actorMemories", actorId] });
      toast.success(`Memory '${entry.key}' TTL refreshed`);
    } catch {
      toast.error("Failed to extend memory TTL");
    } finally {
      setExtending(false);
    }
  };

  return (
    <div className="bg-background border border-white/5 rounded-xl px-4 py-3 space-y-1.5">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0 flex-wrap">
          <code className="text-xs font-mono text-violet-300 bg-violet-500/10 px-1.5 py-0.5 rounded truncate max-w-[200px]">
            {entry.key}
          </code>
          <MemoryTypeBadge type={entry.memoryType} />
          {ttlLabel && (
            <span
              className={cn(
                "text-[10px] font-medium px-1.5 py-0.5 rounded-full",
                ttlColor,
              )}
            >
              {ttlLabel}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {entry.expiresAt && (
            <button
              onClick={handleExtend}
              disabled={extending}
              title="Refresh TTL to full duration"
              className="text-[10px] text-muted-foreground/40 hover:text-emerald-400 transition-premium px-1.5 py-0.5 rounded disabled:opacity-40"
            >
              {extending ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                "Extend"
              )}
            </button>
          )}
          {isMultiline && (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="p-1 text-muted-foreground/40 hover:text-muted-foreground transition-premium"
              aria-label={expanded ? "Collapse" : "Expand"}
            >
              {expanded ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>
          )}
          <button
            onClick={() => onEdit(entry)}
            className="p-1 text-muted-foreground/40 hover:text-violet-400 transition-premium"
            aria-label="Edit"
          >
            <Pencil className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => onDelete(entry.key)}
            disabled={deleting}
            className="p-1 text-muted-foreground/40 hover:text-red-400 transition-premium disabled:opacity-40"
            aria-label="Delete"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
      <pre
        className={cn(
          "text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all leading-relaxed",
          !expanded && isMultiline && "line-clamp-2",
        )}
      >
        {prettyValue}
      </pre>
    </div>
  );
}

function MemoryForm({
  actorId,
  initial,
  onSaved,
  onCancel,
}: {
  actorId: string;
  initial?: ActorMemoryEntry | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const queryClient = useQueryClient();
  const [key, setKey] = useState(initial?.key ?? "");
  const [value, setValue] = useState(() => {
    if (!initial) return "";
    try {
      return JSON.stringify(JSON.parse(initial.value), null, 2);
    } catch {
      return initial.value;
    }
  });
  const [memType, setMemType] = useState<MemoryType>(
    (initial?.memoryType as MemoryType) ?? "semantic",
  );
  const [jsonError, setJsonError] = useState<string | null>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: () =>
      writeActorMemory({ actorId, key, value, memoryType: memType }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["actorMemories", actorId] });
      toast.success(`Memory '${key}' saved`);
      onSaved();
    },
    onError: (e) => toast.error(sanitizeErrorMessage(String(e))),
  });

  const handleValueChange = (v: string) => {
    setValue(v);
    if (!v.trim()) {
      setJsonError(null);
      return;
    }
    try {
      JSON.parse(v);
      setJsonError(null);
    } catch {
      setJsonError("Invalid JSON");
    }
  };

  const isEditing = !!initial;

  return (
    <div className="bg-surface-3/60 border border-violet-500/20 rounded-2xl px-6 py-5 space-y-4">
      <h3 className="text-sm font-semibold text-white">
        {isEditing ? `Edit memory: ${initial?.key}` : "New memory"}
      </h3>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground font-medium">Key</label>
        <input
          value={key}
          onChange={(e) => setKey(e.target.value)}
          disabled={isEditing}
          placeholder="e.g. persona"
          className="w-full bg-background border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-muted-foreground/30 focus:outline-none focus:border-violet-500/50 disabled:opacity-50 font-mono"
        />
      </div>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground font-medium">
          Type
          <span className="ml-2 text-muted-foreground/40 font-normal">
            ({MEMORY_TYPE_META[memType].ttl})
          </span>
        </label>
        <div className="flex gap-2 flex-wrap">
          {MEMORY_TYPES.map((t) => (
            <button
              key={t}
              onClick={() => setMemType(t)}
              className={cn(
                "text-xs px-3 py-1.5 rounded-lg border transition-premium font-medium",
                memType === t
                  ? `${MEMORY_TYPE_META[t].color} ${MEMORY_TYPE_META[t].bg} border-current/30`
                  : "text-muted-foreground bg-background border-white/10 hover:border-white/20",
              )}
            >
              {MEMORY_TYPE_META[t].label}
            </button>
          ))}
        </div>
        {memType === "semantic" && (
          <p className="text-[10px] text-violet-400/70 mt-1">
            Semantic memories persist permanently and are injected as{" "}
            <code className="font-mono">__actor_context__</code> when this actor
            triggers a workflow with inject_memory_context enabled.
          </p>
        )}
      </div>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground font-medium">
          Value{" "}
          <span className="text-muted-foreground/40 font-normal">(JSON)</span>
        </label>
        <textarea
          value={value}
          onChange={(e) => handleValueChange(e.target.value)}
          rows={5}
          placeholder='{"role": "AppSec Engineer", "expertise": ["OWASP", "threat modeling"]}'
          className={cn(
            "w-full bg-background border rounded-lg px-3 py-2 text-sm text-white placeholder-muted-foreground/30 focus:outline-none font-mono resize-y",
            jsonError
              ? "border-red-500/50 focus:border-red-500/70"
              : "border-white/10 focus:border-violet-500/50",
          )}
        />
        {jsonError && <p className="text-[10px] text-red-400">{jsonError}</p>}
      </div>

      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="text-xs text-muted-foreground hover:text-white px-3 py-1.5 rounded-lg border border-white/10 hover:border-white/20 transition-premium"
        >
          Cancel
        </button>
        <button
          onClick={() => mutate()}
          disabled={
            isPending || !key.trim() || !value.trim() || jsonError !== null
          }
          className="flex items-center gap-1.5 text-xs font-semibold bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white px-4 py-1.5 rounded-lg transition-premium"
        >
          <Save className="w-3.5 h-3.5" />
          {isPending ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}

// ── Main MemoryPanel ──────────────────────────────────────────────────────────

export function MemoryPanel({ actorId }: { actorId: string }) {
  const queryClient = useQueryClient();
  const [filterType, setFilterType] = useState<MemoryType | "all">("all");
  const [memSearch, setMemSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<ActorMemoryEntry | null>(null);
  const [deletingKey, setDeletingKey] = useState<string | null>(null);
  const [isImporting, setIsImporting] = useState(false);
  const importRef = React.useRef<HTMLInputElement>(null);

  const { data: memories = [], isLoading } = useQuery<ActorMemoryEntry[]>({
    queryKey: ["actorMemories", actorId],
    queryFn: () => listActorMemories(actorId),
    refetchOnWindowFocus: false,
  });

  const { mutate: doDelete } = useMutation({
    mutationFn: (key: string) => deleteActorMemory(actorId, key),
    onMutate: (key) => setDeletingKey(key),
    onSettled: () => setDeletingKey(null),
    onSuccess: (_, key) => {
      queryClient.invalidateQueries({ queryKey: ["actorMemories", actorId] });
      toast.success(`Memory '${key}' deleted`);
    },
    onError: (e) => toast.error(sanitizeErrorMessage(String(e))),
  });

  const filtered = useMemo(() => {
    let result =
      filterType === "all"
        ? memories
        : memories.filter((m) => m.memoryType === filterType);
    const q = memSearch.trim().toLowerCase();
    if (q)
      result = result.filter(
        (m) =>
          m.key.toLowerCase().includes(q) || m.value.toLowerCase().includes(q),
      );
    return result;
  }, [memories, filterType, memSearch]);

  const grouped = useMemo(() => {
    const g: Record<string, ActorMemoryEntry[]> = {};
    for (const m of filtered) (g[m.memoryType] ??= []).push(m);
    return g;
  }, [filtered]);

  const handleExport = () => {
    const payload = memories.map((m) => ({
      key: m.key,
      value: m.value,
      memoryType: m.memoryType,
    }));
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `actor-${actorId}-memories.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";

    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      toast.error("Invalid JSON file");
      return;
    }

    if (!Array.isArray(parsed)) {
      toast.error("Expected a JSON array of memory entries");
      return;
    }

    const entries = parsed as Array<{
      key?: unknown;
      value?: unknown;
      memoryType?: unknown;
    }>;
    const valid = entries.filter(
      (e) =>
        typeof e.key === "string" &&
        e.key.trim() &&
        typeof e.value === "string",
    );
    if (valid.length === 0) {
      toast.error("No valid entries found (each needs key and value strings)");
      return;
    }

    setIsImporting(true);
    let ok = 0,
      fail = 0;
    for (const entry of valid) {
      try {
        await writeActorMemory({
          actorId,
          key: (entry.key as string).trim(),
          value: entry.value as string,
          memoryType:
            typeof entry.memoryType === "string"
              ? entry.memoryType
              : "semantic",
        });
        ok++;
      } catch {
        fail++;
      }
    }
    setIsImporting(false);
    queryClient.invalidateQueries({ queryKey: ["actorMemories", actorId] });
    if (fail === 0)
      toast.success(`Imported ${ok} memor${ok === 1 ? "y" : "ies"}`);
    else toast.warning(`Imported ${ok}, failed ${fail}`);
  };

  return (
    <div className="space-y-5">
      {/* Info banner */}
      <div className="bg-violet-500/10 border border-violet-500/20 rounded-2xl px-5 py-4">
        <div className="flex items-start gap-3">
          <Brain className="w-5 h-5 text-violet-400 shrink-0 mt-0.5" />
          <p className="text-violet-200 text-sm leading-relaxed">
            <strong>Semantic</strong> memories are permanent and injected as{" "}
            <code className="font-mono text-xs bg-violet-500/20 px-1 rounded">
              __actor_context__
            </code>{" "}
            when this actor triggers a workflow with{" "}
            <em>inject_memory_context</em> enabled. <strong>Episodic</strong>{" "}
            (7d), <strong>Working</strong> (1h), and <strong>Scratchpad</strong>{" "}
            (24h) are time-limited.
          </p>
        </div>
      </div>

      {/* Form */}
      {showForm && (
        <MemoryForm
          actorId={actorId}
          initial={editing}
          onSaved={() => {
            setShowForm(false);
            setEditing(null);
          }}
          onCancel={() => {
            setShowForm(false);
            setEditing(null);
          }}
        />
      )}

      {/* Search */}
      {memories.length > 3 && (
        <div className="relative">
          <Filter className="w-3.5 h-3.5 text-muted-foreground/40 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={memSearch}
            onChange={(e) => setMemSearch(e.target.value)}
            placeholder="Search key or value…"
            className="w-full bg-surface-3/60 border border-white/5 rounded-xl pl-8 pr-8 py-2 text-sm text-white placeholder-muted-foreground/30 focus:outline-none focus:border-violet-500/40 transition-premium"
          />
          {memSearch && (
            <button
              onClick={() => setMemSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/40 hover:text-white transition-premium"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Filter tabs + action buttons */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex gap-1.5 flex-wrap">
          <button
            onClick={() => setFilterType("all")}
            className={cn(
              "text-xs px-2.5 py-1 rounded-lg border transition-premium",
              filterType === "all"
                ? "bg-surface-4/60 text-white border-white/10"
                : "text-muted-foreground border-transparent hover:bg-surface-3/60",
            )}
          >
            All ({memories.length})
          </button>
          {MEMORY_TYPES.map((t) => {
            const count = memories.filter((m) => m.memoryType === t).length;
            if (count === 0) return null;
            const meta = MEMORY_TYPE_META[t];
            return (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={cn(
                  "text-xs px-2.5 py-1 rounded-lg border transition-premium",
                  filterType === t
                    ? `${meta.color} ${meta.bg} border-current/20`
                    : "text-muted-foreground border-transparent hover:bg-surface-3/60",
                )}
              >
                {meta.label} ({count})
              </button>
            );
          })}
        </div>
        <div className="flex items-center gap-2">
          {memories.length > 0 && (
            <button
              onClick={handleExport}
              title="Export memories as JSON"
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-white border border-white/10 hover:border-[rgba(255,255,255,0.16)] px-3 py-1.5 rounded-lg transition-premium"
            >
              <Download className="w-3.5 h-3.5" />
              Export
            </button>
          )}
          <button
            onClick={() => importRef.current?.click()}
            disabled={isImporting}
            title="Import memories from JSON"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-white border border-white/10 hover:border-[rgba(255,255,255,0.16)] px-3 py-1.5 rounded-lg transition-premium disabled:opacity-50"
          >
            <Upload className="w-3.5 h-3.5" />
            {isImporting ? "Importing…" : "Import"}
          </button>
          <input
            ref={importRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleImportFile}
          />
          {!showForm && (
            <button
              onClick={() => {
                setEditing(null);
                setShowForm(true);
              }}
              className="flex items-center gap-1.5 text-xs font-semibold bg-violet-600 hover:bg-violet-500 text-white px-3 py-1.5 rounded-lg transition-premium"
            >
              <Plus className="w-3.5 h-3.5" />
              Add memory
            </button>
          )}
        </div>
      </div>

      {/* Entries */}
      {isLoading ? (
        <div className="space-y-2">
          <SkeletonBlock height="h-16" />
          <SkeletonBlock height="h-16" />
          <SkeletonBlock height="h-16" />
        </div>
      ) : memories.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-14 gap-3">
          <Brain className="w-12 h-12 text-violet-500/20" />
          <p className="text-muted-foreground/40 text-sm">No memories yet.</p>
          <button
            onClick={() => setShowForm(true)}
            className="text-xs text-violet-400 hover:text-violet-300 transition-premium"
          >
            Add the first memory →
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10 gap-2">
          <p className="text-muted-foreground/40 text-sm">
            No memories match your search.
          </p>
          <button
            onClick={() => {
              setMemSearch("");
              setFilterType("all");
            }}
            className="text-xs text-violet-400 hover:text-violet-300 transition-premium"
          >
            Clear filters →
          </button>
        </div>
      ) : (
        <div className="space-y-5">
          {(Object.keys(grouped) as MemoryType[]).map((type) => (
            <div key={type}>
              <div className="flex items-center gap-2 mb-2">
                <MemoryTypeBadge type={type} />
                <span className="text-[10px] text-muted-foreground/40">
                  {MEMORY_TYPE_META[type as MemoryType]?.ttl}
                </span>
              </div>
              <div className="space-y-2">
                {grouped[type].map((entry) => (
                  <MemoryEntryRow
                    key={entry.key}
                    actorId={actorId}
                    entry={entry}
                    onEdit={(e) => {
                      setEditing(e);
                      setShowForm(true);
                    }}
                    onDelete={doDelete}
                    deleting={deletingKey === entry.key}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
