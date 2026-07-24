import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { useWorkflowStore } from "@/store/workflowStore";
import { useMyModulesQuery } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import { getCapabilityConfig } from "@/lib/capabilityConfig";
import {
  Box,
  Code2,
  Search,
  Cpu,
  Globe,
  ChevronDown,
  ChevronRight,
  Clock,
  HardDrive,
  Hash,
  Layers,
  RefreshCw,
  Zap,
  ExternalLink,
} from "lucide-react";
import { DarkInput } from "@/components/ui/DarkInput";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function worldLabel(world: string | null | undefined): string {
  if (!world) return "unknown";
  return getCapabilityConfig(world).label;
}

function worldColor(world: string | null | undefined): string {
  if (!world) return "text-muted-foreground bg-white/5 border-white/10";
  const cfg = getCapabilityConfig(world);
  return `${cfg.textColor} ${cfg.bgColor} ${cfg.borderColor}`;
}

function langColor(lang: string | null | undefined): string {
  if (lang === "rust")
    return "text-orange-400 bg-orange-500/10 border-orange-500/20";
  if (lang === "javascript" || lang === "js")
    return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
  if (lang === "typescript" || lang === "ts")
    return "text-blue-400 bg-blue-500/10 border-blue-500/20";
  return "text-muted-foreground bg-white/5 border-white/10";
}

function parseConfigFields(config: string): string[] {
  try {
    const obj = JSON.parse(config) as Record<string, unknown>;
    return Object.keys(obj);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Module card
// ---------------------------------------------------------------------------

import type { MyModulesQuery } from "@/generated/graphql";
type Module = MyModulesQuery["myModules"][number];

function ModuleCard({
  mod,
  onUseInEditor,
}: {
  mod: Module;
  onUseInEditor: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const configFields = useMemo(
    () => parseConfigFields(mod.config),
    [mod.config],
  );
  const lang = mod.language ?? "rust";

  return (
    <div className="bg-surface-3/40 backdrop-blur-md border border-white/5 rounded-[2rem] overflow-hidden hover:border-primary/20 transition-premium shadow-xl group relative glass">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

      {/* Header row */}
      <div
        className="w-full flex items-center gap-6 p-6 text-left hover:bg-white/[0.02] transition-premium cursor-pointer relative z-10"
        onClick={() => setExpanded((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setExpanded((v) => !v);
        }}
      >
        <div className="w-14 h-14 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center shrink-0 shadow-2xl transition-premium group-hover:scale-110 group-hover:border-primary/30 relative">
          <div className="absolute -inset-2 bg-primary/10 rounded-full blur-xl opacity-0 group-hover:opacity-50 transition-premium" />
          <Cpu className="w-6 h-6 text-primary drop-shadow-[0_0_10px_hsla(var(--primary),0.5)] relative z-10" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap mb-2">
            <h3 className="text-lg font-black text-white tracking-tight font-outfit uppercase leading-none">
              {mod.name}
            </h3>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[9px] font-black uppercase tracking-[0.2em] border shrink-0 transition-premium shadow-sm",
                langColor(lang),
              )}
            >
              {lang}
            </span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[9px] font-black uppercase tracking-[0.2em] border shrink-0 transition-premium shadow-sm",
                worldColor(mod.capabilityWorld),
              )}
            >
              <Zap className="w-2.5 h-2.5 fill-current/20" />
              {worldLabel(mod.capabilityWorld)}
            </span>
          </div>

          {mod.capabilityDescription && (
            <p className="text-xs text-muted-foreground/60 font-bold leading-relaxed line-clamp-1 mb-3">
              {mod.capabilityDescription}
            </p>
          )}

          <div className="flex items-center gap-5 text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30 group-hover:text-muted-foreground/50 transition-premium">
            <span className="flex items-center gap-2">
              <HardDrive className="w-3.5 h-3.5 opacity-40" />
              {formatBytes(mod.sizeBytes)}
            </span>
            <div className="w-1 h-1 rounded-full bg-white/5" />
            <span className="flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 opacity-40" />
              {relativeTime(mod.compiledAt)}
            </span>
            {configFields.length > 0 && (
              <>
                <div className="w-1 h-1 rounded-full bg-white/5" />
                <span className="flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 opacity-40" />
                  {configFields.length} Protocol Field
                  {configFields.length === 1 ? "" : "s"}
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onUseInEditor();
            }}
            className="text-[10px] font-black uppercase tracking-[0.3em] text-primary bg-primary/5 border border-primary/20 rounded-xl px-6 py-3 hover:bg-primary hover:text-white transition-premium shadow-2xl active:scale-95 flex items-center gap-2 group/btn"
          >
            <ExternalLink className="w-4 h-4 transition-transform group-hover/btn:-translate-y-0.5 group-hover/btn:translate-x-0.5" />
            Initialize
          </button>
          <div className="p-3 rounded-xl bg-white/5 border border-white/5 text-muted-foreground group-hover:text-white group-hover:bg-white/10 transition-premium shadow-lg">
            {expanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </div>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-white/5 px-8 py-8 space-y-8 bg-surface-4/40 animate-in slide-in-from-top-4 duration-500 glass-dark">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-10">
            <div className="space-y-3">
              <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em]">
                Module Identifier
              </p>
              <div className="px-4 py-3 rounded-2xl bg-surface-4/60 border border-white/5 font-mono text-[11px] text-primary/60 break-all select-all shadow-inner font-bold">
                {mod.id}
              </div>
            </div>
            <div className="space-y-3">
              <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em]">
                Integrity Hash
              </p>
              <div className="px-4 py-3 rounded-2xl bg-surface-4/60 border border-white/5 font-mono text-[11px] text-muted-foreground/40 break-all select-all shadow-inner font-bold">
                {mod.contentHash}
              </div>
            </div>
          </div>

          {mod.importedInterfaces && mod.importedInterfaces.length > 0 && (
            <div className="space-y-4">
              <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] flex items-center gap-3">
                <Globe className="w-4 h-4 opacity-30" /> Interface Bindings
              </p>
              <div className="flex flex-wrap gap-2.5">
                {mod.importedInterfaces.map((iface: string) => (
                  <span
                    key={iface}
                    className="px-4 py-2 rounded-xl text-[10px] font-black font-mono text-muted-foreground/60 bg-surface-4/60 border border-white/5 hover:border-primary/40 hover:text-white transition-premium cursor-default shadow-sm"
                  >
                    {iface}
                  </span>
                ))}
              </div>
            </div>
          )}

          {configFields.length > 0 && (
            <div className="space-y-4">
              <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] flex items-center gap-3">
                <Hash className="w-4 h-4 opacity-30" /> Protocol Configuration
              </p>
              <div className="flex flex-wrap gap-2.5">
                {configFields.map((f) => (
                  <span
                    key={f}
                    className="px-4 py-2 rounded-xl text-[10px] font-black font-mono text-primary/60 bg-primary/5 border border-primary/20 hover:border-primary/50 hover:text-primary transition-premium cursor-default shadow-sm"
                  >
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyState({ hasSearch }: { hasSearch: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-40 text-center px-10 bg-surface-3/20 border border-white/5 rounded-[4rem] backdrop-blur-3xl glass-dark animate-in fade-in zoom-in-95 duration-700">
      <div className="w-24 h-24 rounded-[3rem] bg-surface-4/60 border border-white/10 flex items-center justify-center mb-10 shadow-2xl relative">
        <div className="absolute -inset-4 bg-primary/5 rounded-full blur-3xl opacity-50" />
        <Box className="w-12 h-12 text-muted-foreground/20 relative z-10" />
      </div>
      <h2 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-4">
        {hasSearch ? "No matching protocols" : "Library offline"}
      </h2>
      <p className="text-muted-foreground/40 text-sm max-w-sm font-bold uppercase tracking-widest leading-relaxed">
        {hasSearch
          ? "No modules in your active library match the current filter parameters."
          : "Synchronize protocols from the Catalog to initialize your local execution library."}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Modules() {
  const navigate = useNavigate();
  const clearWorkflow = useWorkflowStore((s) => s.clearWorkflow);
  const [search, setSearch] = useState("");
  const [worldFilter, setWorldFilter] = useState<string | null>(null);

  const { data, isLoading, refetch, isFetching } = useMyModulesQuery(
    { limit: 200 },
    { staleTime: 5 * 60_000, refetchOnWindowFocus: false },
  );
  const modules = useMemo(() => data?.myModules ?? [], [data]);

  const worlds = useMemo(() => {
    const seen = new Set<string>();
    for (const m of modules) {
      if (m.capabilityWorld) seen.add(m.capabilityWorld);
    }
    return Array.from(seen).sort();
  }, [modules]);

  const filtered = useMemo(() => {
    let result = modules;
    if (worldFilter)
      result = result.filter((m) => m.capabilityWorld === worldFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (m) =>
          m.name.toLowerCase().includes(q) ||
          (m.capabilityDescription ?? "").toLowerCase().includes(q) ||
          m.id.toLowerCase().includes(q),
      );
    }
    return result;
  }, [modules, worldFilter, search]);

  return (
    <div className="px-10 pb-20 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header / Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 mb-12">
        <div className="flex items-center gap-6">
          <div className="w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] relative">
            <div className="absolute inset-0 bg-primary/5 rounded-full blur-xl animate-pulse" />
            <Code2 className="w-6 h-6 text-primary relative z-10" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-1.5">
              Active Library
            </h1>
            <div className="flex items-center gap-3">
              <span className="text-[10px] font-black text-primary/60 uppercase tracking-[0.3em]">
                {isLoading
                  ? "Synchronizing Registry..."
                  : `${modules.length} Operational Module${modules.length !== 1 ? "s" : ""} Online`}
              </span>
              <div className="w-1.5 h-1.5 rounded-full bg-success animate-status-pulse shadow-[0_0_8px_hsla(var(--success),0.5)]" />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="h-14 w-14 bg-surface-3/40 border border-white/5 text-muted-foreground hover:text-white rounded-2xl transition-premium disabled:opacity-40 active:scale-90 shadow-2xl flex items-center justify-center glass group"
            title="Force Synchronize"
          >
            <RefreshCw
              className={cn(
                "w-5 h-5 group-hover:rotate-180 transition-transform duration-700",
                isFetching && "animate-spin",
              )}
            />
          </button>

          {/* Search */}
          <div className="relative group/search flex-1 md:flex-none">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-[1.5rem] blur opacity-0 group-focus-within/search:opacity-100 transition-premium pointer-events-none" />
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/30 pointer-events-none group-focus-within/search:text-primary transition-premium z-10" />
            <DarkInput
              type="text"
              placeholder="SEARCH ACTIVE PROTOCOLS..."
              value={search}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSearch(e.target.value)
              }
              className="w-full md:w-96 h-14 pl-14"
            />
          </div>
        </div>
      </div>

      {/* World filter pills */}
      {worlds.length > 1 && (
        <div className="flex items-center gap-3 flex-wrap mb-12">
          <button
            onClick={() => setWorldFilter(null)}
            className={cn(
              "px-6 py-3 text-[9px] font-black uppercase tracking-[0.3em] rounded-xl border transition-premium active:scale-95 shadow-xl glass",
              worldFilter === null
                ? "bg-white/10 text-white border-white/30"
                : "text-muted-foreground/40 border-white/5 hover:text-white hover:bg-white/5",
            )}
          >
            All Sequences ({modules.length})
          </button>
          {worlds.map((w) => {
            const count = modules.filter((m) => m.capabilityWorld === w).length;
            const isActive = worldFilter === w;
            return (
              <button
                key={w}
                onClick={() => setWorldFilter(isActive ? null : w)}
                className={cn(
                  "inline-flex items-center gap-3 px-6 py-3 text-[9px] font-black uppercase tracking-[0.3em] rounded-xl border transition-premium active:scale-95 shadow-xl glass",
                  isActive
                    ? worldColor(w)
                        .replace("border-", "border-")
                        .replace("bg-", "bg-") + " text-white"
                    : "text-muted-foreground/40 border-white/5 hover:text-white hover:bg-white/5",
                )}
              >
                <Zap className="w-4 h-4 fill-current/20" />
                {worldLabel(w)}
                <span className="tabular-nums opacity-30">{count}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Content */}
      {isLoading ? (
        <div className="space-y-6">
          {Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              className="h-32 bg-surface-3/20 border border-white/5 rounded-[2rem] animate-pulse"
            />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState hasSearch={!!search.trim() || !!worldFilter} />
      ) : (
        <div className="space-y-6">
          {filtered.map((mod) => (
            <ModuleCard
              key={mod.id}
              mod={mod}
              onUseInEditor={() => {
                clearWorkflow();
                navigate(`/editor?moduleId=${mod.id}`);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
