import React, { useState, useMemo } from "react";
import { CapabilityBadge } from "@/components/CapabilityBadge";
import { Input } from "@/components/ui/input";
import { useNavigate } from "react-router";
import { useWorkflowStore } from "@/store/workflowStore";
import { useMyModulesQuery } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import { getCapabilityConfig } from "@/lib/capabilityConfig";
import {
  Box,
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
  if (lang === "rust") return "text-warning bg-warning/10 border-warning/20";
  if (lang === "javascript" || lang === "js")
    return "text-warning bg-warning/10 border-warning/20";
  if (lang === "typescript" || lang === "ts")
    return "text-info bg-info/10 border-info/20";
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
import { Button } from "@/components/ui";
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
    <div className="bg-surface-3/40 border border-white/5 rounded-2xl overflow-hidden hover:border-primary/20 transition-ui group relative">
      {/* Header row */}
      <div
        className="w-full flex items-center gap-6 p-6 text-left hover:bg-white/[0.02] transition-ui cursor-pointer relative z-10"
        onClick={() => setExpanded((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") setExpanded((v) => !v);
        }}
      >
        <div className="w-14 h-14 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center shrink-0 transition-ui group-hover:border-primary/30 relative">
          <Cpu className="w-6 h-6 text-primary relative z-10" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap mb-2">
            <h3 className="text-lg font-semibold text-white font-outfit leading-none">
              {mod.name}
            </h3>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-2xs font-semibold uppercase tracking-wider border shrink-0 transition-ui shadow-sm",
                langColor(lang),
              )}
            >
              {lang}
            </span>
            <CapabilityBadge
              world={mod.capabilityWorld ?? "unknown"}
              className="shrink-0"
            />
          </div>

          {mod.capabilityDescription && (
            <p className="text-xs text-muted-foreground/60 font-medium leading-relaxed line-clamp-1 mb-3">
              {mod.capabilityDescription}
            </p>
          )}

          <div className="flex items-center gap-5 text-xs font-medium text-muted-foreground/60 group-hover:text-muted-foreground/50 transition-ui">
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
                  {configFields.length} config field
                  {configFields.length === 1 ? "" : "s"}
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              onUseInEditor();
            }}
          >
            <ExternalLink className="w-4 h-4 transition-transform" />
            Open in editor
          </Button>
          <div className="p-3 rounded-xl bg-white/5 border border-white/5 text-muted-foreground group-hover:text-white group-hover:bg-white/10 transition-ui">
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
        <div className="border-t border-white/5 px-8 py-8 space-y-8 bg-surface-4/40 bg-surface-3 border border-white/10">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-3">
              <p className="text-xs font-semibold text-muted-foreground/60">
                Module Identifier
              </p>
              <div className="px-4 py-3 rounded-2xl bg-surface-4/60 border border-white/5 font-mono text-xs text-primary/60 break-all select-all font-bold">
                {mod.id}
              </div>
            </div>
            <div className="space-y-3">
              <p className="text-xs font-semibold text-muted-foreground/60">
                Integrity Hash
              </p>
              <div className="px-4 py-3 rounded-2xl bg-surface-4/60 border border-white/5 font-mono text-xs text-muted-foreground/70 break-all select-all font-bold">
                {mod.contentHash}
              </div>
            </div>
          </div>

          {mod.importedInterfaces && mod.importedInterfaces.length > 0 && (
            <div className="space-y-4">
              <p className="text-xs font-semibold text-muted-foreground/60 flex items-center gap-3">
                <Globe className="w-4 h-4 opacity-30" /> Interface Bindings
              </p>
              <div className="flex flex-wrap gap-2.5">
                {mod.importedInterfaces.map((iface: string) => (
                  <span
                    key={iface}
                    className="px-4 py-2 rounded-xl text-xs font-semibold font-mono text-muted-foreground/60 bg-surface-4/60 border border-white/5 hover:border-primary/40 hover:text-white transition-ui cursor-default shadow-sm"
                  >
                    {iface}
                  </span>
                ))}
              </div>
            </div>
          )}

          {configFields.length > 0 && (
            <div className="space-y-4">
              <p className="text-xs font-semibold text-muted-foreground/60 flex items-center gap-3">
                <Hash className="w-4 h-4 opacity-30" /> Configuration
              </p>
              <div className="flex flex-wrap gap-2.5">
                {configFields.map((f) => (
                  <span
                    key={f}
                    className="px-4 py-2 rounded-xl text-xs font-semibold font-mono text-primary/60 bg-primary/5 border border-primary/20 hover:border-primary/50 hover:text-primary transition-ui cursor-default shadow-sm"
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
    <div className="flex flex-col items-center justify-center py-16 text-center px-10 bg-surface-3/20 border border-white/5 rounded-2xl bg-surface-3 border border-white/10">
      <div className="w-14 h-14 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center mb-6 relative">
        <Box className="w-12 h-12 text-muted-foreground/50 relative z-10" />
      </div>
      <h2 className="text-3xl font-semibold text-white tracking-tight font-outfit mb-4">
        {hasSearch ? "No matching modules" : "No modules yet"}
      </h2>
      <p className="text-muted-foreground/70 text-sm max-w-sm leading-relaxed">
        {hasSearch
          ? "No modules match the current filter."
          : "Create a module from a Catalog template to get started."}
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
    <div className="pb-20">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <p className="text-sm text-muted-foreground">
          {isLoading
            ? "Loading…"
            : `${modules.length} module${modules.length !== 1 ? "s" : ""}`}
        </p>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="icon"
            onClick={() => refetch()}
            disabled={isFetching}
            aria-label="Refresh modules"
            title="Refresh modules"
          >
            <RefreshCw
              className={cn("w-4 h-4", isFetching && "animate-spin")}
            />
          </Button>

          {/* Search */}
          <div className="relative group/search flex-1 md:flex-none">
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60 pointer-events-none group-focus-within/search:text-primary transition-ui z-10" />
            <Input
              type="text"
              placeholder="Search modules…"
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
        <div className="flex items-center gap-3 flex-wrap mb-8">
          <button
            onClick={() => setWorldFilter(null)}
            className={cn(
              "px-6 py-3 text-2xs font-semibold rounded-xl border transition-ui",
              worldFilter === null
                ? "bg-white/10 text-white border-white/30"
                : "text-muted-foreground/70 border-white/5 hover:text-white hover:bg-white/5",
            )}
          >
            All ({modules.length})
          </button>
          {worlds.map((w) => {
            const count = modules.filter((m) => m.capabilityWorld === w).length;
            const isActive = worldFilter === w;
            return (
              <button
                key={w}
                onClick={() => setWorldFilter(isActive ? null : w)}
                className={cn(
                  "inline-flex items-center gap-3 px-6 py-3 text-2xs font-semibold rounded-xl border transition-ui",
                  isActive
                    ? worldColor(w)
                        .replace("border-", "border-")
                        .replace("bg-", "bg-") + " text-white"
                    : "text-muted-foreground/70 border-white/5 hover:text-white hover:bg-white/5",
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
              className="h-32 bg-surface-3/20 border border-white/5 rounded-2xl animate-pulse"
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
