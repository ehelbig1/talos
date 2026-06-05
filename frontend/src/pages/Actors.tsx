import React, { useState, useMemo, Suspense, lazy } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  listActors,
  createActor,
  updateActorStatus,
  terminateActor,
  writeActorMemory,
  cloneActor,
  type ActorSummary,
} from "@/lib/graphqlClient";
import { cn } from "@/lib/utils";
import { SkeletonCard } from "@/components/ui";
import { ActorCard, CapabilityBadge } from "./actors/ActorCard";
import { QuickRunModal } from "./actors/QuickRunModal";
import {
  CreateActorPanel,
  ACTOR_TEMPLATES,
  type ActorTemplate,
} from "./actors/CreateActorPanel";
import { Bot, Search, X, Plus, GitCompare, ChevronDown } from "lucide-react";

// ── helpers ───────────────────────────────────────────────────────────────────

type SortKey = "name" | "created" | "status" | "executions";

// ── Actors Page ───────────────────────────────────────────────────────────────

export default function Actors() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("created");
  const [compareMode, setCompareMode] = useState(false);
  const [compareSet, setCompareSet] = useState<Set<string>>(new Set());
  const [quickRunActor, setQuickRunActor] = useState<ActorSummary | null>(null);
  const [cloningId, setCloningId] = useState<string | null>(null);

  const {
    data: actors = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ["actors"],
    queryFn: listActors,
  });

  const pendingCreateInput = React.useRef<
    (Parameters<typeof createActor>[0] & { template?: ActorTemplate }) | null
  >(null);

  const createMut = useMutation({
    mutationFn: (
      input: Parameters<typeof createActor>[0] & { template?: ActorTemplate },
    ) => {
      pendingCreateInput.current = input;
      const { template: _, ...graphqlInput } = input;
      return createActor(graphqlInput);
    },
    onSuccess: async (actor) => {
      const tmpl = pendingCreateInput.current?.template;
      pendingCreateInput.current = null;
      if (tmpl && tmpl.id !== "custom" && tmpl.persona?.role) {
        try {
          await writeActorMemory({
            actorId: actor.id,
            key: "persona",
            value: JSON.stringify(tmpl.persona),
            memoryType: "semantic",
          });
          toast.success(
            `Actor "${actor.name}" created with ${tmpl.name} persona`,
          );
        } catch {
          toast.success(`Actor "${actor.name}" created`);
          toast.error("Persona template could not be saved to memory");
        }
      } else {
        toast.success(`Actor "${actor.name}" created`);
      }
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      setShowCreate(false);
    },
    onError: (e: Error) => {
      pendingCreateInput.current = null;
      toast.error(sanitizeErrorMessage(e.message));
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({
      id,
      status,
    }: {
      id: string;
      status: "active" | "suspended";
    }) => updateActorStatus(id, status),
    onSuccess: (actor) => {
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success(`Actor "${actor.name}" is now ${actor.status}`);
    },
    onError: (e: Error) => toast.error(sanitizeErrorMessage(e.message)),
  });

  const terminateMut = useMutation({
    mutationFn: (id: string) => terminateActor(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success("Actor terminated");
    },
    onError: (e: Error) => toast.error(sanitizeErrorMessage(e.message)),
  });

  const cloneMut = useMutation({
    mutationFn: (id: string) => {
      setCloningId(id);
      return cloneActor(id);
    },
    onSuccess: (cloned) => {
      setCloningId(null);
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success(`Cloned as "${cloned.name}"`);
    },
    onError: (e: Error) => {
      setCloningId(null);
      toast.error(sanitizeErrorMessage(e.message));
    },
  });

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    const result = q
      ? actors.filter(
          (a) =>
            a.name.toLowerCase().includes(q) ||
            (a.description ?? "").toLowerCase().includes(q),
        )
      : [...actors];

    result.sort((a, b) => {
      switch (sortKey) {
        case "name":
          return a.name.localeCompare(b.name);
        case "status":
          return a.status.localeCompare(b.status);
        case "executions":
          return b.executionCount - a.executionCount;
        case "created":
        default:
          return (
            new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
          );
      }
    });

    return result;
  }, [actors, search, sortKey]);

  const liveActors = filtered.filter((a) => a.status !== "terminated");
  const terminatedActors = filtered.filter((a) => a.status === "terminated");
  const totalExecutions = actors.reduce((sum, a) => sum + a.executionCount, 0);

  const SORT_OPTIONS: { key: SortKey; label: string }[] = [
    { key: "created", label: "Newest" },
    { key: "name", label: "Name" },
    { key: "status", label: "Status" },
    { key: "executions", label: "Load" },
  ];

  return (
    <div className="flex flex-col h-full bg-background overflow-hidden relative">
      {/* Dynamic background */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-primary/10 via-background to-background opacity-50" />
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_bottom_right,_var(--tw-gradient-stops))] from-surface-2/20 via-transparent to-transparent opacity-30" />

      {/* Header Area */}
      <header className="px-10 pt-16 pb-10 shrink-0 relative z-10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-10 mb-12">
          <div className="space-y-4">
            <div className="flex items-center gap-6">
              <div className="w-16 h-16 rounded-[2rem] bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_40px_hsla(var(--primary),0.1)] relative">
                <div className="absolute inset-0 bg-primary/5 rounded-full blur-2xl animate-pulse" />
                <Bot className="w-8 h-8 text-primary relative z-10" />
              </div>
              <div>
                <h1 className="text-5xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-2">
                  Identity Registry
                </h1>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-black text-primary/60 uppercase tracking-[0.3em]">
                    Governance Protocol Active
                  </span>
                  <div className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_hsla(var(--primary),0.5)] animate-pulse" />
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest max-w-xl leading-relaxed">
              Governing <span className="text-white/60">{actors.length}</span>{" "}
              autonomous execution identities. Manage capability ceilings and
              persistent operational memory.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {compareMode && (
              <button
                onClick={() => {
                  if (compareSet.size >= 2) {
                    navigate(
                      `/actors/compare?actors=${[...compareSet].join(",")}`,
                    );
                  }
                  setCompareMode(false);
                  setCompareSet(new Set());
                }}
                className={cn(
                  "flex items-center gap-4 px-8 py-4 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl transition-premium shadow-2xl active:scale-95 border glass",
                  compareSet.size >= 2
                    ? "bg-primary text-white border-white/20 shadow-primary/20"
                    : "bg-surface-3/40 text-muted-foreground/30 border-white/5 cursor-default",
                )}
              >
                <GitCompare className="w-5 h-5" />
                {compareSet.size >= 2
                  ? `Initialize Analytics (${compareSet.size})`
                  : "Select Identities"}
              </button>
            )}

            <button
              onClick={() => {
                setCompareMode((v) => !v);
                setCompareSet(new Set());
              }}
              className={cn(
                "flex items-center gap-4 px-8 py-4 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl border transition-premium glass shadow-xl active:scale-95",
                compareMode
                  ? "bg-primary/10 text-primary border-primary/30"
                  : "bg-surface-3/40 text-muted-foreground/40 border-white/5 hover:text-white hover:bg-white/5 hover:border-white/10",
              )}
            >
              <GitCompare className="w-5 h-5 transition-transform group-hover:rotate-12" />
              {compareMode ? "Abort Analytics" : "Analysis Mode"}
            </button>

            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-4 px-10 py-4 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-primary rounded-[1.5rem] transition-premium shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] hover:shadow-[0_20px_45px_-5px_hsla(var(--primary),0.5)] active:scale-95 border border-white/20"
            >
              <div className="p-1 rounded-lg bg-white/20">
                <Plus className="w-5 h-5" />
              </div>
              New Identity
            </button>
          </div>
        </div>

        {/* Operational Telemetry Header */}
        {actors.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-6 p-6 bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] shadow-2xl glass gpu mb-10">
            {[
              {
                label: "Total Population",
                value: actors.length,
                color: "text-white",
              },
              {
                label: "Active Nodes",
                value: actors.filter((a) => a.status === "active").length,
                color: "text-success",
                dot: true,
              },
              {
                label: "Suspended",
                value: actors.filter((a) => a.status === "suspended").length,
                color: "text-warning",
              },
              {
                label: "Terminated",
                value: actors.filter((a) => a.status === "terminated").length,
                color: "text-destructive",
              },
              {
                label: "Aggregate Throughput",
                value:
                  totalExecutions >= 1000
                    ? `${(totalExecutions / 1000).toFixed(1)}k`
                    : totalExecutions,
                color: "text-primary",
              },
            ].map((stat) => (
              <div
                key={stat.label}
                className="px-6 py-2 flex flex-col border-r border-white/5 last:border-0"
              >
                <span className="text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] mb-2">
                  {stat.label}
                </span>
                <div className="flex items-center gap-3">
                  {stat.dot && (
                    <div className="w-2 h-2 rounded-full bg-success animate-status-pulse shadow-[0_0_8px_hsla(var(--success),0.5)]" />
                  )}
                  <span
                    className={cn(
                      "text-3xl font-black tabular-nums leading-none font-outfit tracking-tighter",
                      stat.color,
                    )}
                  >
                    {stat.value}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Filter Toolbar */}
        {actors.length > 0 && (
          <div className="flex flex-col xl:flex-row items-center gap-8 p-3 bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2rem] shadow-2xl glass gpu">
            <div className="relative flex-1 w-full group/search">
              <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within/search:opacity-100 transition-premium pointer-events-none" />
              <Search className="absolute left-6 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground/30 group-focus-within/search:text-primary transition-premium z-10" />
              <input
                type="text"
                placeholder="SEARCH IDENTITY REGISTRY..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-surface-4/40 border border-white/5 text-white rounded-2xl pl-16 pr-6 py-4 text-[11px] font-black uppercase tracking-[0.2em] focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium placeholder:text-muted-foreground/20 relative z-0"
              />
            </div>

            <div className="flex flex-col md:flex-row items-center gap-6 w-full xl:w-auto">
              <div className="flex items-center gap-3 pr-2">
                <span className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] mr-4 whitespace-nowrap">
                  Sequence Registry
                </span>
                <div className="flex p-1.5 bg-surface-4/40 rounded-2xl border border-white/5 shrink-0 overflow-x-auto no-scrollbar glass-light">
                  {SORT_OPTIONS.map((opt) => (
                    <button
                      key={opt.key}
                      onClick={() => setSortKey(opt.key)}
                      className={cn(
                        "px-6 py-2.5 text-[9px] font-black uppercase tracking-[0.2em] rounded-xl transition-premium whitespace-nowrap active:scale-95",
                        sortKey === opt.key
                          ? "bg-primary text-white shadow-xl shadow-primary/20"
                          : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
                      )}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </header>

      {/* Content Area */}
      <div className="flex-1 overflow-auto custom-scrollbar px-10 pt-2 pb-32 relative z-0 gpu optimize-blur">
        <div className="max-w-[1600px] mx-auto">
          {isLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-10">
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <div
                  key={i}
                  className="h-[320px] rounded-[2.5rem] bg-surface-3/20 border border-white/5 animate-pulse"
                />
              ))}
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-40 bg-surface-3/20 border border-white/5 rounded-[4rem] backdrop-blur-3xl glass-dark animate-in fade-in zoom-in-95 duration-700 max-w-4xl mx-auto">
              <div className="w-24 h-24 rounded-[3rem] bg-destructive/10 border border-destructive/20 flex items-center justify-center mb-10 shadow-2xl relative">
                <X className="w-12 h-12 text-destructive relative z-10" />
              </div>
              <h2 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-4">
                Protocol Interrupted
              </h2>
              <p className="text-muted-foreground/40 text-sm max-w-sm font-bold uppercase tracking-widest leading-relaxed text-center px-10">
                {sanitizeErrorMessage(
                  error instanceof Error
                    ? error.message
                    : "The identity synchronization service is currently unavailable.",
                )}
              </p>
            </div>
          ) : actors.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-40 bg-surface-3/20 border border-white/5 border-dashed border-2 rounded-[4rem] backdrop-blur-3xl glass-dark animate-in fade-in zoom-in-95 duration-700 max-w-4xl mx-auto">
              <div className="w-24 h-24 rounded-[3rem] bg-primary/10 border border-primary/20 flex items-center justify-center mb-10 shadow-[0_0_40px_hsla(var(--primary),0.1)] relative group">
                <div className="absolute inset-0 bg-primary/5 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-premium" />
                <Bot className="w-12 h-12 text-primary relative z-10 group-hover:scale-110 transition-premium" />
              </div>
              <h2 className="text-4xl font-black text-white tracking-tighter font-outfit uppercase mb-6">
                Registry Empty
              </h2>
              <p className="text-muted-foreground/40 text-sm max-w-xl font-bold uppercase tracking-widest leading-relaxed text-center px-12 mb-12">
                Actors are bounded execution identities that govern automation
                logic, enforce capability ceilings, and persist operational
                memory across the platform.
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="flex items-center gap-4 px-10 py-5 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-primary rounded-[1.5rem] transition-premium shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] hover:shadow-[0_20px_45px_-5px_hsla(var(--primary),0.5)] active:scale-95 border border-white/20"
              >
                <Plus className="w-5 h-5" /> Provision First Identity
              </button>
            </div>
          ) : (
            <div className="space-y-20">
              {liveActors.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-10">
                  {liveActors.map((actor) => (
                    <ActorCard
                      key={actor.id}
                      actor={actor}
                      onView={() => navigate(`/actors/${actor.id}`)}
                      onQuickRun={() => setQuickRunActor(actor)}
                      onClone={() => cloneMut.mutate(actor.id)}
                      onToggle={() =>
                        toggleMut.mutate({
                          id: actor.id,
                          status:
                            actor.status === "active" ? "suspended" : "active",
                        })
                      }
                      onTerminate={() => terminateMut.mutate(actor.id)}
                      isToggling={
                        toggleMut.isPending &&
                        toggleMut.variables?.id === actor.id
                      }
                      isTerminating={
                        terminateMut.isPending &&
                        terminateMut.variables === actor.id
                      }
                      isCloningId={cloningId}
                      compareMode={compareMode}
                      selectedForCompare={compareSet.has(actor.id)}
                      onToggleCompare={() =>
                        setCompareSet((prev) => {
                          const next = new Set(prev);
                          if (next.has(actor.id)) next.delete(actor.id);
                          else next.add(actor.id);
                          return next;
                        })
                      }
                    />
                  ))}
                </div>
              )}

              {terminatedActors.length > 0 && (
                <details className="group border-t border-white/5 pt-20 animate-in fade-in slide-in-from-bottom-8 duration-1000">
                  <summary className="flex items-center gap-6 text-muted-foreground/30 hover:text-white transition-premium cursor-pointer list-none group/summary">
                    <div className="w-12 h-12 rounded-2xl bg-surface-3/40 border border-white/5 flex items-center justify-center group-open:rotate-90 group-hover/summary:border-white/20 transition-premium shadow-2xl glass">
                      <ChevronDown className="w-5 h-5" />
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[11px] font-black uppercase tracking-[0.4em] leading-none mb-1">
                        Archived Vault
                      </span>
                      <span className="text-[10px] font-bold uppercase tracking-widest opacity-40">
                        {terminatedActors.length} Decommissioned Identit
                        {terminatedActors.length !== 1 ? "ies" : "y"} Registered
                      </span>
                    </div>
                  </summary>
                  <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-10 opacity-40 hover:opacity-100 transition-premium grayscale group-hover:grayscale-0">
                    {terminatedActors.map((actor) => (
                      <ActorCard
                        key={actor.id}
                        actor={actor}
                        onView={() => navigate(`/actors/${actor.id}`)}
                        onQuickRun={() => {}}
                        onClone={() => cloneMut.mutate(actor.id)}
                        onToggle={() => {}}
                        onTerminate={() => {}}
                        isToggling={false}
                        isTerminating={false}
                        isCloningId={cloningId}
                        compareMode={false}
                        selectedForCompare={false}
                        onToggleCompare={() => {}}
                      />
                    ))}
                  </div>
                </details>
              )}
            </div>
          )}
        </div>
      </div>

      <CreateActorPanel
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreate={(input) => createMut.mutate(input)}
        isPending={createMut.isPending}
      />

      <Suspense fallback={null}>
        {quickRunActor && (
          <QuickRunModal
            actor={quickRunActor}
            onClose={() => setQuickRunActor(null)}
          />
        )}
      </Suspense>
    </div>
  );
}
