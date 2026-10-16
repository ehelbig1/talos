import React, { useState, useMemo, Suspense } from "react";
import { useNavigate } from "react-router";
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
} from "@/lib/graphqlApi";
import { cn } from "@/lib/utils";
import { ActorCard } from "./actors/ActorCard";
import { QuickRunModal } from "./actors/QuickRunModal";
import {
  CreateActorPanel,
  type ActorTemplate,
} from "./actors/CreateActorPanel";
import { Bot, Search, X, Plus, GitCompare, ChevronDown } from "lucide-react";
import { Button, PageContainer, PageHeader } from "@/components/ui";

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
      toast.success("Actor deleted");
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
    <div className="h-full overflow-auto bg-background custom-scrollbar">
      <PageContainer>
        <header>
          <PageHeader
            title="Actors"
            description={`${actors.length} actor${actors.length !== 1 ? "s" : ""}. Each actor runs workflows under its own capability ceiling and keeps its own memory.`}
            actions={
              <>
                {compareMode && (
                  <Button
                    variant={compareSet.size >= 2 ? "premium" : "outline"}
                    disabled={compareSet.size < 2}
                    onClick={() => {
                      navigate(
                        `/actors/compare?actors=${[...compareSet].join(",")}`,
                      );
                      setCompareMode(false);
                      setCompareSet(new Set());
                    }}
                  >
                    <GitCompare className="w-4 h-4" />
                    {compareSet.size >= 2
                      ? `Compare (${compareSet.size})`
                      : "Select two or more"}
                  </Button>
                )}
                <Button
                  variant="outline"
                  aria-pressed={compareMode}
                  onClick={() => {
                    setCompareMode((v) => !v);
                    setCompareSet(new Set());
                  }}
                >
                  <GitCompare className="w-4 h-4" />
                  {compareMode ? "Cancel" : "Compare actors"}
                </Button>
                <Button onClick={() => setShowCreate(true)}>
                  <Plus className="w-4 h-4" />
                  New actor
                </Button>
              </>
            }
          />
          {/* Operational Telemetry Header */}
          {actors.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-6 p-6 bg-surface-3/40 border border-white/5 rounded-2xl mb-10">
              {[
                {
                  label: "Actors",
                  value: actors.length,
                  color: "text-white",
                },
                {
                  label: "Active",
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
                  label: "Deleted",
                  value: actors.filter((a) => a.status === "terminated").length,
                  color: "text-destructive",
                },
                {
                  label: "Runs",
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
                  <span className="text-2xs font-semibold text-muted-foreground/60 uppercase tracking-wider mb-2">
                    {stat.label}
                  </span>
                  <div className="flex items-center gap-3">
                    {stat.dot && (
                      <div className="w-2 h-2 rounded-full bg-success" />
                    )}
                    <span
                      className={cn(
                        "text-3xl font-semibold tabular-nums leading-none font-outfit tracking-tight",
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
            <div className="flex flex-col xl:flex-row items-center gap-8 p-3 bg-surface-3/40 border border-white/5 rounded-2xl">
              <div className="relative flex-1 w-full group/search">
                <Search className="absolute left-6 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground/60 group-focus-within/search:text-primary transition-ui z-10" />
                <input
                  type="text"
                  placeholder="Search actors…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-surface-4/40 border border-white/5 text-white rounded-2xl pl-16 pr-6 py-4 text-sm font-semibold focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-ui placeholder:text-muted-foreground/50 relative z-0"
                />
              </div>

              <div className="flex items-center gap-3 w-full xl:w-auto px-2 xl:px-0">
                <span className="text-xs font-semibold text-muted-foreground/60 whitespace-nowrap">
                  Sort by
                </span>
                <div className="flex flex-wrap p-1 bg-surface-4/40 rounded-xl border border-white/5">
                  {SORT_OPTIONS.map((opt) => (
                    <button
                      key={opt.key}
                      onClick={() => setSortKey(opt.key)}
                      className={cn(
                        "px-3 h-8 text-xs font-medium rounded-lg transition-ui whitespace-nowrap",
                        sortKey === opt.key
                          ? "bg-primary text-white"
                          : "text-muted-foreground/70 hover:text-white hover:bg-white/5",
                      )}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}
        </header>

        <div className="pt-8">
          {isLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-10">
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <div
                  key={i}
                  className="h-[320px] rounded-2xl bg-surface-3/20 border border-white/5 animate-pulse"
                />
              ))}
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-40 bg-surface-3/20 border border-white/5 rounded-2xl bg-surface-3 border border-white/10 max-w-4xl mx-auto">
              <div className="w-24 h-24 rounded-2xl bg-destructive/10 border border-destructive/20 flex items-center justify-center mb-10 relative">
                <X className="w-12 h-12 text-destructive relative z-10" />
              </div>
              <h2 className="text-3xl font-semibold text-white tracking-tight font-outfit mb-4">
                Could not load actors
              </h2>
              <p className="text-muted-foreground/70 text-sm max-w-sm font-bold leading-relaxed text-center px-10">
                {sanitizeErrorMessage(
                  error instanceof Error
                    ? error.message
                    : "The actor service is currently unavailable.",
                )}
              </p>
            </div>
          ) : actors.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 px-6 bg-surface-3/40 border border-white/10 border-dashed rounded-2xl max-w-3xl mx-auto">
              <div className="w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-5">
                <Bot className="w-6 h-6 text-primary" />
              </div>
              <h2 className="text-xl font-semibold text-white font-outfit mb-2">
                No actors yet
              </h2>
              <p className="text-muted-foreground text-sm max-w-md leading-relaxed text-center mb-7">
                An actor is an identity a workflow runs as. It has a capability
                ceiling, a budget and its own memory.
              </p>
              <Button onClick={() => setShowCreate(true)}>
                <Plus className="w-4 h-4" /> Create an actor
              </Button>
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
                <details className="group border-t border-white/5 pt-20">
                  <summary className="flex items-center gap-6 text-muted-foreground/60 hover:text-white transition-ui cursor-pointer list-none group/summary">
                    <div className="w-12 h-12 rounded-2xl bg-surface-3/40 border border-white/5 flex items-center justify-center group-open:rotate-90 group-hover/summary:border-white/20 transition-ui">
                      <ChevronDown className="w-5 h-5" />
                    </div>
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold leading-none mb-1">
                        Deleted actors
                      </span>
                      <span className="text-xs font-bold opacity-40">
                        {terminatedActors.length} deleted actor
                        {terminatedActors.length !== 1 ? "s" : ""}
                      </span>
                    </div>
                  </summary>
                  <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-10 opacity-40 hover:opacity-100 transition-ui grayscale group-hover:grayscale-0">
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
      </PageContainer>
    </div>
  );
}
