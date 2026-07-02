import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getNodeTemplates, type NodeTemplate } from "@/lib/graphqlApi";
import { useCreateModuleFromTemplateMutation } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  BookOpen,
  Box,
  CheckCircle2,
  Code2,
  Database,
  Globe,
  Key,
  Layers,
  Loader2,
  Search,
  Shield,
  Webhook,
  X,
  Zap,
} from "lucide-react";
import { Button, Input } from "@/components/ui";
import { DarkInput } from "@/components/ui/DarkInput";

// ---------------------------------------------------------------------------
// Category config — icon + color for each template category
// ---------------------------------------------------------------------------

interface CategoryMeta {
  icon: React.ReactNode;
  textColor: string;
  bgColor: string;
  borderColor: string;
}

const CATEGORY_META: Record<string, CategoryMeta> = {
  http: {
    icon: <Globe size={14} />,
    textColor: "text-blue-400",
    bgColor: "bg-blue-400/10",
    borderColor: "border-blue-400/20",
  },
  webhook: {
    icon: <Webhook size={14} />,
    textColor: "text-indigo-400",
    bgColor: "bg-indigo-400/10",
    borderColor: "border-indigo-400/20",
  },
  compute: {
    icon: <Code2 size={14} />,
    textColor: "text-violet-400",
    bgColor: "bg-violet-400/10",
    borderColor: "border-violet-400/20",
  },
  data: {
    icon: <Database size={14} />,
    textColor: "text-orange-400",
    bgColor: "bg-orange-400/10",
    borderColor: "border-orange-400/20",
  },
  auth: {
    icon: <Key size={14} />,
    textColor: "text-amber-400",
    bgColor: "bg-amber-400/10",
    borderColor: "border-amber-400/20",
  },
  security: {
    icon: <Shield size={14} />,
    textColor: "text-amber-400",
    bgColor: "bg-amber-400/10",
    borderColor: "border-amber-400/20",
  },
  utility: {
    icon: <Zap size={14} />,
    textColor: "text-muted-foreground",
    bgColor: "bg-white/5",
    borderColor: "border-white/10",
  },
  integration: {
    icon: <Layers size={14} />,
    textColor: "text-teal-400",
    bgColor: "bg-teal-400/10",
    borderColor: "border-teal-400/20",
  },
};

function getCategoryMeta(category: string): CategoryMeta {
  const key = category.toLowerCase();
  return (
    CATEGORY_META[key] ?? {
      icon: <Box size={14} />,
      textColor: "text-muted-foreground",
      bgColor: "bg-white/5",
      borderColor: "border-white/10",
    }
  );
}

// ---------------------------------------------------------------------------
// Parse configSchema to extract field count
// ---------------------------------------------------------------------------

function parseFieldCount(configSchema: string): number {
  try {
    const schema = JSON.parse(configSchema) as Record<string, unknown>;
    const props = schema.properties as Record<string, unknown> | undefined;
    return props ? Object.keys(props).length : 0;
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------------------
// Category badge
// ---------------------------------------------------------------------------

function CategoryBadge({ category }: { category: string }) {
  const meta = getCategoryMeta(category);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border",
        meta.textColor,
        meta.bgColor,
        meta.borderColor,
      )}
    >
      {meta.icon}
      {category.charAt(0).toUpperCase() + category.slice(1)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Template card
// ---------------------------------------------------------------------------

function TemplateCard({
  template,
  onUse,
}: {
  template: NodeTemplate;
  onUse: () => void;
}) {
  const fieldCount = parseFieldCount(template.configSchema);
  const hasNetworkAccess = template.allowedHosts.length > 0;
  const meta = getCategoryMeta(template.category);

  return (
    <div className="group flex flex-col bg-surface-3/40 backdrop-blur-md border border-white/5 rounded-[2rem] p-8 hover:border-primary/30 transition-premium shadow-2xl glass relative overflow-hidden h-full">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-6 relative z-10">
        <div className="w-14 h-14 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center shrink-0 shadow-2xl transition-premium group-hover:scale-110 group-hover:border-primary/30 relative">
          <div className="absolute -inset-2 bg-primary/10 rounded-full blur-xl opacity-0 group-hover:opacity-50 transition-premium" />
          <div
            className={cn("relative z-10 transition-colors", meta.textColor)}
          >
            {meta.icon}
          </div>
        </div>
        <CategoryBadge category={template.category} />
      </div>

      <div className="mb-6 relative z-10">
        <h3 className="text-xl font-black text-white tracking-tighter font-outfit uppercase group-hover:text-primary transition-premium leading-tight">
          {template.name}
        </h3>
        <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] mt-1.5">
          {template.id.split(":").pop()} Protocol
        </p>
      </div>

      {/* Description */}
      <p className="text-xs text-muted-foreground/50 font-bold leading-relaxed line-clamp-2 flex-1 mb-8 relative z-10">
        {template.description ??
          "Standard execution protocol for distributed operations."}
      </p>

      {/* Meta chips */}
      <div className="flex flex-wrap gap-3 mb-8 relative z-10">
        {fieldCount > 0 && (
          <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 bg-surface-4/60 border border-white/5 shadow-sm">
            {fieldCount} Schema Field{fieldCount === 1 ? "" : "s"}
          </span>
        )}
        {hasNetworkAccess && (
          <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] text-primary/60 bg-primary/5 border border-primary/20 shadow-sm">
            <Globe className="w-3 h-3 opacity-60" />
            Egress Authorized
          </span>
        )}
      </div>

      {/* Action */}
      <Button
        onClick={onUse}
        variant="outline"
        className="w-full bg-surface-4/40 border-white/10 hover:border-primary/40 hover:bg-primary hover:text-white group-hover:shadow-2xl transition-premium relative z-10 rounded-2xl py-6 text-[10px] font-black uppercase tracking-[0.3em]"
      >
        Synthesize Module
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Install dialog
// ---------------------------------------------------------------------------

import { Dialog } from "@/components/ui/dialog";

interface InstallDialogProps {
  template: NodeTemplate;
  onClose: () => void;
}

function InstallDialog({ template, onClose }: InstallDialogProps) {
  const navigate = useNavigate();
  const [name, setName] = useState(template.name);
  const [config, setConfig] = useState(() => {
    try {
      const schema = JSON.parse(template.configSchema) as {
        properties?: Record<string, unknown>;
      };
      if (schema.properties && Object.keys(schema.properties).length > 0) {
        const defaults: Record<string, string> = {};
        for (const key of Object.keys(schema.properties)) defaults[key] = "";
        return JSON.stringify(defaults, null, 2);
      }
    } catch {
      /* ignore */
    }
    return "{}";
  });
  const [configError, setConfigError] = useState<string | null>(null);
  const [installed, setInstalled] = useState(false);

  const mutation = useCreateModuleFromTemplateMutation({
    onSuccess: () => setInstalled(true),
    onError: () => toast.error("Failed to install module"),
  });

  const handleConfigChange = (v: string) => {
    setConfig(v);
    try {
      JSON.parse(v);
      setConfigError(null);
    } catch {
      setConfigError("INVALID JSON STRUCTURE");
    }
  };

  if (installed) {
    return (
      <Dialog open={true} onClose={onClose} title="Module Initialized">
        <div className="text-center p-6">
          <div className="w-20 h-20 rounded-[2rem] bg-success/10 border border-success/20 flex items-center justify-center mx-auto mb-8 relative z-10 shadow-2xl">
            <CheckCircle2 className="w-10 h-10 text-success drop-shadow-[0_0_15px_hsla(var(--success),0.5)]" />
          </div>

          <div className="relative z-10 mb-10">
            <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed">
              <span className="text-white">{name}</span> HAS BEEN SYNTHESIZED
              AND ADDED TO YOUR ACTIVE LIBRARY.
            </p>
          </div>

          <div className="flex flex-col gap-4 w-full relative z-10">
            <Button
              onClick={() => {
                onClose();
                navigate("/modules");
              }}
              variant="premium"
              className="w-full py-7"
            >
              ACCESS LIBRARY
            </Button>
            <Button onClick={onClose} variant="ghost" className="w-full">
              DISMISS
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open={true} onClose={onClose} title="Initialize Protocol">
      <div className="space-y-10 relative z-10 p-2">
        <div className="relative z-10 -mt-6 mb-4">
          <p className="text-[10px] font-black text-primary/60 uppercase tracking-[0.4em] leading-none">
            {template.name}
          </p>
        </div>

        {/* Name */}
        <div className="space-y-4">
          <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/30 block">
            Deployment Identifier
          </label>
          <Input
            type="text"
            value={name}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setName(e.target.value)
            }
            placeholder="ENTER UNIQUE IDENTIFIER..."
            className="bg-surface-4/40 backdrop-blur-xl border-white/5 focus:border-primary/40 focus:ring-primary/20 h-14 px-6 text-[11px] font-black tracking-widest uppercase"
          />
        </div>

        {/* Config */}
        <div className="space-y-4">
          <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/30 block">
            Operational Configuration (JSON)
          </label>
          <textarea
            value={config}
            onChange={(e) => handleConfigChange(e.target.value)}
            rows={6}
            spellCheck={false}
            className={cn(
              "w-full bg-surface-4/40 backdrop-blur-xl border focus:outline-none rounded-2xl px-6 py-5 text-[11px] font-black font-mono text-white resize-none transition-premium shadow-inner uppercase tracking-widest",
              configError
                ? "border-destructive/40 focus:border-destructive/60 focus:ring-4 focus:ring-destructive/10 text-destructive"
                : "border-white/5 focus:border-primary/40 focus:ring-4 focus:ring-primary/10",
            )}
          />
          {configError && (
            <p className="text-[9px] font-black text-destructive mt-3 uppercase tracking-[0.2em]">
              {configError}
            </p>
          )}
        </div>

        {/* Network access warning */}
        {template.allowedHosts.length > 0 && (
          <div className="bg-warning/5 border border-warning/20 rounded-[1.5rem] px-6 py-5 shadow-2xl relative overflow-hidden group">
            <div className="absolute inset-0 bg-warning/5 opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
            <p className="text-[10px] font-black text-warning uppercase tracking-[0.3em] mb-2 flex items-center gap-3">
              <Globe className="w-4 h-4 opacity-60" /> Security Policy: Network
              Egress Authorized
            </p>
            <p className="text-[11px] text-warning/60 font-bold leading-relaxed uppercase tracking-widest">
              THIS PROTOCOL IS AUTHORIZED TO INITIATE OUTBOUND CONNECTIONS TO:{" "}
              <span className="font-mono text-white/80 underline decoration-warning/30 underline-offset-4">
                {template.allowedHosts.join(", ")}
              </span>
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center justify-end gap-6 pt-6 border-t border-white/5">
          <Button
            variant="ghost"
            onClick={onClose}
            className="text-[10px] font-black tracking-[0.3em]"
          >
            ABORT SYNTHESIS
          </Button>
          <Button
            variant="premium"
            onClick={() =>
              mutation.mutate({
                input: { templateId: template.id, name: name.trim(), config },
              })
            }
            disabled={!!configError || !name.trim() || mutation.isPending}
            className="px-10 py-7"
          >
            {mutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin mr-3" />
                ORCHESTRATING...
              </>
            ) : (
              "INITIALIZE MODULE"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyState({ query }: { query: string }) {
  return (
    <div className="col-span-full flex flex-col items-center justify-center py-40 text-center px-10 bg-surface-3/20 border border-white/5 rounded-[4rem] backdrop-blur-3xl glass-dark animate-in fade-in zoom-in-95 duration-700">
      <div className="w-24 h-24 rounded-[3rem] bg-surface-4/60 border border-white/10 flex items-center justify-center mb-10 shadow-2xl relative">
        <div className="absolute -inset-4 bg-primary/5 rounded-full blur-3xl opacity-50" />
        <BookOpen className="w-12 h-12 text-muted-foreground/20 relative z-10" />
      </div>
      <h2 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-4">
        {query ? "No results found" : "Registry offline"}
      </h2>
      <p className="text-muted-foreground/40 text-sm max-w-sm font-bold uppercase tracking-widest leading-relaxed">
        {query
          ? `The protocol identifier "${query.toUpperCase()}" did not return any matches from the synchronized registry.`
          : "Protocol templates are registered at controller initialization. Contact system administrator if registry is unavailable."}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Catalog() {
  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [installTemplate, setInstallTemplate] = useState<NodeTemplate | null>(
    null,
  );

  const { data: templates = [], isLoading } = useQuery({
    queryKey: ["node-templates"],
    queryFn: () => getNodeTemplates(),
    staleTime: 5 * 60_000,
  });

  const categories = useMemo(() => {
    const seen = new Set<string>();
    const cats: string[] = [];
    for (const t of templates) {
      if (!seen.has(t.category)) {
        seen.add(t.category);
        cats.push(t.category);
      }
    }
    return cats.sort();
  }, [templates]);

  const filtered = useMemo(() => {
    let result = templates;
    if (activeCategory) {
      result = result.filter((t) => t.category === activeCategory);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          (t.description ?? "").toLowerCase().includes(q) ||
          t.category.toLowerCase().includes(q),
      );
    }
    return result;
  }, [templates, activeCategory, search]);

  const grouped = useMemo(() => {
    if (search.trim()) return null;
    const map = new Map<string, NodeTemplate[]>();
    for (const t of filtered) {
      const group = map.get(t.category) ?? [];
      group.push(t);
      map.set(t.category, group);
    }
    return map;
  }, [filtered, search]);

  const handleUse = (template: NodeTemplate) => {
    setInstallTemplate(template);
  };

  return (
    <>
      {installTemplate && (
        <InstallDialog
          template={installTemplate}
          onClose={() => setInstallTemplate(null)}
        />
      )}
      <div className="px-10 pb-20 animate-in fade-in slide-in-from-bottom-4 duration-700">
        {/* Header / Toolbar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 mb-12">
          <div className="flex items-center gap-6">
            <div className="w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] relative">
              <div className="absolute inset-0 bg-primary/5 rounded-full blur-xl animate-pulse" />
              <Layers className="w-6 h-6 text-primary relative z-10" />
            </div>
            <div>
              <h1 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-1.5">
                Registry Catalog
              </h1>
              <div className="flex items-center gap-3">
                <span className="text-[10px] font-black text-primary/60 uppercase tracking-[0.3em]">
                  {isLoading
                    ? "Synchronizing Registry..."
                    : `${templates.length} Protocol Template${templates.length !== 1 ? "s" : ""} Available`}
                </span>
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
              </div>
            </div>
          </div>

          {/* Search */}
          <div className="relative group/search flex-1 md:flex-none">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-[1.5rem] blur opacity-0 group-focus-within/search:opacity-100 transition-premium pointer-events-none" />
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/30 pointer-events-none group-focus-within/search:text-primary transition-premium z-10" />
            <DarkInput
              type="text"
              placeholder="SEARCH PROTOCOL REGISTRY..."
              value={search}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSearch(e.target.value)
              }
              className="w-full md:w-96 h-14 pl-14"
            />
          </div>
        </div>

        {/* Category filter pills */}
        {categories.length > 1 && (
          <div className="flex items-center gap-3 flex-wrap mb-12">
            <button
              onClick={() => setActiveCategory(null)}
              className={cn(
                "px-6 py-3 text-[9px] font-black uppercase tracking-[0.3em] rounded-xl border transition-premium active:scale-95 shadow-xl glass",
                activeCategory === null
                  ? "bg-white/10 text-white border-white/30"
                  : "text-muted-foreground/40 border-white/5 hover:text-white hover:bg-white/5",
              )}
            >
              All Categories ({templates.length})
            </button>
            {categories.map((cat) => {
              const count = templates.filter((t) => t.category === cat).length;
              const meta = getCategoryMeta(cat);
              const isActive = activeCategory === cat;
              return (
                <button
                  key={cat}
                  onClick={() => setActiveCategory(isActive ? null : cat)}
                  className={cn(
                    "inline-flex items-center gap-3 px-6 py-3 text-[9px] font-black uppercase tracking-[0.3em] rounded-xl border transition-premium active:scale-95 shadow-xl glass",
                    isActive
                      ? cn(meta.textColor, meta.bgColor, meta.borderColor) +
                          " text-white"
                      : "text-muted-foreground/40 border-white/5 hover:text-white hover:bg-white/5",
                  )}
                >
                  <span className={isActive ? "text-white" : meta.textColor}>
                    {meta.icon}
                  </span>
                  {cat}
                  <span
                    className={cn(
                      "ml-1 tabular-nums",
                      isActive ? "opacity-30" : "opacity-20",
                    )}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {/* Content */}
        {isLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {Array.from({ length: 8 }).map((_, i) => (
              <div
                key={i}
                className="h-64 bg-surface-3/20 border border-white/5 rounded-[2rem] animate-pulse"
              />
            ))}
          </div>
        ) : search.trim() ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {filtered.length === 0 ? (
              <EmptyState query={search} />
            ) : (
              filtered.map((t) => (
                <TemplateCard
                  key={t.id}
                  template={t}
                  onUse={() => handleUse(t)}
                />
              ))
            )}
          </div>
        ) : (
          grouped && (
            <div className="space-y-24">
              {grouped.size === 0 ? (
                <EmptyState query="" />
              ) : (
                Array.from(grouped.entries()).map(([cat, items]) => {
                  const meta = getCategoryMeta(cat);
                  return (
                    <section
                      key={cat}
                      className="animate-in fade-in slide-in-from-bottom-4 duration-700"
                    >
                      <div className="flex items-center gap-6 mb-10 relative group">
                        <div
                          className={cn(
                            "w-12 h-12 rounded-2xl flex items-center justify-center shadow-2xl transition-premium group-hover:scale-110",
                            meta.bgColor,
                            meta.textColor,
                          )}
                        >
                          {meta.icon}
                        </div>
                        <div>
                          <h2 className="text-2xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-1.5">
                            {cat}
                          </h2>
                          <p className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] leading-none">
                            {items.length} Sequence Protocol
                            {items.length !== 1 ? "s" : ""} Synchronized
                          </p>
                        </div>
                        <div className="flex-1 h-px bg-white/5 ml-8" />
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
                        {items.map((t) => (
                          <TemplateCard
                            key={t.id}
                            template={t}
                            onUse={() => handleUse(t)}
                          />
                        ))}
                      </div>
                    </section>
                  );
                })
              )}
            </div>
          )
        )}
      </div>
    </>
  );
}
