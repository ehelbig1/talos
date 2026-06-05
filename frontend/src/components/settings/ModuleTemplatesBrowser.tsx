import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Package,
  Search,
  Plus,
  Globe,
  Server,
  Cpu,
  X,
  CheckCircle2,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  useNodeTemplatesQuery,
  useCreateModuleFromTemplateMutation,
  NodeTemplatesQuery,
} from "@/generated/graphql";

type NodeTemplate = NodeTemplatesQuery["nodeTemplates"][0];

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  http: <Globe className="w-4 h-4" />,
  data: <Server className="w-4 h-4" />,
  compute: <Cpu className="w-4 h-4" />,
};

const CATEGORY_COLORS: Record<string, string> = {
  http: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  data: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  compute: "text-violet-400 bg-violet-500/10 border-violet-500/20",
};

interface InstallDialogProps {
  template: NodeTemplate;
  onClose: () => void;
}

function InstallDialog({ template, onClose }: InstallDialogProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(template.name);
  const [config, setConfig] = useState("{}");
  const [installed, setInstalled] = useState(false);

  const createMutation = useCreateModuleFromTemplateMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["NodeTemplates"] });
      setInstalled(true);
      toast.success(`Module "${name}" installed`);
    },
    onError: () => toast.error("Failed to install module"),
  });

  if (installed) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
        <div className="bg-card border border-border/80 rounded-2xl p-8 w-full max-w-sm shadow-2xl text-center">
          <div className="w-14 h-14 bg-success/10 border border-success/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle2 className="w-7 h-7 text-success" />
          </div>
          <h3 className="text-sm font-bold text-foreground uppercase tracking-widest mb-1">
            Module Installed
          </h3>
          <p className="text-xs text-muted-foreground mb-6">
            "{name}" is now available in your workflow editor.
          </p>
          <Button
            className="w-full rounded-xl font-bold text-xs uppercase tracking-widest"
            onClick={onClose}
          >
            Done
          </Button>
        </div>
      </div>
    );
  }

  let configError: string | null = null;
  try {
    JSON.parse(config);
  } catch {
    configError = "Invalid JSON";
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-card border border-border/80 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-sm font-bold text-foreground uppercase tracking-widest">
              Install Module
            </h3>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              {template.name}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 hover:bg-muted rounded-lg transition-premium"
          >
            <X className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground block mb-1.5">
              Module Name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-background border border-border/60 rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-premium"
            />
          </div>

          <div>
            <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground block mb-1.5">
              Config (JSON)
            </label>
            <textarea
              value={config}
              onChange={(e) => setConfig(e.target.value)}
              rows={5}
              className={cn(
                "w-full bg-background border rounded-xl px-4 py-2.5 text-sm font-mono text-foreground focus:outline-none focus:ring-1 transition-premium resize-none",
                configError
                  ? "border-destructive/50 focus:border-destructive focus:ring-destructive/20"
                  : "border-border/60 focus:border-primary/50 focus:ring-primary/30",
              )}
            />
            {configError && (
              <p className="text-[10px] text-destructive mt-1">{configError}</p>
            )}
          </div>

          {template.allowedHosts.length > 0 && (
            <div className="bg-warning/5 border border-warning/15 rounded-xl p-3">
              <p className="text-[10px] font-black uppercase tracking-widest text-warning mb-1.5">
                Required Host Access
              </p>
              <div className="flex flex-wrap gap-1.5">
                {template.allowedHosts.map((host) => (
                  <span
                    key={host}
                    className="text-[10px] font-mono bg-background border border-border/60 px-2 py-0.5 rounded text-foreground/80"
                  >
                    {host}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <Button
              className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-xl h-10 text-xs uppercase tracking-widest"
              disabled={
                !name.trim() || !!configError || createMutation.isPending
              }
              onClick={() =>
                createMutation.mutate({
                  input: { templateId: template.id, name, config },
                })
              }
            >
              {createMutation.isPending ? "Installing..." : "Install"}
            </Button>
            <Button
              variant="outline"
              className="flex-1 rounded-xl h-10 text-xs"
              onClick={onClose}
            >
              Cancel
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ModuleTemplatesBrowser() {
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [installing, setInstalling] = useState<NodeTemplate | null>(null);

  const { data, isLoading } = useNodeTemplatesQuery(
    selectedCategory ? { category: selectedCategory } : {},
    { staleTime: 60_000 },
  );
  const templates = data?.nodeTemplates ?? [];

  const filtered = search
    ? templates.filter(
        (t) =>
          t.name.toLowerCase().includes(search.toLowerCase()) ||
          t.description?.toLowerCase().includes(search.toLowerCase()),
      )
    : templates;

  const categories = Array.from(
    new Set(templates.map((t) => t.category)),
  ).sort();

  if (isLoading) {
    return (
      <div className="bg-card/40 border border-border/80 rounded-2xl p-6 shadow-xl animate-pulse">
        <div className="h-4 w-48 bg-muted/50 rounded mb-6" />
        <div className="grid grid-cols-2 gap-3">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-28 bg-background/40 border border-border/40 rounded-xl"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <>
      {installing && (
        <InstallDialog
          template={installing}
          onClose={() => setInstalling(null)}
        />
      )}

      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-br from-violet-500/10 via-transparent to-transparent opacity-30 pointer-events-none transition-premium group-hover:opacity-100" />

        {/* Header */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-8 mb-10 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-violet-500/10 border border-violet-500/20 rounded-[1.5rem] flex items-center justify-center text-violet-400 shadow-[0_0_30px_hsla(var(--violet-500),0.1)] group-hover:scale-110 transition-premium">
              <Package className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-2xl md:text-3xl font-black text-white tracking-tighter uppercase font-outfit leading-tight">
                Blueprint Registry
              </h3>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-[10px] font-black text-violet-400 uppercase tracking-widest bg-violet-500/5 px-3 py-1 rounded-full border border-violet-500/20">
                  {templates.length}_TEMPLATES_LOADED
                </span>
                <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest">
                  Validated_Compute_Units
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Search + category filter */}
        <div className="flex flex-col md:flex-row gap-4 mb-10 relative z-10">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/40" />
            <input
              aria-label="Search blueprints"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="SEARCH_BLUEPRINTS..."
              className="w-full bg-black/40 border border-white/5 rounded-2xl pl-12 pr-6 py-4 text-sm font-black text-white focus:outline-none focus:border-violet-500/40 focus:ring-4 focus:ring-violet-500/10 transition-premium placeholder:text-white/5 shadow-inner"
            />
          </div>
          <div className="flex gap-2 p-2 bg-black/20 border border-white/5 rounded-2xl backdrop-blur-xl">
            <button
              type="button"
              onClick={() => setSelectedCategory(null)}
              className={cn(
                "px-6 py-2 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium",
                !selectedCategory
                  ? "bg-white text-black shadow-xl"
                  : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
              )}
            >
              All_UNITS
            </button>
            {categories.map((cat) => (
              <button
                type="button"
                key={cat}
                onClick={() =>
                  setSelectedCategory(cat === selectedCategory ? null : cat)
                }
                className={cn(
                  "px-6 py-2 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium",
                  selectedCategory === cat
                    ? "bg-violet-500 text-white shadow-xl"
                    : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
                )}
              >
                {cat.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-24 bg-black/20 border border-dashed border-white/5 rounded-[2.5rem] relative z-10">
            <Package className="w-16 h-16 text-muted-foreground/10 mb-6 mx-auto" />
            <p className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.4em]">
              {search
                ? `NO_MATCHES_FOR_${search.toUpperCase()}`
                : "NO_BLUEPRINTS_DETECTED"}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
            {filtered.map((template) => {
              const colorClass =
                CATEGORY_COLORS[template.category] ??
                "text-muted-foreground bg-muted border-border";
              return (
                <div
                  key={template.id}
                  className="bg-black/40 border border-white/5 rounded-[2rem] p-8 hover:border-white/10 hover:bg-black/60 transition-premium group/item flex flex-col gap-6 shadow-inner relative overflow-hidden"
                >
                  <div className="absolute inset-0 bg-gradient-to-br from-violet-500/5 via-transparent to-transparent opacity-0 group-hover/item:opacity-100 transition-premium pointer-events-none" />

                  <div className="flex items-start justify-between gap-4 relative z-10">
                    <div className="flex items-center gap-4 min-w-0">
                      <div
                        className={cn(
                          "p-3 rounded-xl border shrink-0 group-hover/item:scale-110 transition-premium",
                          colorClass,
                        )}
                      >
                        {CATEGORY_ICONS[template.category] ?? (
                          <Package className="w-5 h-5" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <p className="text-lg font-black text-white tracking-tight font-outfit truncate">
                          {template.name}
                        </p>
                        <span
                          className={cn(
                            "text-[9px] font-black uppercase tracking-widest mt-1 block",
                            colorClass.split(" ")[0],
                          )}
                        >
                          {template.category}_PROTOCOL
                        </span>
                      </div>
                    </div>
                  </div>

                  {template.description && (
                    <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed line-clamp-3 relative z-10">
                      {template.description}
                    </p>
                  )}

                  <div className="mt-auto pt-6 border-t border-white/5 flex items-center justify-between relative z-10">
                    <div className="flex items-center gap-2">
                      {template.allowedHosts.slice(0, 2).map((h) => (
                        <span
                          key={h}
                          className="text-[8px] font-black uppercase tracking-widest bg-black/40 border border-white/5 px-2 py-1 rounded-lg text-white/40"
                        >
                          {h.split(".")[0]}
                        </span>
                      ))}
                      {template.allowedHosts.length > 2 && (
                        <span className="text-[8px] font-black text-muted-foreground/20">
                          +{template.allowedHosts.length - 2}
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => setInstalling(template)}
                      className="h-10 px-6 bg-violet-500 text-white rounded-xl text-[10px] font-black uppercase tracking-widest transition-premium hover:shadow-[0_0_20px_hsla(var(--violet-500),0.3)] active:scale-95 flex items-center gap-2 group/btn"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      INSTANTIATE
                      <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover/btn:translate-x-1 group-hover/btn:opacity-100 transition-premium" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
