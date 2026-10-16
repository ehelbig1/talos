import React, { useState, useMemo } from "react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import { Star } from "lucide-react";
import { useNodeTemplatesQuery } from "@/generated/graphql";
import { useUIStore } from "@/store/uiStore";
import { Input } from "@/components/ui/input";

interface NodeTemplate {
  id: string;
  name: string;
  category: string;
  description?: string;
  icon?: string;
}

export function TemplateLibrary({
  onSelect,
}: {
  onSelect: (template: NodeTemplate) => void;
}) {
  const [category, setCategory] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const {
    favoriteTemplates,
    recentTemplates,
    toggleFavorite,
    addRecentTemplate,
  } = useUIStore();

  const { data, isLoading, error } = useNodeTemplatesQuery();
  const templates = data?.nodeTemplates as NodeTemplate[] | undefined;

  // Derive unique categories from the full templates list
  const categories = useMemo(
    () => [...new Set((templates ?? []).map((t) => t.category))].sort(),
    [templates],
  );

  // Filter by category and search query (client-side)
  const filteredTemplates = useMemo(() => {
    let result = templates ?? [];
    if (category) {
      result = result.filter((t) => t.category === category);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.description?.toLowerCase().includes(q) ||
          t.category.toLowerCase().includes(q),
      );
    }
    return result;
  }, [templates, category, searchQuery]);

  // Separate favorites and recent
  const favoriteTemplatesList = useMemo(
    () => filteredTemplates.filter((t) => favoriteTemplates.includes(t.id)),
    [filteredTemplates, favoriteTemplates],
  );

  const recentTemplatesList = useMemo(
    () =>
      recentTemplates
        .map((id) => filteredTemplates.find((t) => t.id === id))
        .filter((t): t is NodeTemplate => t !== undefined),
    [filteredTemplates, recentTemplates],
  );

  const handleSelectTemplate = (template: NodeTemplate) => {
    addRecentTemplate(template.id);
    onSelect(template);
  };

  return (
    <div className="flex flex-col gap-8">
      {/* Search Bar */}
      <div className="relative group">
        <Input
          type="search"
          placeholder="Search templates…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10 px-6"
        />
      </div>

      {/* Category Filters */}
      <div className="flex gap-2 flex-wrap bg-surface-2/40 p-1.5 rounded-2xl border border-white/5">
        <button
          onClick={() => setCategory(null)}
          className={cn(
            "px-5 py-2.5 text-2xs font-semibold rounded-xl transition-ui",
            category === null
              ? "bg-primary text-white"
              : "text-muted-foreground/70 hover:text-white hover:bg-white/5",
          )}
        >
          All Domains
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategory(cat)}
            className={cn(
              "px-5 py-2.5 text-2xs font-semibold rounded-xl transition-ui",
              category === cat
                ? "bg-primary text-white"
                : "text-muted-foreground/70 hover:text-white hover:bg-white/5",
            )}
          >
            {cat}
          </button>
        ))}
      </div>

      <div className="space-y-12 max-h-[500px] overflow-y-auto pr-4 custom-scrollbar">
        {/* Favorites Section */}
        {favoriteTemplatesList.length > 0 && (
          <div>
            <div className="flex items-center gap-3 mb-6 px-1">
              <Star size={16} className="text-amber-400 fill-amber-400" />
              <h3 className="text-xs font-semibold text-white">Favorites</h3>
            </div>
            <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-6">
              {favoriteTemplatesList.map((template) => (
                <TemplateCard
                  key={template.id}
                  template={template}
                  onSelect={() => handleSelectTemplate(template)}
                  onToggleFavorite={() => toggleFavorite(template.id)}
                  isFavorite={true}
                />
              ))}
            </div>
          </div>
        )}

        {/* Recent Templates Section */}
        {recentTemplatesList.length > 0 && (
          <div>
            <div className="flex items-center gap-3 mb-6 px-1">
              <h3 className="text-xs font-semibold text-white/70">
                Recently used
              </h3>
            </div>
            <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-6">
              {recentTemplatesList.map((template) => (
                <TemplateCard
                  key={template.id}
                  template={template}
                  onSelect={() => handleSelectTemplate(template)}
                  onToggleFavorite={() => toggleFavorite(template.id)}
                  isFavorite={favoriteTemplates.includes(template.id)}
                />
              ))}
            </div>
          </div>
        )}

        {/* All Templates */}
        <div>
          <div className="flex items-center gap-3 mb-6 px-1">
            <h3 className="text-xs font-semibold text-white">
              {searchQuery ? "Search results" : "All templates"}
            </h3>
          </div>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(240px,1fr))] gap-6">
            {isLoading && (
              <div className="col-span-full py-20 flex flex-col items-center gap-4 opacity-20">
                <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <p className="text-xs font-semibold">Accessing Registry...</p>
              </div>
            )}
            {!!error && (
              <div className="p-8 bg-destructive/10 border border-destructive/20 rounded-2xl text-destructive text-xs font-semibold col-span-full text-center">
                Registry Sync Failure:{" "}
                {sanitizeErrorMessage((error as Error).message)}
              </div>
            )}
            {!isLoading && filteredTemplates.length === 0 && (
              <div className="col-span-full py-32 flex flex-col items-center gap-6 opacity-10 grayscale">
                <div className="p-8 rounded-2xl bg-surface-3/40 border border-white/5">
                  <Star size={48} className="stroke-[1px]" />
                </div>
                <p className="text-xs font-semibold">No templates found</p>
              </div>
            )}
            {filteredTemplates.map((template) => (
              <TemplateCard
                key={template.id}
                template={template}
                onSelect={() => handleSelectTemplate(template)}
                onToggleFavorite={() => toggleFavorite(template.id)}
                isFavorite={favoriteTemplates.includes(template.id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function TemplateCard({
  template,
  onSelect,
  onToggleFavorite,
  isFavorite,
}: {
  template: NodeTemplate;
  onSelect: () => void;
  onToggleFavorite: () => void;
  isFavorite: boolean;
}) {
  return (
    <div
      className="group relative flex flex-col p-6 rounded-2xl bg-surface-3/40 border border-white/5 transition-ui hover-elevation hover:bg-surface-3/60 focus-within:ring-2 focus-within:ring-primary/20 overflow-hidden cursor-pointer"
      onClick={onSelect}
    >
      {/* Favorite button */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onToggleFavorite();
        }}
        className="absolute top-5 right-5 p-2 rounded-xl bg-surface-4/40 border border-white/5 text-muted-foreground/70 hover:text-amber-400 transition-ui z-20"
        title={isFavorite ? "Remove from favorites" : "Add to favorites"}
        aria-label={isFavorite ? "Remove from favorites" : "Add to favorites"}
        aria-pressed={isFavorite}
      >
        <Star
          size={16}
          className={cn(
            "transition-ui",
            isFavorite
              ? "text-amber-400 fill-amber-400"
              : "group-hover:text-amber-400",
          )}
        />
      </button>

      <div className="relative z-10 flex flex-col h-full">
        <div className="flex items-center justify-center w-14 h-14 bg-surface-4 border border-white/5 rounded-2xl group-hover:border-primary/20 transition-ui mb-6">
          <span className="text-3xl">{template.icon || "📦"}</span>
        </div>

        <h3 className="text-sm font-semibold text-white tracking-tight group-hover:text-primary transition-ui font-outfit mb-1">
          {template.name}
        </h3>

        <span className="text-2xs font-semibold uppercase tracking-wider text-primary/60 mb-4">
          {template.category}
        </span>

        {template.description && (
          <p className="text-xs text-muted-foreground/60 leading-relaxed line-clamp-2 font-bold h-[34px]">
            {template.description}
          </p>
        )}

        <div className="mt-6 flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground/50 group-hover:text-primary/70 transition-ui">
            Use template
          </span>
          <div className="w-6 h-6 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-ui -translate-x-4">
            <Star size={10} className="text-primary" />
          </div>
        </div>
      </div>
    </div>
  );
}
