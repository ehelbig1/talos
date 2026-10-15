import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import React, { useState, useMemo, memo } from "react";
import { type NodeTemplate, useTemplates } from "@/lib/useTemplates";
import { useCreateModuleFromTemplateMutation } from "@/generated/graphql";
import { ConfigForm, type JSONSchema } from "@/components/builder/ConfigForm";
import {
  Search,
  Globe,
  Database,
  Bot,
  ArrowLeft,
  Package,
  Sparkles,
  Filter,
  Check,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";

import {
  Dialog,
  Button,
  Badge,
  Label,
  DarkInput,
  DarkSelect,
  ErrorBanner,
} from "@/components/ui";

interface CreateModuleDialogProps {
  onModuleCreated: (
    moduleId: string,
    moduleName: string,
    config: Record<string, unknown>,
    category?: string,
  ) => void;
  onClose: () => void;
}

export const CreateModuleDialog = memo(function CreateModuleDialog({
  onModuleCreated,
  onClose,
}: CreateModuleDialogProps) {
  const { templates: allTemplates, loading: templatesLoading } = useTemplates();

  // Show all templates including webhooks
  const templates = allTemplates;

  // State
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("");
  const [moduleName, setModuleName] = useState("");
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [parsedSchema, setParsedSchema] = useState<JSONSchema | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  const createModuleMutation = useCreateModuleFromTemplateMutation();

  const selectedTemplate = templates.find((t) => t.id === selectedTemplateId);

  // Auto-suggest module name when template is selected
  React.useEffect(() => {
    if (selectedTemplate && !moduleName) {
      // Generate a friendly default name
      const baseName = selectedTemplate.name.replace(/\s+/g, " ");
      setModuleName(baseName);
    }
  }, [selectedTemplate, moduleName]);

  // Initialize config with defaults when template is selected
  React.useEffect(() => {
    if (selectedTemplate) {
      try {
        const schema = JSON.parse(selectedTemplate.configSchema) as JSONSchema;
        const defaultConfig: Record<string, unknown> = {};

        // Extract default values from schema
        const properties = schema.properties;
        if (properties) {
          Object.entries(properties).forEach(([key, prop]) => {
            if (prop.default !== undefined) {
              defaultConfig[key] = prop.default;
            }
          });
        }

        setConfig(defaultConfig);
        setParsedSchema(schema);
      } catch {
        toast.error("Failed to parse module template configuration schema.");
        setConfig({});
        setParsedSchema(null);
      }
    }
  }, [selectedTemplate]);

  // Get unique categories
  const categories = useMemo(() => {
    const cats = new Set(templates.map((t: NodeTemplate) => t.category));
    return ["all", ...Array.from(cats).sort()];
  }, [templates]);

  // Filter templates by search and category
  const filteredTemplates = useMemo(() => {
    return templates.filter((t) => {
      const matchesSearch =
        !searchQuery ||
        t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.category.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesCategory =
        selectedCategory === "all" || t.category === selectedCategory;

      return matchesSearch && matchesCategory;
    });
  }, [templates, searchQuery, selectedCategory]);

  const handleCreate = async () => {
    if (!selectedTemplateId || !moduleName) {
      setError("Please select a template and enter a name");
      return;
    }

    setCreating(true);
    setError(null);

    try {
      const data = await createModuleMutation.mutateAsync({
        input: {
          templateId: selectedTemplateId,
          name: moduleName,
          config: JSON.stringify(config),
        },
      });

      onModuleCreated(
        data.createModuleFromTemplate.id,
        data.createModuleFromTemplate.name,
        config,
        selectedTemplate?.category,
      );
      onClose();
    } catch (e) {
      setError(
        sanitizeErrorMessage(
          e instanceof Error ? e.message : "Failed to create module",
        ),
      );
    } finally {
      setCreating(false);
    }
  };

  // Step 1: Template selection view
  if (!selectedTemplateId) {
    return (
      <Dialog open={true} onClose={onClose} title="Create module from template">
        <div className="space-y-8">
          <div className="relative overflow-hidden p-6 bg-primary/5 border border-white/5 rounded-2xl bg-white/[0.03] border border-white/5">
            <div className="absolute top-0 right-0 p-4 opacity-10">
              <Sparkles className="w-12 h-12 text-primary" />
            </div>
            <div className="flex items-start gap-4 relative z-10">
              <div className="shrink-0 w-10 h-10 rounded-xl bg-primary/20 border border-primary/30 flex items-center justify-center">
                <Package className="w-5 h-5 text-primary" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-semibold text-white tracking-tight font-outfit">
                  Pick a template
                </p>
                <p className="text-xs text-muted-foreground/60 leading-relaxed">
                  Choose a template to create a reusable module. It will be
                  added to your module library.
                </p>
              </div>
            </div>
          </div>

          {/* Search and Filter Bar */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1 group">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/70 group-focus-within:text-primary transition-ui" />
              <DarkInput
                type="text"
                placeholder="Search templates…"
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSearchQuery(e.target.value)
                }
                className="pl-11 h-12 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10"
              />
            </div>
            <div className="relative group">
              <Filter className="absolute left-4 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/70 group-hover:text-white transition-ui z-10" />
              <DarkSelect
                value={selectedCategory}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                  setSelectedCategory(e.target.value)
                }
                className="pl-10 pr-10 h-12 w-48 bg-surface-2/40 border-white/5 text-sm font-semibold rounded-2xl appearance-none relative z-10"
              >
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat === "all" ? "All categories" : cat}
                  </option>
                ))}
              </DarkSelect>
            </div>
          </div>

          {/* Template Grid */}
          <div className="max-h-[480px] overflow-y-auto pr-2 custom-scrollbar">
            {templatesLoading ? (
              <div className="flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/50">
                <Loader2 className="w-10 h-10 animate-spin text-primary" />
                <p className="text-xs font-semibold">Loading…</p>
              </div>
            ) : filteredTemplates.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 px-8 text-center border-2 border-dashed border-white/5 rounded-2xl bg-surface-1/20 grayscale opacity-20">
                <Search className="w-12 h-12 text-muted-foreground/70 mb-4" />
                <p className="text-xs font-semibold text-muted-foreground">
                  No templates match your search
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                {filteredTemplates.map((template) => (
                  <button
                    key={template.id}
                    onClick={() => setSelectedTemplateId(template.id)}
                    className="group relative bg-surface-2/40 border border-white/5 hover:border-primary/40 hover:bg-surface-2/60 rounded-2xl p-6 text-left transition-ui overflow-hidden"
                  >
                    <div className="absolute top-6 right-6 p-2 rounded-xl bg-surface-4/60 border border-white/5 opacity-0 group-hover:opacity-100 transition-ui">
                      <Sparkles className="w-4 h-4 text-primary" />
                    </div>
                    <div className="flex items-start gap-4 mb-5">
                      <div className="flex items-center justify-center w-14 h-14 bg-surface-3 border border-white/10 rounded-2xl group-hover:border-primary/20 transition-ui">
                        {template.icon ? (
                          <span className="text-3xl">{template.icon}</span>
                        ) : (
                          <Package className="w-6 h-6 text-primary" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold text-white group-hover:text-primary transition-ui font-outfit leading-none mb-1.5">
                          {template.name}
                        </h3>
                        <span className="text-2xs font-semibold uppercase tracking-wider text-primary/60">
                          {template.category}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-muted-foreground/60 line-clamp-2 mb-6 leading-relaxed h-[34px]">
                      {template.description || "No description yet."}
                    </p>

                    <div className="flex flex-wrap gap-2 mt-auto">
                      {template.allowedHosts.length > 0 && (
                        <Badge
                          variant="outline"
                          className="bg-primary/5 text-primary border-primary/20 text-2xs font-semibold px-2 py-0.5 uppercase tracking-wider"
                        >
                          <Globe className="h-2.5 w-2.5 mr-1.5" />
                          {template.allowedHosts.length} host
                          {template.allowedHosts.length !== 1 ? "s" : ""}
                        </Badge>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-between items-center pt-6 border-t border-white/5">
            <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
              {filteredTemplates.length} template
              {filteredTemplates.length !== 1 ? "s" : ""}
            </span>
            <Button
              onClick={onClose}
              variant="ghost"
              className="h-11 px-6 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2 hover:bg-surface-3 rounded-xl border border-white/5"
            >
              Cancel
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  // Step 2: Configuration view
  return (
    <Dialog open={true} onClose={onClose} title="Create module">
      <div className="space-y-8">
        {/* Header with back button */}
        <div className="flex items-center gap-6 pb-6 border-b border-white/5 relative">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSelectedTemplateId("")}
            className="shrink-0 h-10 w-10 rounded-2xl bg-surface-2/60 border border-white/5 hover:bg-surface-3 transition-ui relative z-10"
            aria-label="Back to Templates"
          >
            <ArrowLeft className="w-4 h-4 text-muted-foreground/70" />
          </Button>
          <div className="flex-1 min-w-0 relative z-10">
            <div className="flex items-center gap-4">
              <div className="flex items-center justify-center w-14 h-14 bg-surface-3/60 border border-white/10 rounded-2xl relative">
                {selectedTemplate?.icon ? (
                  <span className="text-4xl relative z-10">
                    {selectedTemplate.icon}
                  </span>
                ) : (
                  <Package className="w-8 h-8 text-primary relative z-10" />
                )}
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-white text-xl font-outfit leading-none mb-1">
                  {selectedTemplate?.name}
                </span>
                <span className="text-xs font-semibold text-primary/60">
                  {selectedTemplate?.category}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="max-h-[520px] overflow-y-auto pr-2 custom-scrollbar space-y-10">
          {/* Module Name */}
          <div className="space-y-4">
            <div className="flex items-center gap-3 px-1">
              <Bot className="w-4 h-4 text-primary" />
              <Label
                htmlFor="module-name"
                className="text-xs font-semibold text-white"
              >
                Module name
              </Label>
            </div>
            <div className="relative group">
              <DarkInput
                id="module-name"
                value={moduleName}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setModuleName(e.target.value)
                }
                placeholder="e.g. notify-dispatcher"
                className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10"
              />
            </div>
            <p className="px-2 text-2xs text-muted-foreground/70 leading-relaxed">
              A unique name for this module in your library and on the workflow
              canvas.
            </p>
          </div>

          {/* Configuration Form */}
          {selectedTemplate && (
            <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-8 space-y-6 relative overflow-hidden bg-surface-3 border border-white/10">
              <div className="flex items-center justify-between relative z-10">
                <div className="flex items-center gap-3">
                  <Database className="w-4 h-4 text-primary" />
                  <h3 className="text-xs font-semibold text-white">
                    Configuration
                  </h3>
                </div>
                <Badge
                  variant="outline"
                  className="bg-primary/5 border-primary/20 text-2xs font-semibold uppercase tracking-wider text-primary px-2"
                >
                  <Check className="w-2.5 h-2.5 mr-1.5" /> JSON SCHEMA VALIDATED
                </Badge>
              </div>

              <div className="pt-6 border-t border-white/5 relative z-10">
                <ConfigForm
                  schema={parsedSchema || { type: "object" }}
                  value={config}
                  onChange={setConfig}
                  category={selectedTemplate.category}
                  templateName={selectedTemplate.name}
                />
              </div>
            </div>
          )}

          {/* Error Display */}
          {error && (
            <div>
              <ErrorBanner message={error} />
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex justify-end items-center gap-4 pt-6 border-t border-white/5">
          <Button
            variant="ghost"
            onClick={onClose}
            className="h-12 px-8 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5"
          >
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={creating || !moduleName}
            className={cn(
              "h-12 px-10 text-sm font-semibold transition-ui rounded-2xl",
              "bg-primary hover:bg-primary/90 text-white border-none",
              (creating || !moduleName) &&
                "opacity-50 grayscale cursor-not-allowed",
            )}
          >
            {creating ? (
              <div className="flex items-center gap-3">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Creating…</span>
              </div>
            ) : (
              "Create module"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
});

export default CreateModuleDialog;
