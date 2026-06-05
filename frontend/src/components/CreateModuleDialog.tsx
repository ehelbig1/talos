import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import React, { useState, useMemo, memo } from "react";
import { type NodeTemplate, useTemplates } from "@/lib/useTemplates";
import { graphqlRequest } from "@/lib/graphqlClient";
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
import { getCapabilityVisuals } from "@/lib/capabilityBadge";

import {
  Dialog,
  Section,
  Button,
  Badge,
  Input,
  Label,
  DarkInput,
  DarkSelect,
  InfoTip,
  InfoBanner,
  ErrorBanner,
} from "@/components/ui";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { FlexContainer } from "@/components/ui/FlexContainer";
import { FormField } from "@/components/ui/FormField";

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
      } catch (e) {
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
      const data = await graphqlRequest<{
        createModuleFromTemplate: { id: string; name: string };
      }>(
        `mutation CreateModule($input: CreateModuleInput!) {
          createModuleFromTemplate(input: $input) {
            id
            name
          }
        }`,
        {
          input: {
            templateId: selectedTemplateId,
            name: moduleName,
            config: JSON.stringify(config),
          },
        },
      );

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
      <Dialog
        open={true}
        onClose={onClose}
        title="Initialize Protocol Blueprint"
      >
        <div className="space-y-8">
          <div className="relative overflow-hidden p-6 bg-primary/5 border border-white/5 rounded-[2.5rem] shadow-inner glass-light">
            <div className="absolute top-0 right-0 p-4 opacity-10">
              <Sparkles className="w-12 h-12 text-primary" />
            </div>
            <div className="flex items-start gap-4 relative z-10">
              <div className="shrink-0 w-10 h-10 rounded-xl bg-primary/20 border border-primary/30 flex items-center justify-center shadow-lg">
                <Package className="w-5 h-5 text-primary" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-black text-white tracking-tight font-outfit uppercase">
                  Protocol Synthesis Engine
                </p>
                <p className="text-[10px] text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed">
                  Select a validated blueprint to initialize a new reusable
                  module. Once synthesized, it will be added to your operational
                  library.
                </p>
              </div>
            </div>
          </div>

          {/* Search and Filter Bar */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1 group">
              <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/40 group-focus-within:text-primary transition-premium" />
              <DarkInput
                type="text"
                placeholder="SEARCH BLUEPRINTS..."
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSearchQuery(e.target.value)
                }
                className="pl-11 h-12 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-[11px] font-black uppercase tracking-widest rounded-2xl relative z-10 shadow-inner"
              />
            </div>
            <div className="relative group">
              <Filter className="absolute left-4 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-white transition-premium z-10" />
              <DarkSelect
                value={selectedCategory}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                  setSelectedCategory(e.target.value)
                }
                className="pl-10 pr-10 h-12 w-48 bg-surface-2/40 border-white/5 text-[10px] font-black uppercase tracking-widest rounded-2xl appearance-none relative z-10 shadow-inner"
              >
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat === "all" ? "ALL DOMAINS" : cat.toUpperCase()}
                  </option>
                ))}
              </DarkSelect>
            </div>
          </div>

          {/* Template Grid */}
          <div className="max-h-[480px] overflow-y-auto pr-2 custom-scrollbar">
            {templatesLoading ? (
              <div className="flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/20">
                <Loader2 className="w-10 h-10 animate-spin text-primary" />
                <p className="text-[10px] font-black uppercase tracking-[0.3em]">
                  Syncing Library...
                </p>
              </div>
            ) : filteredTemplates.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 px-8 text-center border-2 border-dashed border-white/5 rounded-[2.5rem] bg-surface-1/20 grayscale opacity-20">
                <Search className="w-12 h-12 text-muted-foreground/40 mb-4" />
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.3em]">
                  No Blueprints Matched Deployment Query
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                {filteredTemplates.map((template) => (
                  <button
                    key={template.id}
                    onClick={() => setSelectedTemplateId(template.id)}
                    className="group relative bg-surface-2/40 border border-white/5 hover:border-primary/40 hover:bg-surface-2/60 rounded-[2rem] p-6 text-left transition-premium hover:scale-[1.02] shadow-lg active:scale-95 overflow-hidden"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
                    <div className="absolute top-6 right-6 p-2 rounded-xl bg-surface-4/60 border border-white/5 opacity-0 group-hover:opacity-100 transition-premium shadow-xl">
                      <Sparkles className="w-4 h-4 text-primary" />
                    </div>
                    <div className="flex items-start gap-4 mb-5">
                      <div className="flex items-center justify-center w-14 h-14 bg-surface-3 border border-white/10 rounded-2xl group-hover:scale-110 group-hover:border-primary/20 transition-premium shadow-2xl">
                        {template.icon ? (
                          <span className="text-3xl filter drop-shadow-[0_0_8px_rgba(0,0,0,0.5)]">
                            {template.icon}
                          </span>
                        ) : (
                          <Package className="w-6 h-6 text-primary" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-black text-white tracking-tight group-hover:text-primary transition-premium font-outfit uppercase leading-none mb-1.5">
                          {template.name}
                        </h3>
                        <span className="text-[9px] font-black uppercase tracking-[0.2em] text-primary/60">
                          {template.category} ARCHITECTURE
                        </span>
                      </div>
                    </div>

                    <p className="text-[11px] text-muted-foreground/60 line-clamp-2 mb-6 font-bold leading-relaxed h-[34px]">
                      {template.description ||
                        "Experimental protocol awaiting documentation."}
                    </p>

                    <div className="flex flex-wrap gap-2 mt-auto">
                      {template.allowedHosts.length > 0 && (
                        <Badge
                          variant="outline"
                          className="bg-primary/5 text-primary border-primary/20 text-[8px] font-black px-2 py-0.5 uppercase tracking-widest shadow-[0_0_10px_hsla(var(--primary),0.1)]"
                        >
                          <Globe className="h-2.5 w-2.5 mr-1.5" />
                          {template.allowedHosts.length} Network Bound
                        </Badge>
                      )}

                      {(() => {
                        const vis = getCapabilityVisuals(template.category);
                        return (
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[8px] font-black px-2 py-0.5 border uppercase tracking-widest transition-premium",
                              vis.bgColor,
                              vis.color,
                              vis.borderColor,
                            )}
                          >
                            {vis.tierLabel} {vis.label}
                          </Badge>
                        );
                      })()}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-between items-center pt-6 border-t border-white/5">
            <span className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-[0.3em]">
              {filteredTemplates.length} BLUEPRINT
              {filteredTemplates.length !== 1 ? "S" : ""} SYNCHRONIZED
            </span>
            <Button
              onClick={onClose}
              variant="ghost"
              className="h-11 px-6 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-xl border border-white/5 active:scale-95"
            >
              Abort Protocol
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  // Step 2: Configuration view
  return (
    <Dialog open={true} onClose={onClose} title="Configure Module Synthesis">
      <div className="space-y-8">
        {/* Header with back button */}
        <div className="flex items-center gap-6 pb-6 border-b border-white/5 relative">
          <div className="absolute -inset-x-8 -top-8 h-32 bg-gradient-to-b from-primary/5 to-transparent pointer-events-none" />
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSelectedTemplateId("")}
            className="shrink-0 h-10 w-10 rounded-2xl bg-surface-2/60 border border-white/5 hover:bg-surface-3 transition-premium active:scale-90 relative z-10"
            aria-label="Back to Templates"
          >
            <ArrowLeft className="w-4 h-4 text-muted-foreground/40" />
          </Button>
          <div className="flex-1 min-w-0 relative z-10">
            <div className="flex items-center gap-4">
              <div className="flex items-center justify-center w-14 h-14 bg-surface-3/60 border border-white/10 rounded-[1.25rem] shadow-2xl relative">
                <div className="absolute -inset-2 bg-primary/10 rounded-full blur-xl opacity-50" />
                {selectedTemplate?.icon ? (
                  <span className="text-4xl relative z-10 filter drop-shadow-[0_0_8px_rgba(0,0,0,0.5)]">
                    {selectedTemplate.icon}
                  </span>
                ) : (
                  <Package className="w-8 h-8 text-primary relative z-10" />
                )}
              </div>
              <div className="flex flex-col">
                <span className="font-black text-white text-xl tracking-tight font-outfit uppercase leading-none mb-1">
                  {selectedTemplate?.name}
                </span>
                <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary/60">
                  {selectedTemplate?.category} DOMAIN
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
                className="text-[10px] font-black text-white uppercase tracking-[0.2em]"
              >
                Operational Identifier
              </Label>
            </div>
            <div className="relative group">
              <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
              <DarkInput
                id="module-name"
                value={moduleName}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setModuleName(e.target.value)
                }
                placeholder="E.G. NOTIFY_DISPATCHER_X"
                className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-xs font-black uppercase tracking-widest rounded-2xl relative z-10 shadow-inner"
              />
            </div>
            <p className="px-2 text-[9px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest">
              Assign a unique tactical designation to identify this module in
              the operational library and across the workflow canvas.
            </p>
          </div>

          {/* Configuration Form */}
          {selectedTemplate && (
            <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-8 space-y-6 shadow-2xl relative overflow-hidden glass-dark">
              <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />
              <div className="flex items-center justify-between relative z-10">
                <div className="flex items-center gap-3">
                  <Database className="w-4 h-4 text-primary" />
                  <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
                    Synthesis Parameters
                  </h3>
                </div>
                <Badge
                  variant="outline"
                  className="bg-primary/5 border-primary/20 text-[8px] font-black uppercase tracking-widest text-primary px-2"
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
            <div className="animate-in fade-in slide-in-from-top-2 duration-300">
              <ErrorBanner message={error} />
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex justify-end items-center gap-4 pt-6 border-t border-white/5">
          <Button
            variant="ghost"
            onClick={onClose}
            className="h-12 px-8 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95"
          >
            Abort Synthesis
          </Button>
          <Button
            onClick={handleCreate}
            disabled={creating || !moduleName}
            className={cn(
              "h-12 px-10 text-[10px] font-black uppercase tracking-widest transition-premium active:scale-[0.98] rounded-2xl",
              "bg-primary hover:bg-primary/90 text-white border-none",
              "shadow-2xl shadow-primary/20 hover:shadow-primary/40",
              (creating || !moduleName) &&
                "opacity-50 grayscale cursor-not-allowed",
            )}
          >
            {creating ? (
              <div className="flex items-center gap-3">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Synthesizing...</span>
              </div>
            ) : (
              "Finalize Synthesis"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
});

export default CreateModuleDialog;
