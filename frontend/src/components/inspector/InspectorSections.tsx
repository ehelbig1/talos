import React from "react";
import { Button } from "@/components/ui/button";
import { Brain, ShieldCheck, ChevronDown, Activity } from "lucide-react";
import { CopyField } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { WorkflowNodeData } from "@/store/workflowStore";

export function CapabilityBadge({
  capability,
  importedInterfaces,
}: {
  capability: string;
  importedInterfaces?: string[];
}) {
  const visuals = {
    bgColor: "bg-primary/10",
    borderColor: "border-primary/20",
    color: "text-primary",
    icon: ShieldCheck,
    label: capability,
  };

  return (
    <div
      className={cn(
        "inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full border text-2xs font-semibold tracking-wider uppercase transition-ui group overflow-hidden relative",
        visuals.bgColor,
        visuals.borderColor,
        visuals.color,
      )}
    >
      <visuals.icon className="w-3.5 h-3.5 relative z-10" />
      <span className="relative z-10">{visuals.label}</span>
      {importedInterfaces && importedInterfaces.length > 0 && (
        <span className="opacity-40 ml-1 font-bold relative z-10">
          [{importedInterfaces.length}]
        </span>
      )}
    </div>
  );
}

export function LlmConfigSection({
  nodeId,
  data,
  updateNodeData,
}: {
  nodeId: string;
  data: WorkflowNodeData;
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => void;
}) {
  const hasLlm =
    data.capabilityWorld === "secrets-node" ||
    data.capabilityWorld === "database-node" ||
    data.capabilityWorld === "automation-node" ||
    data.importedInterfaces?.some((i: string) => i.includes("llm"));

  if (!hasLlm) return null;

  const selectBase =
    "w-full px-4 py-3 text-xs font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-ui cursor-pointer hover:bg-surface-4/60 appearance-none selection:bg-primary/30";

  return (
    <div className="p-6 bg-surface-3/40 border border-white/5 rounded-2xl space-y-6 relative overflow-hidden group">
      <div className="flex items-center justify-between relative z-10">
        <h4 className="text-xs font-semibold text-white flex items-center gap-3 font-outfit">
          <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 transition-ui">
            <Brain className="w-4 h-4 text-primary" />
          </div>
          Language model
        </h4>
        <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
          <div className="w-1.5 h-1.5 rounded-full bg-primary" />
          <span className="text-2xs font-semibold text-primary tracking-wider uppercase">
            Enabled
          </span>
        </div>
      </div>

      <div className="space-y-6 relative z-10">
        <div className="grid grid-cols-1 gap-6">
          <div className="space-y-3">
            <label className="text-xs text-muted-foreground/60 font-medium ml-1">
              Provider
            </label>
            <div className="relative">
              <select
                className={selectBase}
                value={(data.config?.llm_provider as string) || "anthropic"}
                onChange={(e) =>
                  updateNodeData(nodeId, {
                    config: { ...data.config, llm_provider: e.target.value },
                  })
                }
              >
                <option value="anthropic">ANTHROPIC (CLAUDE)</option>
                <option value="openai">OPENAI (GPT)</option>
                <option value="gemini">GOOGLE (GEMINI)</option>
              </select>
              <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/70 pointer-events-none" />
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-xs text-muted-foreground/60 font-medium ml-1">
              Model
            </label>
            <div className="relative">
              <select
                className={selectBase}
                value={(data.config?.llm_model as string) || ""}
                onChange={(e) =>
                  updateNodeData(nodeId, {
                    config: { ...data.config, llm_model: e.target.value },
                  })
                }
              >
                <optgroup label="ANTHROPIC" className="bg-surface-3">
                  <option value="claude-sonnet-4-6">CLAUDE SONNET 4.6</option>
                  <option value="claude-opus-4-6">CLAUDE OPUS 4.6</option>
                  <option value="claude-haiku-4-5-20251001">
                    CLAUDE HAIKU 4.5
                  </option>
                </optgroup>
                <optgroup label="OPENAI" className="bg-surface-3">
                  <option value="gpt-4o">GPT-4O</option>
                  <option value="gpt-4-turbo">GPT-4 TURBO</option>
                </optgroup>
                <optgroup label="GOOGLE" className="bg-surface-3">
                  <option value="gemini-1.5-pro">GEMINI 1.5 PRO</option>
                  <option value="gemini-1.5-flash">GEMINI 1.5 FLASH</option>
                </optgroup>
              </select>
              <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/70 pointer-events-none" />
            </div>
          </div>
        </div>

        <div className="flex gap-6">
          <div className="flex-1 space-y-3">
            <label className="text-xs text-muted-foreground/60 font-medium ml-1">
              Temperature
            </label>
            <input
              type="number"
              min="0"
              max="2"
              step="0.1"
              className="w-full px-5 py-3 text-xs font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-ui selection:bg-primary/30"
              value={(data.config?.llm_temperature as number) ?? 0.7}
              onChange={(e) =>
                updateNodeData(nodeId, {
                  config: {
                    ...data.config,
                    llm_temperature: Math.min(
                      2,
                      Math.max(0, parseFloat(e.target.value) || 0.7),
                    ),
                  },
                })
              }
            />
          </div>
          <div className="flex-1 space-y-3">
            <label className="text-xs text-muted-foreground/60 font-medium ml-1">
              Maximum tokens
            </label>
            <input
              type="number"
              min="1"
              className="w-full px-5 py-3 text-xs font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-ui selection:bg-primary/30"
              value={(data.config?.llm_max_tokens as number) ?? 4096}
              onChange={(e) =>
                updateNodeData(nodeId, {
                  config: {
                    ...data.config,
                    llm_max_tokens: Math.max(
                      1,
                      parseInt(e.target.value, 10) || 4096,
                    ),
                  },
                })
              }
            />
          </div>
        </div>

        <div className="space-y-3">
          <label className="text-xs text-muted-foreground/60 font-medium ml-1">
            System prompt
          </label>
          <div className="relative group/directive">
            <textarea
              rows={4}
              className="relative w-full px-5 py-4 text-xs font-medium bg-black/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:outline-none transition-ui resize-none font-sans leading-relaxed selection:bg-primary/30 placeholder:text-muted-foreground/50"
              placeholder="Tell the model what to do…"
              value={(data.config?.llm_system_prompt as string) || ""}
              onChange={(e) =>
                updateNodeData(nodeId, {
                  config: { ...data.config, llm_system_prompt: e.target.value },
                })
              }
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export function RetryPolicySection({
  nodeId,
  data,
  updateNodeData,
}: {
  nodeId: string;
  data: WorkflowNodeData;
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => void;
}) {
  const inputBase =
    "w-full px-5 py-3.5 text-xs font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-ui selection:bg-primary/30";

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-3">
          <label className="text-xs text-muted-foreground/60 font-medium ml-1">
            Threshold
          </label>
          <input
            type="number"
            // Empty = no declared count: the engine's method-aware default
            // applies. That is NOT 0, which means "never retry".
            placeholder="default"
            className={inputBase}
            value={data.retryPolicy?.maxRetries ?? ""}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || {};
              updateNodeData(nodeId, {
                retryPolicy: {
                  ...currentPolicy,
                  maxRetries:
                    e.target.value === ""
                      ? undefined
                      : Math.max(0, parseInt(e.target.value, 10) || 0),
                },
              });
            }}
          />
        </div>

        <div className="space-y-3">
          <label className="text-xs text-muted-foreground/60 font-medium ml-1">
            Backoff (ms)
          </label>
          <input
            type="number"
            placeholder="1000"
            className={inputBase}
            value={data.retryPolicy?.backoffMs ?? 1000}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || {};
              updateNodeData(nodeId, {
                retryPolicy: {
                  ...currentPolicy,
                  backoffMs: Math.max(0, parseInt(e.target.value, 10) || 1000),
                },
              });
            }}
          />
        </div>
      </div>

      <div className="space-y-4">
        <label className="text-xs text-muted-foreground/60 font-medium ml-1">
          Condition (Rhai)
        </label>
        <div className="relative group/logic">
          <textarea
            placeholder="ctx.last_error.code == 503"
            className="relative w-full px-6 py-5 bg-black/40 border border-white/5 font-mono text-xs min-h-[140px] transition-ui rounded-2xl selection:bg-primary/30 leading-relaxed focus:outline-none focus:border-primary/40"
            value={data.retryPolicy?.retryCondition ?? ""}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || {};
              updateNodeData(nodeId, {
                retryPolicy: {
                  ...currentPolicy,
                  retryCondition: e.target.value,
                },
              });
            }}
          />
        </div>

        <div className="flex flex-wrap gap-3 pt-2">
          {[
            { label: "Server error", value: "ctx.last_error.code >= 500" },
            {
              label: "Rate limit",
              value: 'ctx.last_error.message.contains("rate limit")',
            },
            { label: "Always", value: "true" },
          ].map((snippet) => (
            <Button
              variant="outline"
              size="sm"
              key={snippet.label}
              onClick={() => {
                const currentPolicy = data.retryPolicy || {};
                updateNodeData(nodeId, {
                  retryPolicy: {
                    ...currentPolicy,
                    retryCondition: snippet.value,
                  },
                });
              }}
            >
              {snippet.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}

export function SystemInternalsSection({
  node,
  moduleId,
  copiedNodeId,
  copiedModuleId,
  onCopyNodeId,
  onCopyModuleId,
  onDelete,
}: {
  node: { id: string };
  moduleId: string;
  copiedNodeId: boolean;
  copiedModuleId: boolean;
  onCopyNodeId: () => void;
  onCopyModuleId: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="space-y-8 py-4">
      <div className="space-y-4">
        <label className="text-xs text-muted-foreground/60 font-medium ml-1 flex items-center gap-2">
          <Activity size={12} className="text-primary/70" />
          Identifiers
        </label>
        <div className="grid gap-4">
          <CopyField
            label="Node ID"
            value={node.id}
            copied={copiedNodeId}
            onCopy={onCopyNodeId}
          />
          <CopyField
            label="Module ID"
            value={moduleId}
            copied={copiedModuleId}
            onCopy={onCopyModuleId}
          />
        </div>
      </div>

      <div className="pt-8 border-t border-white/5">
        <Button
          variant="outline"
          className="w-full text-destructive border-destructive/20 hover:bg-destructive/10 hover:text-destructive"
          onClick={onDelete}
        >
          <span className="relative z-10">Delete node</span>
        </Button>
      </div>
    </div>
  );
}
