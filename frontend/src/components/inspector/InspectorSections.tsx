import React from "react";
import {
  Brain,
  ShieldCheck,
  Settings,
  ChevronDown,
  Activity,
} from "lucide-react";
import {
  FormField,
  Input,
  Textarea,
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
  CopyField,
} from "@/components/ui";
import { cn } from "@/lib/utils";
import { NodeStatusType } from "@/store/executionStore";
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
        "inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full border text-[9px] font-black tracking-[0.2em] uppercase transition-premium group overflow-hidden relative shadow-[0_0_15px_hsla(var(--primary),0.1)]",
        visuals.bgColor,
        visuals.borderColor,
        visuals.color,
      )}
    >
      <div className="absolute inset-0 bg-gradient-to-r from-primary/10 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium" />
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
    "w-full px-4 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium cursor-pointer hover:bg-surface-4/60 appearance-none selection:bg-primary/30";

  return (
    <div className="p-6 bg-surface-3/40 border border-white/5 rounded-3xl space-y-6 shadow-2xl relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-20 pointer-events-none" />

      <div className="flex items-center justify-between relative z-10">
        <h4 className="text-[11px] font-black text-white flex items-center gap-3 uppercase tracking-[0.3em] font-outfit">
          <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 shadow-[0_0_20px_hsla(var(--primary),0.15)] group-hover:scale-110 transition-premium">
            <Brain className="w-4 h-4 text-primary" />
          </div>
          Neural Core
        </h4>
        <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
          <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
          <span className="text-[8px] font-black text-primary tracking-widest uppercase">
            Active_Link
          </span>
        </div>
      </div>

      <div className="space-y-6 relative z-10">
        <div className="grid grid-cols-1 gap-6">
          <div className="space-y-3">
            <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Cognitive Architecture
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
              <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/40 pointer-events-none" />
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Model Parameter
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
              <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/40 pointer-events-none" />
            </div>
          </div>
        </div>

        <div className="flex gap-6">
          <div className="flex-1 space-y-3">
            <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Entropy
            </label>
            <input
              type="number"
              min="0"
              max="2"
              step="0.1"
              className="w-full px-5 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium selection:bg-primary/30"
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
            <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Capacitance
            </label>
            <input
              type="number"
              min="1"
              className="w-full px-5 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium selection:bg-primary/30"
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
          <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
            Primary Directive
          </label>
          <div className="relative group/directive">
            <div className="absolute -inset-0.5 bg-primary/10 rounded-2xl blur opacity-0 group-hover/directive:opacity-100 transition-premium" />
            <textarea
              rows={4}
              className="relative w-full px-5 py-4 text-[11px] font-medium bg-black/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:outline-none transition-premium resize-none font-sans leading-relaxed selection:bg-primary/30 placeholder:text-muted-foreground/20"
              placeholder="DEFINE_OPERATIONAL_DIRECTIVE..."
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
    "w-full px-5 py-3.5 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium selection:bg-primary/30";

  return (
    <div className="space-y-8 animate-in slide-in-from-top-4 duration-500">
      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-3">
          <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
            Threshold
          </label>
          <input
            type="number"
            placeholder="0"
            className={inputBase}
            value={data.retryPolicy?.maxRetries ?? 0}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || { maxRetries: 0 };
              updateNodeData(nodeId, {
                retryPolicy: {
                  ...currentPolicy,
                  maxRetries: Math.max(0, parseInt(e.target.value, 10) || 0),
                },
              });
            }}
          />
        </div>

        <div className="space-y-3">
          <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
            Backoff (ms)
          </label>
          <input
            type="number"
            placeholder="1000"
            className={inputBase}
            value={data.retryPolicy?.backoffMs ?? 1000}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || { maxRetries: 0 };
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
        <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
          Condition Logic (Rhai)
        </label>
        <div className="relative group/logic">
          <div className="absolute -inset-1 bg-primary/5 rounded-3xl blur opacity-20 group-hover/logic:opacity-40 transition-premium" />
          <textarea
            placeholder="ctx.last_error.code == 503"
            className="relative w-full px-6 py-5 bg-black/40 border border-white/5 font-mono text-[11px] min-h-[140px] transition-premium rounded-[2rem] selection:bg-primary/30 leading-relaxed focus:outline-none focus:border-primary/40 focus:shadow-[0_0_30px_hsla(var(--primary),0.05)]"
            value={data.retryPolicy?.retryCondition ?? ""}
            onChange={(e) => {
              const currentPolicy = data.retryPolicy || { maxRetries: 0 };
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
            { label: "PROTOCOL_FAULT", value: "ctx.last_error.code >= 500" },
            {
              label: "RATE_LIMIT",
              value: 'ctx.last_error.message.contains("rate limit")',
            },
            { label: "PERSISTENT", value: "true" },
          ].map((snippet) => (
            <button
              type="button"
              key={snippet.label}
              onClick={() => {
                const currentPolicy = data.retryPolicy || { maxRetries: 0 };
                updateNodeData(nodeId, {
                  retryPolicy: {
                    ...currentPolicy,
                    retryCondition: snippet.value,
                  },
                });
              }}
              className="text-[9px] font-black px-4 py-2 bg-white/5 hover:bg-primary/10 border border-white/5 rounded-xl text-muted-foreground/40 hover:text-primary transition-premium shadow-lg uppercase tracking-[0.2em] active:scale-95"
            >
              {snippet.label}
            </button>
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
    <div className="space-y-8 py-4 animate-in fade-in duration-700">
      <div className="space-y-4">
        <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1 flex items-center gap-2">
          <Activity size={12} className="text-primary/40" />
          Protocol Identity
        </label>
        <div className="grid gap-4">
          <CopyField
            label="Node_ID"
            value={node.id}
            copied={copiedNodeId}
            onCopy={onCopyNodeId}
          />
          <CopyField
            label="Source_ID"
            value={moduleId}
            copied={copiedModuleId}
            onCopy={onCopyModuleId}
          />
        </div>
      </div>

      <div className="pt-8 border-t border-white/5">
        <button
          type="button"
          onClick={onDelete}
          className="w-full py-4 rounded-2xl border border-destructive/20 bg-destructive/5 text-destructive text-[10px] font-black uppercase tracking-[0.3em] hover:bg-destructive/10 hover:border-destructive/40 transition-premium shadow-2xl active:scale-[0.98] group overflow-hidden relative"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-destructive/10 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium" />
          <span className="relative z-10">Decommission Protocol Node</span>
        </button>
      </div>
    </div>
  );
}
