import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X, ChevronRight, Info, Zap, Shield, Gauge } from "lucide-react";
import { cn } from "@/lib/utils";
import { StepIndicator } from "@/components/ui";
import { getMyCapabilityCeiling } from "@/lib/graphqlClient";
import { getCapabilityConfig, CAPABILITY_LADDER } from "@/lib/capabilityConfig";
import { CapabilityBadge } from "./ActorCard";

// ── Actor persona templates ───────────────────────────────────────────────────

export interface ActorTemplate {
  id: string;
  name: string;
  description: string;
  defaultCapability: string;
  persona: {
    role: string;
    expertise: string[];
    tone: string;
    approach: string;
  };
  suggestedName: string;
}

export const ACTOR_TEMPLATES: ActorTemplate[] = [
  {
    id: "appsec",
    name: "Application Security Engineer",
    description: "Focuses on vulnerabilities, threat modeling, and security reviews",
    defaultCapability: "http-node",
    suggestedName: "appsec-engineer",
    persona: {
      role: "Application Security Engineer",
      expertise: ["OWASP Top 10", "threat modeling", "SAST/DAST", "secure code review", "CVE analysis"],
      tone: "precise and risk-focused",
      approach: "Always evaluate security implications, identify attack surfaces, and recommend mitigations",
    },
  },
  {
    id: "swe",
    name: "Software Engineer",
    description: "Focuses on implementation quality, architecture, and developer experience",
    defaultCapability: "http-node",
    suggestedName: "software-engineer",
    persona: {
      role: "Software Engineer",
      expertise: ["system design", "code quality", "performance optimization", "API design", "testing"],
      tone: "pragmatic and implementation-focused",
      approach: "Prioritize clean abstractions, maintainability, and developer experience over theoretical ideals",
    },
  },
  {
    id: "data-analyst",
    name: "Data Analyst",
    description: "Focuses on data quality, patterns, statistical insights, and visualization",
    defaultCapability: "http-node",
    suggestedName: "data-analyst",
    persona: {
      role: "Data Analyst",
      expertise: ["statistical analysis", "data quality", "trend identification", "SQL", "visualization"],
      tone: "analytical and evidence-driven",
      approach: "Ground conclusions in data, quantify uncertainty, and flag potential biases",
    },
  },
  {
    id: "product",
    name: "Product Manager",
    description: "Focuses on user value, business impact, and prioritization",
    defaultCapability: "http-node",
    suggestedName: "product-manager",
    persona: {
      role: "Product Manager",
      expertise: ["user research", "roadmap planning", "metrics", "stakeholder alignment", "prioritization frameworks"],
      tone: "user-centric and impact-focused",
      approach: "Frame everything in terms of user problems and business value; weigh tradeoffs explicitly",
    },
  },
  {
    id: "devops",
    name: "DevOps Engineer",
    description: "Focuses on reliability, deployment, observability, and infrastructure",
    defaultCapability: "network-node",
    suggestedName: "devops-engineer",
    persona: {
      role: "DevOps Engineer",
      expertise: ["CI/CD", "infrastructure-as-code", "observability", "SRE practices", "container orchestration"],
      tone: "operational and reliability-focused",
      approach: "Optimize for deployment safety, observability, and graceful failure handling",
    },
  },
  {
    id: "custom",
    name: "Custom",
    description: "Start blank and define your own persona in the Memory tab after creation",
    defaultCapability: "minimal-node",
    suggestedName: "",
    persona: { role: "", expertise: [], tone: "", approach: "" },
  },
];

// ── Budget presets ────────────────────────────────────────────────────────────

const BUDGET_PRESETS = [
  {
    id: "light",
    label: "Light",
    summary: "10 exec/min, suspend on exceed",
    rateLimit: 10,
    recommended: false,
    icon: Zap,
    note: "The actor will be automatically suspended if it exceeds 10 executions per minute.",
  },
  {
    id: "standard",
    label: "Standard",
    summary: "50 exec/min, alert on exceed",
    rateLimit: 50,
    recommended: true,
    icon: Gauge,
    note: "An alert is raised when the actor exceeds 50 executions per minute. Execution continues.",
  },
  {
    id: "strict",
    label: "Strict",
    summary: "5 exec/min, block on exceed",
    rateLimit: 5,
    recommended: false,
    icon: Shield,
    note: "New executions are blocked until the rate window resets. Best for sensitive actors.",
  },
  {
    id: "unlimited",
    label: "Unlimited",
    summary: "No limits — not recommended for production",
    rateLimit: null,
    recommended: false,
    icon: null,
    note: "No rate limiting is applied. Only use for trusted internal automation in development.",
  },
] as const;

type BudgetPresetId = "light" | "standard" | "strict" | "unlimited";

// ── CreateActorPanel ──────────────────────────────────────────────────────────

interface CreateActorPanelProps {
  open: boolean;
  onClose: () => void;
  onCreate: (input: {
    name: string;
    description?: string;
    maxCapabilityWorld?: string;
    rateLimit?: number;
    template?: ActorTemplate;
  }) => void;
  isPending: boolean;
}

export function CreateActorPanel({ open, onClose, onCreate, isPending }: CreateActorPanelProps) {
  const [step, setStep] = useState(0);
  const [selectedTemplate, setSelectedTemplate] = useState<ActorTemplate | null>(null);
  const [name, setName] = useState("");
  const [description, setDesc] = useState("");
  const [capWorld, setCapWorld] = useState("minimal-node");
  const [budgetId, setBudgetId] = useState<BudgetPresetId>("standard");
  const [showAdvanced, setShowAdvanced] = useState(false);

  const selectedCapIdx = CAPABILITY_LADDER.indexOf(capWorld);

  const { data: ceilingWorld = "automation-node" } = useQuery({
    queryKey: ["myCapabilityCeiling"],
    queryFn: getMyCapabilityCeiling,
    staleTime: 60_000,
  });
  const ceilingIdx = CAPABILITY_LADDER.indexOf(ceilingWorld);
  const effectiveCeilingIdx = ceilingIdx === -1 ? CAPABILITY_LADDER.length - 1 : ceilingIdx;

  function reset() {
    setStep(0);
    setSelectedTemplate(null);
    setName("");
    setDesc("");
    setCapWorld("minimal-node");
    setBudgetId("standard");
    setShowAdvanced(false);
  }

  function applyTemplate(t: ActorTemplate) {
    setSelectedTemplate(t);
    if (t.id !== "custom") {
      if (!name) setName(t.suggestedName);
      if (!description) setDesc(t.description);
      setCapWorld(t.defaultCapability);
    }
  }

  function handleClose() {
    reset();
    onClose();
  }

  function handleCreate() {
    const preset = BUDGET_PRESETS.find((p) => p.id === budgetId);
    onCreate({
      name: name.trim(),
      description: description.trim() || undefined,
      maxCapabilityWorld: capWorld,
      rateLimit: preset?.rateLimit ?? undefined,
      template: selectedTemplate ?? undefined,
    });
  }

  const canAdvance = name.trim().length > 0 && selectedTemplate !== null;
  const selectedBudgetPreset = BUDGET_PRESETS.find((p) => p.id === budgetId)!;

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-md animate-in fade-in duration-500" onClick={handleClose} />

      {/* Panel */}
      <div className="fixed right-0 top-0 bottom-0 z-[101] w-full md:w-[560px] bg-surface-3/40 backdrop-blur-3xl border-l border-white/10 flex flex-col shadow-[0_0_100px_rgba(0,0,0,0.8)] glass gpu animate-in slide-in-from-right-full duration-700 ease-premium">
        {/* Panel header */}
        <div className="flex items-center justify-between px-10 py-10 border-b border-white/5 shrink-0 bg-white/5">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-pulse" />
              <h2 className="text-white font-black text-2xl font-outfit uppercase tracking-tighter">Provision Actor</h2>
            </div>
            <p className="text-muted-foreground/30 text-[10px] font-black uppercase tracking-[0.3em]">Initialize Bounded Execution Identity</p>
          </div>
          <button onClick={handleClose} className="w-12 h-12 flex items-center justify-center rounded-2xl text-muted-foreground/40 hover:text-white hover:bg-white/10 border border-transparent hover:border-white/10 transition-premium active:scale-90">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Step indicator */}
        <div className="px-10 py-8 border-b border-white/5 shrink-0 bg-white/2">
          <StepIndicator
            steps={[{ label: "Configuration" }, { label: "Deployment Review" }]}
            currentStep={step}
          />
        </div>

        {/* Step content */}
        <div className="flex-1 overflow-y-auto px-10 py-10 custom-scrollbar optimize-blur">
          {/* Step 0: Template + Identity */}
          {step === 0 && (
            <div className="flex flex-col gap-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
              {/* Template selection */}
              <div className="space-y-6">
                <div className="flex items-center gap-3">
                    <Info className="w-4 h-4 text-primary/40" />
                    <p className="text-muted-foreground/60 text-xs font-bold uppercase tracking-widest leading-relaxed">
                    Select a core persona template to initialize identity protocols.
                    </p>
                </div>
                <div className="grid grid-cols-1 gap-4">
                  {ACTOR_TEMPLATES.map((t) => {
                    const isSelected = selectedTemplate?.id === t.id;
                    return (
                      <button
                        key={t.id}
                        onClick={() => applyTemplate(t)}
                        className={cn(
                          "w-full text-left p-6 rounded-[1.5rem] border transition-premium relative overflow-hidden group shadow-sm",
                          isSelected
                            ? "border-primary/40 bg-primary/10 shadow-[0_0_30px_hsla(var(--primary),0.1)]"
                            : "border-white/5 bg-white/2 hover:border-primary/20 hover:bg-white/5",
                        )}
                      >
                        <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium" />
                        <div className="flex items-center justify-between gap-4 relative z-10 mb-2">
                          <span className={cn("text-base font-black font-outfit uppercase tracking-tight", isSelected ? "text-primary" : "text-white")}>{t.name}</span>
                          {t.id !== "custom" && (
                            <span className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-[0.2em] bg-white/5 px-2 py-1 rounded-lg border border-white/5">
                                {t.defaultCapability}
                            </span>
                          )}
                        </div>
                        <p className="text-muted-foreground/40 text-[11px] font-bold leading-relaxed uppercase tracking-wide relative z-10">{t.description}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Identity fields */}
              {selectedTemplate && (
                <div className="flex flex-col gap-8 border-t border-white/5 pt-10 animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200">
                  <div className="space-y-3">
                    <label className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] ml-1">
                      Identity Identifier <span className="text-primary">*</span>
                    </label>
                    <div className="relative group/input">
                        <div className="absolute -inset-0.5 bg-primary/20 rounded-[1.25rem] blur opacity-0 group-focus-within/input:opacity-100 transition-premium pointer-events-none" />
                        <input
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="e.g. secure-provision-actor"
                            maxLength={64}
                            autoFocus
                            className="w-full bg-surface-4/40 border border-white/10 rounded-[1.25rem] px-6 py-4 text-sm text-white placeholder:text-muted-foreground/20 focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium relative z-10 font-medium"
                        />
                    </div>
                    <p className="text-[9px] text-muted-foreground/20 font-bold uppercase tracking-widest ml-1">Kebab-case alphanumeric identifier sequence.</p>
                  </div>
                  <div className="space-y-3">
                    <label className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] ml-1">Operational Protocol Description</label>
                    <div className="relative group/textarea">
                        <div className="absolute -inset-0.5 bg-primary/20 rounded-[1.25rem] blur opacity-0 group-focus-within/textarea:opacity-100 transition-premium pointer-events-none" />
                        <textarea
                            value={description}
                            onChange={(e) => setDesc(e.target.value)}
                            placeholder="Specify primary operational objectives..."
                            rows={3}
                            className="w-full bg-surface-4/40 border border-white/10 rounded-[1.25rem] px-6 py-4 text-sm text-white placeholder:text-muted-foreground/20 focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium resize-none relative z-10 font-medium"
                        />
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 1: Review & Create */}
          {step === 1 && (
            <div className="flex flex-col gap-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
              {/* Summary card */}
              <div className="rounded-[2.5rem] border border-white/5 bg-white/5 p-10 glass-light relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />
                <p className="text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.4em] mb-8 relative z-10">Deployment Specification</p>
                <div className="flex flex-col gap-6 relative z-10">
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest">Identifier</span>
                    <span className="text-sm text-white font-black font-outfit uppercase tracking-tight">{name}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest">Protocol Persona</span>
                    <span className="text-sm text-white font-black font-outfit uppercase tracking-tight">{selectedTemplate?.name ?? "Custom"}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest">Capability Ceiling</span>
                    <CapabilityBadge world={capWorld} size="md" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest">Throughput Limit</span>
                    <span className="text-sm text-primary font-black font-outfit uppercase tracking-tight">
                      {selectedBudgetPreset.rateLimit != null ? `${selectedBudgetPreset.rateLimit} cycles / min` : "Unrestricted"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Advanced settings */}
              <button
                onClick={() => setShowAdvanced((v) => !v)}
                className="flex items-center gap-4 px-6 py-4 bg-white/5 border border-white/5 rounded-2xl text-[10px] font-black text-muted-foreground/40 uppercase tracking-[0.3em] hover:text-white hover:bg-white/10 hover:border-white/20 transition-premium active:scale-95 group shadow-xl"
              >
                <ChevronRight className={cn("w-4 h-4 transition-transform text-primary/40 group-hover:text-primary", showAdvanced && "rotate-90")} />
                Toggle Advanced Governance Controls
              </button>

              {showAdvanced && (
                <div className="flex flex-col gap-10 animate-in fade-in slide-in-from-top-4 duration-700 ease-premium">
                  {/* Capability ceiling */}
                  <div className="space-y-6">
                    <div>
                      <p className="text-[10px] font-black text-white/60 uppercase tracking-[0.3em] mb-2">Capability Architecture</p>
                      <p className="text-[11px] text-muted-foreground/30 font-bold leading-relaxed uppercase tracking-widest">Specify the maximum permission ceiling for autonomous orchestration.</p>
                    </div>
                    <div className="flex flex-col gap-3">
                      {CAPABILITY_LADDER.map((world, idx) => {
                        const cfg = getCapabilityConfig(world);
                        const isSelected = capWorld === world;
                        const isAboveCeiling = idx > effectiveCeilingIdx;
                        return (
                          <button
                            key={world}
                            onClick={() => !isAboveCeiling && setCapWorld(world)}
                            disabled={isAboveCeiling}
                            className={cn(
                              "w-full text-left rounded-[1.25rem] border p-5 transition-premium relative overflow-hidden group shadow-sm",
                              isAboveCeiling
                                ? "opacity-20 cursor-not-allowed border-white/5 bg-transparent"
                                : isSelected
                                  ? "border-primary/40 bg-primary/10 shadow-[0_0_20px_hsla(var(--primary),0.05)]"
                                  : "border-white/5 bg-white/2 hover:border-white/20 hover:bg-white/5",
                            )}
                          >
                            <div className="flex items-center gap-4 relative z-10">
                              <div className={cn("w-5 h-5 rounded-full border-2 shrink-0 flex items-center justify-center transition-premium", isSelected ? "border-primary bg-primary shadow-[0_0_10px_hsla(var(--primary),0.5)]" : "border-white/10")}>
                                {isSelected && <div className="w-2 h-2 rounded-full bg-white" />}
                              </div>
                              <span className={cn("text-xs font-black uppercase tracking-widest transition-colors", isSelected ? "text-white" : "text-muted-foreground/40 group-hover:text-muted-foreground/60")}>{cfg.label}</span>
                              <span className="text-[10px] text-muted-foreground/20 font-mono ml-auto uppercase tracking-tighter">{world}</span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Budget */}
                  <div className="space-y-6">
                    <div>
                      <p className="text-[10px] font-black text-white/60 uppercase tracking-[0.3em] mb-2">Throughput Throttle</p>
                      <p className="text-[11px] text-muted-foreground/30 font-bold leading-relaxed uppercase tracking-widest">Enforce execution ceilings to prevent protocol cascade failure.</p>
                    </div>
                    <div className="grid grid-cols-1 gap-3">
                      {BUDGET_PRESETS.map((preset) => {
                        const isSelected = budgetId === preset.id;
                        return (
                          <button
                            key={preset.id}
                            onClick={() => setBudgetId(preset.id)}
                            className={cn(
                              "w-full text-left rounded-[1.25rem] border p-5 transition-premium relative overflow-hidden group shadow-sm",
                              isSelected
                                ? "border-primary/40 bg-primary/10 shadow-[0_0_20px_hsla(var(--primary),0.05)]"
                                : "border-white/5 bg-white/2 hover:border-white/20 hover:bg-white/5",
                            )}
                          >
                            <div className="flex items-center gap-4 relative z-10">
                              <div className={cn("w-5 h-5 rounded-full border-2 shrink-0 flex items-center justify-center transition-premium", isSelected ? "border-primary bg-primary shadow-[0_0_10px_hsla(var(--primary),0.5)]" : "border-white/10")}>
                                {isSelected && <div className="w-2 h-2 rounded-full bg-white" />}
                              </div>
                              <div className="flex flex-col">
                                <span className={cn("text-xs font-black uppercase tracking-widest transition-colors", isSelected ? "text-white" : "text-muted-foreground/40 group-hover:text-muted-foreground/60")}>{preset.label}</span>
                                <span className="text-[9px] text-muted-foreground/20 font-bold uppercase tracking-widest mt-1">{preset.summary}</span>
                              </div>
                              {preset.recommended && (
                                <span className="text-[8px] font-black px-2 py-1 rounded bg-primary/20 text-primary uppercase tracking-[0.2em] ml-auto border border-primary/20">Optimal</span>
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer nav */}
        <div className="px-10 py-10 border-t border-white/5 flex items-center justify-between shrink-0 bg-white/2">
          <button
            type="button"
            onClick={step === 0 ? handleClose : () => setStep(0)}
            className="px-10 py-5 text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 bg-white/5 border border-white/5 rounded-2xl hover:text-white hover:bg-white/10 hover:border-white/20 transition-premium active:scale-95"
          >
            {step === 0 ? "Abort" : "Previous Step"}
          </button>

          {step === 0 ? (
            <button
              type="button"
              onClick={() => setStep(1)}
              disabled={!canAdvance}
              className="flex items-center gap-4 px-10 py-5 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-primary rounded-2xl transition-premium shadow-2xl hover:shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] disabled:opacity-20 disabled:cursor-not-allowed hover:scale-105 active:scale-95 border border-white/20"
            >
              Verify Protocol <ChevronRight className="w-5 h-5" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleCreate}
              disabled={isPending}
              className="flex items-center gap-4 px-12 py-5 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-primary rounded-2xl transition-premium shadow-2xl hover:shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] disabled:opacity-50 disabled:cursor-not-allowed hover:scale-105 active:scale-95 border border-white/20"
            >
              {isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Initializing...
                  </>
              ) : "Deploy Identity"}
            </button>
          )}
        </div>
      </div>
    </>
  );
}
