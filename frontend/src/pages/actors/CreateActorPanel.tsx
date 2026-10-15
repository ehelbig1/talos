import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X, ChevronRight, Info, Zap, Shield, Gauge } from "lucide-react";
import { cn } from "@/lib/utils";
import { StepIndicator } from "@/components/ui";
import { getMyCapabilityCeiling } from "@/lib/graphqlApi";
import { getCapabilityConfig, ceilingOptions } from "@/lib/capabilityConfig";
import { useGetCapabilityWorldHierarchyQuery } from "@/generated/graphql";
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
    description:
      "Focuses on vulnerabilities, threat modeling, and security reviews",
    defaultCapability: "http-node",
    suggestedName: "appsec-engineer",
    persona: {
      role: "Application Security Engineer",
      expertise: [
        "OWASP Top 10",
        "threat modeling",
        "SAST/DAST",
        "secure code review",
        "CVE analysis",
      ],
      tone: "precise and risk-focused",
      approach:
        "Always evaluate security implications, identify attack surfaces, and recommend mitigations",
    },
  },
  {
    id: "swe",
    name: "Software Engineer",
    description:
      "Focuses on implementation quality, architecture, and developer experience",
    defaultCapability: "http-node",
    suggestedName: "software-engineer",
    persona: {
      role: "Software Engineer",
      expertise: [
        "system design",
        "code quality",
        "performance optimization",
        "API design",
        "testing",
      ],
      tone: "pragmatic and implementation-focused",
      approach:
        "Prioritize clean abstractions, maintainability, and developer experience over theoretical ideals",
    },
  },
  {
    id: "data-analyst",
    name: "Data Analyst",
    description:
      "Focuses on data quality, patterns, statistical insights, and visualization",
    defaultCapability: "http-node",
    suggestedName: "data-analyst",
    persona: {
      role: "Data Analyst",
      expertise: [
        "statistical analysis",
        "data quality",
        "trend identification",
        "SQL",
        "visualization",
      ],
      tone: "analytical and evidence-driven",
      approach:
        "Ground conclusions in data, quantify uncertainty, and flag potential biases",
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
      expertise: [
        "user research",
        "roadmap planning",
        "metrics",
        "stakeholder alignment",
        "prioritization frameworks",
      ],
      tone: "user-centric and impact-focused",
      approach:
        "Frame everything in terms of user problems and business value; weigh tradeoffs explicitly",
    },
  },
  {
    id: "devops",
    name: "DevOps Engineer",
    description:
      "Focuses on reliability, deployment, observability, and infrastructure",
    defaultCapability: "network-node",
    suggestedName: "devops-engineer",
    persona: {
      role: "DevOps Engineer",
      expertise: [
        "CI/CD",
        "infrastructure-as-code",
        "observability",
        "SRE practices",
        "container orchestration",
      ],
      tone: "operational and reliability-focused",
      approach:
        "Optimize for deployment safety, observability, and graceful failure handling",
    },
  },
  {
    id: "custom",
    name: "Custom",
    description:
      "Start blank and define your own persona in the Memory tab after creation",
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

export function CreateActorPanel({
  open,
  onClose,
  onCreate,
  isPending,
}: CreateActorPanelProps) {
  const [step, setStep] = useState(0);
  const [selectedTemplate, setSelectedTemplate] =
    useState<ActorTemplate | null>(null);
  const [name, setName] = useState("");
  const [description, setDesc] = useState("");
  const [capWorld, setCapWorld] = useState("minimal-node");
  const [budgetId, setBudgetId] = useState<BudgetPresetId>("standard");
  const [showAdvanced, setShowAdvanced] = useState(false);

  // No default ceiling: until the backend has said what the caller holds,
  // every world renders as unavailable rather than as permitted.
  const { data: ceilingWorld } = useQuery({
    queryKey: ["myCapabilityCeiling"],
    queryFn: getMyCapabilityCeiling,
    staleTime: 60_000,
  });
  const { data: hierarchyData } = useGetCapabilityWorldHierarchyQuery();
  const worldOptions = ceilingOptions(
    hierarchyData?.capabilityWorldHierarchy ?? [],
    ceilingWorld,
  );

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
      <div
        className="fixed inset-0 z-[100] bg-black/60 animate-in fade-in duration-500"
        onClick={handleClose}
      />

      {/* Panel */}
      <div className="fixed right-0 top-0 bottom-0 z-[101] w-full md:w-[560px] bg-surface-3/40 border-l border-white/10 flex flex-col animate-in slide-in-from-right-full duration-700 ease-premium">
        {/* Panel header */}
        <div className="flex items-center justify-between px-10 py-10 border-b border-white/5 shrink-0 bg-white/5">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <h2 className="text-white font-semibold text-2xl font-outfit tracking-tight">
                New actor
              </h2>
            </div>
            <p className="text-muted-foreground/60 text-xs font-semibold">
              An identity your workflows run as
            </p>
          </div>
          <button
            onClick={handleClose}
            className="w-12 h-12 flex items-center justify-center rounded-2xl text-muted-foreground/70 hover:text-white hover:bg-white/10 border border-transparent hover:border-white/10 transition-premium active:scale-90"
          >
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
        <div className="flex-1 overflow-y-auto px-10 py-10 custom-scrollbar">
          {/* Step 0: Template + Identity */}
          {step === 0 && (
            <div className="flex flex-col gap-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
              {/* Template selection */}
              <div className="space-y-6">
                <div className="flex items-center gap-3">
                  <Info className="w-4 h-4 text-primary/70" />
                  <p className="text-muted-foreground/60 text-xs leading-relaxed">
                    Start from a persona template.
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
                          "w-full text-left p-6 rounded-2xl border transition-premium relative overflow-hidden group shadow-sm",
                          isSelected
                            ? "border-primary/40 bg-primary/10"
                            : "border-white/5 bg-white/2 hover:border-primary/20 hover:bg-white/5",
                        )}
                      >
                        <div className="flex items-center justify-between gap-4 relative z-10 mb-2">
                          <span
                            className={cn(
                              "text-base font-semibold font-outfit tracking-tight",
                              isSelected ? "text-primary" : "text-white",
                            )}
                          >
                            {t.name}
                          </span>
                          {t.id !== "custom" && (
                            <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider bg-white/5 px-2 py-1 rounded-lg border border-white/5">
                              {t.defaultCapability}
                            </span>
                          )}
                        </div>
                        <p className="text-muted-foreground/70 text-xs leading-relaxed relative z-10">
                          {t.description}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Identity fields */}
              {selectedTemplate && (
                <div className="flex flex-col gap-8 border-t border-white/5 pt-10 animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200">
                  <div className="space-y-3">
                    <label className="text-xs font-semibold text-muted-foreground/60 ml-1">
                      Name <span className="text-primary">*</span>
                    </label>
                    <div className="relative group/input">
                      <input
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="e.g. inbox-assistant"
                        maxLength={64}
                        autoFocus
                        className="w-full bg-surface-4/40 border border-white/10 rounded-2xl px-6 py-4 text-sm text-white placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium relative z-10 font-medium"
                      />
                    </div>
                    <p className="text-2xs text-muted-foreground/50 font-bold uppercase tracking-wider ml-1">
                      Lowercase letters, numbers and hyphens.
                    </p>
                  </div>
                  <div className="space-y-3">
                    <label className="text-xs font-semibold text-muted-foreground/60 ml-1">
                      Description
                    </label>
                    <div className="relative group/textarea">
                      <textarea
                        value={description}
                        onChange={(e) => setDesc(e.target.value)}
                        placeholder="What is this actor for?"
                        rows={3}
                        className="w-full bg-surface-4/40 border border-white/10 rounded-2xl px-6 py-4 text-sm text-white placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium resize-none relative z-10 font-medium"
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
              <div className="rounded-2xl border border-white/5 bg-white/5 p-10 bg-white/[0.03] border border-white/5 relative overflow-hidden">
                <p className="text-xs font-semibold text-muted-foreground/50 mb-8 relative z-10">
                  Deployment Specification
                </p>
                <div className="flex flex-col gap-6 relative z-10">
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-xs font-bold text-muted-foreground/70">
                      Identifier
                    </span>
                    <span className="text-sm text-white font-semibold font-outfit">
                      {name}
                    </span>
                  </div>
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-xs font-bold text-muted-foreground/70">
                      Persona
                    </span>
                    <span className="text-sm text-white font-semibold font-outfit tracking-tight">
                      {selectedTemplate?.name ?? "Custom"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <span className="text-xs font-bold text-muted-foreground/70">
                      Capability Ceiling
                    </span>
                    <CapabilityBadge world={capWorld} size="md" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-muted-foreground/70">
                      Throughput Limit
                    </span>
                    <span className="text-sm text-primary font-semibold font-outfit tracking-tight">
                      {selectedBudgetPreset.rateLimit != null
                        ? `${selectedBudgetPreset.rateLimit} cycles / min`
                        : "Unrestricted"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Advanced settings */}
              <button
                onClick={() => setShowAdvanced((v) => !v)}
                className="flex items-center gap-4 px-6 py-4 bg-white/5 border border-white/5 rounded-2xl text-sm font-semibold text-muted-foreground/70 hover:text-white hover:bg-white/10 hover:border-white/20 transition-premium active:scale-95 group"
              >
                <ChevronRight
                  className={cn(
                    "w-4 h-4 transition-transform text-primary/70 group-hover:text-primary",
                    showAdvanced && "rotate-90",
                  )}
                />
                Advanced limits
              </button>

              {showAdvanced && (
                <div className="flex flex-col gap-10 animate-in fade-in slide-in-from-top-4 duration-700 ease-premium">
                  {/* Capability ceiling */}
                  <div className="space-y-6">
                    <div>
                      <p className="text-xs font-semibold text-white/60 mb-2">
                        Capability Architecture
                      </p>
                      <p className="text-xs text-muted-foreground/60 leading-relaxed">
                        The most this actor's modules are allowed to do.
                      </p>
                    </div>
                    <div className="flex flex-col gap-3">
                      {worldOptions.map(({ world, permitted }) => {
                        const cfg = getCapabilityConfig(world);
                        const isSelected = capWorld === world;
                        const isAboveCeiling = !permitted;
                        return (
                          <button
                            key={world}
                            onClick={() =>
                              !isAboveCeiling && setCapWorld(world)
                            }
                            disabled={isAboveCeiling}
                            className={cn(
                              "w-full text-left rounded-2xl border p-5 transition-premium relative overflow-hidden group shadow-sm",
                              isAboveCeiling
                                ? "opacity-20 cursor-not-allowed border-white/5 bg-transparent"
                                : isSelected
                                  ? "border-primary/40 bg-primary/10"
                                  : "border-white/5 bg-white/2 hover:border-white/20 hover:bg-white/5",
                            )}
                          >
                            <div className="flex items-center gap-4 relative z-10">
                              <div
                                className={cn(
                                  "w-5 h-5 rounded-full border-2 shrink-0 flex items-center justify-center transition-premium",
                                  isSelected
                                    ? "border-primary bg-primary"
                                    : "border-white/10",
                                )}
                              >
                                {isSelected && (
                                  <div className="w-2 h-2 rounded-full bg-white" />
                                )}
                              </div>
                              <span
                                className={cn(
                                  "text-xs font-semibold transition-colors",
                                  isSelected
                                    ? "text-white"
                                    : "text-muted-foreground/70 group-hover:text-muted-foreground/60",
                                )}
                              >
                                {cfg.label}
                              </span>
                              <span className="text-xs text-muted-foreground/50 font-mono ml-auto tracking-tighter">
                                {world}
                              </span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Budget */}
                  <div className="space-y-6">
                    <div>
                      <p className="text-xs font-semibold text-white/60 mb-2">
                        Throughput Throttle
                      </p>
                      <p className="text-xs text-muted-foreground/60 leading-relaxed">
                        Caps on runs and spend so a runaway workflow stops.
                      </p>
                    </div>
                    <div className="grid grid-cols-1 gap-3">
                      {BUDGET_PRESETS.map((preset) => {
                        const isSelected = budgetId === preset.id;
                        return (
                          <button
                            key={preset.id}
                            onClick={() => setBudgetId(preset.id)}
                            className={cn(
                              "w-full text-left rounded-2xl border p-5 transition-premium relative overflow-hidden group shadow-sm",
                              isSelected
                                ? "border-primary/40 bg-primary/10"
                                : "border-white/5 bg-white/2 hover:border-white/20 hover:bg-white/5",
                            )}
                          >
                            <div className="flex items-center gap-4 relative z-10">
                              <div
                                className={cn(
                                  "w-5 h-5 rounded-full border-2 shrink-0 flex items-center justify-center transition-premium",
                                  isSelected
                                    ? "border-primary bg-primary"
                                    : "border-white/10",
                                )}
                              >
                                {isSelected && (
                                  <div className="w-2 h-2 rounded-full bg-white" />
                                )}
                              </div>
                              <div className="flex flex-col">
                                <span
                                  className={cn(
                                    "text-xs font-semibold transition-colors",
                                    isSelected
                                      ? "text-white"
                                      : "text-muted-foreground/70 group-hover:text-muted-foreground/60",
                                  )}
                                >
                                  {preset.label}
                                </span>
                                <span className="text-2xs text-muted-foreground/50 font-bold uppercase tracking-wider mt-1">
                                  {preset.summary}
                                </span>
                              </div>
                              {preset.recommended && (
                                <span className="text-2xs font-semibold px-2 py-1 rounded bg-primary/20 text-primary uppercase tracking-wider ml-auto border border-primary/20">
                                  Optimal
                                </span>
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
            className="px-10 py-5 text-sm font-semibold text-muted-foreground/70 bg-white/5 border border-white/5 rounded-2xl hover:text-white hover:bg-white/10 hover:border-white/20 transition-premium active:scale-95"
          >
            {step === 0 ? "Abort" : "Previous Step"}
          </button>

          {step === 0 ? (
            <button
              type="button"
              onClick={() => setStep(1)}
              disabled={!canAdvance}
              className="flex items-center gap-4 px-10 py-5 text-sm font-semibold text-white bg-primary rounded-2xl transition-premium disabled:opacity-20 disabled:cursor-not-allowed active:scale-95 border border-white/20"
            >
              Next <ChevronRight className="w-5 h-5" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleCreate}
              disabled={isPending}
              className="flex items-center gap-4 px-12 py-5 text-sm font-semibold text-white bg-primary rounded-2xl transition-premium disabled:opacity-50 disabled:cursor-not-allowed active:scale-95 border border-white/20"
            >
              {isPending ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  Creating…
                </>
              ) : (
                "Create actor"
              )}
            </button>
          )}
        </div>
      </div>
    </>
  );
}
