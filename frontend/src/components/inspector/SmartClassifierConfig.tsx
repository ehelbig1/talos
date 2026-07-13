import React, { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  Sparkles,
  Plus,
  X,
  ChevronDown,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
} from "lucide-react";
import { Input, Textarea, Button, DarkSelect } from "@/components/ui";
import { cn } from "@/lib/utils";
import { listActors } from "@/lib/graphqlApi";
import { lifecycleStyle, lifecycleLabel } from "@/lib/mlLifecycle";
import {
  useProvisionMlClassifierMutation,
  useSetWorkflowActorIdMutation,
  useMlModelsQuery,
} from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import type { WorkflowNodeData } from "@/store/workflowStore";

// The Smart Classifier module's config contract (module-templates/smart-classifier/talos.json).
const PROVIDERS = ["ollama", "anthropic", "openai", "gemini"] as const;
const DEFAULT_MODEL = "qwen3.6:latest";
// Mirrors talos-ml provision.rs: name is [A-Za-z0-9._-], 1–128 chars.
const NAME_RE = /^[A-Za-z0-9._-]{1,128}$/;

interface SmartClassifierConfigProps {
  nodeId: string;
  config: Record<string, unknown>;
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => void;
}

const labelStyle =
  "text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1";
const inputBase =
  "w-full px-5 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium placeholder:text-muted-foreground/20";
const textareaBase =
  "w-full px-5 py-4 text-[11px] font-mono bg-black/40 border border-white/5 rounded-[2rem] text-foreground/80 focus:border-primary/40 focus:outline-none transition-premium resize-none leading-relaxed custom-scrollbar";

/**
 * First-class configuration surface for a `smart-classifier` module node.
 *
 * Replaces the raw JSON editor with a task-oriented form AND the one-click
 * provisioning affordance that makes the node "smart": pick the owning actor,
 * press "Set up classifier", and the model/dataset/policy are provisioned
 * (`provisionMlClassifier`) and the workflow is bound to that actor
 * (`setWorkflowActorId`, required so serving + distillation resolve the same
 * tenant). The resolved model name is stamped into `config.MODEL_NAME`.
 *
 * The node starts LLM-only and distills into a fast model over time; the
 * lifecycle badge shows where it is on that path.
 */
export const SmartClassifierConfig: React.FC<SmartClassifierConfigProps> = ({
  nodeId,
  config,
  updateNodeData,
}) => {
  const workflowId = useWorkflowStore((s) => s.workflowId);
  const queryClient = useQueryClient();

  // --- config-backed fields ---
  const modelName = (config.MODEL_NAME as string) || "";
  const systemPrompt = (config.SYSTEM_PROMPT as string) || "";
  const labels = useMemo(
    () => (Array.isArray(config.LABELS) ? (config.LABELS as string[]) : []),
    [config.LABELS],
  );
  const provider = (config.PROVIDER as string) || "ollama";
  const model = (config.MODEL as string) || DEFAULT_MODEL;

  const setField = React.useCallback(
    (field: string, value: unknown) => {
      updateNodeData(nodeId, { config: { ...config, [field]: value } });
    },
    [config, nodeId, updateNodeData],
  );

  // --- provisioning form state ---
  const [name, setName] = useState(() => modelName);
  const [actorId, setActorId] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const { data: actors = [] } = useQuery({
    queryKey: ["actors"],
    queryFn: listActors,
  });
  const activeActors = actors.filter(
    (a) => a.status !== "archived" && a.status !== "terminated",
  );

  // Lifecycle state for the provisioned model (badge). All models, filtered
  // client-side by name — mirrors the ModelReview page.
  const { data: modelsData } = useMlModelsQuery(
    {},
    { enabled: !!modelName, refetchOnWindowFocus: true },
  );
  const liveModel = modelName
    ? modelsData?.mlModels.find((m) => m.name === modelName)
    : undefined;

  const provision = useProvisionMlClassifierMutation();
  const bindActor = useSetWorkflowActorIdMutation();
  const isProvisioning = provision.isPending || bindActor.isPending;

  // --- label editing ---
  const addLabel = () => {
    const l = newLabel.trim();
    if (!l || labels.includes(l)) return;
    setField("LABELS", [...labels, l]);
    setNewLabel("");
  };
  const removeLabel = (l: string) =>
    setField(
      "LABELS",
      labels.filter((x) => x !== l),
    );

  // --- provisioning validation (client mirror of the server rules) ---
  const external = provider !== "ollama";
  const nameValid = NAME_RE.test(name.trim());
  const canProvision =
    !!workflowId &&
    nameValid &&
    labels.length >= 2 &&
    !!actorId &&
    !isProvisioning;

  const provisionReason = !workflowId
    ? "Save the workflow first — the classifier binds to it."
    : !name.trim()
      ? "Give the classifier a name."
      : !nameValid
        ? "Name must be 1–128 chars of letters, numbers, . _ -"
        : labels.length < 2
          ? "Add at least 2 labels."
          : !actorId
            ? "Choose the actor that owns this classifier."
            : null;

  const handleProvision = async () => {
    if (!canProvision || !workflowId) return;
    try {
      const res = await provision.mutateAsync({
        name: name.trim(),
        labels,
        actorId,
        fallbackProvider: provider,
        fallbackModel: model,
        // The provider was chosen explicitly here; a non-local provider is an
        // opt-in data-egress decision, so pass the flag through to clear the
        // server-side locality gate. Default (ollama) stays local.
        allowExternalLlm: external,
      });
      const out = res.provisionMlClassifier;
      // Bind the workflow to the owning actor — serving + distillation resolve
      // tenancy from workflows.actor_id, so this is required, not cosmetic.
      await bindActor.mutateAsync({ workflowId, actorId });

      // Stamp the resolved model name into config (idempotent-safe).
      setField("MODEL_NAME", out.modelName);
      // Keep advanced fallback fields explicit in config for the module.
      updateNodeData(nodeId, {
        config: {
          ...config,
          MODEL_NAME: out.modelName,
          PROVIDER: provider,
          MODEL: model,
        },
      });
      queryClient.invalidateQueries({ queryKey: ["MlModels"] });
      toast.success(
        out.alreadyExisted
          ? `Reused existing model "${out.modelName}" (${out.lifecycleState})`
          : `Classifier "${out.modelName}" provisioned — starts LLM-only, distills as it runs`,
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Provisioning failed");
    }
  };

  return (
    <div className="space-y-8 animate-in slide-in-from-top-4 duration-500">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
          <Sparkles className="w-4 h-4" />
        </div>
        <div>
          <p className="text-[11px] font-black text-white uppercase tracking-widest">
            Smart Classifier
          </p>
          <p className="text-[9px] text-muted-foreground/50 font-medium">
            Starts as an LLM · distills into a fast model over time
          </p>
        </div>
      </div>

      {/* Provisioning / status */}
      {modelName ? (
        <div className="space-y-3 px-5 py-4 bg-surface-3/40 border border-white/5 rounded-2xl">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <CheckCircle2 className="w-4 h-4 text-success shrink-0" />
              <span className="text-[11px] font-mono font-bold text-foreground/80 truncate">
                {modelName}
              </span>
            </div>
            <span
              className={cn(
                "text-[9px] font-black px-2 py-0.5 rounded-md border uppercase tracking-wider shrink-0",
                lifecycleStyle(liveModel?.lifecycleState),
              )}
            >
              {lifecycleLabel(liveModel?.lifecycleState)}
            </span>
          </div>
          {!!liveModel && liveModel.pendingDisagreements > 0 && (
            <Link
              to="/models"
              className="flex items-center gap-1.5 text-[10px] font-bold text-warning hover:text-warning/80 transition-premium"
            >
              <AlertTriangle className="w-3 h-3" />
              {liveModel.pendingDisagreements} to review
              <ArrowUpRight className="w-3 h-3" />
            </Link>
          )}
        </div>
      ) : (
        <div className="space-y-4 px-5 py-5 bg-primary/[0.03] border border-primary/10 rounded-[1.5rem]">
          <div className="space-y-3">
            <label className={labelStyle}>Classifier Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="support-email-urgency"
              className={inputBase}
            />
          </div>
          <div className="space-y-3">
            <label className={labelStyle}>Owning Actor</label>
            <DarkSelect
              value={actorId}
              onChange={(e) => setActorId(e.target.value)}
              className="w-full"
            >
              <option value="">Select an actor…</option>
              {activeActors.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </DarkSelect>
            <p className="text-[9px] text-muted-foreground/40 font-medium px-1 leading-relaxed">
              The actor owns the model and receives the disagreement digest.
              Serving and learning run under its tenancy.
            </p>
          </div>
          <Button
            onClick={handleProvision}
            disabled={!canProvision}
            className="w-full h-11 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl bg-primary/20 border border-primary/30 text-primary hover:bg-primary/30 disabled:opacity-40 disabled:cursor-not-allowed transition-premium"
          >
            {isProvisioning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />
                Setting up…
              </>
            ) : (
              "Set up classifier"
            )}
          </Button>
          {provisionReason && (
            <p className="text-[9px] text-muted-foreground/40 font-medium text-center">
              {provisionReason}
            </p>
          )}
        </div>
      )}

      {/* Classification task */}
      <div className="space-y-3">
        <label className={labelStyle}>Classification Task</label>
        <Textarea
          rows={4}
          value={systemPrompt}
          onChange={(e) => setField("SYSTEM_PROMPT", e.target.value)}
          placeholder="Classify this support email by urgency."
          className={textareaBase}
        />
        <p className="text-[9px] text-muted-foreground/40 font-medium px-1">
          The allowed labels and JSON response format are appended
          automatically.
        </p>
      </div>

      {/* Labels */}
      <div className="space-y-3">
        <label className={labelStyle}>Labels ({labels.length})</label>
        <div className="flex flex-wrap gap-2">
          {labels.map((l) => (
            <span
              key={l}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-surface-4/60 border border-white/10 rounded-xl text-foreground/80"
            >
              {l}
              <button
                onClick={() => removeLabel(l)}
                aria-label={`Remove ${l}`}
                className="text-muted-foreground/40 hover:text-destructive transition-premium"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <Input
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addLabel();
              }
            }}
            placeholder="Add a label…"
            className={inputBase}
          />
          <Button
            onClick={addLabel}
            aria-label="Add label"
            className="h-11 px-4 rounded-2xl bg-white/5 border border-white/5 text-white/60 hover:text-white hover:bg-white/10 transition-premium shrink-0"
          >
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        {!!modelName && (
          <p className="text-[9px] text-warning/60 font-medium px-1 leading-relaxed">
            Changing labels after setup does not re-train the model — its label
            set was fixed at provisioning.
          </p>
        )}
      </div>

      {/* Advanced: LLM fallback leg */}
      <div className="space-y-3">
        <button
          onClick={() => setAdvancedOpen((v) => !v)}
          className="flex items-center gap-2 text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.3em] hover:text-white transition-premium"
        >
          <ChevronDown
            className={cn(
              "w-3.5 h-3.5 transition-transform",
              advancedOpen && "rotate-180",
            )}
          />
          LLM Fallback
        </button>
        {advancedOpen && (
          <div className="space-y-4 animate-in slide-in-from-top-2 duration-300">
            <div className="space-y-3">
              <label className={labelStyle}>Provider</label>
              <DarkSelect
                value={provider}
                onChange={(e) => setField("PROVIDER", e.target.value)}
                className="w-full"
              >
                {PROVIDERS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </DarkSelect>
              {external && (
                <p className="text-[9px] text-warning/70 font-medium px-1 flex items-center gap-1.5 leading-relaxed">
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  External provider — input leaves the host. Use ollama to keep
                  classification local (Tier-1).
                </p>
              )}
            </div>
            <div className="space-y-3">
              <label className={labelStyle}>Fallback Model</label>
              <Input
                value={model}
                onChange={(e) => setField("MODEL", e.target.value)}
                placeholder={DEFAULT_MODEL}
                className={inputBase}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
