import React, { useState, useEffect, useRef } from "react";
import { Spinner } from "@/components/ui/spinner";
import { Input } from "@/components/ui/input";
import { Dialog, Button, Badge } from "@/components/ui";
import { CopyField } from "@/components/ui/CopyField";
import { lazy, Suspense } from "react";
const TemplateLibrary = lazy(() =>
  import("@/components/templates/TemplateLibrary").then((module) => ({
    default: module.TemplateLibrary,
  })),
);
import { ConfigForm, type JSONSchema } from "./ConfigForm";
import { GoogleCalendarSelector } from "./GoogleCalendarSelector";
import { toast } from "sonner";
import { getTemplateDefaults } from "@/lib/smartConfig";
import {
  useCreateModuleFromTemplateMutation,
  useCreateWebhookTriggerMutation,
  useGetNodeTemplateQuery,
} from "@/generated/graphql";
import {
  ArrowLeft,
  Webhook,
  CheckCircle,
  X,
  Database,
  Shield,
  Zap,
  Bot,
} from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";

interface ModuleBuilderProps {
  open: boolean;
  onClose: () => void;
  onModuleCreated: (
    moduleId: string,
    moduleName: string,
    config: string,
    category: string,
  ) => void;
}

export function ModuleBuilder({
  open,
  onClose,
  onModuleCreated,
}: ModuleBuilderProps) {
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(
    null,
  );
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [moduleName, setModuleName] = useState("");
  const [webhookSettings, setWebhookSettings] = useState({
    maxRequestsPerMinute: 100,
    allowedIps: [] as string[],
  });
  const [createdWebhook, setCreatedWebhook] = useState<{
    id: string;
    url: string;
  } | null>(null);
  const [ipInput, setIpInput] = useState("");

  // Fetch full template details when one is selected. The generated hook
  // returns `{ nodeTemplate }`; map it to the flat `selectedTemplate` shape
  // the rest of the component consumes.
  const {
    data: templateData,
    isLoading: templateLoading,
    error: templateError,
  } = useGetNodeTemplateQuery(
    { id: selectedTemplateId ?? "" },
    { enabled: !!selectedTemplateId },
  );
  const selectedTemplate = templateData?.nodeTemplate ?? null;

  // Apply smart defaults once a freshly-selected template's details
  // arrive. Done during render via the "store information from previous
  // renders" pattern (https://react.dev/learn/you-might-not-need-an-effect)
  // rather than an effect, so it doesn't cascade an extra committed
  // render (react-hooks/set-state-in-effect). The `appliedDefaultsFor`
  // guard makes it fire at most once per template id and breaks the
  // render loop when a template has no defaults.
  const [appliedDefaultsFor, setAppliedDefaultsFor] = useState<string | null>(
    null,
  );
  if (
    selectedTemplate &&
    selectedTemplate.id !== appliedDefaultsFor &&
    Object.keys(config).length === 0
  ) {
    setAppliedDefaultsFor(selectedTemplate.id);
    const defaults = getTemplateDefaults(
      selectedTemplate.category,
      selectedTemplate.name,
    );
    if (Object.keys(defaults).length > 0) {
      setConfig(defaults);
    }
  }

  const isWebhookTemplate =
    selectedTemplate?.category === "webhook" ||
    selectedTemplate?.name?.toLowerCase().includes("webhook");

  const createModuleMutation = useCreateModuleFromTemplateMutation({
    onSuccess: (data) => {
      const moduleId = data.createModuleFromTemplate.id;
      if (isWebhookTemplate) {
        createWebhookMutation.mutate({
          input: {
            moduleId: moduleId,
            name: moduleName,
            enabled: true,
            maxRequestsPerMinute: webhookSettings.maxRequestsPerMinute,
            allowedIps:
              webhookSettings.allowedIps.length > 0
                ? webhookSettings.allowedIps
                : null,
          },
        });
      } else {
        onModuleCreated(
          moduleId,
          moduleName,
          JSON.stringify(config),
          selectedTemplate?.category || "general",
        );
        resetAndClose();
      }
    },
    onError: () => {
      // Error handled by UI
    },
  });

  const createWebhookMutation = useCreateWebhookTriggerMutation({
    onSuccess: (data) => {
      const moduleId = createModuleMutation.data?.createModuleFromTemplate.id;
      if (!moduleId) return;

      onModuleCreated(
        moduleId,
        moduleName,
        JSON.stringify(config),
        selectedTemplate?.category || "general",
      );

      setCreatedWebhook({
        id: data.createWebhookTrigger.id,
        url: data.createWebhookTrigger.webhookUrl,
      });
    },
    onError: () => {
      toast.error("Failed to create webhook trigger");
    },
  });

  const resetAndClose = () => {
    setSelectedTemplateId(null);
    setConfig({});
    setModuleName("");
    setWebhookSettings({
      maxRequestsPerMinute: 100,
      allowedIps: [],
    });
    setCreatedWebhook(null);
    setIpInput("");
    onClose();
  };

  if (!open) return null;

  return (
    <Dialog open={true} onClose={onClose} title="Module builder">
      <div className="space-y-8">
        {!selectedTemplateId ? (
          <div>
            <Suspense
              fallback={
                <div className="flex flex-col items-center justify-center py-16 gap-4 text-muted-foreground/50">
                  <Spinner className="w-10 h-10 text-primary" />
                  <p className="text-xs font-semibold">
                    Initializing Library...
                  </p>
                </div>
              }
            >
              <TemplateLibrary
                onSelect={(template: { id: string }) =>
                  setSelectedTemplateId(template.id)
                }
              />
            </Suspense>
          </div>
        ) : templateLoading ? (
          <div className="flex flex-col items-center justify-center py-16 gap-4 text-muted-foreground/50">
            <Spinner className="w-10 h-10 text-primary" />
            <p className="text-xs font-semibold">Loading template…</p>
          </div>
        ) : templateError ? (
          <div className="p-8 bg-destructive/10 border border-destructive/20 rounded-2xl text-destructive bg-surface-3 border border-white/10">
            <div className="flex items-start gap-4">
              <Shield className="w-6 h-6 shrink-0" />
              <div className="space-y-1">
                <p className="text-sm font-semibold tracking-tight font-outfit">
                  Template Corruption Detected
                </p>
                <p className="text-xs font-bold opacity-60 leading-relaxed">
                  {sanitizeErrorMessage((templateError as Error).message)}
                </p>
              </div>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => setSelectedTemplateId(null)}
              className="mt-8 w-full h-12 border-destructive/20 text-destructive hover:bg-destructive/10 rounded-2xl font-semibold text-sm transition-ui"
            >
              <ArrowLeft className="h-3.5 w-3.5 mr-2" /> Return to Library
            </Button>
          </div>
        ) : createdWebhook ? (
          <WebhookSuccessView
            webhookUrl={createdWebhook.url}
            templateName={selectedTemplate?.name || ""}
            onClose={resetAndClose}
          />
        ) : selectedTemplate ? (
          <div className="space-y-10">
            {/* Template Identity */}
            <div className="flex items-center gap-6 pb-8 border-b border-white/5 relative">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setSelectedTemplateId(null)}
                className="shrink-0 h-12 w-12 rounded-2xl bg-surface-2/60 border border-white/5 hover:bg-surface-3 transition-ui relative z-10"
                aria-label="Back to Templates"
              >
                <ArrowLeft className="h-4 w-4 text-muted-foreground/70" />
              </Button>
              <div className="flex items-center gap-4 relative z-10">
                <div className="flex items-center justify-center w-16 h-16 bg-surface-3/60 border border-white/10 rounded-2xl relative">
                  {selectedTemplate.icon ? (
                    <span className="text-2xl relative z-10">
                      {selectedTemplate.icon}
                    </span>
                  ) : (
                    <Zap className="w-8 h-8 text-primary relative z-10" />
                  )}
                </div>
                <div className="flex flex-col">
                  <h3 className="font-semibold text-white text-2xl font-outfit leading-none mb-1.5">
                    {selectedTemplate.name}
                  </h3>
                  <span className="text-xs font-semibold text-primary/60">
                    {selectedTemplate.category} ARCHITECTURE
                  </span>
                </div>
              </div>
            </div>

            {/* Core Settings */}
            <div className="space-y-10">
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1">
                  <Bot className="w-4 h-4 text-primary" />
                  <label className="text-xs font-semibold text-white">
                    Module name
                  </label>
                </div>
                <div className="relative group">
                  <Input
                    type="text"
                    value={moduleName}
                    onChange={(e) => setModuleName(e.target.value)}
                    placeholder="e.g. data-extractor"
                    className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10"
                  />
                </div>
              </div>

              {/* Integration Specifics */}
              {selectedTemplate.category === "calendar" &&
                selectedTemplate.name.includes("Calendar") && (
                  <div>
                    <GoogleCalendarSelector
                      onSelect={(calendarConfig) => {
                        setConfig((prev) => ({ ...prev, ...calendarConfig }));
                      }}
                    />
                  </div>
                )}

              {selectedTemplate.configSchema && (
                <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-10 space-y-6 relative overflow-hidden bg-surface-3 border border-white/10">
                  <div className="flex items-center gap-3 relative z-10 mb-6">
                    <Database className="w-4 h-4 text-primary" />
                    <h3 className="text-xs font-semibold text-white">
                      Configuration Schema
                    </h3>
                  </div>
                  <div className="relative z-10 pt-8 border-t border-white/5">
                    <ConfigForm
                      schema={
                        JSON.parse(selectedTemplate.configSchema) as JSONSchema
                      }
                      value={config}
                      onChange={setConfig}
                      category={selectedTemplate.category}
                      templateName={selectedTemplate.name}
                    />
                  </div>
                </div>
              )}

              {isWebhookTemplate && (
                <div className="relative group/webhook">
                  <div className="relative p-10 bg-surface-2/40 border border-white/5 rounded-2xl space-y-10 bg-surface-3 border border-white/10">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Webhook className="h-5 w-5 text-primary" />
                        <h3 className="text-xs font-semibold text-primary">
                          Webhook Orchestration
                        </h3>
                      </div>
                      <Badge className="bg-primary/10 text-primary border-primary/20 text-2xs font-semibold px-2 py-1 uppercase tracking-wider">
                        Receives webhooks
                      </Badge>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-4">
                        <label className="block text-xs font-semibold text-white/70 ml-1">
                          Rate Limit Threshold
                        </label>
                        <div className="relative">
                          <Input
                            type="number"
                            value={webhookSettings.maxRequestsPerMinute}
                            onChange={(e) =>
                              setWebhookSettings({
                                ...webhookSettings,
                                maxRequestsPerMinute:
                                  parseInt(e.target.value) || 100,
                              })
                            }
                            min="1"
                            max="1000"
                            className="h-14 bg-surface-3/60 border-white/5 focus:border-primary/40 text-sm font-semibold rounded-2xl"
                          />
                          <span className="absolute right-5 top-1/2 -translate-y-1/2 text-xs font-medium text-muted-foreground/50">
                            requests/min
                          </span>
                        </div>
                        <p className="text-2xs text-muted-foreground/50 px-2 leading-relaxed">
                          Maximum burst requests per 60s cycle. Monitor for
                          peaks.
                        </p>
                      </div>

                      <div className="space-y-4">
                        <label className="block text-xs font-semibold text-white/70 ml-1">
                          Ingress Restriction (IP)
                        </label>
                        <div className="flex gap-2">
                          <Input
                            type="text"
                            value={ipInput}
                            onChange={(e) => setIpInput(e.target.value)}
                            placeholder="0.0.0.0"
                            className="flex-1 h-14 bg-surface-3/60 border-white/5 focus:border-primary/40 text-sm font-semibold rounded-2xl"
                            onKeyDown={(e) => {
                              if (e.key === "Enter" && ipInput.trim()) {
                                setWebhookSettings({
                                  ...webhookSettings,
                                  allowedIps: [
                                    ...webhookSettings.allowedIps,
                                    ipInput.trim(),
                                  ],
                                });
                                setIpInput("");
                              }
                            }}
                          />
                          <Button
                            type="button"
                            onClick={() => {
                              if (ipInput.trim()) {
                                setWebhookSettings({
                                  ...webhookSettings,
                                  allowedIps: [
                                    ...webhookSettings.allowedIps,
                                    ipInput.trim(),
                                  ],
                                });
                                setIpInput("");
                              }
                            }}
                            className="h-14 px-6 bg-primary hover:bg-primary/90 text-white border-none rounded-2xl transition-ui"
                          >
                            Add
                          </Button>
                        </div>
                        {webhookSettings.allowedIps.length > 0 && (
                          <div className="flex flex-wrap gap-2 pt-2">
                            {webhookSettings.allowedIps.map((ip, index) => (
                              <span
                                key={ip}
                                className="px-4 py-2 bg-surface-3/80 border border-white/10 rounded-xl text-2xs font-semibold uppercase tracking-wider flex items-center gap-3 text-primary"
                              >
                                {ip}
                                <button
                                  type="button"
                                  aria-label="Remove IP address"
                                  onClick={() => {
                                    setWebhookSettings({
                                      ...webhookSettings,
                                      allowedIps:
                                        webhookSettings.allowedIps.filter(
                                          (_, i) => i !== index,
                                        ),
                                    });
                                  }}
                                  className="text-white/50 hover:text-white transition-ui"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-4 pt-8 border-t border-white/5 relative z-10">
              <Button
                variant="ghost"
                onClick={onClose}
                className="h-14 px-10 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2/60 hover:bg-surface-3 rounded-2xl border border-white/5"
              >
                Cancel
              </Button>
              <Button
                onClick={() =>
                  createModuleMutation.mutate({
                    input: {
                      templateId: selectedTemplate.id,
                      name: moduleName,
                      config: JSON.stringify(config),
                    },
                  })
                }
                disabled={!moduleName || createModuleMutation.isPending}
                className={cn(
                  "h-12 px-6 text-sm font-semibold transition-ui rounded-2xl",
                  "bg-primary hover:bg-primary/90 text-white border-none",
                  (!moduleName || createModuleMutation.isPending) &&
                    "opacity-50 grayscale cursor-not-allowed",
                )}
              >
                {createModuleMutation.isPending ? (
                  <div className="flex items-center gap-3">
                    <Spinner className="w-4 h-4" />
                    <span>Deploying Unit...</span>
                  </div>
                ) : (
                  "Finalize Deployment"
                )}
              </Button>
            </div>

            {createModuleMutation.isError && (
              <div className="p-6 bg-destructive/10 border border-destructive/20 rounded-2xl text-destructive text-xs font-semibold text-center bg-surface-3 border border-white/10">
                Critical Deployment Failure:{" "}
                {sanitizeErrorMessage(
                  createModuleMutation.error instanceof Error
                    ? createModuleMutation.error.message
                    : "Unknown interference",
                )}
              </div>
            )}
          </div>
        ) : null}
      </div>
    </Dialog>
  );
}

function WebhookSuccessView({
  webhookUrl,
  templateName,
  onClose,
}: {
  webhookUrl: string;
  templateName: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  // MCP-903 (2026-05-14): track the copy-feedback timer so an unmount
  // mid-flight (Dialog close 0–2s after copy click) doesn't fire
  // setState on an unmounted component. Same pattern as MCP-893
  // (Google/Gmail watch-channel flash timers).
  const copyTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current !== null) {
        window.clearTimeout(copyTimeoutRef.current);
        copyTimeoutRef.current = null;
      }
    };
  }, []);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(webhookUrl);
      setCopied(true);
      toast.success("Webhook URL copied to clipboard");
      if (copyTimeoutRef.current !== null) {
        window.clearTimeout(copyTimeoutRef.current);
      }
      copyTimeoutRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimeoutRef.current = null;
      }, 2000);
    } catch {
      // Failed to copy
    }
  };

  const isSlackWebhook = templateName.toLowerCase().includes("slack");

  return (
    <div className="space-y-10">
      <div className="text-center relative">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-success/10 border border-success/20 mb-6 relative z-10">
          <CheckCircle className="h-12 w-12 text-success" />
        </div>
        <h2 className="text-2xl font-semibold text-white tracking-tight font-outfit leading-none mb-4 relative z-10">
          Webhook ready
        </h2>
        <p className="text-xs text-success font-semibold tracking-[0.5em] relative z-10">
          Incoming requests will start this workflow
        </p>
      </div>

      <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-10 space-y-8 relative overflow-hidden bg-surface-3 border border-white/10">
        <CopyField
          label="Ingress Endpoint URL"
          value={webhookUrl}
          copied={copied}
          onCopy={copyToClipboard}
        />
      </div>

      {isSlackWebhook ? (
        <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-12 relative overflow-hidden bg-surface-3 border border-white/10">
          <div className="flex items-center gap-4 mb-6">
            <Webhook className="w-6 h-6 text-primary" />
            <h3 className="text-xs font-semibold text-white">
              Set up Slack events
            </h3>
          </div>
          <ol className="space-y-8">
            {[
              {
                text: "Open the Slack API site",
                link: "api.slack.com/apps",
              },
              { text: "Select your app" },
              { text: "Open Event Subscriptions" },
              { text: "Turn on 'Enable Events'" },
              { text: "Paste the webhook URL into the Request URL field" },
              {
                text: "Subscribe to the bot events you need (e.g. message.channels)",
              },
            ].map((step, idx) => (
              <li key={idx} className="flex gap-6 items-start group">
                <span className="shrink-0 w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-xs font-semibold text-muted-foreground/70 group-hover:text-white group-hover:border-primary/40 transition-ui">
                  {idx + 1}
                </span>
                <p className="text-sm font-bold text-muted-foreground/60 leading-relaxed pt-1 group-hover:text-white transition-ui">
                  {step.text}{" "}
                  {step.link && (
                    <a
                      href={`https://${step.link}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary underline decoration-primary/20 underline-offset-4 hover:decoration-primary transition-ui ml-1"
                    >
                      {step.link}
                    </a>
                  )}
                </p>
              </li>
            ))}
          </ol>
        </div>
      ) : (
        <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-12 relative overflow-hidden bg-surface-3 border border-white/10">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20">
              <Zap className="w-6 h-6 text-primary" />
            </div>
            <h3 className="text-xs font-semibold text-white">
              Set up the sender
            </h3>
          </div>
          <ol className="space-y-8">
            {[
              "Copy the webhook URL above",
              "Configure the sending service to POST to it",
              "Send the body as application/json",
              "Send a test request to confirm it arrives",
            ].map((step, idx) => (
              <li key={idx} className="flex gap-6 items-start group">
                <span className="shrink-0 w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-xs font-semibold text-muted-foreground/70 group-hover:text-white group-hover:border-primary/40 transition-ui">
                  {idx + 1}
                </span>
                <p className="text-sm font-bold text-muted-foreground/60 leading-relaxed pt-1 group-hover:text-white transition-ui">
                  {step}
                </p>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="p-8 bg-warning/5 border border-warning/20 rounded-2xl flex items-start gap-5 bg-white/[0.03] border border-white/5">
        <div className="shrink-0 p-3 rounded-2xl bg-warning/10 border border-warning/20">
          <Shield className="w-5 h-5 text-warning" />
        </div>
        <p className="text-xs text-warning leading-relaxed">
          Rate limits and IP restrictions apply as configured. Incoming requests
          show up in the Dashboard.
        </p>
      </div>

      <Button
        type="button"
        onClick={onClose}
        className="w-full h-16 bg-success hover:bg-success/90 text-success-foreground text-sm font-semibold rounded-2xl transition-ui"
      >
        Acknowledge Deployment
      </Button>
    </div>
  );
}
