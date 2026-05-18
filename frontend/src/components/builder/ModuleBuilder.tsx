import React, { useState, useEffect, useRef } from "react";
import { Dialog, Section, Button, Badge, DarkInput, SectionHeader } from "@/components/ui";
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
import { useQuery } from "@tanstack/react-query";
import { graphqlRequest } from "@/lib/graphqlClient";
import {
  useCreateModuleFromTemplateMutation,
  useCreateWebhookTriggerMutation,
} from "@/generated/graphql";
import { InfoTip } from "@/components/ui/InfoTip";
import { InfoBanner } from "@/components/ui/InfoBanner";
import { ArrowLeft, Webhook, CheckCircle, X, Loader2, Sparkles, Database, Shield, Globe, Zap, Bot } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";

interface NodeTemplateDetails {
  id: string;
  name: string;
  category: string;
  description?: string;
  configSchema?: string;
  icon?: string;
}

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

  // Fetch full template details when one is selected
  const {
    data: selectedTemplate,
    isLoading: templateLoading,
    error: templateError,
  } = useQuery({
    queryKey: ["template", selectedTemplateId],
    queryFn: async () => {
      if (!selectedTemplateId) return null;

      const query = `
        query GetTemplate($id: UUID!) {
          nodeTemplate(id: $id) {
            id
            name
            category
            description
            configSchema
            icon
          }
        }
      `;
      const result = await graphqlRequest<{
        nodeTemplate: NodeTemplateDetails;
      }>(query, {
        id: selectedTemplateId,
      });

      return result.nodeTemplate;
    },
    enabled: !!selectedTemplateId,
  });

  // Apply smart defaults when template loads
  useEffect(() => {
    if (selectedTemplate && Object.keys(config).length === 0) {
      const defaults = getTemplateDefaults(
        selectedTemplate.category,
        selectedTemplate.name,
      );
      if (Object.keys(defaults).length > 0) {
        setConfig(defaults);
      }
    }
  }, [selectedTemplate]);

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
    onError: (error) => {
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
    onError: (error) => {
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
    <Dialog open={true} onClose={onClose} title="Strategic Module Architect">
      <div className="space-y-8">
        {!selectedTemplateId ? (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-700">
              <Suspense
                fallback={
                  <div className="flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/20">
                    <Loader2 className="w-10 h-10 animate-spin text-primary" />
                    <p className="text-[10px] font-black uppercase tracking-[0.3em]">Initializing Library...</p>
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
          <div className="flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/20">
            <Loader2 className="w-10 h-10 animate-spin text-primary" />
            <p className="text-[10px] font-black uppercase tracking-[0.3em]">Synthesizing Template...</p>
          </div>
        ) : templateError ? (
          <div className="p-8 bg-destructive/10 border border-destructive/20 rounded-[2.5rem] text-destructive animate-in shake duration-500 shadow-2xl glass-dark">
            <div className="flex items-start gap-4">
                <Shield className="w-6 h-6 shrink-0" />
                <div className="space-y-1">
                    <p className="text-sm font-black uppercase tracking-tight font-outfit">Template Corruption Detected</p>
                    <p className="text-[11px] font-bold opacity-60 leading-relaxed">
                        {sanitizeErrorMessage((templateError as Error).message)}
                    </p>
                </div>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => setSelectedTemplateId(null)}
              className="mt-8 w-full h-12 border-destructive/20 text-destructive hover:bg-destructive/10 rounded-2xl font-black uppercase tracking-widest text-[10px] transition-premium active:scale-95"
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
          <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Template Identity */}
            <div className="flex items-center gap-6 pb-8 border-b border-white/5 relative">
              <div className="absolute -inset-x-8 -top-8 h-32 bg-gradient-to-b from-primary/5 to-transparent pointer-events-none" />
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setSelectedTemplateId(null)}
                className="shrink-0 h-12 w-12 rounded-2xl bg-surface-2/60 border border-white/5 hover:bg-surface-3 transition-premium active:scale-90 relative z-10"
                aria-label="Back to Templates"
              >
                <ArrowLeft className="h-4 w-4 text-muted-foreground/40" />
              </Button>
              <div className="flex items-center gap-4 relative z-10">
                  <div className="flex items-center justify-center w-16 h-16 bg-surface-3/60 border border-white/10 rounded-[1.5rem] shadow-2xl relative">
                    <div className="absolute -inset-2 bg-primary/10 rounded-full blur-xl opacity-50" />
                    {selectedTemplate.icon ? (
                      <span className="text-4xl filter drop-shadow-[0_0_8px_rgba(0,0,0,0.5)] relative z-10">{selectedTemplate.icon}</span>
                    ) : (
                      <Zap className="w-8 h-8 text-primary relative z-10" />
                    )}
                  </div>
                  <div className="flex flex-col">
                    <h3 className="font-black text-white text-2xl tracking-tight font-outfit uppercase leading-none mb-1.5">
                      {selectedTemplate.name}
                    </h3>
                    <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary/60">
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
                    <label className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
                        Tactical Name
                    </label>
                  </div>
                  <div className="relative group">
                      <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
                      <DarkInput
                        type="text"
                        value={moduleName}
                        onChange={(e) => setModuleName(e.target.value)}
                        placeholder="E.G. DATA_EXTRACTION_UNIT"
                        className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-xs font-black uppercase tracking-widest rounded-2xl relative z-10 shadow-inner"
                      />
                  </div>
                </div>

                {/* Integration Specifics */}
                {selectedTemplate.category === "calendar" &&
                  selectedTemplate.name.includes("Calendar") && (
                    <div className="animate-in fade-in slide-in-from-top-4">
                        <GoogleCalendarSelector
                          onSelect={(calendarConfig) => {
                            setConfig((prev) => ({ ...prev, ...calendarConfig }));
                          }}
                        />
                    </div>
                  )}

                {selectedTemplate.configSchema && (
                  <div className="bg-surface-2/40 border border-white/5 rounded-[2.5rem] p-10 space-y-6 shadow-2xl relative overflow-hidden glass-dark">
                    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />
                    <div className="flex items-center gap-3 relative z-10 mb-6">
                        <Database className="w-4 h-4 text-primary" />
                        <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
                            Configuration Schema
                        </h3>
                    </div>
                    <div className="relative z-10 pt-8 border-t border-white/5">
                        <ConfigForm
                          schema={JSON.parse(selectedTemplate.configSchema) as JSONSchema}
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
                    <div className="absolute -inset-0.5 bg-indigo-500/10 rounded-[2.5rem] blur opacity-50 pointer-events-none" />
                    <div className="relative p-10 bg-surface-2/40 border border-white/5 rounded-[2.5rem] space-y-10 shadow-2xl glass-dark">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <Webhook className="h-5 w-5 text-indigo-400" />
                              <h3 className="text-[10px] font-black text-indigo-400 uppercase tracking-[0.3em]">
                                Webhook Orchestration
                              </h3>
                            </div>
                            <Badge className="bg-indigo-500/10 text-indigo-400 border-indigo-500/20 text-[8px] font-black px-2 py-1 uppercase tracking-widest">
                                External Ingress
                            </Badge>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                            <div className="space-y-4">
                              <label className="block text-[10px] font-black text-white/40 uppercase tracking-widest ml-1">
                                Rate Limit Threshold
                              </label>
                              <div className="relative">
                                  <DarkInput
                                    type="number"
                                    value={webhookSettings.maxRequestsPerMinute}
                                    onChange={(e) =>
                                      setWebhookSettings({
                                        ...webhookSettings,
                                        maxRequestsPerMinute: parseInt(e.target.value) || 100,
                                      })
                                    }
                                    min="1"
                                    max="1000"
                                    className="h-14 bg-surface-3/60 border-white/5 focus:border-indigo-500/40 text-xs font-black uppercase tracking-widest rounded-2xl shadow-inner"
                                  />
                                  <span className="absolute right-5 top-1/2 -translate-y-1/2 text-[9px] font-black text-muted-foreground/20 uppercase tracking-tighter">RPM</span>
                              </div>
                              <p className="text-[8px] text-muted-foreground/20 font-black uppercase tracking-widest px-2 leading-relaxed">
                                Maximum burst requests per 60s cycle. Monitor for peaks.
                              </p>
                            </div>

                            <div className="space-y-4">
                              <label className="block text-[10px] font-black text-white/40 uppercase tracking-widest ml-1">
                                Ingress Restriction (IP)
                              </label>
                              <div className="flex gap-2">
                                <DarkInput
                                  type="text"
                                  value={ipInput}
                                  onChange={(e) => setIpInput(e.target.value)}
                                  placeholder="0.0.0.0"
                                  className="flex-1 h-14 bg-surface-3/60 border-white/5 focus:border-indigo-500/40 text-xs font-black uppercase tracking-widest rounded-2xl shadow-inner"
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
                                  className="h-14 px-6 bg-indigo-500 hover:bg-indigo-400 text-white border-none rounded-2xl active:scale-95 transition-premium shadow-xl shadow-indigo-500/20"
                                >
                                  Add
                                </Button>
                              </div>
                              {webhookSettings.allowedIps.length > 0 && (
                                <div className="flex flex-wrap gap-2 pt-2">
                                  {webhookSettings.allowedIps.map((ip, index) => (
                                    <span
                                      key={ip}
                                      className="px-4 py-2 bg-surface-3/80 border border-white/10 rounded-xl text-[9px] font-black uppercase tracking-widest flex items-center gap-3 text-indigo-400 shadow-xl animate-in zoom-in-95 duration-200"
                                    >
                                      {ip}
                                      <button
                                        type="button"
                                        onClick={() => {
                                          setWebhookSettings({
                                            ...webhookSettings,
                                            allowedIps: webhookSettings.allowedIps.filter(
                                              (_, i) => i !== index,
                                            ),
                                          });
                                        }}
                                        className="text-white/20 hover:text-white transition-premium"
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
                className="h-14 px-10 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2/60 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95"
              >
                Abort Architect
              </Button>
              <Button
                onClick={() => createModuleMutation.mutate({
                  input: {
                    templateId: selectedTemplate.id,
                    name: moduleName,
                    config: JSON.stringify(config),
                  },
                })}
                disabled={!moduleName || createModuleMutation.isPending}
                className={cn(
                  "h-14 px-12 text-[10px] font-black uppercase tracking-widest transition-premium active:scale-[0.98] rounded-2xl",
                  "bg-primary hover:bg-primary/90 text-white border-none shadow-2xl shadow-primary/20 hover:shadow-primary/40",
                  (!moduleName || createModuleMutation.isPending) && "opacity-50 grayscale cursor-not-allowed"
                )}
              >
                {createModuleMutation.isPending ? (
                  <div className="flex items-center gap-3">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Deploying Unit...</span>
                  </div>
                ) : (
                  "Finalize Deployment"
                )}
              </Button>
            </div>

            {createModuleMutation.isError && (
              <div className="p-6 bg-destructive/10 border border-destructive/20 rounded-[2.5rem] text-destructive text-[10px] font-black uppercase tracking-widest text-center shadow-2xl animate-in shake duration-500 glass-dark">
                Critical Deployment Failure:{" "}
                {sanitizeErrorMessage(
                  createModuleMutation.error instanceof Error
                    ? createModuleMutation.error.message
                    : "Unknown interference"
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
    } catch (err) {
      // Failed to copy
    }
  };

  const isSlackWebhook = templateName.toLowerCase().includes("slack");

  return (
    <div className="space-y-10 animate-in fade-in slide-in-from-bottom-8 duration-1000">
      <div className="text-center relative">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 bg-success/10 rounded-full blur-[80px] animate-pulse" />
        <div className="inline-flex items-center justify-center w-24 h-24 rounded-[3rem] bg-success/10 border border-success/20 mb-10 shadow-[0_0_50px_hsla(var(--success),0.2)] relative z-10">
            <CheckCircle className="h-12 w-12 text-success" />
        </div>
        <h2 className="text-4xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-4 relative z-10">
          Uplink Established
        </h2>
        <p className="text-[10px] text-success font-black uppercase tracking-[0.5em] relative z-10">
          Strategic Ingress Vector Ready
        </p>
      </div>

      <div className="bg-surface-2/40 border border-white/5 rounded-[3rem] p-10 space-y-8 shadow-2xl relative overflow-hidden glass-dark">
        <div className="absolute inset-0 bg-gradient-to-br from-success/5 via-transparent to-transparent opacity-50 pointer-events-none" />
        <CopyField
          label="Ingress Endpoint URL"
          value={webhookUrl}
          copied={copied}
          onCopy={copyToClipboard}
        />
      </div>

      {isSlackWebhook ? (
        <div className="bg-surface-2/40 border border-white/5 rounded-[3rem] p-12 relative overflow-hidden shadow-2xl glass-dark">
          <div className="flex items-center gap-4 mb-10">
            <Webhook className="w-6 h-6 text-indigo-400" />
            <h3 className="text-[12px] font-black text-white uppercase tracking-[0.3em]">
                Slack Operational Directive
            </h3>
          </div>
          <ol className="space-y-8">
            {[
              { text: "Access the Slack API Gateway", link: "api.slack.com/apps" },
              { text: "Select your designated application" },
              { text: "Initialize Event Subscriptions" },
              { text: "Activate 'Enable Events' protocol" },
              { text: "Inject the Ingress URL into the Request field" },
              { text: "Subscribe to required bot event vectors (e.g. message.channels)" }
            ].map((step, idx) => (
              <li key={idx} className="flex gap-6 items-start group">
                <span className="shrink-0 w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-[11px] font-black text-muted-foreground/40 group-hover:text-white group-hover:border-primary/40 transition-premium shadow-lg">
                    {idx + 1}
                </span>
                <p className="text-sm font-bold text-muted-foreground/60 leading-relaxed pt-1 group-hover:text-white transition-premium">
                    {step.text} {step.link && <a href={`https://${step.link}`} target="_blank" rel="noopener noreferrer" className="text-indigo-400 underline decoration-indigo-400/20 underline-offset-4 hover:decoration-indigo-400 transition-premium ml-1">{step.link}</a>}
                </p>
              </li>
            ))}
          </ol>
        </div>
      ) : (
        <div className="bg-surface-2/40 border border-white/5 rounded-[3rem] p-12 relative overflow-hidden shadow-2xl glass-dark">
          <div className="flex items-center gap-4 mb-10">
            <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 shadow-lg">
                <Zap className="w-6 h-6 text-primary" />
            </div>
            <h3 className="text-[12px] font-black text-white uppercase tracking-[0.3em]">
                Ingress Setup Directive
            </h3>
          </div>
          <ol className="space-y-8">
            {[
              "Copy the strategic ingress URL above",
              "Configure your external emitter to send POST requests",
              "Ensure headers align with application/json protocols",
              "Initiate test transmission to verify vector stability"
            ].map((step, idx) => (
              <li key={idx} className="flex gap-6 items-start group">
                <span className="shrink-0 w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-[11px] font-black text-muted-foreground/40 group-hover:text-white group-hover:border-primary/40 transition-premium shadow-lg">
                    {idx + 1}
                </span>
                <p className="text-sm font-bold text-muted-foreground/60 leading-relaxed pt-1 group-hover:text-white transition-premium">
                    {step}
                </p>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="p-8 bg-warning/5 border border-warning/20 rounded-[2.5rem] flex items-start gap-5 glass-light">
          <div className="shrink-0 p-3 rounded-2xl bg-warning/10 border border-warning/20 shadow-lg">
              <Shield className="w-5 h-5 text-warning" />
          </div>
          <p className="text-[11px] text-warning font-bold uppercase tracking-widest leading-relaxed">
            Rate limiting and IP restrictions are active based on your tactical configuration. Monitor ingress telemetry in the Dashboard.
          </p>
      </div>

      <Button
        type="button"
        onClick={onClose}
        className="w-full h-16 bg-success hover:bg-success/90 text-white text-[12px] font-black uppercase tracking-[0.4em] rounded-[1.5rem] transition-premium shadow-2xl shadow-success/20 hover:shadow-success/40 active:scale-[0.98]"
      >
        Acknowledge Deployment
      </Button>
    </div>
  );
}
