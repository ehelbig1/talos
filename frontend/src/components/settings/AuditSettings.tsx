import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { toast } from "sonner";
import {
  useGetAuditSettingsQuery,
  useUpdateAuditSettingsMutation,
} from "@/generated/graphql";
import {
  Shield,
  Activity,
  Database,
  Lock,
  Settings2,
  ArrowRight,
  Server,
  CloudUpload,
  Check,
  Zap,
  Globe,
  Loader2,
} from "lucide-react";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

export default function AuditSettings() {
  const queryClient = useQueryClient();

  const { data, isLoading } = useGetAuditSettingsQuery();

  const [enabled, setEnabled] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [protocol, setProtocol] = useState("grpc");
  const [headers, setHeaders] = useState("");

  // Seed the editable form from the fetched settings whenever the query
  // result changes (initial load + post-save refetch). Done during render
  // via the "store information from previous renders" pattern
  // (https://react.dev/learn/you-might-not-need-an-effect) instead of a
  // setState-in-effect, so it doesn't cascade an extra committed render.
  const [lastData, setLastData] = React.useState(data);
  if (data !== lastData) {
    setLastData(data);
    if (data?.auditSettings) {
      setEnabled(data.auditSettings.streamingEnabled);
      setEndpoint(data.auditSettings.otlpEndpoint || "");
      setProtocol(data.auditSettings.otlpProtocol || "grpc");
    }
  }

  const {
    mutate: updateSettings,
    isPending: saving,
    isSuccess: isUpdated,
  } = useUpdateAuditSettingsMutation({
    onSuccess: () => {
      toast.success("Audit settings updated successfully.");
      queryClient.invalidateQueries({ queryKey: ["GetAuditSettings"] });
      setHeaders("");
    },
    onError: () => {
      toast.error("Failed to update audit settings.");
    },
  });

  const handleSave = () => {
    updateSettings({
      enabled,
      endpoint: endpoint || null,
      protocol: protocol,
      headers: headers ? headers : null,
    });
  };

  if (isLoading)
    return (
      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="space-y-6">
          <div className="h-32 bg-white/[0.02] border border-white/5 rounded-[2rem]" />
          <div className="grid grid-cols-2 gap-6">
            <div className="h-20 bg-white/[0.02] border border-white/5 rounded-2xl" />
            <div className="h-20 bg-white/[0.02] border border-white/5 rounded-2xl" />
          </div>
        </div>
      </div>
    );

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Header */}
      <div className="flex items-center gap-6">
        <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[2rem] flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] group">
          <Shield className="w-8 h-8 text-primary group-hover:scale-110 transition-premium" />
        </div>
        <div>
          <SectionHeader
            level="h2"
            className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-1"
          >
            Audit Streaming
          </SectionHeader>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-primary bg-primary/5 px-3 py-1 rounded-full border border-primary/20">
              Enterprise_Protocol
            </span>
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40">
              OpenTelemetry_Pipeline
            </span>
          </div>
        </div>
      </div>

      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

        <div className="relative z-10">
          <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed mb-10 max-w-2xl">
            Stream zero-trust AI execution logs directly into your existing SIEM
            using secure OpenTelemetry pipelines. Every execution is signed and
            non-repudiable.
          </p>

          <div className="bg-black/40 border border-white/5 rounded-[2rem] p-8 transition-premium group/box">
            <div className="flex items-center justify-between mb-10">
              <div className="flex items-center gap-6">
                <div
                  className={cn(
                    "w-14 h-14 rounded-2xl flex items-center justify-center transition-premium shadow-2xl",
                    enabled
                      ? "bg-success/10 border border-success/20 text-success"
                      : "bg-white/5 border border-white/10 text-muted-foreground/20",
                  )}
                >
                  <CloudUpload className="w-7 h-7" />
                </div>
                <div>
                  <h4 className="text-xl font-black text-white tracking-tight uppercase font-outfit">
                    Real-time Propagation
                  </h4>
                  <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest mt-1">
                    Toggle audit log streaming via OTLP
                  </p>
                </div>
              </div>

              <button
                type="button"
                role="switch"
                aria-checked={enabled}
                aria-label="Toggle audit log streaming"
                onClick={() => setEnabled(!enabled)}
                className={cn(
                  "relative inline-flex h-8 w-14 items-center rounded-full transition-premium focus:outline-none ring-offset-black",
                  enabled
                    ? "bg-success shadow-[0_0_20px_hsla(var(--success),0.4)]"
                    : "bg-white/10",
                )}
              >
                <span
                  className={cn(
                    "inline-block h-6 w-6 transform rounded-full bg-white transition-transform shadow-lg",
                    enabled ? "translate-x-7" : "translate-x-1",
                  )}
                />
              </button>
            </div>

            {enabled && (
              <div className="space-y-8 animate-in fade-in slide-in-from-top-4 duration-500">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-8 border-t border-white/5">
                  <div className="space-y-3">
                    <Label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 flex items-center gap-2 ml-1">
                      <Server className="w-3.5 h-3.5 text-primary" />
                      Collector_Endpoint
                    </Label>
                    <Input
                      value={endpoint}
                      onChange={(e) => setEndpoint(e.target.value)}
                      placeholder="https://otel-collector.internal:4317"
                      className="h-14 bg-black/40 border-white/5 rounded-2xl text-xs font-mono text-white placeholder:text-muted-foreground/20 focus:ring-primary/20 transition-premium shadow-inner"
                    />
                  </div>

                  <div className="space-y-3">
                    <Label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 flex items-center gap-2 ml-1">
                      <Settings2 className="w-3.5 h-3.5 text-primary" />
                      Transport_Protocol
                    </Label>
                    <div className="relative">
                      <select
                        value={protocol}
                        onChange={(e) => setProtocol(e.target.value)}
                        className="w-full h-14 px-6 bg-black/40 border border-white/5 rounded-2xl text-xs font-mono text-white focus:outline-none focus:ring-4 focus:ring-primary/10 transition-premium appearance-none cursor-pointer hover:bg-black/60 shadow-inner"
                      >
                        {/* MCP-866 (2026-05-14): only gRPC is wired through
                            talos-audit-ledger today. HTTP/Protobuf was offered
                            here but the backend always built with_tonic()
                            regardless, so selecting it silently kept gRPC. Will
                            reinstate when the HTTP exporter branch lands. */}
                        <option value="grpc">gRPC (Binary/Protobuf)</option>
                      </select>
                      <div className="absolute right-6 top-1/2 -translate-y-1/2 pointer-events-none text-muted-foreground/40">
                        <ArrowRight className="w-4 h-4 rotate-90" />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <Label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 flex items-center gap-2 ml-1">
                    <Lock className="w-3.5 h-3.5 text-primary" />
                    Authentication_Headers (JSON_VOLATILE)
                  </Label>
                  <Textarea
                    value={headers}
                    onChange={(e) => setHeaders(e.target.value)}
                    placeholder='{ "Authorization": "Bearer ...", "x-team-id": "..." }'
                    className="bg-black/40 border-white/5 text-white placeholder:text-muted-foreground/20 rounded-2xl min-h-[120px] font-mono text-xs resize-none focus:ring-primary/20 transition-premium border-dashed shadow-inner p-6"
                  />
                  <div className="flex items-center gap-3 px-1 mt-2">
                    <div className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
                    <p className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-widest">
                      Headers are AES-256-GCM encrypted before vault commit.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="flex justify-end mt-10">
            <Button
              onClick={handleSave}
              disabled={saving}
              variant="premium"
              className="h-16 px-12 rounded-2xl shadow-2xl"
            >
              {saving ? (
                <div className="flex items-center gap-3">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>SYNCING_CONFIG...</span>
                </div>
              ) : isUpdated ? (
                <div className="flex items-center gap-3">
                  <Check className="w-5 h-5 text-success" />
                  <span>CONFIG_SYNCHRONIZED</span>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <CloudUpload className="w-5 h-5" />
                  <span>UPDATE_AUDIT_PROTOCOL</span>
                </div>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-surface-3/40 border border-white/5 rounded-[2.5rem] p-8 flex items-start gap-6 hover:border-white/10 transition-premium group">
        <div className="w-14 h-14 bg-primary/5 border border-primary/10 rounded-2xl flex items-center justify-center shrink-0 group-hover:bg-primary/10 transition-premium shadow-inner">
          <Database className="w-7 h-7 text-primary" />
        </div>
        <div className="space-y-2">
          <h4 className="text-lg font-black text-white uppercase tracking-tight font-outfit">
            Persistence & Isolation
          </h4>
          <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest max-w-3xl">
            Talos automatically buffers audit events locally during network
            partitions. Once the OTLP collector is reachable, buffered logs are
            flushed in chronological order to maintain strict causality and
            compliance.
          </p>
        </div>
      </div>
    </div>
  );
}
