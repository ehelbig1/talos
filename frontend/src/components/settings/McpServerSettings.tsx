import React, { useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { CopyField } from "@/components/ui/CopyField";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import type { McpAgent } from "@/lib/graphqlApi";
import { listMcpAgents, revokeMcpAgent } from "@/lib/graphqlApi";
import { gql } from "@/lib/graphqlClient";
import type { RegisterMcpAgentMutation } from "@/generated/graphql";
import { useRegisterMcpAgentMutation } from "@/generated/graphql";

export const REGISTER_MCP_AGENT = gql`
  mutation RegisterMcpAgent($name: String!, $role: String!) {
    registerMcpAgent(name: $name, roleName: $role) {
      agentId
      name
      token
      role
    }
  }
`;
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Monitor,
  Bot,
  Info,
  Terminal,
  Shield,
  Copy,
  Check,
  ChevronRight,
  Server,
  Zap,
  UserCheck,
  Trash2,
  Calendar,
  Clock,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";

const AVAILABLE_ROLES = [
  { name: "System Administrator", desc: "Full access to all capabilities" },
  { name: "DevOps Auto-Remediation", desc: "HTTP, network, and messaging" },
  { name: "Financial Analyst", desc: "Database access only" },
  { name: "Human Resources", desc: "Filesystem and database" },
];

export default function McpServerSettings() {
  const { copy, copied } = useCopyToClipboard();
  const [pluginName, setPluginName] = useState("");
  const [selectedRole, setSelectedRole] = useState("System Administrator");
  const [createdAgent, setCreatedAgent] = useState<
    RegisterMcpAgentMutation["registerMcpAgent"] | null
  >(null);
  const queryClient = useQueryClient();
  // Agents are fetched via react-query so loading/data is derived rather
  // than mirrored through a setState-in-effect. `refetch` is used after a
  // successful registration; the revoke path updates the cache optimistically.
  const {
    data: agents = [],
    isLoading: loading,
    isError: agentsError,
    refetch: refetchAgents,
  } = useQuery<McpAgent[]>({
    queryKey: ["mcpAgents"],
    queryFn: listMcpAgents,
  });
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeConfirmId, setRevokeConfirmId] = useState<string | null>(null);

  const baseUrl = window.location.origin
    .replace(":3002", ":8000")
    .replace(":5173", ":8000");
  const localEndpoint = `${baseUrl}/mcp/local`;
  const authEndpoint = `${baseUrl}/mcp`;

  // Surface load failures as a toast (fetch + retry owned by react-query).
  // No setState here, so it stays a pure side-effect synchronization.
  useEffect(() => {
    if (agentsError) toast.error("Failed to load active protocol agents");
  }, [agentsError]);

  const { mutate: registerAgent, isPending: creating } =
    useRegisterMcpAgentMutation({
      onSuccess: (data: RegisterMcpAgentMutation) => {
        if (data.registerMcpAgent) {
          setCreatedAgent(data.registerMcpAgent);
          setPluginName("");
          refetchAgents();
          toast.success("MCP Protocol Agent provisioned successfully");
        }
      },
      onError: (err: Error) => {
        toast.error(
          sanitizeErrorMessage(err.message || "Failed to provision agent"),
        );
      },
    });

  const handleCreatePlugin = () => {
    if (!pluginName.trim()) {
      toast.error("Protocol identifier required");
      return;
    }
    registerAgent({ name: pluginName.trim(), role: selectedRole });
  };

  const handleRevoke = (id: string) => {
    setRevokeConfirmId(id);
  };

  const executeRevoke = async () => {
    const id = revokeConfirmId;
    if (!id) return;
    setRevokeConfirmId(null);
    try {
      setRevokingId(id);
      const success = await revokeMcpAgent(id);
      if (success) {
        toast.success("Agent protocol access revoked");
        // Optimistically drop the revoked agent from the query cache.
        queryClient.setQueryData<McpAgent[]>(["mcpAgents"], (prev) =>
          (prev ?? []).filter((a) => a.id !== id),
        );
      } else {
        toast.error("Revocation sequence failed");
      }
    } catch {
      toast.error("Security violation during revocation");
    } finally {
      setRevokingId(null);
    }
  };

  const inputBase =
    "w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-xs font-black uppercase tracking-widest text-white placeholder:text-muted-foreground/20 focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium shadow-inner";
  const selectBase =
    "w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-xs font-black uppercase tracking-widest text-white focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium shadow-inner appearance-none cursor-pointer";

  return (
    <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-1000 max-w-7xl mx-auto">
      <ConfirmDialog
        open={revokeConfirmId !== null}
        title="Protocol Revocation"
        message="TERMINATE AGENT ACCESS? ALL ACTIVE MODEL CONTEXT SESSIONS WILL BE SEVERED IMMEDIATELY."
        confirmLabel="TERMINATE_PROTOCOL"
        destructive
        onConfirm={executeRevoke}
        onCancel={() => setRevokeConfirmId(null)}
      />

      <div className="bg-surface-3/30 border border-white/5 rounded-[3rem] p-10 shadow-2xl backdrop-blur-3xl relative overflow-hidden group/header">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-50 pointer-events-none transition-premium group-hover/header:opacity-100" />

        <div className="flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[1.5rem] flex items-center justify-center text-primary shadow-[0_0_30px_hsla(var(--primary),0.1)] group-hover/header:scale-110 transition-premium">
              <Monitor size={32} />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-2xl md:text-3xl font-black text-white tracking-tighter uppercase leading-tight">
                Model Context Protocol
              </h2>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  <span className="text-[9px] text-primary font-black uppercase tracking-widest leading-none">
                    Active_MCP_Uplink
                  </span>
                </div>
                <div className="w-1 h-1 rounded-full bg-white/10" />
                <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em] leading-none">
                  Cross-Model Operational Sync Layer
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex flex-col items-end gap-1">
              <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                SCHEMA_VERSION
              </span>
              <code className="text-[11px] font-mono text-primary font-bold">
                V1.2.0-STABLE
              </code>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Form & Endpoints */}
        <div className="lg:col-span-1 space-y-8">
          <div className="bg-surface-3/30 border border-white/5 rounded-[2.5rem] p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-50" />

            <div className="flex items-center gap-3 mb-8 relative z-10">
              <Shield className="w-4 h-4 text-primary" />
              <h4 className="text-[11px] font-black uppercase tracking-[0.3em] text-white/40">
                Agent_Provisioning
              </h4>
            </div>

            <div className="space-y-6 relative z-10">
              <div className="space-y-2.5">
                <label className="text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30 ml-1">
                  Protocol Identifier
                </label>
                <div className="relative group/input">
                  <Bot className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/20 group-focus-within/input:text-primary transition-premium" />
                  <input
                    type="text"
                    placeholder="ENTER_AGENT_ALIAS..."
                    value={pluginName}
                    onChange={(e) => setPluginName(e.target.value)}
                    className={cn(inputBase, "pl-14")}
                  />
                </div>
              </div>

              <div className="space-y-2.5">
                <label className="text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30 ml-1">
                  Operational Role
                </label>
                <div className="relative group/input">
                  <UserCheck className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/20 group-focus-within/input:text-primary transition-premium pointer-events-none" />
                  <select
                    value={selectedRole}
                    onChange={(e) => setSelectedRole(e.target.value)}
                    className={cn(selectBase, "pl-14")}
                  >
                    {AVAILABLE_ROLES.map((r) => (
                      <option
                        key={r.name}
                        value={r.name}
                        className="bg-surface-3"
                      >
                        {r.name.toUpperCase()}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <Button
                onClick={handleCreatePlugin}
                disabled={creating || !pluginName.trim()}
                variant="premium"
                className="w-full h-14 rounded-2xl shadow-2xl shadow-primary/20"
              >
                {creating ? (
                  <div className="flex items-center gap-3">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>SYNTHESIZING...</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <Zap className="w-4 h-4" />
                    <span>PROVISION_AGENT</span>
                  </div>
                )}
              </Button>

              {createdAgent && (
                <div className="mt-6 p-6 bg-primary/5 border border-primary/20 rounded-[2rem] space-y-4 animate-in zoom-in-95 duration-500 relative overflow-hidden group/token">
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent opacity-50" />
                  <div className="flex items-center gap-3 text-primary relative z-10">
                    <Check className="w-4 h-4" />
                    <span className="text-[9px] font-black uppercase tracking-widest">
                      Protocol_Token_Synthesized
                    </span>
                  </div>
                  <div className="relative z-10">
                    <CopyField
                      label="BEARER_TOKEN"
                      value={createdAgent.token}
                      copied={copied}
                      onCopy={() => copy(createdAgent.token)}
                      className="bg-black/60 border-primary/10 text-primary rounded-xl font-mono"
                    />
                  </div>
                  <p className="text-[8px] text-primary/40 font-black uppercase tracking-widest text-center leading-relaxed relative z-10">
                    Credential will be purged from volatile memory upon closure.
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-surface-3/30 border border-white/5 rounded-[2.5rem] p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden">
            <div className="flex items-center gap-3 mb-8">
              <Server className="w-4 h-4 text-primary" />
              <h4 className="text-[11px] font-black uppercase tracking-[0.3em] text-white/40">
                Uplink_Endpoints
              </h4>
            </div>

            <div className="space-y-4">
              <div className="p-5 bg-black/40 border border-white/5 rounded-2xl space-y-3 shadow-inner group">
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30">
                    Local_Dev
                  </span>
                  <span className="text-[8px] font-black uppercase px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                    NO_AUTH
                  </span>
                </div>
                <code className="text-[10px] font-mono text-primary/60 block truncate">
                  {localEndpoint}
                </code>
                <button
                  onClick={() => {
                    copy(localEndpoint);
                    toast.success("Local endpoint copied");
                  }}
                  className="w-full py-2 text-[9px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white hover:bg-white/5 rounded-lg border border-white/5 transition-premium"
                >
                  COPY_LOCAL_URI
                </button>
              </div>

              <div className="p-5 bg-black/40 border border-white/5 rounded-2xl space-y-3 shadow-inner group">
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30">
                    Production
                  </span>
                  <span className="text-[8px] font-black uppercase px-2 py-0.5 rounded bg-warning/10 text-warning border border-warning/20">
                    JWT_REQUIRED
                  </span>
                </div>
                <code className="text-[10px] font-mono text-warning/60 block truncate">
                  {authEndpoint}
                </code>
                <button
                  onClick={() => {
                    copy(authEndpoint);
                    toast.success("Production endpoint copied");
                  }}
                  className="w-full py-2 text-[9px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white hover:bg-white/5 rounded-lg border border-white/5 transition-premium"
                >
                  COPY_AUTH_URI
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Agents & Instructions */}
        <div className="lg:col-span-2 space-y-8">
          {/* Active Agents */}
          <div className="bg-surface-3/30 border border-white/5 rounded-[3rem] p-10 shadow-2xl backdrop-blur-xl relative overflow-hidden min-h-[400px]">
            <div className="flex items-center justify-between mb-10">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary shadow-inner">
                  <Bot size={24} />
                </div>
                <div>
                  <h4 className="text-xl font-black text-white tracking-tight uppercase">
                    Registry
                  </h4>
                  <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.3em]">
                    Active Protocol Entities
                  </p>
                </div>
              </div>
              {agents.length > 0 && (
                <div className="flex flex-col items-end gap-1">
                  <span className="text-2xl font-black text-white tracking-tighter leading-none">
                    {agents.length}
                  </span>
                  <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest">
                    ACTIVE_AGENTS
                  </span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {loading ? (
                <div className="col-span-full py-24 flex flex-col items-center justify-center gap-4">
                  <Loader2 className="w-8 h-8 text-primary animate-spin" />
                  <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.4em]">
                    Synchronizing Registry...
                  </p>
                </div>
              ) : agents.length === 0 ? (
                <div className="col-span-full py-24 flex flex-col items-center justify-center border border-dashed border-white/5 rounded-[2.5rem] bg-white/[0.01] group">
                  <Bot className="w-16 h-16 text-muted-foreground/10 mb-6 transition-premium group-hover:scale-110 group-hover:text-primary/10" />
                  <p className="text-[11px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                    No Operational Agents Detected
                  </p>
                </div>
              ) : (
                agents.map((agent) => (
                  <div
                    key={agent.id}
                    className="group bg-white/[0.02] border border-white/5 rounded-[2rem] p-6 transition-premium hover:bg-white/[0.04] hover:border-white/10 hover:shadow-2xl relative overflow-hidden"
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

                    <div className="flex items-start justify-between relative z-10 mb-6">
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 bg-surface-4/40 border border-white/5 rounded-xl flex items-center justify-center text-muted-foreground/40 group-hover:text-primary transition-premium">
                          <Terminal size={18} />
                        </div>
                        <div>
                          <h5 className="text-sm font-black text-white tracking-tight uppercase group-hover:text-primary transition-premium">
                            {agent.name}
                          </h5>
                          <p className="text-[8px] font-mono text-muted-foreground/20 mt-1 uppercase">
                            ID: {agent.id.slice(0, 16)}...
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => handleRevoke(agent.id)}
                        disabled={revokingId === agent.id}
                        className="w-10 h-10 flex items-center justify-center rounded-xl bg-destructive/5 border border-destructive/10 text-destructive/40 hover:text-white hover:bg-destructive hover:border-destructive transition-premium active:scale-90"
                      >
                        {revokingId === agent.id ? (
                          <Loader2 size={14} className="animate-spin" />
                        ) : (
                          <Trash2 size={14} />
                        )}
                      </button>
                    </div>

                    <div className="grid grid-cols-2 gap-4 relative z-10">
                      <div className="flex flex-col gap-1">
                        <span className="text-[8px] text-muted-foreground/20 font-black uppercase tracking-widest">
                          INITIALIZED
                        </span>
                        <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-black uppercase tracking-tighter">
                          <Calendar size={12} className="opacity-30" />
                          {new Date(agent.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[8px] text-muted-foreground/20 font-black uppercase tracking-widest">
                          LAST_UPLINK
                        </span>
                        <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-black uppercase tracking-tighter">
                          <Clock size={12} className="opacity-30" />
                          {agent.lastUsedAt
                            ? new Date(agent.lastUsedAt).toLocaleDateString()
                            : "NEVER"}
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Integration Guides */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {[
              {
                title: "Claude Desktop (Local)",
                desc: "VOLATILE_DEVELOPMENT_ENVIRONMENT",
                config: `{
  "mcpServers": {
    "talos-local": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-sse", "${localEndpoint}"]
    }
  }
}`,
              },
              {
                title: "Claude Desktop (Secured)",
                desc: "PRODUCTION_PROTOCOL_BRIDGE",
                config: `{
  "mcpServers": {
    "talos": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-sse", "${authEndpoint}"],
      "env": {
        "TALOS_TOKEN": "YOUR_PROTOCOL_TOKEN"
      }
    }
  }
}`,
              },
            ].map((inst, idx) => (
              <div
                key={idx}
                className="bg-surface-3/30 border border-white/5 rounded-[2.5rem] p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden group/guide"
              >
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-50" />

                <div className="flex items-center justify-between mb-6 relative z-10">
                  <div className="space-y-1">
                    <h5 className="text-[11px] font-black text-white uppercase tracking-[0.2em]">
                      {inst.title}
                    </h5>
                    <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest">
                      {inst.desc}
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      copy(inst.config);
                      toast.success("Configuration copied");
                    }}
                    className="p-3 bg-white/5 border border-white/10 rounded-xl text-muted-foreground hover:text-white hover:bg-white/10 transition-premium"
                  >
                    <Copy size={16} />
                  </button>
                </div>

                <div className="relative z-10">
                  <div className="absolute top-4 right-6 text-[8px] font-black text-primary/40 uppercase tracking-[0.3em] pointer-events-none">
                    JSON_SPEC
                  </div>
                  <pre className="bg-black/60 border border-white/5 rounded-2xl p-6 text-[11px] font-mono text-primary/60 leading-relaxed overflow-x-auto custom-scrollbar selection:bg-primary/30">
                    {inst.config}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-surface-3/20 border border-white/5 rounded-[3rem] p-10 glass-dark relative overflow-hidden group/info">
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30" />
        <div className="flex flex-col md:flex-row items-center gap-10 relative z-10">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 flex-1">
            {[
              { name: "COMPILE_SANDBOX", icon: <Zap size={14} /> },
              { name: "CREATE_WORKFLOW", icon: <Server size={14} /> },
              { name: "TRIGGER_WORKFLOW", icon: <Zap size={14} /> },
              { name: "AUDIT_LOGS", icon: <Shield size={14} /> },
            ].map((tool) => (
              <div
                key={tool.name}
                className="flex items-center gap-4 group/tool"
              >
                <div className="w-10 h-10 bg-white/5 border border-white/5 rounded-xl flex items-center justify-center text-muted-foreground/20 group-hover/tool:text-primary group-hover/tool:border-primary/20 transition-premium">
                  {tool.icon}
                </div>
                <span className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] group-hover/tool:text-white transition-premium">
                  {tool.name}
                </span>
              </div>
            ))}
          </div>
          <div className="w-px h-12 bg-white/5 hidden md:block" />
          <div className="max-w-md">
            <div className="flex items-center gap-3 mb-2 text-primary">
              <Info size={16} />
              <span className="text-[10px] font-black uppercase tracking-[0.2em]">
                PROTOCOL_ADVISORY
              </span>
            </div>
            <p className="text-[10px] text-muted-foreground/40 font-medium leading-relaxed uppercase tracking-widest">
              MCP agents operate with delegated authority. Use short-lived
              tokens and granular roles to maintain operational security
              perimeters.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
