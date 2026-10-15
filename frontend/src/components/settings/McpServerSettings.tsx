import React, { useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
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
          toast.success("MCP agent created");
        }
      },
      onError: (err: Error) => {
        toast.error(
          sanitizeErrorMessage(err.message || "Failed to create agent"),
        );
      },
    });

  const handleCreatePlugin = () => {
    if (!pluginName.trim()) {
      toast.error("Agent name is required");
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
        toast.success("Agent access revoked");
        // Optimistically drop the revoked agent from the query cache.
        queryClient.setQueryData<McpAgent[]>(["mcpAgents"], (prev) =>
          (prev ?? []).filter((a) => a.id !== id),
        );
      } else {
        toast.error("Failed to revoke agent");
      }
    } catch {
      toast.error("Security violation during revocation");
    } finally {
      setRevokingId(null);
    }
  };

  const inputBase =
    "w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-sm font-semibold text-white placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium";
  const selectBase =
    "w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-sm font-semibold text-white focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium appearance-none cursor-pointer";

  return (
    <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-1000 max-w-7xl mx-auto">
      <ConfirmDialog
        open={revokeConfirmId !== null}
        title="Revoke agent access"
        message="Revoke this agent's access? Any open MCP sessions it has will end immediately."
        confirmLabel="Revoke access"
        destructive
        onConfirm={executeRevoke}
        onCancel={() => setRevokeConfirmId(null)}
      />

      <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-10 relative overflow-hidden group/header">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary transition-premium">
              <Monitor size={32} />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-2xl md:text-3xl font-semibold text-white tracking-tight leading-tight">
                Model Context Protocol
              </h2>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  <span className="text-2xs text-primary font-semibold uppercase tracking-wider leading-none">
                    MCP server running
                  </span>
                </div>
                <div className="w-1 h-1 rounded-full bg-white/10" />
                <span className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider leading-none">
                  Let AI agents use Talos as a tool
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex flex-col items-end gap-1">
              <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                Schema version
              </span>
              <code className="text-xs font-mono text-primary font-bold">
                V1.2.0-STABLE
              </code>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Form & Endpoints */}
        <div className="lg:col-span-1 space-y-8">
          <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-8 relative overflow-hidden group">
            <div className="flex items-center gap-3 mb-8 relative z-10">
              <Shield className="w-4 h-4 text-primary" />
              <h4 className="text-xs font-semibold text-white/70">New agent</h4>
            </div>

            <div className="space-y-6 relative z-10">
              <div className="space-y-2.5">
                <label className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60 ml-1">
                  Agent name
                </label>
                <div className="relative group/input">
                  <Bot className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/50 group-focus-within/input:text-primary transition-premium" />
                  <input
                    type="text"
                    placeholder="e.g. Claude Desktop"
                    value={pluginName}
                    onChange={(e) => setPluginName(e.target.value)}
                    className={cn(inputBase, "pl-14")}
                  />
                </div>
              </div>

              <div className="space-y-2.5">
                <label className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60 ml-1">
                  Role
                </label>
                <div className="relative group/input">
                  <UserCheck className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/50 group-focus-within/input:text-primary transition-premium pointer-events-none" />
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
                className="w-full h-14 rounded-2xl"
              >
                {creating ? (
                  <div className="flex items-center gap-3">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Creating…</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <Zap className="w-4 h-4" />
                    <span>Create agent</span>
                  </div>
                )}
              </Button>

              {createdAgent && (
                <div className="mt-6 p-6 bg-primary/5 border border-primary/20 rounded-2xl space-y-4 animate-in zoom-in-95 duration-500 relative overflow-hidden group/token">
                  <div className="flex items-center gap-3 text-primary relative z-10">
                    <Check className="w-4 h-4" />
                    <span className="text-2xs font-semibold uppercase tracking-wider">
                      Agent token created
                    </span>
                  </div>
                  <div className="relative z-10">
                    <CopyField
                      label="Bearer token"
                      value={createdAgent.token}
                      copied={copied}
                      onCopy={() => copy(createdAgent.token)}
                      className="bg-black/60 border-primary/10 text-primary rounded-xl font-mono"
                    />
                  </div>
                  <p className="text-2xs text-primary/70 text-center leading-relaxed relative z-10">
                    Credential will be purged from volatile memory upon closure.
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-8 relative overflow-hidden">
            <div className="flex items-center gap-3 mb-8">
              <Server className="w-4 h-4 text-primary" />
              <h4 className="text-xs font-semibold text-white/70">Endpoints</h4>
            </div>

            <div className="space-y-4">
              <div className="p-5 bg-black/40 border border-white/5 rounded-2xl space-y-3 group">
                <div className="flex items-center justify-between">
                  <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60">
                    Local development
                  </span>
                  <span className="text-2xs font-semibold uppercase px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                    No auth
                  </span>
                </div>
                <code className="text-xs font-mono text-primary/60 block truncate">
                  {localEndpoint}
                </code>
                <button
                  onClick={() => {
                    copy(localEndpoint);
                    toast.success("Local endpoint copied");
                  }}
                  className="w-full py-2 text-2xs font-semibold text-muted-foreground/70 hover:text-white hover:bg-white/5 rounded-lg border border-white/5 transition-premium"
                >
                  Copy local URL
                </button>
              </div>

              <div className="p-5 bg-black/40 border border-white/5 rounded-2xl space-y-3 group">
                <div className="flex items-center justify-between">
                  <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60">
                    Production
                  </span>
                  <span className="text-2xs font-semibold uppercase px-2 py-0.5 rounded bg-warning/10 text-warning border border-warning/20">
                    Token required
                  </span>
                </div>
                <code className="text-xs font-mono text-warning/60 block truncate">
                  {authEndpoint}
                </code>
                <button
                  onClick={() => {
                    copy(authEndpoint);
                    toast.success("Production endpoint copied");
                  }}
                  className="w-full py-2 text-2xs font-semibold text-muted-foreground/70 hover:text-white hover:bg-white/5 rounded-lg border border-white/5 transition-premium"
                >
                  Copy production URL
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Agents & Instructions */}
        <div className="lg:col-span-2 space-y-8">
          {/* Active Agents */}
          <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-10 relative overflow-hidden min-h-[400px]">
            <div className="flex items-center justify-between mb-10">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary">
                  <Bot size={24} />
                </div>
                <div>
                  <h4 className="text-xl font-semibold text-white tracking-tight">
                    Registry
                  </h4>
                  <p className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                    Agents with access
                  </p>
                </div>
              </div>
              {agents.length > 0 && (
                <div className="flex flex-col items-end gap-1">
                  <span className="text-2xl font-semibold text-white tracking-tight leading-none">
                    {agents.length}
                  </span>
                  <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                    agents
                  </span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {loading ? (
                <div className="col-span-full py-24 flex flex-col items-center justify-center gap-4">
                  <Loader2 className="w-8 h-8 text-primary animate-spin" />
                  <p className="text-xs text-muted-foreground/70 font-semibold">
                    Loading…
                  </p>
                </div>
              ) : agents.length === 0 ? (
                <div className="col-span-full py-24 flex flex-col items-center justify-center border border-dashed border-white/5 rounded-2xl bg-white/[0.01] group">
                  <Bot className="w-16 h-16 text-muted-foreground/30 mb-6 transition-premium group-hover:text-primary/10" />
                  <p className="text-xs text-muted-foreground/60 font-semibold">
                    No agents yet
                  </p>
                </div>
              ) : (
                agents.map((agent) => (
                  <div
                    key={agent.id}
                    className="group bg-white/[0.02] border border-white/5 rounded-2xl p-6 transition-premium hover:bg-white/[0.04] hover:border-white/10 relative overflow-hidden"
                  >
                    <div className="flex items-start justify-between relative z-10 mb-6">
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 bg-surface-4/40 border border-white/5 rounded-xl flex items-center justify-center text-muted-foreground/70 group-hover:text-primary transition-premium">
                          <Terminal size={18} />
                        </div>
                        <div>
                          <h5 className="text-sm font-semibold text-white group-hover:text-primary transition-premium">
                            {agent.name}
                          </h5>
                          <p className="text-2xs font-mono text-muted-foreground/50 mt-1 uppercase">
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
                        <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
                          Created
                        </span>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-semibold tracking-tighter">
                          <Calendar size={12} className="opacity-30" />
                          {new Date(agent.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
                          Last used
                        </span>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-semibold tracking-tighter">
                          <Clock size={12} className="opacity-30" />
                          {agent.lastUsedAt
                            ? new Date(agent.lastUsedAt).toLocaleDateString()
                            : "Never"}
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
                desc: "Development only",
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
                desc: "Production, with a token",
                config: `{
  "mcpServers": {
    "talos": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-sse", "${authEndpoint}"],
      "env": {
        "TALOS_TOKEN": "<your agent token>"
      }
    }
  }
}`,
              },
            ].map((inst, idx) => (
              <div
                key={idx}
                className="bg-surface-3/30 border border-white/5 rounded-2xl p-8 relative overflow-hidden group/guide"
              >
                <div className="flex items-center justify-between mb-6 relative z-10">
                  <div className="space-y-1">
                    <h5 className="text-xs font-semibold text-white">
                      {inst.title}
                    </h5>
                    <p className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
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
                  <div className="absolute top-4 right-6 text-2xs font-semibold text-primary/70 uppercase tracking-wider pointer-events-none">
                    JSON
                  </div>
                  <pre className="bg-black/60 border border-white/5 rounded-2xl p-6 text-xs font-mono text-primary/60 leading-relaxed overflow-x-auto custom-scrollbar selection:bg-primary/30">
                    {inst.config}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-surface-3/20 border border-white/5 rounded-2xl p-10 bg-surface-3 border border-white/10 relative overflow-hidden group/info">
        <div className="flex flex-col md:flex-row items-center gap-10 relative z-10">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 flex-1">
            {[
              { name: "Compile modules", icon: <Zap size={14} /> },
              { name: "Create workflows", icon: <Server size={14} /> },
              { name: "Trigger workflows", icon: <Zap size={14} /> },
              { name: "Read audit logs", icon: <Shield size={14} /> },
            ].map((tool) => (
              <div
                key={tool.name}
                className="flex items-center gap-4 group/tool"
              >
                <div className="w-10 h-10 bg-white/5 border border-white/5 rounded-xl flex items-center justify-center text-muted-foreground/50 group-hover/tool:text-primary group-hover/tool:border-primary/20 transition-premium">
                  {tool.icon}
                </div>
                <span className="text-xs font-semibold text-muted-foreground/60 group-hover/tool:text-white transition-premium">
                  {tool.name}
                </span>
              </div>
            ))}
          </div>
          <div className="w-px h-12 bg-white/5 hidden md:block" />
          <div className="max-w-md">
            <div className="flex items-center gap-3 mb-2 text-primary">
              <Info size={16} />
              <span className="text-xs font-semibold">Security note</span>
            </div>
            <p className="text-xs text-muted-foreground/70 font-medium leading-relaxed">
              MCP agents act with your authority. Use short-lived tokens and the
              narrowest role that works.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
