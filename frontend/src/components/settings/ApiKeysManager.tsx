import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { Input } from "@/components/ui/input";
import {
  Plus,
  Calendar,
  Shield,
  Copy,
  Trash2,
  X,
  Key,
  Info,
  Terminal,
  Fingerprint,
  Clock,
  RefreshCw,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { gql } from "@/lib/graphqlClient";
import type { ApiKeyInfo } from "@/generated/graphql";
import {
  useListApiKeysQuery,
  useCreateApiKeyMutation,
  useRevokeApiKeyMutation,
  useRotateApiKeyMutation,
  useDeleteApiKeyMutation,
} from "@/generated/graphql";

const _LIST_API_KEYS = gql`
  query ListApiKeys($pagination: PaginationInput) {
    apiKeys(pagination: $pagination) {
      id
      name
      keyPrefix
      scopes
      createdAt
      expiresAt
      lastUsedAt
      isActive
      usageCount
    }
  }
`;

const _CREATE_API_KEY = gql`
  mutation CreateApiKey($input: CreateApiKeyInput!) {
    createApiKey(input: $input) {
      id
      name
      key
      scopes
      expiresAt
    }
  }
`;

const _REVOKE_API_KEY = gql`
  mutation RevokeApiKey($keyId: UUID!) {
    revokeApiKey(keyId: $keyId)
  }
`;

const _ROTATE_API_KEY = gql`
  mutation RotateApiKey($keyId: UUID!) {
    rotateApiKey(keyId: $keyId) {
      id
      name
      key
      scopes
      expiresAt
    }
  }
`;

const _DELETE_API_KEY = gql`
  mutation DeleteApiKey($keyId: UUID!) {
    deleteApiKey(keyId: $keyId)
  }
`;

/**
 * UI component that lists the current user's API keys and allows creation of a new one.
 */
export default function ApiKeysManager() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [expiresIn, setExpiresIn] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Load API keys for the current user
  const { data, isLoading } = useListApiKeysQuery();
  const keys = data?.apiKeys;

  // Mutation to create a new API key
  const createMutation = useCreateApiKeyMutation({
    onSuccess: (data) => {
      setNewKey(data.createApiKey.key);
      queryClient.invalidateQueries({ queryKey: ["ListApiKeys"] });
      setName("");
      setExpiresIn("");
      setSelectedScopes([]);
      setShowCreate(false);
      toast.success("API key created successfully");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(`Failed to create API key: ${err.message}`),
      );
    },
  });

  const handleCreate = () => {
    createMutation.mutate({
      input: {
        name,
        scopes: selectedScopes,
        expiresInDays: expiresIn ? parseInt(expiresIn, 10) : null,
      },
    });
  };

  // Mutation to revoke an API key
  const revokeMutation = useRevokeApiKeyMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ListApiKeys"] });
      setRevokingId(null);
      toast.success("API key revoked");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(`Failed to revoke API key: ${err.message}`),
      );
    },
  });

  const handleRevoke = (id: string) => {
    revokeMutation.mutate({ keyId: id });
  };

  // Mutation to rotate an API key (creates new key, invalidates old one)
  const rotateMutation = useRotateApiKeyMutation({
    onSuccess: (data) => {
      setRotatingId(null);
      setNewKey(data.rotateApiKey.key);
      queryClient.invalidateQueries({ queryKey: ["ListApiKeys"] });
      toast.success("API key rotated — save your new key");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(`Failed to rotate API key: ${err.message}`),
      );
    },
  });

  const handleRotate = (id: string) => {
    rotateMutation.mutate({ keyId: id });
  };

  // Mutation to permanently delete an API key
  const deleteMutation = useDeleteApiKeyMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ListApiKeys"] });
      setDeletingId(null);
      toast.success("API key deleted");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(`Failed to delete API key: ${err.message}`),
      );
    },
  });

  const handleDelete = (id: string) => {
    deleteMutation.mutate({ keyId: id });
  };

  const toggleScope = (value: string) => {
    setSelectedScopes((prev) =>
      prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value],
    );
  };

  const availableScopes = [
    {
      value: "workflows:read",
      label: "Read Workflows",
      desc: "View workflows and history",
    },
    {
      value: "workflows:write",
      label: "Write Workflows",
      desc: "Create and edit workflows",
    },
    {
      value: "secrets:read",
      label: "Read Secrets",
      desc: "Access encrypted secrets",
    },
    {
      value: "secrets:write",
      label: "Write Secrets",
      desc: "Update secrets and keys",
    },
    {
      value: "webhooks:access",
      label: "Webhooks Access",
      desc: "Trigger internal webhooks",
    },
    {
      value: "admin",
      label: "Admin access",
      desc: "Full control over all resources",
    },
  ];

  return (
    <div className="max-w-6xl mx-auto py-4 space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-indigo-500/10 border border-indigo-500/20 rounded-xl flex items-center justify-center text-indigo-400 shadow-inner">
            <Key size={24} />
          </div>
          <div>
            <h2 className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase leading-tight">
              API Ingress Keys
            </h2>
            <p className="text-sm text-muted-foreground font-medium tracking-tight">
              Manage keys for external system access and CI/CD integrations
            </p>
          </div>
        </div>
        <Button
          onClick={() => setShowCreate(true)}
          className="bg-indigo-600 hover:bg-indigo-500 text-white shadow-xl shadow-indigo-500/20 font-bold px-6 py-6 h-auto rounded-xl transition-premium hover:scale-[1.02]"
        >
          <Plus className="w-5 h-5 mr-1" />
          Create New Key
        </Button>
      </div>

      <div className="relative">
        <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-[22px] blur opacity-75 group-hover:opacity-100 transition duration-1000 group-hover:duration-200"></div>
        <Card className="relative bg-surface-3/80 border-white/10 backdrop-blur-xl overflow-hidden rounded-[20px] shadow-2xl border">
          {isLoading ? (
            <div className="p-24 flex flex-col items-center justify-center gap-4">
              <LoadingSpinner className="w-8 h-8 text-indigo-500" />
              <p className="text-xs text-muted-foreground uppercase tracking-widest font-bold animate-pulse">
                Loading Keys...
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-white/[0.02] border-b border-white/5">
                    <th className="px-8 py-5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                      Key Name
                    </th>
                    <th className="px-8 py-5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                      Permissions
                    </th>
                    <th className="px-8 py-5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                      Created
                    </th>
                    <th className="px-8 py-5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                      Status
                    </th>
                    <th className="px-8 py-5 text-right text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {keys && keys.length > 0 ? (
                    keys.map((k: ApiKeyInfo) => {
                      const isExpired =
                        k.expiresAt && new Date(k.expiresAt) < new Date();
                      return (
                        <tr
                          key={k.id}
                          className="group hover:bg-indigo-500/[0.02] transition-premium"
                        >
                          <td className="px-8 py-5">
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                                <Key className="w-4 h-4" />
                              </div>
                              <div className="text-sm font-bold text-foreground leading-tight">
                                {k.name}
                              </div>
                            </div>
                          </td>
                          <td className="px-8 py-5">
                            <div className="flex flex-wrap gap-1.5 min-w-[200px]">
                              {k.scopes.map((s) => (
                                <span
                                  key={s}
                                  className="px-2 py-0.5 bg-surface-4/60 border border-white/10 rounded text-[9px] text-indigo-400 uppercase tracking-widest font-bold"
                                >
                                  {s.split(":").pop()}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-8 py-5">
                            <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium tracking-tight whitespace-nowrap">
                              <Calendar className="w-3.5 h-3.5 text-muted-foreground/50" />
                              {formatDate(k.createdAt)}
                            </div>
                          </td>
                          <td className="px-8 py-5">
                            {isExpired ? (
                              <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-red-500/10 border border-red-500/20 text-[10px] font-bold text-red-400 rounded-md uppercase tracking-wider">
                                <Clock className="w-3 h-3" />
                                Expired
                              </span>
                            ) : k.expiresAt ? (
                              <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-amber-500/10 border border-amber-500/20 text-[10px] font-bold text-amber-500 rounded-md uppercase tracking-wider">
                                <Calendar className="w-3.5 h-3.5" />
                                {formatDate(k.expiresAt)}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-indigo-500/10 border border-indigo-500/20 text-[10px] font-bold text-indigo-400 rounded-md uppercase tracking-wider">
                                <Shield className="w-3 h-3" />
                                Permanent
                              </span>
                            )}
                          </td>
                          <td className="px-8 py-5 text-right">
                            <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-premium">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setRotatingId(k.id)}
                                className="text-muted-foreground hover:text-indigo-400 hover:bg-indigo-400/10 h-9 px-3 font-bold transition-premium text-xs gap-1.5"
                              >
                                <RefreshCw className="w-4 h-4" />
                                Rotate
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setRevokingId(k.id)}
                                className="text-muted-foreground hover:text-amber-400 hover:bg-amber-400/10 h-9 px-3 font-bold transition-premium text-xs gap-1.5"
                              >
                                <Shield className="w-4 h-4" />
                                Revoke
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setDeletingId(k.id)}
                                className="text-muted-foreground hover:text-red-400 hover:bg-red-400/10 h-9 px-3 font-bold transition-premium text-xs gap-1.5"
                              >
                                <Trash2 className="w-4 h-4" />
                                Delete
                              </Button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-8 py-20 text-center">
                        <div className="flex flex-col items-center gap-4">
                          <div className="w-16 h-16 rounded-full bg-surface-3/60 border border-white/5 flex items-center justify-center text-muted-foreground/40">
                            <Terminal size={32} />
                          </div>
                          <div className="max-w-xs mx-auto">
                            <p className="text-sm font-bold text-muted-foreground mb-1">
                              No API keys found
                            </p>
                            <p className="text-xs text-muted-foreground max-w-[240px] leading-relaxed">
                              Create your first key to start using the Talos CLI
                              or automated integrations.
                            </p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="p-6 bg-surface-3/40 border border-white/5 rounded-2xl flex items-start gap-4 max-w-2xl">
        <div className="w-10 h-10 bg-indigo-500/10 border border-indigo-500/20 rounded-lg flex items-center justify-center text-indigo-400 shrink-0">
          <Info size={18} />
        </div>
        <div>
          <h4 className="text-sm font-bold text-foreground mb-1">
            Security Best Practice
          </h4>
          <p className="text-xs text-muted-foreground leading-relaxed">
            API keys carry the same permissions as your user account. We
            recommend using **short-lived keys** and assigning only the
            **minimum necessary scopes** for each integration.
          </p>
        </div>
      </div>

      {/* Create dialog */}
      {showCreate && (
        <Dialog open={true} onClose={() => setShowCreate(false)}>
          <div
            className="bg-surface-3/90 border border-white/5 shadow-[0_0_50px_rgba(0,0,0,0.5)] rounded-2xl overflow-hidden w-[520px] animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-indigo-500/10 rounded-xl flex items-center justify-center border border-indigo-500/20 text-indigo-400">
                  <Key size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-foreground tracking-tight">
                    Create API Key
                  </h3>
                  <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest leading-none mt-1">
                    New access credential
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-white/5 text-muted-foreground hover:text-white transition-premium"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-8 space-y-8">
              <div className="space-y-3">
                <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
                  Key Identity
                </label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-muted-foreground group-focus-within:text-indigo-400 transition-premium">
                    <Fingerprint size={18} />
                  </div>
                  <Input
                    placeholder="e.g. GitHub Actions Runner"
                    value={name}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                      setName(e.target.value)
                    }
                    className="pl-12 bg-surface-4/60 border-white/5 focus:border-indigo-500 focus:ring-indigo-500/10 transition-premium h-12 text-sm font-medium rounded-xl shadow-inner"
                  />
                </div>
              </div>

              <div className="space-y-3">
                <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
                  Expiration Policy
                </label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-muted-foreground group-focus-within:text-indigo-400 transition-premium">
                    <Calendar size={18} />
                  </div>
                  <Input
                    type="number"
                    placeholder="Lifetime in days (optional)"
                    value={expiresIn}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                      setExpiresIn(e.target.value)
                    }
                    className="pl-12 bg-surface-4/60 border-white/5 focus:border-indigo-500 focus:ring-indigo-500/10 transition-premium h-12 text-sm font-medium rounded-xl shadow-inner"
                  />
                </div>
              </div>

              <div className="space-y-4">
                <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
                  Scope configuration
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {availableScopes.map((s) => (
                    <button
                      key={s.value}
                      onClick={() => toggleScope(s.value)}
                      className={cn(
                        "flex flex-col items-start p-4 rounded-xl border transition-premium text-left group/scope",
                        selectedScopes.includes(s.value)
                          ? "bg-indigo-500/10 border-indigo-500/40 text-indigo-100 shadow-[0_4px_12px_rgba(99,102,241,0.1)]"
                          : "bg-surface-4/60 border-white/5 text-muted-foreground hover:border-white/10 hover:bg-white/[0.02]",
                      )}
                    >
                      <div className="flex items-center justify-between w-full mb-1.5">
                        <span
                          className={cn(
                            "text-[9px] font-bold uppercase tracking-widest",
                            selectedScopes.includes(s.value)
                              ? "text-indigo-400"
                              : "text-muted-foreground",
                          )}
                        >
                          {s.value.split(":")[0]}
                        </span>
                        <div
                          className={cn(
                            "w-4 h-4 rounded-full border transition-premium flex items-center justify-center",
                            selectedScopes.includes(s.value)
                              ? "bg-indigo-500 border-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.4)]"
                              : "bg-surface-3/60 border-white/5",
                          )}
                        >
                          <Plus
                            className={cn(
                              "w-2.5 h-2.5 text-white transition-transform",
                              selectedScopes.includes(s.value) && "rotate-45",
                            )}
                          />
                        </div>
                      </div>
                      <div className="text-xs font-bold leading-tight mb-1">
                        {s.label}
                      </div>
                      <div className="text-[10px] text-muted-foreground font-medium leading-tight group-hover/scope:text-muted-foreground transition-premium">
                        {s.desc}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex justify-end gap-3">
              <Button
                variant="ghost"
                onClick={() => setShowCreate(false)}
                disabled={createMutation.isPending}
                className="text-muted-foreground hover:text-white hover:bg-white/5 font-bold"
              >
                Discard
              </Button>
              <Button
                onClick={handleCreate}
                disabled={
                  createMutation.isPending ||
                  !name ||
                  selectedScopes.length === 0
                }
                className="bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/20 px-8 h-11 rounded-xl font-bold transition-premium"
              >
                {createMutation.isPending ? (
                  <div className="flex items-center gap-2">
                    <LoadingSpinner className="w-4 h-4" />
                    <span>Processing...</span>
                  </div>
                ) : (
                  "Generate Key"
                )}
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Show newly created or rotated key (one-time display) */}
      {newKey && (
        <Dialog open={true} onClose={() => setNewKey(null)}>
          <div
            className="bg-surface-3/90 border border-amber-500/20 shadow-[0_0_100px_rgba(245,158,11,0.1)] rounded-2xl overflow-hidden w-[520px] animate-in zoom-in-95 duration-300"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-8 py-6 border-b border-amber-500/10 flex items-center justify-between bg-amber-500/[0.03]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-amber-500/10 rounded-xl flex items-center justify-center border border-amber-500/20 text-amber-500">
                  <Shield size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-amber-500 tracking-tight">
                    Key Generated
                  </h3>
                  <p className="text-[10px] text-amber-600 font-bold uppercase tracking-widest leading-none mt-1">
                    One-time security display
                  </p>
                </div>
              </div>
            </div>

            <div className="p-8 space-y-6">
              <div className="p-5 bg-amber-500/[0.02] border border-amber-500/10 rounded-2xl">
                <div className="flex items-start gap-3 mb-4">
                  <Info className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                  <p className="text-xs text-amber-200/60 leading-relaxed font-medium">
                    This secret key will{" "}
                    <span className="text-amber-400 font-bold uppercase italic px-1">
                      never be shown again
                    </span>
                    . If you lose it, you must revoke this key and create a new
                    one.
                  </p>
                </div>
                <div className="relative group">
                  <div className="absolute top-3 left-4 text-[9px] font-bold uppercase tracking-[0.2em] text-muted-foreground pointer-events-none">
                    Talos Secret Credential
                  </div>
                  <pre className="bg-black border border-white/5 text-amber-500 p-6 pt-10 rounded-xl text-[14px] font-mono break-all whitespace-pre-wrap leading-relaxed shadow-inner">
                    {newKey}
                  </pre>
                  <Button
                    size="sm"
                    className="absolute top-3 right-3 h-8 px-3 bg-amber-500 hover:bg-amber-400 text-black font-bold text-xs rounded-lg transition-transform hover:scale-105 active:scale-95"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(newKey);
                        toast.success("Key copied to clipboard");
                      } catch {
                        toast.error(
                          "Failed to copy — clipboard unavailable (requires HTTPS)",
                        );
                      }
                    }}
                  >
                    <Copy className="w-3.5 h-3.5 mr-1.5" />
                    Copy Key
                  </Button>
                </div>
              </div>
            </div>

            <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex justify-end">
              <Button
                onClick={() => setNewKey(null)}
                className="bg-white/10 hover:bg-white/10 text-foreground border border-white/10 px-8 h-11 rounded-xl font-bold transition-premium"
              >
                I've Saved It
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Revoke confirmation */}
      {revokingId && (
        <Dialog open={true} onClose={() => setRevokingId(null)}>
          <div
            className="bg-surface-3/90 border border-amber-500/20 shadow-2xl rounded-2xl overflow-hidden w-[400px] animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8 text-center space-y-4">
              <div className="w-16 h-16 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex items-center justify-center text-amber-500 mx-auto shadow-inner">
                <Shield size={32} />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Revoke API Key?
                </h3>
                <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
                  Any automation or script using this key will immediately lose
                  access. The key will remain in the list as inactive. This
                  action cannot be undone.
                </p>
              </div>
            </div>

            <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
              <Button
                variant="ghost"
                onClick={() => setRevokingId(null)}
                className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
              >
                Cancel
              </Button>
              <Button
                onClick={() => handleRevoke(revokingId)}
                disabled={revokeMutation.isPending}
                className="flex-1 bg-amber-600 hover:bg-amber-500 text-white shadow-xl shadow-amber-900/20 font-bold h-12 rounded-xl transition-premium"
              >
                {revokeMutation.isPending ? "Revoking..." : "Revoke Key"}
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Rotate confirmation */}
      {rotatingId && (
        <Dialog open={true} onClose={() => setRotatingId(null)}>
          <div
            className="bg-surface-3/90 border border-indigo-500/20 shadow-2xl rounded-2xl overflow-hidden w-[460px] animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8 text-center space-y-4">
              <div className="w-16 h-16 bg-indigo-500/10 border border-indigo-500/20 rounded-2xl flex items-center justify-center text-indigo-400 mx-auto shadow-inner">
                <RefreshCw size={32} />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Rotate API Key?
                </h3>
                <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
                  Rotating creates a new key with the same permissions. The old
                  key is immediately invalidated. You'll need to update any
                  systems using this key.
                </p>
              </div>
              <div className="p-4 bg-indigo-500/5 border border-indigo-500/15 rounded-xl text-left">
                <div className="flex items-start gap-2.5">
                  <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    The new secret will be shown once after rotation. Make sure
                    you have a place to save it before proceeding.
                  </p>
                </div>
              </div>
            </div>

            <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
              <Button
                variant="ghost"
                onClick={() => setRotatingId(null)}
                className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
              >
                Cancel
              </Button>
              <Button
                onClick={() => handleRotate(rotatingId)}
                disabled={rotateMutation.isPending}
                className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white shadow-xl shadow-indigo-900/20 font-bold h-12 rounded-xl transition-premium"
              >
                {rotateMutation.isPending ? (
                  <div className="flex items-center gap-2">
                    <LoadingSpinner className="w-4 h-4" />
                    <span>Rotating...</span>
                  </div>
                ) : (
                  "Rotate Key"
                )}
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Delete confirmation */}
      {deletingId && (
        <Dialog open={true} onClose={() => setDeletingId(null)}>
          <div
            className="bg-surface-3/90 border border-red-500/20 shadow-2xl rounded-2xl overflow-hidden w-[400px] animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8 text-center space-y-4">
              <div className="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center text-red-500 mx-auto shadow-inner">
                <Trash2 size={32} />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Delete API Key?
                </h3>
                <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
                  This permanently removes the key from your account. Any
                  automation or script using this key will immediately lose
                  access. This action cannot be undone.
                </p>
              </div>
            </div>

            <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
              <Button
                variant="ghost"
                onClick={() => setDeletingId(null)}
                className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
              >
                Cancel
              </Button>
              <Button
                onClick={() => handleDelete(deletingId)}
                disabled={deleteMutation.isPending}
                className="flex-1 bg-red-600 hover:bg-red-500 text-white shadow-xl shadow-red-900/20 font-bold h-12 rounded-xl transition-premium"
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete Key"}
              </Button>
            </div>
          </div>
        </Dialog>
      )}
    </div>
  );
}
