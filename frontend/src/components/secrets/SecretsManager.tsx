import React, { useState } from "react";
import { Card } from "@/components/ui/card";
import { useQueryClient } from "@tanstack/react-query";
import { gql } from "@/lib/graphqlClient";
import type { Secret } from "@/generated/graphql";
import {
  useGetSecretsQuery,
  useDeleteSecretMutation,
  useRotateEncryptionKeyMutation,
  useUpdateSecretMutation,
} from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { CreateSecretDialog } from "./CreateSecretDialog";
import { AuditLogViewer } from "./AuditLogViewer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { formatDate } from "@/lib/format";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Key,
  Plus,
  ShieldCheck,
  Eye,
  EyeOff,
  Activity,
  Trash2,
  History,
  Lock as LockIcon,
  RefreshCw,
  AlertTriangle,
  Pencil,
  X,
} from "lucide-react";

const GET_SECRETS = gql`
  query GetSecrets($pagination: PaginationInput) {
    secrets(pagination: $pagination) {
      id
      name
      keyPath
      description
      createdAt
      lastAccessedAt
      accessCount
      expiresAt
    }
  }
`;

const DELETE_SECRET = gql`
  mutation DeleteSecret($keyPath: String!) {
    deleteSecret(keyPath: $keyPath)
  }
`;

const ROTATE_ENCRYPTION_KEY = gql`
  mutation RotateEncryptionKey {
    rotateEncryptionKey
  }
`;

function SecretsManager() {
  const [showCreate, setShowCreate] = useState(false);
  const [selectedSecret, setSelectedSecret] = useState<Secret | null>(null);
  const [revealedSecretId, setRevealedSecretId] = useState<string | null>(null);
  const [confirmReveal, setConfirmReveal] = useState<string | null>(null);
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [secretToDelete, setSecretToDelete] = useState<Secret | null>(null);
  const [confirmRotateKey, setConfirmRotateKey] = useState(false);
  const [secretToEdit, setSecretToEdit] = useState<Secret | null>(null);
  const [editValue, setEditValue] = useState("");
  const queryClient = useQueryClient();

  const updateSecretMutation = useUpdateSecretMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["GetSecrets"] });
      toast.success("Secret updated");
      setSecretToEdit(null);
      setEditValue("");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to update secret"),
      );
    },
  });

  // Load secrets
  const {
    data: secretsData,
    isLoading,
    error,
    refetch,
  } = useGetSecretsQuery({});
  const secrets = secretsData?.secrets;

  const deleteSecretMutation = useDeleteSecretMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["GetSecrets"] });
      toast.success("Secret deleted successfully");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to delete secret"),
      );
    },
  });

  const rotateKeyMutation = useRotateEncryptionKeyMutation({
    onSuccess: (data) => {
      if (data.rotateEncryptionKey) {
        toast.success(`Key rotated to version ${data.rotateEncryptionKey}`);
        queryClient.invalidateQueries({ queryKey: ["GetSecrets"] });
      }
    },
    onError: (err: Error) => {
      toast.error(sanitizeErrorMessage(err.message || "Key rotation failed"));
    },
  });

  const handleDelete = (secret: Secret) => {
    setSecretToDelete(secret);
  };

  const revealSecret = (secretId: string) => {
    setRevealedSecretId(secretId);
    setConfirmReveal(null);
  };

  return (
    <div className="space-y-12 max-w-6xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-1000">
      <ConfirmDialog
        open={secretToDelete !== null}
        title="PROTOCOL_DELETION_AUTHORIZATION"
        message={
          secretToDelete
            ? `Are you certain you wish to purge secret "${secretToDelete.name}"? This action is irreversible across all protocol layers.`
            : ""
        }
        confirmLabel="Purge_Secret"
        destructive
        isLoading={deleteSecretMutation.isPending}
        onConfirm={() => {
          if (secretToDelete) {
            deleteSecretMutation.mutate({ keyPath: secretToDelete.keyPath });
          }
          setSecretToDelete(null);
        }}
        onCancel={() => setSecretToDelete(null)}
      />

      <ConfirmDialog
        open={confirmRotateKey}
        title="MASTER_KEY_ROTATION_INTENT"
        message="Initiate master encryption key rotation? All future protocol encryption will leverage the new key version. Legacy access remains valid for 30 cycles."
        confirmLabel="Initiate_Rotation"
        destructive
        isLoading={rotateKeyMutation.isPending}
        onConfirm={() => {
          rotateKeyMutation.mutate({});
          setConfirmRotateKey(false);
        }}
        onCancel={() => setConfirmRotateKey(false)}
      />

      {/* Edit secret value dialog */}
      {secretToEdit && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-300">
          <div className="bg-surface-3/60 border border-white/5 rounded-[2.5rem] p-10 w-full max-w-lg shadow-[0_0_100px_rgba(0,0,0,0.5)] glass relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />

            <div className="flex items-center justify-between mb-8 relative z-10">
              <div className="flex items-center gap-5">
                <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shadow-[0_0_15px_hsla(var(--primary),0.1)]">
                  <Pencil size={20} />
                </div>
                <div>
                  <h3 className="text-xl font-black text-white uppercase tracking-tighter">
                    Update Secret
                  </h3>
                  <p className="text-[10px] text-primary font-black uppercase tracking-widest mt-0.5">
                    {secretToEdit.name}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSecretToEdit(null);
                  setEditValue("");
                }}
                className="p-2.5 hover:bg-white/5 rounded-xl transition-premium active:scale-90 text-muted-foreground/40 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-8 relative z-10">
              <div className="space-y-3">
                <label className="text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30 ml-1">
                  NEW_PROTOCOL_VALUE
                </label>
                <div className="relative group/input">
                  <div className="absolute -inset-0.5 bg-primary/10 rounded-2xl blur opacity-0 group-hover/input:opacity-100 transition-premium" />
                  <input
                    type="password"
                    autoFocus
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    placeholder="ENTER_SECURE_PAYLOAD..."
                    className="relative w-full bg-black/40 border border-white/5 rounded-2xl px-6 py-4 text-sm text-foreground focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-premium placeholder:text-muted-foreground/10"
                  />
                </div>
              </div>

              <div className="flex gap-4">
                <button
                  className="flex-1 bg-primary text-black font-black py-4 rounded-2xl text-[10px] uppercase tracking-[0.2em] transition-premium active:scale-95 shadow-2xl shadow-primary/20 disabled:opacity-50 disabled:grayscale"
                  disabled={!editValue.trim() || updateSecretMutation.isPending}
                  onClick={() =>
                    updateSecretMutation.mutate({
                      input: {
                        keyPath: secretToEdit.keyPath,
                        value: editValue,
                      },
                    })
                  }
                >
                  {updateSecretMutation.isPending
                    ? "SYNCHRONIZING..."
                    : "COMMIT_UPDATE"}
                </button>
                <button
                  className="px-8 py-4 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 hover:text-white hover:bg-white/5 transition-premium active:scale-95"
                  onClick={() => {
                    setSecretToEdit(null);
                    setEditValue("");
                  }}
                >
                  CANCEL
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative group">
        <div className="absolute -inset-8 bg-primary/5 rounded-[4rem] blur-[80px] opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-center gap-6 relative z-10">
          <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[1.5rem] flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] group-hover:scale-110 group-hover:rotate-3 transition-premium">
            <Key className="w-8 h-8 text-primary" />
          </div>
          <div className="flex flex-col">
            <h2 className="text-4xl font-black text-white tracking-tighter uppercase">
              Secure Registry
            </h2>
            <div className="flex items-center gap-3 mt-1.5">
              <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[9px] text-primary font-black uppercase tracking-widest leading-none">
                  Hardware_Encrypted
                </span>
              </div>
              <div className="w-1 h-1 rounded-full bg-white/10" />
              <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em] leading-none">
                Envelope Protocol V4.2
              </span>
            </div>
          </div>
        </div>

        <button
          onClick={() => setShowCreate(true)}
          className="relative z-10 bg-primary text-black font-black px-10 h-16 rounded-2xl shadow-2xl shadow-primary/20 flex items-center gap-4 transition-premium active:scale-95 group/btn overflow-hidden"
        >
          <div className="absolute inset-0 bg-white/20 translate-y-full group-hover/btn:translate-y-0 transition-transform duration-300" />
          <Plus className="w-6 h-6 group-hover/btn:rotate-90 transition-transform relative z-10" />
          <span className="uppercase tracking-[0.2em] text-[10px] relative z-10">
            Provision_Secret
          </span>
        </button>
      </div>

      <div className="bg-surface-3/30 border border-white/5 rounded-[3rem] shadow-2xl overflow-hidden min-h-[500px] glass relative group/registry">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-20 pointer-events-none" />

        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-48 gap-6">
            <div className="relative">
              <div className="w-16 h-16 border-2 border-primary/10 rounded-full" />
              <div className="w-16 h-16 border-t-2 border-primary rounded-full animate-spin absolute inset-0" />
            </div>
            <p className="text-[10px] text-primary/60 font-black uppercase tracking-[0.4em] animate-status-pulse">
              Deciphering Registry...
            </p>
          </div>
        ) : error ? (
          <div className="p-12 text-center text-destructive bg-destructive/5 flex flex-col items-center gap-4">
            <AlertTriangle className="w-8 h-8" />
            <p className="font-black uppercase tracking-widest text-[11px]">
              CRITICAL_UPLINK_FAILURE: REGISTRY_ACCESS_DENIED
            </p>
          </div>
        ) : secrets && secrets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-48 text-center px-10 space-y-8">
            <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-[2rem] flex items-center justify-center text-white/10 group-hover/registry:text-primary/20 transition-premium group-hover/registry:scale-110 duration-700">
              <LockIcon size={40} />
            </div>
            <div className="space-y-3">
              <h3 className="text-2xl font-black text-white/60 tracking-tight uppercase">
                Registry_Void
              </h3>
              <p className="text-xs text-muted-foreground/40 max-w-sm mx-auto font-medium leading-relaxed">
                No secure entities detected in current workspace scope.
                Provision a new payload to begin protocol integration.
              </p>
            </div>
            <button
              onClick={() => setShowCreate(true)}
              className="px-8 py-4 border border-primary/20 text-primary text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl hover:bg-primary/10 transition-premium active:scale-95"
            >
              Initialize_Registry_Entry
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-white/5 border-b border-white/5">
                  <th className="px-10 py-6 text-left text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30">
                    ENTITY_IDENTIFIER
                  </th>
                  <th className="px-10 py-6 text-left text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30">
                    SECURE_UPLINK_PATH
                  </th>
                  <th className="px-10 py-6 text-left text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30">
                    TELEMETRY
                  </th>
                  <th className="px-10 py-6 text-right text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground/30">
                    PROTOCOL_ACTIONS
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {secrets?.map((secret) => (
                  <tr
                    key={secret.id}
                    className="group hover:bg-white/[0.02] transition-premium"
                  >
                    <td className="px-10 py-8">
                      <div className="flex flex-col gap-1.5">
                        <span className="font-black text-white tracking-tight uppercase text-sm">
                          {secret.name}
                        </span>
                        {secret.description && (
                          <span className="text-[10px] text-muted-foreground/40 font-medium line-clamp-1">
                            {secret.description}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-10 py-8">
                      <div className="flex items-center gap-4 group/reveal">
                        <div className="relative group/code">
                          <div className="absolute -inset-2 bg-primary/10 rounded-xl blur opacity-0 group-hover/code:opacity-100 transition-premium" />
                          <code className="relative px-4 py-2 bg-black/40 border border-white/5 rounded-xl text-[11px] font-mono text-primary/80 shadow-inner block min-w-[140px] text-center">
                            {revealedSecretId === secret.id
                              ? secret.keyPath
                              : "••••••••••••"}
                          </code>
                        </div>
                        {revealedSecretId === secret.id ? (
                          <button
                            onClick={() => setRevealedSecretId(null)}
                            className="p-2.5 text-muted-foreground/40 hover:text-white transition-premium rounded-xl hover:bg-white/5 active:scale-90"
                            title="Obscure Payload"
                          >
                            <EyeOff size={16} />
                          </button>
                        ) : confirmReveal === secret.id ? (
                          <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/20 px-4 py-2 rounded-2xl animate-in zoom-in-95">
                            <span className="text-[9px] font-black text-amber-500 uppercase tracking-widest">
                              CONFIRM_REVEAL?
                            </span>
                            <button
                              onClick={() => revealSecret(secret.id)}
                              className="text-[9px] font-black text-amber-400 hover:text-white transition-premium underline underline-offset-4 uppercase"
                            >
                              YES
                            </button>
                            <button
                              onClick={() => setConfirmReveal(null)}
                              className="p-1 text-muted-foreground/40 hover:text-white transition-premium"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmReveal(secret.id)}
                            className="p-2.5 text-primary/60 hover:text-primary transition-premium rounded-xl hover:bg-primary/10 active:scale-90"
                            title="Reveal Payload"
                          >
                            <Eye size={16} />
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="px-10 py-8">
                      <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2.5 text-[10px] text-white/40 font-bold uppercase tracking-widest">
                          <History size={14} className="text-primary/40" />
                          {secret.lastAccessedAt
                            ? formatDate(secret.lastAccessedAt)
                            : "UNTOUCHED"}
                        </div>
                        <div className="flex items-center gap-2.5">
                          <Activity size={12} className="text-success/40" />
                          <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                            {secret.accessCount} INTERROGATIONS
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-10 py-8 text-right">
                      <div className="flex gap-3 justify-end">
                        <button
                          onClick={() => {
                            setSelectedSecret(secret);
                            setShowAuditLog(true);
                          }}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/40 hover:text-white hover:bg-white/5 border border-white/5 transition-premium rounded-xl active:scale-90"
                          title="Audit Telemetry"
                        >
                          <History size={18} />
                        </button>
                        <button
                          onClick={() => {
                            setSecretToEdit(secret);
                            setEditValue("");
                          }}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/40 hover:text-primary hover:bg-primary/10 border border-white/5 transition-premium rounded-xl active:scale-90"
                          title="Reconfigure Payload"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={() => handleDelete(secret)}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10 border border-white/5 transition-premium rounded-xl active:scale-90"
                          title="Purge Entity"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Advanced Security Section */}
      <div className="bg-amber-500/5 border border-amber-500/20 rounded-[3rem] p-12 shadow-2xl backdrop-blur-xl group relative overflow-hidden transition-premium hover:border-amber-500/40">
        <div className="absolute top-0 right-0 w-96 h-96 bg-amber-500/10 rounded-full blur-[120px] -mr-48 -mt-48 pointer-events-none group-hover:bg-amber-500/20 transition-premium duration-1000" />

        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-12 relative z-10">
          <div className="flex-1 space-y-6">
            <div className="flex items-center gap-6">
              <div className="w-16 h-16 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex items-center justify-center shadow-inner group-hover:scale-110 group-hover:rotate-6 transition-premium duration-500">
                <ShieldCheck className="w-8 h-8 text-amber-500" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-2xl font-black text-white uppercase tracking-tighter">
                  Master Entropy Protocol
                </h4>
                <div className="flex items-center gap-3 mt-1.5">
                  <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/20 px-3 py-1 rounded-full">
                    <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                    <span className="text-[9px] text-amber-500 font-black uppercase tracking-widest leading-none">
                      Critical_Security
                    </span>
                  </div>
                  <div className="w-1 h-1 rounded-full bg-amber-500/30" />
                  <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest leading-none">
                    Hardware_Secured
                  </span>
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/60 leading-relaxed max-w-3xl font-medium">
              Rotate the root encryption vector to re-seed the cryptographic
              foundation of the entire workspace.
              <span className="text-amber-500/80 font-black ml-1 uppercase text-[11px]">
                Autonomous re-encryption will activate upon the next
                interrogation of each entity.
              </span>
              Legacy entropy states are archived for a 30-cycle grace period to
              ensure protocol continuity.
            </p>
          </div>

          <button
            className="bg-amber-500 text-black font-black uppercase tracking-[0.2em] text-[11px] px-12 h-20 rounded-[2rem] transition-premium active:scale-95 flex items-center gap-4 shadow-2xl shadow-amber-500/20 group/rotate relative overflow-hidden shrink-0"
            onClick={() => {
              setConfirmRotateKey(true);
            }}
          >
            <div className="absolute inset-0 bg-white/20 translate-y-full group-hover/rotate:translate-y-0 transition-transform duration-300" />
            <RefreshCw
              className={cn(
                "w-5 h-5 relative z-10 transition-transform duration-1000 group-hover/rotate:rotate-180",
                rotateKeyMutation.isPending && "animate-spin",
              )}
            />
            <span className="relative z-10">
              {rotateKeyMutation.isPending
                ? "ROTATING..."
                : "ROTATE_MASTER_ENTROPY"}
            </span>
          </button>
        </div>
      </div>

      {showCreate && (
        <CreateSecretDialog
          open={showCreate}
          onClose={() => setShowCreate(false)}
          onCreate={() => {
            setShowCreate(false);
            refetch();
          }}
        />
      )}

      {showAuditLog && selectedSecret && (
        <AuditLogViewer
          open={showAuditLog}
          secret={selectedSecret}
          onClose={() => setShowAuditLog(false)}
        />
      )}
    </div>
  );
}

export default React.memo(SecretsManager);
