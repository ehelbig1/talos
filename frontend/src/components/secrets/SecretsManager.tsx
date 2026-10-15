import React, { useState } from "react";
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

const _GET_SECRETS = gql`
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

const _DELETE_SECRET = gql`
  mutation DeleteSecret($keyPath: String!) {
    deleteSecret(keyPath: $keyPath)
  }
`;

const _ROTATE_ENCRYPTION_KEY = gql`
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
        title="Delete secret"
        message={
          secretToDelete
            ? `Delete secret "${secretToDelete.name}"? Any module that reads it will stop working. This cannot be undone.`
            : ""
        }
        confirmLabel="Delete secret"
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
        title="Rotate master key?"
        message="Rotate the master encryption key? New writes use the new key. The old key stays readable for 30 days."
        confirmLabel="Rotate key"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 animate-in fade-in duration-300">
          <div className="bg-surface-3/60 border border-white/5 rounded-2xl p-10 w-full max-w-lg relative overflow-hidden group">
            <div className="flex items-center justify-between mb-8 relative z-10">
              <div className="flex items-center gap-5">
                <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                  <Pencil size={20} />
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-white tracking-tight">
                    Update Secret
                  </h3>
                  <p className="text-xs text-primary font-semibold mt-0.5">
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
                className="p-2.5 hover:bg-white/5 rounded-xl transition-premium active:scale-90 text-muted-foreground/70 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-8 relative z-10">
              <div className="space-y-3">
                <label className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60 ml-1">
                  New value
                </label>
                <div className="relative group/input">
                  <input
                    type="password"
                    autoFocus
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    placeholder="Enter the new secret value"
                    className="relative w-full bg-black/40 border border-white/5 rounded-2xl px-6 py-4 text-sm text-foreground focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-premium placeholder:text-muted-foreground/50"
                  />
                </div>
              </div>

              <div className="flex gap-4">
                <button
                  className="flex-1 bg-primary text-black font-semibold py-4 rounded-2xl text-sm transition-premium active:scale-95 disabled:opacity-50 disabled:grayscale"
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
                  {updateSecretMutation.isPending ? "Saving…" : "Save"}
                </button>
                <button
                  className="px-8 py-4 rounded-2xl text-sm font-semibold text-muted-foreground/70 hover:text-white hover:bg-white/5 transition-premium active:scale-95"
                  onClick={() => {
                    setSecretToEdit(null);
                    setEditValue("");
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative group">
        <div className="flex items-center gap-6 relative z-10">
          <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center transition-premium">
            <Key className="w-8 h-8 text-primary" />
          </div>
          <div className="flex flex-col">
            <h2 className="text-4xl font-semibold text-white tracking-tight">
              Secrets
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              API keys and tokens, encrypted at rest. Modules read them without
              seeing the value.
            </p>
          </div>
        </div>

        <button
          onClick={() => setShowCreate(true)}
          className="relative z-10 bg-primary text-white font-semibold px-5 h-11 rounded-xl flex items-center gap-2 transition-premium active:scale-[0.98] hover:bg-primary/90 whitespace-nowrap"
        >
          <Plus className="w-4 h-4" />
          <span className="text-sm">New secret</span>
        </button>
      </div>

      <div className="bg-surface-3/30 border border-white/5 rounded-2xl overflow-hidden min-h-[500px] relative group/registry">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-48 gap-6">
            <div className="relative">
              <div className="w-16 h-16 border-2 border-primary/10 rounded-full" />
              <div className="w-16 h-16 border-t-2 border-primary rounded-full animate-spin absolute inset-0" />
            </div>
            <p className="text-xs text-primary/60 font-semibold animate-status-pulse">
              Deciphering Registry...
            </p>
          </div>
        ) : error ? (
          <div className="p-12 text-center text-destructive bg-destructive/5 flex flex-col items-center gap-4">
            <AlertTriangle className="w-8 h-8" />
            <p className="font-semibold text-xs">Could not load secrets</p>
          </div>
        ) : secrets && secrets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-48 text-center px-10 space-y-8">
            <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-white/10 group-hover/registry:text-primary/20 transition-premium duration-700">
              <LockIcon size={40} />
            </div>
            <div className="space-y-3">
              <h3 className="text-2xl font-semibold text-white/60 tracking-tight">
                No secrets yet
              </h3>
              <p className="text-xs text-muted-foreground/70 max-w-sm mx-auto font-medium leading-relaxed">
                Store API keys and tokens here so modules can use them without
                seeing them in plain text.
              </p>
            </div>
            <button
              onClick={() => setShowCreate(true)}
              className="px-8 py-4 border border-primary/20 text-primary text-sm font-semibold rounded-2xl hover:bg-primary/10 transition-premium active:scale-95"
            >
              Add secret
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-white/5 border-b border-white/5">
                  <th className="px-10 py-6 text-left text-2xs font-semibold text-muted-foreground/60">
                    Name
                  </th>
                  <th className="px-10 py-6 text-left text-2xs font-semibold text-muted-foreground/60">
                    Path
                  </th>
                  <th className="px-10 py-6 text-left text-2xs font-semibold text-muted-foreground/60">
                    Last used
                  </th>
                  <th className="px-10 py-6 text-right text-2xs font-semibold text-muted-foreground/60">
                    Actions
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
                        <span className="font-semibold text-white tracking-tight text-sm">
                          {secret.name}
                        </span>
                        {secret.description && (
                          <span className="text-xs text-muted-foreground/70 font-medium line-clamp-1">
                            {secret.description}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-10 py-8">
                      <div className="flex items-center gap-4 group/reveal">
                        <div className="relative group/code">
                          <code className="relative px-4 py-2 bg-black/40 border border-white/5 rounded-xl text-xs font-mono text-primary/80 block min-w-[140px] text-center">
                            {revealedSecretId === secret.id
                              ? secret.keyPath
                              : "••••••••••••"}
                          </code>
                        </div>
                        {revealedSecretId === secret.id ? (
                          <button
                            onClick={() => setRevealedSecretId(null)}
                            className="p-2.5 text-muted-foreground/70 hover:text-white transition-premium rounded-xl hover:bg-white/5 active:scale-90"
                            title="Obscure Payload"
                          >
                            <EyeOff size={16} />
                          </button>
                        ) : confirmReveal === secret.id ? (
                          <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/20 px-4 py-2 rounded-2xl animate-in zoom-in-95">
                            <span className="text-2xs font-semibold text-amber-500 uppercase tracking-wider">
                              Reveal value?
                            </span>
                            <button
                              onClick={() => revealSecret(secret.id)}
                              className="text-2xs font-semibold text-amber-400 hover:text-white transition-premium underline underline-offset-4 uppercase"
                            >
                              YES
                            </button>
                            <button
                              onClick={() => setConfirmReveal(null)}
                              className="p-1 text-muted-foreground/70 hover:text-white transition-premium"
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
                        <div className="flex items-center gap-2.5 text-xs text-white/70 font-bold">
                          <History size={14} className="text-primary/70" />
                          {secret.lastAccessedAt
                            ? formatDate(secret.lastAccessedAt)
                            : "Never"}
                        </div>
                        <div className="flex items-center gap-2.5">
                          <Activity size={12} className="text-success/40" />
                          <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                            {secret.accessCount} read
                            {secret.accessCount !== 1 ? "s" : ""}
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
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-white hover:bg-white/5 border border-white/5 transition-premium rounded-xl active:scale-90"
                          title="Audit log"
                        >
                          <History size={18} />
                        </button>
                        <button
                          onClick={() => {
                            setSecretToEdit(secret);
                            setEditValue("");
                          }}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-primary hover:bg-primary/10 border border-white/5 transition-premium rounded-xl active:scale-90"
                          title="Reconfigure Payload"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={() => handleDelete(secret)}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-destructive hover:bg-destructive/10 border border-white/5 transition-premium rounded-xl active:scale-90"
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
      <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-12 group relative overflow-hidden transition-premium hover:border-amber-500/40">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-12 relative z-10">
          <div className="flex-1 space-y-6">
            <div className="flex items-center gap-6">
              <div className="w-16 h-16 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex items-center justify-center group-hover:rotate-6 transition-premium duration-500">
                <ShieldCheck className="w-8 h-8 text-amber-500" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-2xl font-semibold text-white tracking-tight">
                  Master encryption key
                </h4>
                <div className="flex items-center gap-3 mt-1.5">
                  <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/20 px-3 py-1 rounded-full">
                    <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                    <span className="text-2xs text-amber-500 font-semibold uppercase tracking-wider leading-none">
                      High impact
                    </span>
                  </div>
                  <div className="w-1 h-1 rounded-full bg-amber-500/30" />
                  <span className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider leading-none">
                    Rotation re-encrypts every secret
                  </span>
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/60 leading-relaxed max-w-3xl font-medium">
              Rotate the key that protects every secret in this workspace.
              <span className="text-amber-500/80 font-semibold ml-1 text-xs">
                Each secret is re-encrypted the next time it is read.
              </span>
              The old key stays readable for 30 days so nothing breaks in the
              meantime.
            </p>
          </div>

          <button
            className="bg-amber-500 text-black font-semibold text-sm px-12 h-20 rounded-2xl transition-premium active:scale-95 flex items-center gap-4 shadow-amber-500/20 group/rotate relative overflow-hidden shrink-0"
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
              {rotateKeyMutation.isPending ? "Rotating…" : "Rotate master key"}
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
