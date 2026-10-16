import React, { useState } from "react";
import { Dialog } from "@/components/ui/dialog";
import { LoadingState } from "@/components/ui/spinner";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
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
    <div className="space-y-12 max-w-6xl mx-auto">
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
        <Dialog
          open
          onClose={() => {
            setSecretToEdit(null);
            setEditValue("");
          }}
          title="Update secret"
          className="max-w-lg"
        >
          <p className="text-sm text-primary font-semibold -mt-4 mb-6">
            {secretToEdit.name}
          </p>

          <div className="space-y-8 relative z-10">
            <div className="space-y-3">
              <label className="text-xs font-medium text-muted-foreground/60 ml-1">
                New value
              </label>
              <div className="relative group/input">
                <Input
                  type="password"
                  autoFocus
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  placeholder="Enter the new secret value"
                  className="relative"
                />
              </div>
            </div>

            <div className="flex gap-4">
              <Button
                className="flex-1"
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
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setSecretToEdit(null);
                  setEditValue("");
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative group">
        <div className="flex items-center gap-6 relative z-10">
          <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center transition-ui">
            <Key className="w-8 h-8 text-primary" />
          </div>
          <div className="flex flex-col">
            <h2 className="text-2xl font-semibold text-white tracking-tight">
              Secrets
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              API keys and tokens, encrypted at rest. Modules read them without
              seeing the value.
            </p>
          </div>
        </div>

        <Button onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" />
          New secret
        </Button>
      </div>

      <div className="bg-surface-3/30 border border-white/5 rounded-2xl overflow-hidden min-h-[500px] relative group/registry">
        {isLoading ? (
          <LoadingState label="Loading secrets…" />
        ) : error ? (
          <div className="p-12 text-center text-destructive bg-destructive/5 flex flex-col items-center gap-4">
            <AlertTriangle className="w-8 h-8" />
            <p className="font-semibold text-xs">Could not load secrets</p>
          </div>
        ) : secrets && secrets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center px-10 space-y-8">
            <div className="w-14 h-14 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-white/10 group-hover/registry:text-primary/20 transition-ui">
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
            <Button variant="outline" onClick={() => setShowCreate(true)}>
              Add secret
            </Button>
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
                    className="group hover:bg-white/[0.02] transition-ui"
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
                            className="p-2.5 text-muted-foreground/70 hover:text-white transition-ui rounded-xl hover:bg-white/5"
                            title="Hide value"
                            aria-label="Hide value"
                          >
                            <EyeOff size={16} />
                          </button>
                        ) : confirmReveal === secret.id ? (
                          <div className="flex items-center gap-3 bg-warning/10 border border-warning/20 px-4 py-2 rounded-2xl">
                            <span className="text-xs font-medium text-warning">
                              Reveal value?
                            </span>
                            <button
                              onClick={() => revealSecret(secret.id)}
                              className="text-xs font-medium text-warning hover:text-white transition-ui underline underline-offset-4"
                            >
                              YES
                            </button>
                            <button
                              onClick={() => setConfirmReveal(null)}
                              aria-label="Cancel"
                              className="p-1 text-muted-foreground/70 hover:text-white transition-ui"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmReveal(secret.id)}
                            className="p-2.5 text-primary/60 hover:text-primary transition-ui rounded-xl hover:bg-primary/10"
                            title="Show value"
                            aria-label="Show value"
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
                          <span className="text-xs text-muted-foreground/60 font-medium">
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
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-white hover:bg-white/5 border border-white/5 transition-ui rounded-xl"
                          title="Audit log"
                          aria-label="Audit log"
                        >
                          <History size={18} />
                        </button>
                        <button
                          onClick={() => {
                            setSecretToEdit(secret);
                            setEditValue("");
                          }}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-primary hover:bg-primary/10 border border-white/5 transition-ui rounded-xl"
                          title="Edit secret"
                          aria-label="Edit secret"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={() => handleDelete(secret)}
                          className="w-11 h-11 flex items-center justify-center text-muted-foreground/70 hover:text-destructive hover:bg-destructive/10 border border-white/5 transition-ui rounded-xl"
                          title="Delete secret"
                          aria-label="Delete secret"
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
      <div className="bg-warning/5 border border-warning/20 rounded-2xl p-12 group relative overflow-hidden transition-ui hover:border-warning/40">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8 relative z-10">
          <div className="flex-1 space-y-6">
            <div className="flex items-center gap-6">
              <div className="w-16 h-16 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center transition-ui">
                <ShieldCheck className="w-8 h-8 text-warning" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-2xl font-semibold text-white tracking-tight">
                  Master encryption key
                </h4>
                <div className="flex items-center gap-3 mt-1.5">
                  <div className="flex items-center gap-2 bg-warning/10 border border-warning/20 px-3 py-1 rounded-full">
                    <div className="w-1.5 h-1.5 rounded-full bg-warning" />
                    <span className="text-2xs text-warning font-semibold uppercase tracking-wider leading-none">
                      High impact
                    </span>
                  </div>
                  <div className="w-1 h-1 rounded-full bg-warning/30" />
                  <span className="text-xs text-muted-foreground/70 font-medium leading-none">
                    Rotation re-encrypts every secret
                  </span>
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/60 leading-relaxed max-w-3xl font-medium">
              Rotate the key that protects every secret in this workspace.
              <span className="text-warning/80 font-semibold ml-1 text-xs">
                Each secret is re-encrypted the next time it is read.
              </span>
              The old key stays readable for 30 days so nothing breaks in the
              meantime.
            </p>
          </div>

          <Button
            variant="outline"
            size="lg"
            onClick={() => {
              setConfirmRotateKey(true);
            }}
          >
            <RefreshCw
              className={cn(
                "w-5 h-5 relative z-10 transition-transform",
                rotateKeyMutation.isPending && "animate-spin",
              )}
            />
            <span className="relative z-10">
              {rotateKeyMutation.isPending ? "Rotating…" : "Rotate master key"}
            </span>
          </Button>
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
