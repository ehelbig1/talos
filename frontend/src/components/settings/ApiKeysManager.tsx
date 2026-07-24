import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Plus, Key, Info } from "lucide-react";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  useListApiKeysQuery,
  useCreateApiKeyMutation,
  useRevokeApiKeyMutation,
  useRotateApiKeyMutation,
  useDeleteApiKeyMutation,
} from "@/generated/graphql";
import { KeysTable } from "./api-keys/KeysTable";
import { CreateKeyDialog } from "./api-keys/CreateKeyDialog";
import { NewKeyDialog } from "./api-keys/NewKeyDialog";
import {
  RevokeKeyDialog,
  RotateKeyDialog,
  DeleteKeyDialog,
} from "./api-keys/ConfirmKeyDialogs";

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

      <KeysTable
        keys={keys}
        isLoading={isLoading}
        onRotate={setRotatingId}
        onRevoke={setRevokingId}
        onDelete={setDeletingId}
      />

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
        <CreateKeyDialog
          name={name}
          expiresIn={expiresIn}
          selectedScopes={selectedScopes}
          isPending={createMutation.isPending}
          onNameChange={setName}
          onExpiresInChange={setExpiresIn}
          onToggleScope={toggleScope}
          onClose={() => setShowCreate(false)}
          onCreate={handleCreate}
        />
      )}

      {/* Show newly created or rotated key (one-time display) */}
      {newKey && (
        <NewKeyDialog newKey={newKey} onClose={() => setNewKey(null)} />
      )}

      {/* Revoke confirmation */}
      {revokingId && (
        <RevokeKeyDialog
          isPending={revokeMutation.isPending}
          onCancel={() => setRevokingId(null)}
          onConfirm={() => handleRevoke(revokingId)}
        />
      )}

      {/* Rotate confirmation */}
      {rotatingId && (
        <RotateKeyDialog
          isPending={rotateMutation.isPending}
          onCancel={() => setRotatingId(null)}
          onConfirm={() => handleRotate(rotatingId)}
        />
      )}

      {/* Delete confirmation */}
      {deletingId && (
        <DeleteKeyDialog
          isPending={deleteMutation.isPending}
          onCancel={() => setDeletingId(null)}
          onConfirm={() => handleDelete(deletingId)}
        />
      )}
    </div>
  );
}
