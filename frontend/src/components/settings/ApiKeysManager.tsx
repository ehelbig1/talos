import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Plus, Info } from "lucide-react";
import { toast } from "sonner";
import { userFacingErrorMessage } from "@/lib/sanitize";
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
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { SectionHeader } from "@/components/ui/SectionHeader";

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
    onError: (err: unknown) => {
      toast.error(userFacingErrorMessage(err, "Could not create the key."));
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
    onError: (err: unknown) => {
      toast.error(userFacingErrorMessage(err, "Could not revoke the key."));
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
    onError: (err: unknown) => {
      toast.error(userFacingErrorMessage(err, "Could not rotate the key."));
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
    onError: (err: unknown) => {
      toast.error(userFacingErrorMessage(err, "Could not delete the key."));
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
    <div className="max-w-6xl mx-auto py-4 space-y-8">
      <div className="flex items-center justify-between gap-6">
        <div>
          <SectionHeader
            level="h2"
            className="text-2xl font-semibold text-white tracking-tight"
          >
            API keys
          </SectionHeader>
          <p className="text-sm text-muted-foreground mt-2">
            Keys for scripts, CI and other systems that call Talos as you.
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" />
          New key
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
        <div className="w-10 h-10 bg-primary/10 border border-primary/20 rounded-lg flex items-center justify-center text-primary shrink-0">
          <Info size={18} />
        </div>
        <div>
          <h4 className="text-sm font-semibold text-foreground mb-1">
            A key acts as you
          </h4>
          <p className="text-xs text-muted-foreground leading-relaxed">
            A key carries the same permissions as your account. Give each
            integration a short-lived key with only the scopes it needs.
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
        <ConfirmDialog
          open
          title="Revoke this key?"
          message="Anything using this key loses access now. The key stays in the list as inactive. This cannot be undone."
          confirmLabel="Revoke key"
          destructive
          isLoading={revokeMutation.isPending}
          onCancel={() => setRevokingId(null)}
          onConfirm={() => handleRevoke(revokingId)}
        />
      )}

      {/* Rotate confirmation */}
      {rotatingId && (
        <ConfirmDialog
          open
          title="Rotate this key?"
          message="A new key with the same permissions replaces this one, and the old key stops working now. The new secret is shown once, so have somewhere to save it."
          confirmLabel="Rotate key"
          isLoading={rotateMutation.isPending}
          onCancel={() => setRotatingId(null)}
          onConfirm={() => handleRotate(rotatingId)}
        />
      )}

      {/* Delete confirmation */}
      {deletingId && (
        <ConfirmDialog
          open
          title="Delete this key?"
          message="The key is removed from your account and anything using it loses access now. This cannot be undone."
          confirmLabel="Delete key"
          destructive
          isLoading={deleteMutation.isPending}
          onCancel={() => setDeletingId(null)}
          onConfirm={() => handleDelete(deletingId)}
        />
      )}
    </div>
  );
}
