import React, { useState } from "react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/input";
import { AlertTriangle, Plus, X, Check, ExternalLink } from "lucide-react";
import {
  useCreateSecretMutation,
  useGetSecretsQuery,
} from "@/generated/graphql";

export interface InlineSecretCreatorProps {
  onSecretCreated: (secretRef: string) => void;
  fieldLabel?: string;
}

export function InlineSecretCreator({
  onSecretCreated,
}: InlineSecretCreatorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState("");

  const createMutation = useCreateSecretMutation({
    onSuccess: () => {
      const secretRef = `secret:${name}`;
      setName("");
      setValue("");
      setIsOpen(false);
      onSecretCreated(secretRef);
    },
    onError: (err: Error) => {
      setError(sanitizeErrorMessage(err.message || "Failed to create secret"));
    },
  });

  const handleCreate = () => {
    if (!name || !value) {
      setError("Both name and value are required");
      return;
    }
    setError("");
    createMutation.mutate({
      input: {
        name,
        keyPath: name,
        value,
        description: "Created inline from editor",
      },
    });
  };

  return (
    <div className="inline-secret-creator">
      {!isOpen ? (
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="flex items-center text-sm px-3 py-1.5 border border-dashed border-primary/40 text-primary rounded-lg hover:bg-primary/5 hover:border-primary/60 transition-premium font-bold tracking-tight"
        >
          <Plus className="w-4 h-4 mr-2" />
          Create New Secret
        </button>
      ) : (
        <div className="border border-border rounded-lg p-3 space-y-3 bg-card">
          <div className="flex items-center justify-between">
            <SectionHeader level="h4" className="text-sm font-semibold">
              Create Secret
            </SectionHeader>
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                setError("");
              }}
              className="flex items-center text-[10px] font-bold uppercase tracking-wider text-muted-foreground hover:text-foreground transition-premium"
            >
              <X className="w-3.5 h-3.5 mr-1" />
              Cancel
            </button>
          </div>

          <div className="space-y-2">
            <FormField label="Name">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="my-api-key"
                className="h-8 text-sm"
              />
            </FormField>

            <FormField label="Value">
              <Input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="Enter secret value"
                type="password"
                className="h-8 text-sm"
              />
            </FormField>

            {error && (
              <p className="flex items-center text-xs text-destructive font-medium">
                <AlertTriangle className="w-3.5 h-3.5 mr-1.5 shrink-0" />
                {error}
              </p>
            )}

            <div className="flex gap-2 pt-1">
              <Button
                type="button"
                size="sm"
                onClick={handleCreate}
                disabled={createMutation.isPending || !name || !value}
                className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground font-bold h-8"
              >
                {createMutation.isPending ? (
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full animate-spin" />
                    <span>Creating...</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5" />
                    <span>Create</span>
                  </div>
                )}
              </Button>
              <a
                href="#/secrets"
                className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-primary hover:text-primary/80 transition-premium px-2"
              >
                <span>Full Form</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export interface SecretFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  description?: string;
}

export function SecretField({
  label,
  value,
  onChange,
  description,
}: SecretFieldProps) {
  const [selectedSecret, setSelectedSecret] = useState(value);

  const handleSecretCreated = (secretRef: string) => {
    setSelectedSecret(secretRef);
    onChange(secretRef);
  };

  const { data } = useGetSecretsQuery({ pagination: { limit: 100 } });

  const availableSecrets: string[] =
    data?.secrets?.map((s) => `secret:${s.keyPath}`) || [];

  return (
    <FormField label={label}>
      {description && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
      <div className="flex gap-2 items-start">
        <select
          value={selectedSecret}
          onChange={(e) => {
            setSelectedSecret(e.target.value);
            onChange(e.target.value);
          }}
          className="flex-1 h-9 px-3 py-2 border border-input rounded-md text-sm bg-background"
        >
          <option value="">Select secret...</option>
          {availableSecrets.map((secret) => (
            <option key={secret} value={secret}>
              {secret}
            </option>
          ))}
        </select>
      </div>
      <InlineSecretCreator
        onSecretCreated={handleSecretCreated}
        fieldLabel={label}
      />
    </FormField>
  );
}
