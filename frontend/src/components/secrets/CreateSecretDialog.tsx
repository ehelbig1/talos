import React, { useState } from "react";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { Dialog } from "@/components/ui";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { SecurityNotice } from "@/components/ui/SecurityNotice";
import { TextButton } from "@/components/ui/TextButton";
import { FlexContainer } from "@/components/ui/FlexContainer";
import {
  AlertTriangle,
  Check,
  X,
  Eye,
  EyeOff,
  ShieldCheck,
} from "lucide-react";
import { useCreateSecretMutation } from "@/generated/graphql";
import { gql } from "@/lib/graphqlClient";

const CREATE_SECRET = gql`
  mutation CreateSecret($input: CreateSecretInput!) {
    createSecret(input: $input) {
      id
      name
      keyPath
    }
  }
`;

interface CreateSecretDialogProps {
  open: boolean;
  onClose: () => void;
  onCreate: () => void;
}

export function CreateSecretDialog({
  open,
  onClose,
  onCreate,
}: CreateSecretDialogProps) {
  const [name, setName] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [showValue, setShowValue] = useState(false);

  const createMutation = useCreateSecretMutation({
    onSuccess: () => {
      toast.success("Secret created successfully");
      onCreate();
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to create secret"),
      );
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate({
      input: {
        name,
        keyPath,
        value,
        description: description || null,
      },
    });
  };

  if (!open) return null;

  return (
    <Dialog open={open} onClose={onClose} title="Create New Secret">
      <div className="p-1">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-4">
            <FormField
              label="Secret Name"
              description="A human-readable name for this secret"
            >
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. OpenAI Production Key"
                required
                className="bg-background/50 border-border focus:border-primary/50 transition-premium"
              />
            </FormField>

            <FormField
              label="Key Path"
              description="Hierarchical path to reference this secret (e.g., service/env/key)"
            >
              <Input
                value={keyPath}
                onChange={(e) => setKeyPath(e.target.value)}
                placeholder="e.g. openai/prod/api-key"
                required
                className="bg-background/50 border-border focus:border-primary/50 transition-premium"
              />
            </FormField>

            <FormField label="Description">
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What is this secret used for?"
                rows={2}
                className="bg-background/50 border-border focus:border-primary/50 transition-premium resize-none"
              />
            </FormField>

            <FormField label="Secret Value">
              <div className="relative">
                <Input
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="sk-..."
                  required
                  type={showValue ? "text" : "password"}
                  className="bg-background/50 border-border focus:border-primary/50 transition-premium pr-12"
                />
                <button
                  type="button"
                  onClick={() => setShowValue(!showValue)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-premium p-1.5 hover:bg-accent rounded-md"
                  title={showValue ? "Hide value" : "Show value"}
                >
                  {showValue ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </FormField>
          </div>

          <SecurityNotice className="bg-warning/5 border border-warning/10 text-warning/80 rounded-xl p-4 text-sm leading-relaxed">
            <div className="flex gap-3">
              <AlertTriangle className="w-5 h-5 text-warning mt-0.5 shrink-0" />
              <p>
                <strong>Security Notice:</strong> This value will be
                envelope-encrypted and stored securely. Once created, the raw
                value can never be retrieved or displayed in the UI again.
              </p>
            </div>
          </SecurityNotice>

          <div className="flex items-center justify-end gap-3 pt-6 border-t border-border/50 bg-muted/5 -mx-1 px-1 -mb-1 pb-1">
            <Button
              type="button"
              variant="ghost"
              onClick={onClose}
              className="text-muted-foreground hover:text-foreground hover:bg-accent font-black uppercase tracking-widest text-[10px] h-11 px-6 rounded-xl transition-premium"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!name || !keyPath || !value || createMutation.isPending}
              className="bg-primary hover:bg-primary/90 text-primary-foreground shadow-xl shadow-primary/20 px-8 h-11 border-b-4 border-primary/50 active:scale-95 transition-premium font-black uppercase tracking-widest text-[10px] rounded-xl"
            >
              {createMutation.isPending ? (
                <div className="flex items-center gap-2">
                  <div className="w-3.5 h-3.5 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full animate-spin" />
                  <span>Creating...</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  <span>Create Secret</span>
                </div>
              )}
            </Button>
          </div>

          {createMutation.isError && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-xl text-destructive text-sm">
              <p className="font-semibold mb-1">Failed to create secret</p>
              {sanitizeErrorMessage(
                createMutation.error instanceof Error
                  ? createMutation.error.message
                  : "An unexpected error occurred.",
              )}
            </div>
          )}
        </form>
      </div>
    </Dialog>
  );
}
