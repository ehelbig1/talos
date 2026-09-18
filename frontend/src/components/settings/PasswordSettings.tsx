import React, { useState } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { gql } from "@/lib/graphqlClient";
import { useChangePasswordMutation } from "@/generated/graphql";

const _CHANGE_PASSWORD = gql`
  mutation ChangePassword($input: ChangePasswordInput!) {
    changePassword(input: $input)
  }
`;

// Mirrors the server policy's length bounds so an obvious mistake is caught
// before a request. The server is the authority: it also checks character
// classes and reserved passwords, and its message is shown as-is.
const MIN_LENGTH = 12;
const MAX_LENGTH = 72;

/** Why the form cannot be submitted yet, or null when it can. */
export function passwordFormProblem(
  current: string,
  next: string,
  confirm: string,
): string | null {
  if (!current) return "Enter your current password.";
  if (next.length < MIN_LENGTH)
    return `The new password must be at least ${MIN_LENGTH} characters.`;
  if (new TextEncoder().encode(next).length > MAX_LENGTH)
    return `The new password must be no more than ${MAX_LENGTH} bytes.`;
  if (next !== confirm) return "The new passwords do not match.";
  if (next === current)
    return "The new password must be different from the current one.";
  return null;
}

export default function PasswordSettings() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);

  const mutation = useChangePasswordMutation({
    onSuccess: () => {
      // The server signed out every other session and re-issued this one.
      setCurrent("");
      setNext("");
      setConfirm("");
      setTouched(false);
      toast.success(
        "Password changed. Every other session has been signed out.",
      );
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to change password"),
      );
    },
  });

  const problem = passwordFormProblem(current, next, confirm);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (problem || mutation.isPending) return;
    mutation.mutate({
      input: { currentPassword: current, newPassword: next },
    });
  };

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-[3rem] p-10 glass relative overflow-hidden">
      <div className="relative z-10 space-y-8 max-w-xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-black text-white tracking-tight">
              Change password
            </h3>
            <p className="text-xs text-muted-foreground">
              Changing your password signs out every other session.
            </p>
          </div>
        </div>

        <form className="space-y-5" onSubmit={submit} noValidate>
          <div className="space-y-2">
            <Label htmlFor="current-password">Current password</Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-password">New password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              maxLength={MAX_LENGTH}
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {MIN_LENGTH}–{MAX_LENGTH} characters, using at least two of:
              uppercase, lowercase, digits, symbols.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              maxLength={MAX_LENGTH}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>

          {touched && problem && (
            <p role="alert" className="text-sm text-destructive">
              {problem}
            </p>
          )}

          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? <LoadingSpinner /> : "Change password"}
          </Button>
        </form>
      </div>
    </div>
  );
}
