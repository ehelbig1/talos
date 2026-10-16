import React, { useState } from "react";
import { Spinner } from "@/components/ui/spinner";
import { Input } from "@/components/ui/input";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import {
  ShieldAlert,
  KeyRound,
  RotateCcw,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Info,
  Eye,
  EyeOff,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage, userFacingErrorMessage } from "@/lib/sanitize";
import { toast } from "sonner";
import type {
  DekRotationResult,
  ReEncryptionResult,
  MasterKeyRotationResult,
} from "@/generated/graphql";
import {
  useRotateDekMutation,
  useReEncryptSecretsMutation,
  useRotateMasterKeyMutation,
  useRotateEncryptionKeyMutation,
} from "@/generated/graphql";

// ─── Sub-types for result state ───────────────────────────────────────────────

type DekResult = Pick<DekRotationResult, "newDekId" | "message">;
type ReEncryptResult = Pick<ReEncryptionResult, "reEncryptedCount" | "message">;
type MasterKeyResult = Pick<
  MasterKeyRotationResult,
  "reEncryptedDekCount" | "message"
>;

// ─── Shared sub-components ────────────────────────────────────────────────────

interface WarningBadgeProps {
  level: "critical" | "high" | "medium";
  children: React.ReactNode;
}

function WarningBadge({ level, children }: WarningBadgeProps) {
  return (
    <Badge
      className={cn(
        "text-2xs font-semibold uppercase tracking-wider px-3 py-1 rounded-full border gap-2 shadow-sm",
        level === "critical" &&
          "bg-destructive/10 border-destructive/30 text-destructive",
        level === "high" && "bg-warning/10 border-warning/30 text-warning",
        level === "medium" && "bg-primary/10 border-primary/20 text-primary",
      )}
    >
      <AlertTriangle className="w-3 h-3" />
      {children}
    </Badge>
  );
}

interface ResultBoxProps {
  children: React.ReactNode;
}

function ResultBox({ children }: ResultBoxProps) {
  return (
    <div className="mt-6 flex items-start gap-4 p-5 bg-success/5 border border-success/20 rounded-2xl">
      <CheckCircle2 className="w-5 h-5 text-success shrink-0 mt-0.5" />
      <div className="text-xs text-success/80 leading-relaxed">{children}</div>
    </div>
  );
}

// ─── Card 1 — Rotate DEK ─────────────────────────────────────────────────────

function RotateDekCard() {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [result, setResult] = useState<DekResult | null>(null);

  const mutation = useRotateDekMutation({
    onSuccess: (data) => {
      setResult(data.rotateDek);
      toast.success("Data Encryption Key rotated");
    },
    onError: (err: Error) => {
      toast.error(sanitizeErrorMessage(err.message || "Failed to rotate DEK"));
    },
  });

  return (
    <>
      <div
        className={cn(
          "bg-white/[0.02] border border-white/5 rounded-2xl p-8 hover:bg-white/[0.04] hover:border-white/10 transition-ui group relative overflow-hidden",
          result && "border-success/20",
        )}
      >
        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary shrink-0 transition-ui">
              <KeyRound size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
                  Rotate data encryption key
                </h3>
                <WarningBadge level="medium">Affects all users</WarningBadge>
              </div>
              <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-xl">
                Generates a new Data Encryption Key. Existing secrets remain
                encrypted with the old DEK until you run a re-encryption sweep.
                Both old and new DEKs remain active in parallel during
                migration.
              </p>
            </div>
          </div>
          <Button
            onClick={() => setConfirmOpen(true)}
            disabled={mutation.isPending}
            className="shrink-0 h-14 px-8 rounded-2xl"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <Spinner className="w-4 h-4" />
                <span>Rotating…</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                Rotate DEK
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="relative z-10">
            <ResultBox>
              <p>{sanitizeErrorMessage(result.message)}</p>
              <p className="mt-2 text-xs text-success/40 font-mono">
                New DEK id: {String(result.newDekId)}
              </p>
              <div className="mt-4 flex items-center gap-2 text-2xs text-warning/60 font-semibold tracking-wider">
                <Zap className="w-3 h-3" />
                Next: run the re-encryption sweep to complete the migration.
              </div>
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Rotate data encryption key?"
        message="A new DEK will be created. Your existing secrets will continue to work but will use the old DEK until you run re-encryption. This is reversible."
        confirmLabel="Rotate DEK"
        destructive={false}
        onConfirm={() => {
          setConfirmOpen(false);
          mutation.mutate({});
        }}
        onCancel={() => setConfirmOpen(false)}
      />
    </>
  );
}

// ─── Card 2 — Re-encrypt Secrets ─────────────────────────────────────────────

function ReEncryptSecretsCard() {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [result, setResult] = useState<ReEncryptResult | null>(null);

  const mutation = useReEncryptSecretsMutation({
    onSuccess: (data) => {
      setResult(data.reEncryptSecrets);
      toast.success("Secrets re-encrypted successfully");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to re-encrypt secrets"),
      );
    },
  });

  return (
    <>
      <div
        className={cn(
          "bg-white/[0.02] border border-white/5 rounded-2xl p-8 hover:bg-white/[0.04] hover:border-white/10 transition-ui group relative overflow-hidden",
          result && "border-success/20",
        )}
      >
        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center text-warning shrink-0 transition-ui">
              <Lock size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
                  Re-encrypt all secrets
                </h3>
                <WarningBadge level="medium">Compute intensive</WarningBadge>
              </div>
              <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-xl">
                Re-encrypts every stored secret using the currently active DEK.
                Run this after rotating the DEK to complete the migration. The
                operation is atomic per-secret and safe to re-run.
              </p>
            </div>
          </div>
          <Button
            onClick={() => setConfirmOpen(true)}
            disabled={mutation.isPending}
            className="shrink-0 h-14 px-8 rounded-2xl"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <Spinner className="w-4 h-4" />
                <span>Re-encrypting…</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                Re-encrypt secrets
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="relative z-10">
            <ResultBox>
              <p>{sanitizeErrorMessage(result.message)}</p>
              <p className="mt-2 text-xs text-success/40">
                {result.reEncryptedCount} secret
                {result.reEncryptedCount !== 1 ? "s" : ""} re-encrypted with the
                active DEK
              </p>
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Re-encrypt all secrets?"
        message={`This will re-encrypt every stored secret using the active DEK. The process is safe to interrupt and resume. Secrets remain accessible throughout.`}
        confirmLabel="Re-encrypt secrets"
        destructive={false}
        onConfirm={() => {
          setConfirmOpen(false);
          mutation.mutate({});
        }}
        onCancel={() => setConfirmOpen(false)}
      />
    </>
  );
}

// ─── Card 3 — Rotate Master Key ───────────────────────────────────────────────

function RotateMasterKeyCard() {
  const [newMasterKey, setNewMasterKey] = useState("");
  const [confirmPhrase, setConfirmPhrase] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [result, setResult] = useState<MasterKeyResult | null>(null);

  const mutation = useRotateMasterKeyMutation({
    onSuccess: (data) => {
      setResult(data.rotateMasterKey);
      setNewMasterKey("");
      setConfirmPhrase("");
      toast.success(
        "DEKs rewrapped — now remove TALOS_MASTER_KEY_PREVIOUS and roll the controllers",
      );
    },
    onError: (err: Error) => {
      toast.error(userFacingErrorMessage(err, "Failed to rotate master key"));
    },
  });

  const isKeyValid =
    newMasterKey.length === 64 && /^[0-9a-fA-F]+$/.test(newMasterKey);
  const isConfirmed = confirmPhrase === "I understand";
  const canSubmit = isKeyValid && isConfirmed && !mutation.isPending;

  const handleSubmit = () => {
    if (!canSubmit) return;
    mutation.mutate({ newMasterKey });
  };

  return (
    <div
      className={cn(
        "bg-black/40 border-2 rounded-2xl p-10 overflow-hidden relative transition-ui group",
        result ? "border-success/20" : "border-destructive/20",
      )}
    >
      <div className="relative z-10 space-y-8">
        {/* Title row */}
        <div className="flex items-start gap-6">
          <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-center justify-center text-destructive shrink-0 transition-ui">
            <ShieldAlert size={32} />
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap mb-3">
              <h3 className="text-2xl font-semibold text-white tracking-tight font-outfit">
                Rotate root master key
              </h3>
              <WarningBadge level="critical">
                Staged / highest privilege
              </WarningBadge>
            </div>
            <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-2xl">
              Step 2 of a staged rotation: rewraps every DEK the new master key
              cannot yet open. The key is never swapped from this page — it must
              already be deployed. This is the highest privilege security
              operation.
            </p>
          </div>
        </div>

        {/* Strong warning box */}
        <div className="flex items-start gap-5 p-6 bg-destructive/[0.04] border border-destructive/20 rounded-2xl">
          <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-1" />
          <div className="text-xs text-destructive/80 leading-relaxed space-y-2">
            <p className="text-destructive">
              STAGED PROCEDURE — FOLLOW IN ORDER.
            </p>
            <ol className="opacity-60 font-bold list-decimal pl-4 space-y-1">
              <li>
                On every controller set TALOS_MASTER_KEY to the NEW key and
                TALOS_MASTER_KEY_PREVIOUS to the OLD key, then roll the fleet.
              </li>
              <li>
                Enter the new key below and commit. Rows stay readable
                throughout; an interrupted run can simply be repeated.
              </li>
              <li>
                Remove TALOS_MASTER_KEY_PREVIOUS and roll again. Until then the
                old key is still required — do not discard it.
              </li>
            </ol>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* New master key input */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              New master key (64 hex characters)
            </label>
            <div className="relative group/input">
              <Input
                type={showKey ? "text" : "password"}
                placeholder="64 hex characters"
                value={newMasterKey}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setNewMasterKey(e.target.value)
                }
                className={cn(
                  "text-xs font-mono",
                  newMasterKey.length > 0 &&
                    !isKeyValid &&
                    "border-destructive/40 focus:border-destructive/60",
                  isKeyValid && "border-success/40 focus:border-success/60",
                )}
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute inset-y-0 right-5 flex items-center text-muted-foreground/70 hover:text-white transition-ui"
              >
                {showKey ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {newMasterKey.length > 0 && !isKeyValid && (
              <p className="text-xs text-destructive font-medium pl-1 mt-1">
                Key must be 64 hex characters ({newMasterKey.length}/64)
              </p>
            )}
            {isKeyValid && (
              <p className="text-xs text-success font-medium pl-1 mt-1 flex items-center gap-2">
                <CheckCircle2 className="w-3 h-3" />
                Key length OK
              </p>
            )}
          </div>

          {/* Confirmation gate */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Confirmation
            </label>
            <div className="relative">
              <Input
                type="text"
                placeholder="Type 'I understand' to confirm..."
                value={confirmPhrase}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setConfirmPhrase(e.target.value)
                }
                className={cn(isConfirmed && "border-success/40")}
              />
            </div>
          </div>
        </div>

        {/* Submit button */}
        <div className="flex justify-end pt-4">
          <Button
            onClick={handleSubmit}
            disabled={!canSubmit}
            className="h-16 px-12 rounded-2xl bg-destructive/10 hover:bg-destructive text-destructive hover:text-black border border-destructive/20 transition-ui"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <Spinner className="w-5 h-5" />
                <span>Rewrapping keys…</span>
              </div>
            ) : (
              <>
                <ShieldAlert className="w-5 h-5 mr-4" />
                Rotate master key
              </>
            )}
          </Button>
        </div>

        {result && (
          <ResultBox>
            <p>
              Rewrap complete. Final step: remove TALOS_MASTER_KEY_PREVIOUS from
              every controller and roll again.
            </p>
            <p className="mt-2 text-xs text-success/40">
              {result.reEncryptedDekCount} DEK
              {result.reEncryptedDekCount !== 1 ? "s" : ""} rewrapped under the
              new master key
            </p>
          </ResultBox>
        )}
      </div>
    </div>
  );
}

// ─── Card 4 — Rotate Secret Encryption Key ───────────────────────────────────

function RotateEncryptionKeyCard() {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [rotatedCount, setRotatedCount] = useState<number | null>(null);

  const mutation = useRotateEncryptionKeyMutation({
    onSuccess: (data) => {
      setRotatedCount(data.rotateEncryptionKey);
      toast.success("Encryption key rotated");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to rotate encryption key"),
      );
    },
  });

  return (
    <>
      <div
        className={cn(
          "bg-white/[0.02] border border-white/5 rounded-2xl p-8 hover:bg-white/[0.04] hover:border-white/10 transition-ui group relative overflow-hidden",
          rotatedCount !== null && "border-success/20",
        )}
      >
        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center text-muted-foreground shrink-0 transition-ui">
              <RotateCcw size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
                  Rotate secret encryption key
                </h3>
                <WarningBadge level="high">Irreversible</WarningBadge>
              </div>
              <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-xl">
                Rotates the symmetric encryption key used for at-rest secret
                storage. All secrets are re-encrypted in place. Existing
                integrations remain unaffected.
              </p>
            </div>
          </div>
          <Button
            onClick={() => setConfirmOpen(true)}
            disabled={mutation.isPending}
            className="shrink-0 h-14 px-8 rounded-2xl bg-white/5 hover:bg-white/10 text-white border border-white/10"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <Spinner className="w-4 h-4" />
                <span>Rotating…</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                Rotate key
              </>
            )}
          </Button>
        </div>

        {rotatedCount !== null && (
          <div className="relative z-10">
            <ResultBox>
              Rotation complete.{" "}
              <span className="text-white">{rotatedCount}</span> secrets
              re-encrypted.
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Rotate secret encryption key?"
        message="All secrets will be re-encrypted with a new symmetric key. The operation is safe but irreversible — the old key will be discarded."
        confirmLabel="Rotate key"
        destructive
        onConfirm={() => {
          setConfirmOpen(false);
          mutation.mutate({});
        }}
        onCancel={() => setConfirmOpen(false)}
      />
    </>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function SecurityManager() {
  return (
    <div className="max-w-6xl mx-auto py-4 space-y-10">
      {/* Page header */}
      <div className="flex items-center gap-6">
        <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-center justify-center text-destructive relative">
          <ShieldAlert size={32} className="relative z-10" />
        </div>
        <div>
          <SectionHeader
            level="h2"
            className="text-2xl md:text-3xl font-semibold text-white tracking-tight font-outfit mb-1 leading-tight"
          >
            Encryption keys
          </SectionHeader>
          <p className="text-xs text-muted-foreground/70 font-semibold">
            Key rotation and re-encryption
          </p>
        </div>
      </div>

      {/* Global warning banner */}
      <div className="flex items-start gap-5 px-8 py-6 bg-destructive/[0.03] border border-destructive/10 rounded-2xl relative overflow-hidden group">
        <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-1 relative z-10" />
        <div className="relative z-10">
          <p className="text-sm font-semibold text-white mb-1.5 break-words">
            These operations affect the whole system
          </p>
          <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-4xl">
            Key rotation affects all users and integrations immediately. Make
            sure you have a verified backup and recovery plan first. Every
            rotation is recorded in the audit log.
          </p>
        </div>
      </div>

      {/* Operation cards */}
      <div className="space-y-6">
        <div className="text-xs font-semibold text-muted-foreground/50 px-1">
          Data and secret keys
        </div>
        <RotateDekCard />
        <ReEncryptSecretsCard />
        <RotateEncryptionKeyCard />
      </div>

      <div className="space-y-6">
        <div className="text-xs font-semibold text-muted-foreground/50 px-1">
          Root master key
        </div>
        <RotateMasterKeyCard />
      </div>

      {/* Info footer */}
      <div className="flex items-start gap-6 p-8 bg-surface-3/40 border border-white/5 rounded-2xl relative overflow-hidden group">
        <div className="w-14 h-14 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center text-muted-foreground/70 shrink-0 relative z-10 transition-ui">
          <Info size={28} />
        </div>
        <div className="relative z-10">
          <h4 className="text-sm font-semibold text-white mb-2">
            Recommendation
          </h4>
          <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-2xl">
            Rotate DEKs every 90 days. Leave the root master key alone unless
            you suspect it has been compromised or a migration requires a new
            one.
          </p>
        </div>
      </div>
    </div>
  );
}
