import React, { useState } from "react";
import { Card } from "@/components/ui/card";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
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
import { sanitizeErrorMessage } from "@/lib/sanitize";
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
        "text-[9px] font-black uppercase tracking-[0.2em] px-3 py-1 rounded-full border gap-2 shadow-sm",
        level === "critical" &&
          "bg-destructive/10 border-destructive/30 text-destructive shadow-[0_0_15px_hsla(var(--destructive),0.2)]",
        level === "high" &&
          "bg-warning/10 border-warning/30 text-warning shadow-[0_0_15px_hsla(var(--warning),0.2)]",
        level === "medium" &&
          "bg-primary/10 border-primary/20 text-primary shadow-[0_0_15px_hsla(var(--primary),0.2)]",
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
    <div className="mt-6 flex items-start gap-4 p-5 bg-success/5 border border-success/20 rounded-[1.5rem] animate-in fade-in slide-in-from-top-2 duration-500 shadow-inner">
      <CheckCircle2 className="w-5 h-5 text-success shrink-0 mt-0.5" />
      <div className="text-xs text-success/80 font-black uppercase tracking-widest leading-relaxed">
        {children}
      </div>
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
          "bg-white/[0.02] border border-white/5 rounded-[2rem] p-8 hover:bg-white/[0.04] hover:border-white/10 transition-premium group relative overflow-hidden",
          result && "border-success/20",
        )}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary shrink-0 shadow-2xl group-hover:scale-110 transition-premium">
              <KeyRound size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-black text-white tracking-tight uppercase font-outfit">
                  Rotate Protocol DEK
                </h3>
                <WarningBadge level="medium">Operational Risk</WarningBadge>
              </div>
              <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-xl">
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
            variant="premium"
            className="shrink-0 h-14 px-8 rounded-2xl shadow-2xl"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <LoadingSpinner className="w-4 h-4" />
                <span>ROTATING...</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                ROTATE_DEK
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="relative z-10">
            <ResultBox>
              <p>{sanitizeErrorMessage(result.message)}</p>
              <p className="mt-2 text-[10px] text-success/40 font-mono">
                NEW_DEK_ID: {String(result.newDekId)}
              </p>
              <div className="mt-4 flex items-center gap-2 text-[9px] text-warning/60 font-black tracking-widest">
                <Zap className="w-3 h-3" />
                ADVISORY: INITIATE RE-ENCRYPTION SWEEP TO COMPLETE MIGRATION.
              </div>
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Rotate Data Encryption Key?"
        message="A new DEK will be created. Your existing secrets will continue to work but will use the old DEK until you run re-encryption. This is reversible."
        confirmLabel="ROTATE_DEK"
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
          "bg-white/[0.02] border border-white/5 rounded-[2rem] p-8 hover:bg-white/[0.04] hover:border-white/10 transition-premium group relative overflow-hidden",
          result && "border-success/20",
        )}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-warning/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center text-warning shrink-0 shadow-2xl group-hover:scale-110 transition-premium">
              <Lock size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-black text-white tracking-tight uppercase font-outfit">
                  Mass Re-encryption
                </h3>
                <WarningBadge level="medium">Compute Intensive</WarningBadge>
              </div>
              <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-xl">
                Re-encrypts every stored secret using the currently active DEK.
                Run this after rotating the DEK to complete the migration. The
                operation is atomic per-secret and safe to re-run.
              </p>
            </div>
          </div>
          <Button
            onClick={() => setConfirmOpen(true)}
            disabled={mutation.isPending}
            variant="premium"
            className="shrink-0 h-14 px-8 rounded-2xl shadow-2xl"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <LoadingSpinner className="w-4 h-4" />
                <span>PROCESSING...</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                INITIATE_SWEEP
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="relative z-10">
            <ResultBox>
              <p>{sanitizeErrorMessage(result.message)}</p>
              <p className="mt-2 text-[10px] text-success/40">
                {result.reEncryptedCount} ENTRIES_PROCESSED_WITH_ACTIVE_DEK
              </p>
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Re-encrypt All Secrets?"
        message={`This will re-encrypt every stored secret using the active DEK. The process is safe to interrupt and resume. Secrets remain accessible throughout.`}
        confirmLabel="INITIATE_SWEEP"
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
      toast.success("Master key rotated — all DEKs re-encrypted");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to rotate master key"),
      );
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
        "bg-black/40 border-2 rounded-[2.5rem] p-10 overflow-hidden relative transition-premium group",
        result
          ? "border-success/20 shadow-[0_0_50px_hsla(var(--success),0.05)]"
          : "border-destructive/20 shadow-[0_0_50px_hsla(var(--destructive),0.05)]",
      )}
    >
      <div
        className={cn(
          "absolute inset-0 opacity-10 blur-[120px] pointer-events-none",
          result ? "bg-success/20" : "bg-destructive/20",
        )}
      />

      <div className="relative z-10 space-y-8">
        {/* Title row */}
        <div className="flex items-start gap-6">
          <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-center justify-center text-destructive shrink-0 shadow-2xl group-hover:scale-110 transition-premium">
            <ShieldAlert size={32} />
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap mb-3">
              <h3 className="text-2xl font-black text-white tracking-tight uppercase font-outfit">
                Rotate Root Master Key
              </h3>
              <WarningBadge level="critical">
                Terminal / Non-Reversible
              </WarningBadge>
            </div>
            <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-2xl">
              Replaces the root master key and re-encrypts all DEKs. The old
              master key will no longer be able to decrypt any data after this
              operation completes. This is the highest privilege security
              operation.
            </p>
          </div>
        </div>

        {/* Strong warning box */}
        <div className="flex items-start gap-5 p-6 bg-destructive/[0.04] border border-destructive/20 rounded-[2rem] shadow-inner">
          <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-1 shadow-[0_0_15px_hsla(var(--destructive),0.5)]" />
          <div className="text-xs text-destructive/80 font-black uppercase tracking-widest leading-relaxed space-y-2">
            <p className="text-destructive">
              CRITICAL: THIS OPERATION CANNOT BE UNDONE.
            </p>
            <p className="opacity-60 font-bold">
              All DEKs will be re-encrypted with the new master key. Legacy
              entropy will be permanently purged. Ensure you have established
              secure persistence for the new key before commitment.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* New master key input */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              New 64-character Hex Entropy
            </label>
            <div className="relative group/input">
              <input
                type={showKey ? "text" : "password"}
                placeholder="ENTER_HEX_ENTROPY..."
                value={newMasterKey}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setNewMasterKey(e.target.value)
                }
                className={cn(
                  "w-full h-14 px-6 bg-black/40 border border-white/5 rounded-2xl text-xs font-mono text-white placeholder:text-muted-foreground/20 focus:outline-none focus:ring-4 focus:ring-destructive/10 transition-premium shadow-inner",
                  newMasterKey.length > 0 &&
                    !isKeyValid &&
                    "border-destructive/40 focus:border-destructive/60",
                  isKeyValid && "border-success/40 focus:border-success/60",
                )}
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute inset-y-0 right-5 flex items-center text-muted-foreground/40 hover:text-white transition-premium"
              >
                {showKey ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {newMasterKey.length > 0 && !isKeyValid && (
              <p className="text-[9px] text-destructive font-black uppercase tracking-widest pl-1 mt-1">
                ERROR: INVALID_ENTROPY_LENGTH ({newMasterKey.length}/64)
              </p>
            )}
            {isKeyValid && (
              <p className="text-[9px] text-success font-black uppercase tracking-widest pl-1 mt-1 flex items-center gap-2">
                <CheckCircle2 className="w-3 h-3" />
                ENTROPY_VERIFIED
              </p>
            )}
          </div>

          {/* Confirmation gate */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              Governance Acknowledgment
            </label>
            <div className="relative">
              <input
                type="text"
                placeholder="Type 'I understand' to confirm..."
                value={confirmPhrase}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setConfirmPhrase(e.target.value)
                }
                className={cn(
                  "w-full h-14 px-6 bg-black/40 border border-white/5 rounded-2xl text-xs font-black uppercase tracking-widest text-white placeholder:text-muted-foreground/20 focus:outline-none focus:ring-4 focus:ring-primary/10 transition-premium shadow-inner",
                  isConfirmed && "border-success/40",
                )}
              />
            </div>
          </div>
        </div>

        {/* Submit button */}
        <div className="flex justify-end pt-4">
          <Button
            onClick={handleSubmit}
            disabled={!canSubmit}
            variant="premium"
            className="h-16 px-12 rounded-2xl shadow-2xl bg-destructive/10 hover:bg-destructive text-destructive hover:text-black border border-destructive/20 transition-premium"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <LoadingSpinner className="w-5 h-5" />
                <span>RE-ENCRYPTING_ROOT...</span>
              </div>
            ) : (
              <>
                <ShieldAlert className="w-5 h-5 mr-4" />
                COMMIT_ROOT_ROTATION
              </>
            )}
          </Button>
        </div>

        {result && (
          <ResultBox>
            <p>{sanitizeErrorMessage(result.message)}</p>
            <p className="mt-2 text-[10px] text-success/40">
              {result.reEncryptedDekCount} DEK_NODES_SYNCHRONIZED_WITH_NEW_ROOT
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
          "bg-white/[0.02] border border-white/5 rounded-[2rem] p-8 hover:bg-white/[0.04] hover:border-white/10 transition-premium group relative overflow-hidden",
          rotatedCount !== null && "border-success/20",
        )}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-start justify-between gap-8 relative z-10">
          <div className="flex items-start gap-6">
            <div className="w-14 h-14 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center text-muted-foreground shrink-0 shadow-2xl group-hover:scale-110 transition-premium">
              <RotateCcw size={28} />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-3">
                <h3 className="text-xl font-black text-white tracking-tight uppercase font-outfit">
                  Symmetric Key Rotation
                </h3>
                <WarningBadge level="high">Active Destructive</WarningBadge>
              </div>
              <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-xl">
                Rotates the symmetric encryption key used for at-rest secret
                storage. All secrets are re-encrypted in place. Existing
                integrations remain unaffected.
              </p>
            </div>
          </div>
          <Button
            onClick={() => setConfirmOpen(true)}
            disabled={mutation.isPending}
            variant="premium"
            className="shrink-0 h-14 px-8 rounded-2xl shadow-2xl bg-white/5 hover:bg-white/10 text-white border border-white/10"
          >
            {mutation.isPending ? (
              <div className="flex items-center gap-3">
                <LoadingSpinner className="w-4 h-4" />
                <span>ROTATING...</span>
              </div>
            ) : (
              <>
                <RotateCcw className="w-4 h-4 mr-3" />
                ROTATE_SYMMETRIC
              </>
            )}
          </Button>
        </div>

        {rotatedCount !== null && (
          <div className="relative z-10">
            <ResultBox>
              ROTATION_PROTOCOL_COMPLETE.{" "}
              <span className="text-white">{rotatedCount}</span>{" "}
              SECRETS_SYNCHRONIZED.
            </ResultBox>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title="Rotate Secret Encryption Key?"
        message="All secrets will be re-encrypted with a new symmetric key. The operation is safe but irreversible — the old key will be discarded."
        confirmLabel="ROTATE_KEY"
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
    <div className="max-w-6xl mx-auto py-4 space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Page header */}
      <div className="flex items-center gap-6">
        <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-[2rem] flex items-center justify-center text-destructive shadow-[0_0_30px_hsla(var(--destructive),0.1)] relative">
          <div className="absolute inset-0 bg-destructive/5 rounded-full blur-xl animate-pulse" />
          <ShieldAlert size={32} className="relative z-10" />
        </div>
        <div>
          <SectionHeader
            level="h2"
            className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-1 leading-tight"
          >
            Entropy Control
          </SectionHeader>
          <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em]">
            Encryption Infrastructure & Key Governance
          </p>
        </div>
      </div>

      {/* Global warning banner */}
      <div className="flex items-start gap-5 px-8 py-6 bg-destructive/[0.03] border border-destructive/10 rounded-[2.5rem] relative overflow-hidden group">
        <div className="absolute inset-0 bg-destructive/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
        <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-1 shadow-[0_0_15px_hsla(var(--destructive),0.5)] relative z-10" />
        <div className="relative z-10">
          <p className="text-sm font-black text-white uppercase tracking-widest mb-1.5 break-words">
            SENSITIVE_SYSTEM_OPERATIONS_THRESHOLD
          </p>
          <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-4xl">
            Key rotation operations affect all users and integrations
            immediately. Ensure active backup redundancy and verified recovery
            protocols are established. All entropy shifts are logged to the
            non-repudiable audit trail.
          </p>
        </div>
      </div>

      {/* Operation cards */}
      <div className="space-y-6">
        <div className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 px-1">
          Active_Rotation_Bridges
        </div>
        <RotateDekCard />
        <ReEncryptSecretsCard />
        <RotateEncryptionKeyCard />
      </div>

      <div className="space-y-6">
        <div className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 px-1">
          Root_Entropy_Protocol
        </div>
        <RotateMasterKeyCard />
      </div>

      {/* Info footer */}
      <div className="flex items-start gap-6 p-8 bg-surface-3/40 border border-white/5 rounded-[2.5rem] relative overflow-hidden group">
        <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
        <div className="w-14 h-14 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center text-muted-foreground/40 shrink-0 relative z-10 group-hover:scale-105 transition-premium">
          <Info size={28} />
        </div>
        <div className="relative z-10">
          <h4 className="text-sm font-black text-white uppercase tracking-widest mb-2">
            GOVERNANCE_ADVISORY
          </h4>
          <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-2xl">
            Maintain a 90-day rotation cadence for DEKs. The master root should
            remain static unless non-zero trust compromise is detected or
            architectural entropy shift is required.
          </p>
        </div>
      </div>
    </div>
  );
}
