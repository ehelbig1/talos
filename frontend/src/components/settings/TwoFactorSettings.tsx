import React, { useState, useRef, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { Input } from "@/components/ui/input";
import {
  ShieldCheck,
  ShieldAlert,
  Smartphone,
  Lock,
  ArrowRight,
  Copy,
  Check,
  AlertTriangle,
  QrCode,
  ArrowLeft,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { userFacingErrorMessage } from "@/lib/sanitize";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { gql } from "@/lib/graphqlClient";
import { qrCodeImageSrc } from "@/lib/qrCode";
import {
  useSetup2FaMutation,
  useEnable2FaMutation,
  useDisable2FaMutation,
} from "@/generated/graphql";

const _SETUP_2FA = gql`
  mutation Setup2FA {
    setupTwoFactor {
      secret
      qrCodeUrl
      qrCodePng
    }
  }
`;

const _ENABLE_2FA = gql`
  mutation Enable2FA($input: Enable2FAInput!) {
    enableTwoFactor(input: $input) {
      backupCodes
    }
  }
`;

const _DISABLE_2FA = gql`
  mutation Disable2FA {
    disableTwoFactor
  }
`;

interface TwoFactorSetup {
  secret: string;
  qrCodeUrl: string;
  qrCodePng: string;
}

export default function TwoFactorSettings({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const [step, setStep] = useState<"initial" | "setup" | "verify">("initial");
  const [setupData, setSetupData] = useState<TwoFactorSetup | null>(null);
  const [verificationCode, setVerificationCode] = useState("");
  const [isCopying, setIsCopying] = useState(false);
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  const setupMutation = useSetup2FaMutation({
    onSuccess: (data) => {
      setSetupData(data.setupTwoFactor);
      setStep("setup");
    },
    onError: (err: Error) => {
      toast.error(
        userFacingErrorMessage(err, "Failed to initialize 2FA setup"),
      );
    },
  });

  const enableMutation = useEnable2FaMutation({
    onSuccess: (data) => {
      if (data.enableTwoFactor) {
        toast.success("Two-Factor Authentication enabled successfully");
        queryClient.invalidateQueries({ queryKey: ["currentUser"] });
        setStep("initial");
        setVerificationCode("");
      } else {
        toast.error("Invalid verification code");
      }
    },
    onError: (err: Error) => {
      toast.error(userFacingErrorMessage(err, "Failed to enable 2FA"));
    },
  });

  const disableMutation = useDisable2FaMutation({
    onSuccess: () => {
      toast.success("Two-Factor Authentication disabled");
      queryClient.invalidateQueries({ queryKey: ["currentUser"] });
    },
    onError: (err: Error) => {
      toast.error(userFacingErrorMessage(err, "Failed to disable 2FA"));
    },
  });

  const copySecret = async () => {
    if (!setupData?.secret) return;
    try {
      await navigator.clipboard.writeText(setupData.secret);
      setIsCopying(true);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setIsCopying(false), 2000);
      toast.success("Secret key copied");
    } catch {
      toast.error("Failed to copy — clipboard unavailable (requires HTTPS)");
    }
  };

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden group">
      <div className="relative z-10">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 mb-12">
          <div className="flex items-center gap-6">
            <div
              className={cn(
                "w-16 h-16 rounded-2xl flex items-center justify-center border transition-ui",
                enabled
                  ? "bg-primary/10 border-primary/20 text-primary"
                  : "bg-white/5 border-white/10 text-muted-foreground/50",
              )}
            >
              {enabled ? (
                <ShieldCheck className="w-8 h-8" />
              ) : (
                <ShieldAlert className="w-8 h-8" />
              )}
            </div>
            <div>
              <h3 className="text-2xl md:text-3xl font-semibold text-white tracking-tight font-outfit leading-tight">
                Two-factor authentication
              </h3>
              <p className="text-xs text-muted-foreground/70 font-semibold mt-2">
                {enabled ? "Enabled" : "Not enabled"}
              </p>
            </div>
          </div>

          {enabled && (
            <Button
              variant="outline"
              className="h-12 px-6 text-destructive border-destructive/20 hover:bg-destructive/10 hover:border-destructive/40 rounded-xl font-semibold text-sm transition-ui"
              onClick={() => setShowDisableConfirm(true)}
            >
              Turn off
            </Button>
          )}
        </div>

        {enabled ? (
          <div className="bg-success/5 border border-success/20 rounded-2xl p-8 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-6">
              <div className="w-14 h-14 rounded-2xl bg-success/10 flex items-center justify-center text-success">
                <Check className="w-7 h-7" />
              </div>
              <div>
                <span className="text-lg font-semibold text-white tracking-tight font-outfit block">
                  Two-factor authentication is on
                </span>
                <span className="text-xs text-success/60 font-semibold mt-1 block">
                  Protected by a TOTP authenticator app
                </span>
              </div>
            </div>

            <ConfirmDialog
              open={showDisableConfirm}
              title="Turn off two-factor authentication?"
              message="Removing two-factor authentication makes your account less secure. This change is recorded in the audit log."
              confirmLabel="Turn off"
              destructive
              onConfirm={() => {
                disableMutation.mutate({});
                setShowDisableConfirm(false);
              }}
              onCancel={() => setShowDisableConfirm(false)}
            />
          </div>
        ) : step === "initial" ? (
          <div className="space-y-10">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="group p-8 bg-black/40 rounded-2xl border border-white/5 hover:border-primary/30 transition-ui relative overflow-hidden">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-6 transition-ui relative z-10">
                  <Smartphone className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-semibold text-white mb-3 relative z-10">
                  Authenticator app
                </h4>
                <p className="text-xs text-muted-foreground/70 leading-relaxed relative z-10">
                  Support for Google Authenticator, Authy, and hardware security
                  keys via TOTP.
                </p>
              </div>

              <div className="group p-8 bg-black/40 rounded-2xl border border-white/5 hover:border-primary/30 transition-ui relative overflow-hidden">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-6 transition-ui relative z-10">
                  <Lock className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-semibold text-white mb-3 relative z-10">
                  Sign-in protection
                </h4>
                <p className="text-xs text-muted-foreground/70 leading-relaxed relative z-10">
                  Ensures only verified people can sign in, even if credentials
                  leak.
                </p>
              </div>
            </div>

            <Button
              className="w-full h-16 text-base font-semibold rounded-2xl"
              variant="premium"
              onClick={() => setupMutation.mutate({})}
              disabled={setupMutation.isPending}
            >
              {setupMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                <>
                  Set up two-factor authentication
                  <ArrowRight className="w-5 h-5 ml-4" />
                </>
              )}
            </Button>
          </div>
        ) : step === "setup" && setupData ? (
          <div className="space-y-10">
            <div className="flex flex-col lg:flex-row items-stretch gap-10">
              <div className="bg-white p-6 rounded-2xl flex items-center justify-center ring-4 ring-primary/10 mx-auto lg:mx-0 shrink-0">
                <img
                  src={qrCodeImageSrc(setupData.qrCodePng)}
                  alt="2FA QR Code"
                  className="w-48 h-48"
                />
              </div>

              <div className="flex-1 space-y-8">
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-semibold text-primary border border-primary/20">
                      01
                    </div>
                    <h4 className="text-sm font-semibold text-white">
                      Scan the QR code
                    </h4>
                  </div>
                  <p className="text-xs text-muted-foreground/70 leading-relaxed pl-12">
                    Open your authenticator app and scan this code. It will
                    start generating 6-digit verification codes.
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-semibold text-primary border border-primary/20">
                      02
                    </div>
                    <h4 className="text-sm font-semibold text-white">
                      Manual setup key
                    </h4>
                  </div>
                  <p className="text-xs text-muted-foreground/70 leading-relaxed pl-12 mb-4">
                    If you cannot scan the code, enter this key manually:
                  </p>
                  <div className="pl-12">
                    <div className="bg-black/40 border border-white/5 rounded-2xl px-6 py-4 flex items-center justify-between group">
                      <code className="text-sm font-mono text-primary font-semibold tracking-wider selection:bg-primary/30">
                        {setupData.secret}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={copySecret}
                        className="h-10 w-10 hover:bg-primary/10 hover:text-primary transition-ui rounded-xl"
                      >
                        {isCopying ? (
                          <Check className="w-4 h-4 text-success" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-8 flex items-center justify-between border-t border-white/5">
              <Button
                variant="ghost"
                className="text-xs font-semibold text-muted-foreground/70 hover:text-white transition-ui"
                onClick={() => setStep("initial")}
              >
                <ArrowLeft className="w-4 h-4 mr-3" />
                Cancel
              </Button>
              <Button
                variant="premium"
                className="px-12 h-14 rounded-xl"
                onClick={() => setStep("verify")}
              >
                Next <ArrowRight className="w-4 h-4 ml-3" />
              </Button>
            </div>
          </div>
        ) : step === "verify" ? (
          <div className="space-y-10 max-w-md mx-auto py-4">
            <div className="text-center space-y-6">
              <div className="w-24 h-24 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-8 border border-primary/20 relative group">
                <QrCode className="w-12 h-12 text-primary relative z-10" />
              </div>
              <h4 className="text-2xl font-semibold text-white tracking-tight font-outfit">
                Verify
              </h4>
              <p className="text-xs text-muted-foreground/70 leading-relaxed">
                Enter the 6-digit code from your authenticator app.
              </p>
            </div>

            <div className="space-y-8">
              <div className="relative group">
                <Input
                  type="text"
                  placeholder="000000"
                  maxLength={6}
                  className="text-center text-4xl tracking-[0.8em] font-semibold h-24 bg-black/40 border-white/5 focus:border-primary/40 focus:ring-primary/10 rounded-2xl transition-ui text-white placeholder:text-white/5"
                  value={verificationCode}
                  onChange={(e) =>
                    setVerificationCode(e.target.value.replace(/\D/g, ""))
                  }
                  autoFocus
                />
              </div>

              <div className="flex gap-4">
                <Button
                  variant="outline"
                  className="flex-1 h-14 rounded-2xl border-white/10 hover:bg-white/5 text-sm font-semibold"
                  onClick={() => setStep("setup")}
                >
                  Back
                </Button>
                <Button
                  variant="premium"
                  className="flex-1 h-14 rounded-2xl"
                  disabled={
                    verificationCode.length !== 6 || enableMutation.isPending
                  }
                  onClick={() => {
                    if (setupData) {
                      enableMutation.mutate({
                        input: {
                          secret: setupData.secret,
                          code: verificationCode,
                        },
                      });
                    }
                  }}
                >
                  {enableMutation.isPending ? <LoadingSpinner /> : "Turn on"}
                </Button>
              </div>
            </div>

            <div className="p-6 bg-warning/5 border border-warning/10 rounded-2xl mt-10 relative overflow-hidden group">
              <div className="flex items-center gap-3 text-warning font-semibold text-xs mb-3 relative z-10">
                <AlertTriangle className="w-4 h-4" />
                Keep your backup codes safe
              </div>
              <p className="text-xs text-muted-foreground/70 leading-relaxed relative z-10">
                Turning this on ties sign-in to your authenticator app. Store
                your backup codes somewhere safe, offline, for emergency
                recovery.
              </p>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
