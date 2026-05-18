import React, { useState, useRef, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
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
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { gql } from "@/lib/graphqlClient";
import {
  useSetup2FaMutation,
  useEnable2FaMutation,
  useDisable2FaMutation,
} from "@/generated/graphql";

const SETUP_2FA = gql`
  mutation Setup2FA {
    setupTwoFactor {
      secret
      qrCodeUrl
      qrCodePng
    }
  }
`;

const ENABLE_2FA = gql`
  mutation Enable2FA($input: Enable2FAInput!) {
    enableTwoFactor(input: $input) {
      backupCodes
    }
  }
`;

const DISABLE_2FA = gql`
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
      toast.error(sanitizeErrorMessage(err.message || "Failed to initialize 2FA setup"));
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
      toast.error(sanitizeErrorMessage(err.message || "Failed to enable 2FA"));
    },
  });

  const disableMutation = useDisable2FaMutation({
    onSuccess: () => {
      toast.success("Two-Factor Authentication disabled");
      queryClient.invalidateQueries({ queryKey: ["currentUser"] });
    },
    onError: (err: Error) => {
      toast.error(sanitizeErrorMessage(err.message || "Failed to disable 2FA"));
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
    <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

      <div className="relative z-10">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 mb-12">
          <div className="flex items-center gap-6">
            <div
              className={cn(
                "w-16 h-16 rounded-[1.5rem] flex items-center justify-center border shadow-2xl transition-premium duration-700",
                enabled
                  ? "bg-primary/10 border-primary/20 text-primary shadow-[0_0_30px_hsla(var(--primary),0.1)]"
                  : "bg-white/5 border-white/10 text-muted-foreground/20",
              )}
            >
              {enabled ? (
                <ShieldCheck className="w-8 h-8" />
              ) : (
                <ShieldAlert className="w-8 h-8" />
              )}
            </div>
            <div>
              <h3 className="text-2xl md:text-3xl font-black text-white tracking-tighter uppercase font-outfit leading-tight">
                Two-Factor Protocol
              </h3>
              <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em] mt-2">
                {enabled ? "ACTIVE_SECURITY_PERIMETER" : "UNSECURED_IDENTITY_STATE"}
              </p>
            </div>
          </div>

          {enabled && (
            <Button
              variant="outline"
              className="h-12 px-6 text-destructive border-destructive/20 hover:bg-destructive/10 hover:border-destructive/40 rounded-xl font-black uppercase text-[10px] tracking-widest transition-premium"
              onClick={() => setShowDisableConfirm(true)}
            >
              DEACTIVATE_PROTECTION
            </Button>
          )}
        </div>

        {enabled ? (
          <div className="bg-success/5 border border-success/20 rounded-[2rem] p-8 flex flex-col md:flex-row items-center justify-between gap-6 animate-in fade-in slide-in-from-top-4 duration-500 shadow-inner">
            <div className="flex items-center gap-6">
              <div className="w-14 h-14 rounded-2xl bg-success/10 flex items-center justify-center text-success shadow-[0_0_20px_hsla(var(--success),0.2)]">
                <Check className="w-7 h-7" />
              </div>
              <div>
                <span className="text-lg font-black text-white tracking-tight uppercase font-outfit block">
                  Identity_Sovereignty_Verified
                </span>
                <span className="text-[10px] text-success/60 font-black uppercase tracking-widest mt-1 block">
                  Protected by TOTP Protocol V2
                </span>
              </div>
            </div>

            <ConfirmDialog
              open={showDisableConfirm}
              title="Deactivate Protection?"
              message="Removing two-factor authentication significantly decreases your operational security. This operation will be logged in the permanent audit trail."
              confirmLabel="Yes, Deactivate"
              destructive
              onConfirm={() => {
                disableMutation.mutate({});
                setShowDisableConfirm(false);
              }}
              onCancel={() => setShowDisableConfirm(false)}
            />
          </div>
        ) : step === "initial" ? (
          <div className="space-y-10 animate-in fade-in duration-700">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="group p-8 bg-black/40 rounded-[2rem] border border-white/5 hover:border-primary/30 transition-premium shadow-inner relative overflow-hidden">
                <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-6 group-hover:scale-110 transition-premium relative z-10">
                  <Smartphone className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-black text-white uppercase tracking-widest mb-3 relative z-10">
                  Authenticator_App
                </h4>
                <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest relative z-10">
                  Support for Google Authenticator, Authy, and hardware security keys via TOTP.
                </p>
              </div>

              <div className="group p-8 bg-black/40 rounded-[2rem] border border-white/5 hover:border-primary/30 transition-premium shadow-inner relative overflow-hidden">
                <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-6 group-hover:scale-110 transition-premium relative z-10">
                  <Lock className="w-6 h-6" />
                </div>
                <h4 className="text-sm font-black text-white uppercase tracking-widest mb-3 relative z-10">
                  Login_Shield
                </h4>
                <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest relative z-10">
                  Ensures only verified operatives can access the console, even if credentials leak.
                </p>
              </div>
            </div>

            <Button
              className="w-full h-16 text-base font-black uppercase tracking-[0.3em] rounded-2xl shadow-2xl"
              variant="premium"
              onClick={() => setupMutation.mutate({})}
              disabled={setupMutation.isPending}
            >
              {setupMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                <>
                  INITIALIZE_SETUP_SEQUENCE
                  <ArrowRight className="w-5 h-5 ml-4" />
                </>
              )}
            </Button>
          </div>
        ) : step === "setup" && setupData ? (
          <div className="space-y-10 animate-in fade-in slide-in-from-right-8 duration-700">
            <div className="flex flex-col lg:flex-row items-stretch gap-10">
              <div className="bg-white p-6 rounded-[2rem] shadow-2xl flex items-center justify-center ring-4 ring-primary/10 mx-auto lg:mx-0 shrink-0">
                <img
                  src={setupData.qrCodePng}
                  alt="2FA QR Code"
                  className="w-48 h-48"
                />
              </div>

              <div className="flex-1 space-y-8">
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-black text-primary border border-primary/20">
                      01
                    </div>
                    <h4 className="text-sm font-black text-white uppercase tracking-widest">
                      Scan_Protocol_Code
                    </h4>
                  </div>
                  <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest pl-12">
                    Open your security application and capture the visual key. It will begin synthesizing 6-digit verification bursts.
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-black text-primary border border-primary/20">
                      02
                    </div>
                    <h4 className="text-sm font-black text-white uppercase tracking-widest">
                      Manual_Cipher_Key
                    </h4>
                  </div>
                  <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest pl-12 mb-4">
                    If the visual scan fails, enter the following alphanumeric secret manually:
                  </p>
                  <div className="pl-12">
                    <div className="bg-black/40 border border-white/5 rounded-2xl px-6 py-4 flex items-center justify-between group shadow-inner">
                      <code className="text-sm font-mono text-primary font-black tracking-[0.2em] selection:bg-primary/30">
                        {setupData.secret}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={copySecret}
                        className="h-10 w-10 hover:bg-primary/10 hover:text-primary transition-premium rounded-xl"
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
                className="text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium"
                onClick={() => setStep("initial")}
              >
                <ArrowLeft className="w-4 h-4 mr-3" />
                ABORT_SEQUENCE
              </Button>
              <Button
                variant="premium"
                className="px-12 h-14 rounded-xl shadow-2xl"
                onClick={() => setStep("verify")}
              >
                VERIFICATION_STEP <ArrowRight className="w-4 h-4 ml-3" />
              </Button>
            </div>
          </div>
        ) : step === "verify" ? (
          <div className="space-y-10 animate-in fade-in zoom-in-95 duration-700 max-w-md mx-auto py-4">
            <div className="text-center space-y-6">
              <div className="w-24 h-24 bg-primary/10 rounded-[2rem] flex items-center justify-center mx-auto mb-8 shadow-inner border border-primary/20 relative group">
                <div className="absolute inset-0 bg-primary/5 rounded-full blur-2xl group-hover:scale-150 transition-premium" />
                <QrCode className="w-12 h-12 text-primary relative z-10" />
              </div>
              <h4 className="text-2xl font-black text-white tracking-tighter uppercase font-outfit">
                Verify_Protocol
              </h4>
              <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.2em] leading-relaxed">
                Enter the 6-digit burst from your device to secure your identity perimeter.
              </p>
            </div>

            <div className="space-y-8">
              <div className="relative group">
                <Input
                  type="text"
                  placeholder="000000"
                  maxLength={6}
                  className="text-center text-4xl tracking-[0.8em] font-black h-24 bg-black/40 border-white/5 focus:border-primary/40 focus:ring-primary/10 rounded-[2rem] shadow-inner transition-premium text-white placeholder:text-white/5"
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
                  className="flex-1 h-14 rounded-2xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
                  onClick={() => setStep("setup")}
                >
                  RETURN_TO_STEP_02
                </Button>
                <Button
                  variant="premium"
                  className="flex-1 h-14 rounded-2xl shadow-2xl"
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
                  {enableMutation.isPending ? (
                    <LoadingSpinner />
                  ) : (
                    "ACTIVATE_SHIELD"
                  )}
                </Button>
              </div>
            </div>

            <div className="p-6 bg-warning/5 border border-warning/10 rounded-2xl mt-10 relative overflow-hidden group">
              <div className="absolute inset-0 bg-warning/5 opacity-0 group-hover:opacity-100 transition-premium blur-xl pointer-events-none" />
              <div className="flex items-center gap-3 text-warning font-black text-[10px] uppercase tracking-[0.3em] mb-3 relative z-10">
                <AlertTriangle className="w-4 h-4" />
                CRITICAL_SECURITY_NOTICE
              </div>
              <p className="text-[11px] text-muted-foreground/40 leading-relaxed font-bold uppercase tracking-widest relative z-10">
                Activation binds this account to your hardware authenticator. Ensure backup keys are stored in a non-digital vault for emergency recovery.
              </p>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
