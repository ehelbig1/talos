import { config } from "@/config";
import React, { useState } from "react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  login as authLogin,
  signup as authSignup,
  verifyTwoFactor,
} from "@/lib/auth";
import { useAuth } from "@/contexts/AuthContext";
import { DarkInput } from "@/components/ui/DarkInput";
import { Zap, Loader2, ShieldCheck, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

const BACKEND_URL = config.apiUrl;

export function AuthForm() {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [step, setStep] = useState<"credentials" | "two-factor">("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [twoFactorCode, setTwoFactorCode] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { login: setAuthUser } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      if (mode === "login") {
        const result = await authLogin(email, password);
        setAuthUser(result.user);
        if (result.user.twoFactorEnabled && !result.user.isTwoFactorVerified) {
          setStep("two-factor");
        }
      } else {
        const result = await authSignup(email, password, name || undefined);
        setAuthUser(result.user);
        if (result.user.twoFactorEnabled && !result.user.isTwoFactorVerified) {
          setStep("two-factor");
        }
      }
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Login failed",
        ),
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleTwoFactorSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const user = await verifyTwoFactor(twoFactorCode);
      setAuthUser(user);
    } catch (err: unknown) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Invalid verification code",
        ),
      );
    } finally {
      setIsLoading(false);
    }
  };

  const labelClass =
    "block mb-2 text-[10px] font-black text-muted-foreground/40 uppercase tracking-[0.2em] ml-1";

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0F1117] relative overflow-hidden font-inter">
      {/* Dynamic Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-50" />
      <div className="absolute top-[-20%] right-[-10%] w-[70%] h-[70%] bg-primary/5 rounded-full blur-[140px] animate-pulse" />
      <div className="absolute bottom-[-15%] left-[-15%] w-[50%] h-[50%] bg-violet-500/5 rounded-full blur-[120px] animate-pulse delay-1000" />

      <div className="relative z-10 w-full max-w-[440px] px-6 py-12 animate-in fade-in slide-in-from-bottom-8 duration-1000">
        <div className="bg-surface-1/60 border border-white/5 rounded-[2.5rem] p-10 shadow-2xl glass-dark backdrop-blur-3xl relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent pointer-events-none" />

          {/* Logo & Branding */}
          <div className="text-center mb-10 relative">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-[2rem] bg-primary/10 border border-primary/20 mb-6 shadow-[0_0_30px_hsla(var(--primary),0.2)] group hover:scale-110 transition-premium">
              <Zap
                className="w-8 h-8 text-primary animate-status-pulse"
                fill="currentColor"
              />
            </div>
            <h1 className="text-4xl font-black text-white tracking-tighter font-outfit leading-none mb-3">
              TALOS
            </h1>
            <p className="text-[10px] text-primary/40 font-black uppercase tracking-[0.4em]">
              Operational Gateway
            </p>
          </div>

          {/* Mode Toggle */}
          {step === "credentials" && (
            <div className="flex bg-surface-2/40 border border-white/5 rounded-2xl p-1.5 mb-8 shadow-inner">
              <button
                onClick={() => setMode("login")}
                className={cn(
                  "flex-1 py-3 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium",
                  mode === "login"
                    ? "bg-primary text-white shadow-xl"
                    : "text-muted-foreground/40 hover:text-white",
                )}
              >
                Access
              </button>
              <button
                onClick={() => setMode("signup")}
                className={cn(
                  "flex-1 py-3 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium",
                  mode === "signup"
                    ? "bg-primary text-white shadow-xl"
                    : "text-muted-foreground/40 hover:text-white",
                )}
              >
                Enroll
              </button>
            </div>
          )}

          {step === "credentials" ? (
            <form
              aria-label="auth-form"
              onSubmit={handleSubmit}
              className="space-y-6"
            >
              {mode === "signup" && (
                <div className="animate-in fade-in slide-in-from-top-2 duration-300">
                  <label htmlFor="name" className={labelClass}>
                    Operator Name
                  </label>
                  <DarkInput
                    id="name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="E.G. COMMANDER_DATA"
                    className="h-12 bg-surface-3/40 border-white/5 focus:ring-primary/40 text-xs font-bold uppercase tracking-widest rounded-2xl"
                  />
                </div>
              )}

              <div>
                <label htmlFor="email" className={labelClass}>
                  Uplink Identifier
                </label>
                <DarkInput
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="ID@TALOS.SYS"
                  required
                  className="h-12 bg-surface-3/40 border-white/5 focus:ring-primary/40 text-xs font-bold uppercase tracking-widest rounded-2xl"
                />
              </div>

              <div>
                <label htmlFor="password" className={labelClass}>
                  Access Protocol
                </label>
                <DarkInput
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  minLength={12}
                  className="h-12 bg-surface-3/40 border-white/5 focus:ring-primary/40 text-xs font-bold tracking-[0.5em] rounded-2xl"
                />
                <p className="mt-3 text-[9px] text-muted-foreground/30 font-bold uppercase tracking-widest leading-relaxed px-1">
                  Requires 12+ characters, mixed case, numeric & tactical
                  symbols.
                </p>
              </div>

              {error && (
                <div className="bg-destructive/10 border border-destructive/20 text-destructive text-[10px] font-black uppercase tracking-widest rounded-2xl px-4 py-3 shadow-xl animate-in shake duration-500">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="w-full h-14 bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-[11px] font-black uppercase tracking-[0.2em] rounded-2xl transition-premium shadow-2xl active:scale-95 group relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0 -translate-x-full group-hover:translate-x-full transition-transform duration-1000" />
                {isLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin mx-auto" />
                ) : mode === "login" ? (
                  "Initiate Session"
                ) : (
                  "Register Identity"
                )}
              </button>
            </form>
          ) : (
            <form
              aria-label="two-factor-form"
              onSubmit={handleTwoFactorSubmit}
              className="space-y-8"
            >
              <div className="text-center space-y-2">
                <div className="inline-flex p-3 rounded-2xl bg-warning/10 border border-warning/20 mb-2">
                  <ShieldCheck className="w-6 h-6 text-warning" />
                </div>
                <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest leading-relaxed">
                  Dual-Factor Verification Required.
                  <br />
                  Enter 6-digit terminal code.
                </p>
              </div>

              <div>
                <DarkInput
                  id="twoFactorCode"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  autoComplete="one-time-code"
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value)}
                  placeholder="000000"
                  required
                  maxLength={6}
                  className="h-16 text-center text-2xl tracking-[0.8em] font-mono bg-surface-3/40 border-white/5 focus:ring-warning/40 text-warning rounded-2xl shadow-inner"
                />
              </div>

              {error && (
                <div className="bg-destructive/10 border border-destructive/20 text-destructive text-[10px] font-black uppercase tracking-widest rounded-2xl px-4 py-3 shadow-xl">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || twoFactorCode.length < 6}
                className="w-full h-14 bg-warning hover:bg-warning/90 disabled:opacity-40 disabled:cursor-not-allowed text-warning-foreground text-[11px] font-black uppercase tracking-[0.2em] rounded-2xl transition-premium shadow-2xl active:scale-95"
              >
                {isLoading ? "Verifying..." : "Confirm Protocol"}
              </button>

              <button
                type="button"
                onClick={() => {
                  setStep("credentials");
                  setError("");
                }}
                className="w-full text-[9px] text-muted-foreground/40 hover:text-white font-black uppercase tracking-[0.2em] transition-premium"
              >
                ← Return to Identifiers
              </button>
            </form>
          )}

          {/* Strategic Divider */}
          <div className="flex items-center gap-6 my-10 opacity-20">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent to-white" />
            <span className="text-[9px] text-white font-black tracking-[0.3em] uppercase">
              Uplink
            </span>
            <div className="flex-1 h-px bg-gradient-to-l from-transparent to-white" />
          </div>

          {/* Multi-Provider Auth */}
          {step === "credentials" && (
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => {
                  window.location.href = `${BACKEND_URL}/auth/oauth/google/login`;
                }}
                className="flex items-center justify-center gap-3 h-12 bg-surface-2/40 border border-white/5 hover:border-white/20 hover:bg-surface-2/60 text-white rounded-2xl transition-premium group"
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 20 20"
                  className="grayscale group-hover:grayscale-0 transition-premium"
                >
                  <path
                    d="M19.6 10.23c0-.82-.1-1.42-.25-2.05H10v3.72h5.5c-.15.96-.74 2.31-2.04 3.22v2.45h3.16c1.89-1.73 2.98-4.3 2.98-7.34z"
                    fill="#4285F4"
                  />
                  <path
                    d="M13.46 15.13c-.83.59-1.96 1-3.46 1-2.64 0-4.88-1.74-5.68-4.15H1.07v2.52C2.72 17.75 6.09 20 10 20c2.7 0 4.96-.89 6.62-2.42l-3.16-2.45z"
                    fill="#34A853"
                  />
                  <path
                    d="M3.99 10c0-.69.12-1.35.32-1.97V5.51H1.07A10.02 10.02 0 000 10c0 1.61.39 3.14 1.07 4.49l3.24-2.52c-.2-.62-.32-1.28-.32-1.97z"
                    fill="#FBBC05"
                  />
                  <path
                    d="M10 3.88c1.88 0 3.13.81 3.85 1.48l2.84-2.76C14.96.99 12.7 0 10 0 6.09 0 2.72 2.25 1.07 5.51l3.24 2.52C5.12 5.62 7.36 3.88 10 3.88z"
                    fill="#EA4335"
                  />
                </svg>
                <span className="text-[10px] font-black uppercase tracking-widest">
                  Google
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  window.location.href = `${BACKEND_URL}/auth/oauth/okta/login`;
                }}
                className="flex items-center justify-center gap-3 h-12 bg-surface-2/40 border border-white/5 hover:border-white/20 hover:bg-surface-2/60 text-white rounded-2xl transition-premium group"
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 20 20"
                  className="grayscale group-hover:grayscale-0 transition-premium"
                >
                  <circle cx="10" cy="10" r="10" fill="#007DC1" />
                  <path
                    d="M10 4c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6 2.69-6 6-6z"
                    fill="white"
                  />
                  <path d="M10 7a3 3 0 100 6 3 3 0 000-6z" fill="#007DC1" />
                </svg>
                <span className="text-[10px] font-black uppercase tracking-widest">
                  Okta
                </span>
              </button>
            </div>
          )}

          {mode === "signup" && (
            <p className="mt-8 text-center text-[9px] text-muted-foreground/30 font-bold uppercase tracking-[0.1em] leading-relaxed">
              BY ENROLLING, YOU ADHERE TO THE TALOS
              <br />
              <span className="text-muted-foreground/50 hover:text-white transition-premium cursor-pointer">
                OPERATIONAL DIRECTIVE
              </span>{" "}
              &{" "}
              <span className="text-muted-foreground/50 hover:text-white transition-premium cursor-pointer">
                PRIVACY PROTOCOL
              </span>
              .
            </p>
          )}
        </div>

        {/* Footer Link */}
        <div className="mt-10 text-center">
          <p className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.3em]">
            &copy; 2026 TALOS STUDIO ORCHESTRATION LAYER
          </p>
        </div>
      </div>
    </div>
  );
}
