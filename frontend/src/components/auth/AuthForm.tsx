import { config } from "@/config";
import React, { useState } from "react";
import { userFacingErrorMessage } from "@/lib/sanitize";
import {
  login as authLogin,
  signup as authSignup,
  verifyTwoFactor,
} from "@/lib/auth";
import { useAuth } from "@/contexts/AuthContext";
import { DarkInput } from "@/components/ui/DarkInput";
import { Zap, Loader2, ShieldCheck } from "lucide-react";
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
      setError(userFacingErrorMessage(err, "Login failed"));
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
      setError(userFacingErrorMessage(err, "Invalid verification code"));
    } finally {
      setIsLoading(false);
    }
  };

  const labelClass = "block mb-2 text-sm font-medium text-muted-foreground";

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden font-inter">
      {/* Dynamic Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-50 pointer-events-none" />

      <div className="relative z-10 w-full max-w-[420px] px-6 py-12 animate-in fade-in duration-500">
        <div className="bg-surface-1/80 border border-white/10 rounded-3xl p-10 shadow-2xl backdrop-blur-xl relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent pointer-events-none" />

          {/* Logo & Branding */}
          <div className="text-center mb-10 relative">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 mb-5">
              <Zap className="w-7 h-7 text-primary" fill="currentColor" />
            </div>
            <h1 className="text-3xl font-bold text-white tracking-tight font-outfit leading-none mb-2">
              Talos
            </h1>
            <p className="text-sm text-muted-foreground">Workflow automation</p>
          </div>

          {/* Mode Toggle */}
          {step === "credentials" && (
            <div className="flex bg-surface-2/60 border border-white/5 rounded-2xl p-1 mb-8">
              <button
                onClick={() => setMode("login")}
                className={cn(
                  "flex-1 py-2.5 text-sm font-medium rounded-xl transition-premium",
                  mode === "login"
                    ? "bg-primary text-white"
                    : "text-muted-foreground hover:text-white",
                )}
              >
                Sign in
              </button>
              <button
                onClick={() => setMode("signup")}
                className={cn(
                  "flex-1 py-2.5 text-sm font-medium rounded-xl transition-premium",
                  mode === "signup"
                    ? "bg-primary text-white"
                    : "text-muted-foreground hover:text-white",
                )}
              >
                Create account
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
                    Name
                  </label>
                  <DarkInput
                    id="name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Your name"
                    className="h-11 bg-surface-3/60 border-white/10 focus:ring-primary/40 text-sm rounded-xl"
                  />
                </div>
              )}

              <div>
                <label htmlFor="email" className={labelClass}>
                  Email
                </label>
                <DarkInput
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  className="h-11 bg-surface-3/60 border-white/10 focus:ring-primary/40 text-sm rounded-xl"
                />
              </div>

              <div>
                <label htmlFor="password" className={labelClass}>
                  Password
                </label>
                <DarkInput
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  minLength={12}
                  className="h-11 bg-surface-3/60 border-white/10 focus:ring-primary/40 text-sm rounded-xl"
                />
                <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
                  At least 12 characters, with upper and lower case, a number
                  and a symbol.
                </p>
              </div>

              {error && (
                <div
                  role="alert"
                  className="bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-xl px-4 py-3"
                >
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="w-full h-11 bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-xl transition-premium active:scale-[0.98]"
              >
                {isLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin mx-auto" />
                ) : mode === "login" ? (
                  "Sign in"
                ) : (
                  "Create account"
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
                <div className="inline-flex p-3 rounded-xl bg-warning/10 border border-warning/20 mb-2">
                  <ShieldCheck className="w-6 h-6 text-warning" />
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Enter the 6-digit code from your authenticator app.
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
                  className="h-14 text-center text-2xl tracking-[0.5em] font-mono bg-surface-3/60 border-white/10 focus:ring-warning/40 text-white rounded-xl"
                />
              </div>

              {error && (
                <div
                  role="alert"
                  className="bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-xl px-4 py-3"
                >
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || twoFactorCode.length < 6}
                className="w-full h-11 bg-warning hover:bg-warning/90 disabled:opacity-40 disabled:cursor-not-allowed text-warning-foreground text-sm font-semibold rounded-xl transition-premium active:scale-[0.98]"
              >
                {isLoading ? "Verifying…" : "Verify"}
              </button>

              <button
                type="button"
                onClick={() => {
                  setStep("credentials");
                  setError("");
                }}
                className="w-full text-sm text-muted-foreground hover:text-white transition-premium"
              >
                ← Back
              </button>
            </form>
          )}

          {/* Strategic Divider */}
          <div className="flex items-center gap-4 my-8">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-xs text-muted-foreground">
              or continue with
            </span>
            <div className="flex-1 h-px bg-white/10" />
          </div>

          {/* Multi-Provider Auth */}
          {step === "credentials" && (
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => {
                  window.location.href = `${BACKEND_URL}/auth/oauth/google/login`;
                }}
                className="flex items-center justify-center gap-3 h-11 bg-surface-2/60 border border-white/10 hover:border-white/20 hover:bg-surface-2 text-white rounded-xl transition-premium"
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 20 20"
                  aria-hidden="true"
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
                <span className="text-sm font-medium">Google</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  window.location.href = `${BACKEND_URL}/auth/oauth/okta/login`;
                }}
                className="flex items-center justify-center gap-3 h-11 bg-surface-2/60 border border-white/10 hover:border-white/20 hover:bg-surface-2 text-white rounded-xl transition-premium"
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 20 20"
                  aria-hidden="true"
                >
                  <circle cx="10" cy="10" r="10" fill="#007DC1" />
                  <path
                    d="M10 4c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6 2.69-6 6-6z"
                    fill="white"
                  />
                  <path d="M10 7a3 3 0 100 6 3 3 0 000-6z" fill="#007DC1" />
                </svg>
                <span className="text-sm font-medium">Okta</span>
              </button>
            </div>
          )}

          {mode === "signup" && (
            <p className="mt-8 text-center text-xs text-muted-foreground leading-relaxed">
              By creating an account you agree to the Talos terms of service and
              privacy policy.
            </p>
          )}
        </div>

        {/* Footer Link */}
        <div className="mt-10 text-center">
          <p className="text-xs text-muted-foreground/60">&copy; 2026 Talos</p>
        </div>
      </div>
    </div>
  );
}
