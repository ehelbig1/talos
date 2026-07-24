import React, { useEffect, useState } from "react";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { useNavigate } from "react-router";
import { Check, X } from "lucide-react";

export function OAuthCallback() {
  const [status, setStatus] = useState<"loading" | "success" | "error">(
    "loading",
  );
  const [message, setMessage] = useState("Completing sign in...");
  const navigate = useNavigate();

  const processedRef = React.useRef(false);

  useEffect(() => {
    const timeouts: ReturnType<typeof setTimeout>[] = [];

    const handleCallback = async () => {
      if (processedRef.current) return;
      processedRef.current = true;
      try {
        const params = new URLSearchParams(window.location.search);
        const success = params.get("success");
        const error = params.get("error");
        const code = params.get("code");

        if (code && !success && !error) {
          // MCP-905 (2026-05-14): provider-agnostic message. Pre-fix this
          // hardcoded "Google" + "Google Cloud Console" but the same
          // /auth/callback path serves Okta, Snyk, Atlassian, Gmail,
          // Slack — pointing an Okta user at their Google Cloud
          // Console wastes their time. The provider name lives in the
          // `state` param the controller minted (or can be inferred
          // from a `provider` param if the controller adds one); fall
          // back to a generic phrasing when neither is present.
          const provider =
            params.get("provider") || params.get("state")?.split(":")[0] || "";
          const providerLabel =
            provider && /^[a-z][a-z0-9_-]{0,32}$/i.test(provider)
              ? provider
              : "your OAuth provider";
          setStatus("error");
          setMessage(
            `Configuration error: ${providerLabel} redirected to the frontend instead of the backend. ` +
              `Check your ${providerLabel} OAuth app settings and ensure the Authorized redirect URI ` +
              `points to your BACKEND (e.g. https://your-backend/auth/oauth/${provider || "<provider>"}/callback), ` +
              `not the frontend.`,
          );
          return;
        }

        if (error) {
          setStatus("error");
          // Map structured error codes to safe, user-friendly messages.
          // Never display raw backend error strings — they may expose internal details.
          const safeMessage = (() => {
            switch (error) {
              case "email_not_verified":
                return "Your email address is not verified. Please verify it with your OAuth provider and try again.";
              case "account_disabled":
                return "This account has been disabled. Please contact support.";
              case "provider_error":
                return "The authentication provider returned an error. Please try again.";
              case "csrf_mismatch":
                return "Security check failed. Please try signing in again.";
              default:
                return "Authentication failed. Please try again or contact support if the problem persists.";
            }
          })();
          setMessage(safeMessage);
          return;
        }

        if (success === "true") {
          setStatus("success");
          if (window.opener && window.opener !== window) {
            setMessage("Integration successful! You can close this window.");
            timeouts.push(
              setTimeout(() => {
                window.close();
              }, 1000),
            );
          } else {
            setMessage("Sign in successful! Redirecting...");
            timeouts.push(
              setTimeout(() => {
                navigate("/");
              }, 1500),
            );
          }
        } else {
          setStatus("error");
          setMessage("Authentication failed: Invalid callback");
        }
      } catch {
        setStatus("error");
        setMessage("An unexpected error occurred. Please try again.");
      }
    };

    handleCallback();

    return () => {
      timeouts.forEach(clearTimeout);
    };
  }, [navigate]); // login is handled server-side via cookie redirect

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0F1117]">
      <div className="bg-surface-3/60 border border-white/5 rounded-xl p-12 w-full max-w-md shadow-2xl text-center">
        {status === "loading" && (
          <>
            <div className="animate-spin w-14 h-14 mx-auto mb-6 rounded-full border-4 border-white/10 border-t-violet-500" />
            <SectionHeader
              level="h2"
              className="text-xl font-semibold text-white mb-2"
            >
              Authenticating
            </SectionHeader>
            <p className="text-muted-foreground text-sm">{message}</p>
          </>
        )}

        {status === "success" && (
          <>
            <div className="w-14 h-14 mx-auto mb-6 bg-green-500 rounded-full flex items-center justify-center">
              <Check className="w-7 h-7 text-white" strokeWidth={3} />
            </div>
            <SectionHeader
              level="h2"
              className="text-xl font-semibold text-white mb-2"
            >
              Success!
            </SectionHeader>
            <p className="text-muted-foreground text-sm">{message}</p>
          </>
        )}

        {status === "error" && (
          <>
            <div className="w-14 h-14 mx-auto mb-6 bg-red-500 rounded-full flex items-center justify-center">
              <X className="w-7 h-7 text-white" strokeWidth={3} />
            </div>
            <SectionHeader
              level="h2"
              className="text-xl font-semibold text-white mb-2"
            >
              Authentication Failed
            </SectionHeader>
            <p className="text-muted-foreground text-sm mb-6">{message}</p>
            <button
              onClick={() => navigate("/")}
              className="px-6 py-2.5 bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium rounded-lg transition-premium"
            >
              Back to Login
            </button>
          </>
        )}
      </div>
    </div>
  );
}
