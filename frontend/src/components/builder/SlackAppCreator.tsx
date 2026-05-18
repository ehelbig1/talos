import React, { useRef, useState } from "react";
import { Dialog, Section } from "@/components/ui";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { FlexContainer } from "@/components/ui/FlexContainer";
import { authedFetch } from "@/lib/authedFetch";

interface SlackAppCreatorProps {
  webhookUrl: string;
  eventTypes: string[];
  onAppCreated: (credentials: {
    appId: string;
    clientId: string;
    clientSecret: string;
    signingSecret: string;
    verificationToken: string;
    botUserId: string;
  }) => void;
  onCancel: () => void;
}

interface SlackAppResponse {
  app_id: string;
  client_id: string;
  client_secret: string;
  signing_secret: string;
  verification_token: string;
  bot_user_id: string;
}

export function SlackAppCreator({
  webhookUrl,
  eventTypes,
  onAppCreated,
  onCancel,
}: SlackAppCreatorProps) {
  const [step, setStep] = useState<
    "info" | "token" | "creating" | "success" | "error"
  >("info");
  const [appName, setAppName] = useState("");
  const [description, setDescription] = useState("");
  // Use a ref instead of state so the sensitive xoxp token is never held in
  // React component state (and therefore never visible in React DevTools).
  const userTokenRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [createdApp, setCreatedApp] = useState<SlackAppResponse | null>(null);

  const handleCreate = async () => {
    if (!appName.trim()) {
      setError("App name is required");
      return;
    }

    const userToken = userTokenRef.current?.value ?? "";
    if (!userToken.trim() || !userToken.startsWith("xoxp-")) {
      setError("Please enter a valid Slack user token (starts with xoxp-)");
      return;
    }

    setStep("creating");
    setError(null);

    let response: Response;
    try {
      response = await authedFetch("/api/slack/apps/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_name: appName,
          description: description || `Webhook listener created in Talos`,
          webhook_url: webhookUrl,
          event_types:
            eventTypes.length > 0 ? eventTypes : ["message.channels"],
          user_token: userToken,
        }),
      });
    } catch {
      // authedFetch throws on non-2xx responses with a sanitized message.
      // Re-wrap as the generic "Failed to create" prefix so the UI catch
      // block surfaces our user-facing copy rather than the raw server text.
      if (userTokenRef.current) userTokenRef.current.value = "";
      setError(
        "Failed to create Slack app. Please check your token and try again.",
      );
      setStep("error");
      return;
    }

    try {
      // Clear the sensitive token from the DOM input immediately after sending.
      if (userTokenRef.current) userTokenRef.current.value = "";

      const data = await response.json();

      if (!data.success) {
        throw new Error(
          "Failed to create Slack app. Please check your token and try again.",
        );
      }

      setCreatedApp(data);
      setStep("success");

      // Pass credentials to parent
      onAppCreated({
        appId: data.app_id,
        clientId: data.client_id,
        clientSecret: data.client_secret,
        signingSecret: data.signing_secret,
        verificationToken: data.verification_token,
        botUserId: data.bot_user_id,
      });
    } catch (err) {
      // Display a safe, generic message — never expose raw server error strings.
      setError(
        err instanceof Error && err.message.startsWith("Failed to create")
          ? err.message
          : "An error occurred while creating the Slack app. Please try again.",
      );
      setStep("error");
    }
  };

  return (
    <Dialog open={true} onClose={onCancel} title="Create Slack App">
      <div className="bg-surface-3/60 rounded-xl max-w-2xl w-11/12 max-h-[90vh] overflow-auto p-8 shadow-xl">
        {/* Header */}
        <div className="mb-8 text-center">
          <div className="text-4xl mb-4">🚀</div>
          <SectionHeader level="h2" className="m-0 text-xl text-foreground">
            Create Slack App
          </SectionHeader>
          <p className="mt-2 text-muted-foreground text-sm">
            Automatically configure a new Slack app for your webhook
          </p>
        </div>

        {/* Info Step */}
        {step === "info" && (
          <>
            <Section>
              <label
                htmlFor="slack-app-name"
                className="block mb-1 font-bold text-sm"
              >
                App Name *
              </label>
              <input
                id="slack-app-name"
                type="text"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="My Webhook App"
                className="w-full p-2 border-2 border-white/10 rounded text-sm"
                autoFocus
              />
            </Section>

            <Section>
              <label
                htmlFor="slack-app-desc"
                className="block mb-1 font-bold text-sm"
              >
                Description (Optional)
              </label>
              <textarea
                id="slack-app-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Receives events from Slack and processes them"
                rows={3}
                className="w-full p-2 border-2 border-white/10 rounded text-sm"
              />
            </Section>

            <Section>
              <div className="text-sm mb-2">
                <strong>📋 Configuration Preview:</strong>
              </div>
              <ul className="ml-6 text-xs text-muted-foreground">
                <li>
                  Webhook URL:{" "}
                  <code className="bg-surface-3/60 px-1 py-0.5 rounded">
                    {webhookUrl || "Will be provided after webhook creation"}
                  </code>
                </li>
                <li>
                  Event Types:{" "}
                  {eventTypes.length > 0
                    ? eventTypes.join(", ")
                    : "message.channels (default)"}
                </li>
                <li>
                  Required Scopes: channels:read, users:read, channels:history,
                  chat:write
                </li>
              </ul>
            </Section>

            <FlexContainer gap="0.75rem">
              <Button
                onClick={() => setStep("token")}
                disabled={!appName.trim()}
                className="flex-1"
                variant={appName.trim() ? "default" : "outline"}
              >
                Next: Authorize
              </Button>
              <Button variant="outline" onClick={onCancel}>
                Cancel
              </Button>
            </FlexContainer>
          </>
        )}

        {/* Token Step */}
        {step === "token" && (
          <>
            <Section className="p-4 bg-yellow-100 border border-yellow-300 rounded">
              <div className="text-sm text-yellow-800">
                <strong>🔐 Authorization Required</strong>
                <p className="mt-2">
                  To create a Slack app, you need a user token with{" "}
                  <code>apps:write</code> scope.
                </p>
              </div>
            </Section>

            <Section className="text-sm leading-relaxed">
              <p className="mb-2 font-bold">How to get a user token:</p>
              <ol className="ml-6 list-decimal">
                <li>
                  Go to{" "}
                  <a
                    href="https://api.slack.com/apps"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-purple-800"
                  >
                    api.slack.com/apps
                  </a>
                </li>
                <li>Create a temporary app or use an existing one</li>
                <li>
                  Navigate to <strong>OAuth & Permissions</strong>
                </li>
                <li>
                  Under <strong>User Token Scopes</strong>, add{" "}
                  <code>apps:write</code>
                </li>
                <li>Install/Reinstall the app to your workspace</li>
                <li>
                  Copy the <strong>User OAuth Token</strong> (starts with{" "}
                  <code>xoxp-</code>)
                </li>
              </ol>
            </Section>

            <Section>
              <label
                htmlFor="slack-token"
                className="block mb-1 font-bold text-sm"
              >
                User OAuth Token *
              </label>
              {/* Uncontrolled input — value is read via ref only at submit time
                  so the token is never held in React component state. */}
              <input
                id="slack-token"
                type="password"
                ref={userTokenRef}
                placeholder="xoxp-your-user-token"
                className="w-full p-2 border-2 border-white/10 rounded text-sm"
                autoComplete="off"
              />
              <p className="mt-2 text-xs text-muted-foreground">
                This token will only be used once to create the app and won't be
                stored.
              </p>
            </Section>

            {error && (
              <Section className="p-3 bg-red-100 border border-red-300 rounded">
                ⚠️ {error}
              </Section>
            )}

            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleCreate}
                className="flex-1 px-4 py-2 bg-green-600 text-white rounded font-bold"
              >
                Create App
              </button>
              <button
                type="button"
                onClick={() => setStep("info")}
                className="px-4 py-2 bg-surface-3/60 text-muted-foreground border-2 border-white/10 rounded"
              >
                Back
              </button>
            </div>
          </>
        )}

        {/* Creating Step */}
        {step === "creating" && (
          <div className="text-center py-8">
            <div className="text-5xl mb-4">⏳</div>
            <SectionHeader level="h3" className="mb-2">
              Creating Your Slack App...
            </SectionHeader>
            <p className="text-muted-foreground text-sm">
              This may take a few seconds
            </p>
          </div>
        )}

        {/* Success Step */}
        {step === "success" && createdApp && (
          <>
            <div style={{ textAlign: "center", marginBottom: "2rem" }}>
              <div style={{ fontSize: "4rem", marginBottom: "1rem" }}>✅</div>
              <SectionHeader
                level="h3"
                style={{ margin: "0 0 0.5rem 0", color: "#007a5a" }}
              >
                App Created Successfully!
              </SectionHeader>
              <p style={{ margin: 0, color: "#666", fontSize: "0.875rem" }}>
                Your Slack app "{appName}" has been configured
              </p>
            </div>

            <Section className="p-4 bg-blue-50 border border-blue-200 rounded">
              <div className="text-sm mb-2 font-bold">📝 App Credentials:</div>
              <div className="text-xs font-mono leading-snug">
                {createdApp.app_id && (
                  <div>
                    <strong>App ID:</strong> {createdApp.app_id}
                  </div>
                )}
                {createdApp.client_id && (
                  <div>
                    <strong>Client ID:</strong> {createdApp.client_id}
                  </div>
                )}
                {createdApp.bot_user_id && (
                  <div>
                    <strong>Bot User ID:</strong> {createdApp.bot_user_id}
                  </div>
                )}
              </div>
            </Section>

            <Section className="p-4 bg-green-100 border border-green-200 rounded">
              <div className="text-sm text-green-800">
                <strong>✓ Next Steps:</strong>
                <ol className="ml-6 list-decimal">
                  <li>Install the app to your Slack workspace</li>
                  <li>
                    The credentials have been auto-filled in your webhook
                    configuration
                  </li>
                  <li>Test your webhook by sending a message in Slack!</li>
                </ol>
              </div>
            </Section>

            <button
              type="button"
              onClick={onCancel}
              className="w-full py-2 bg-green-600 text-white rounded font-bold"
            >
              Done
            </button>
          </>
        )}

        {/* Error Step */}
        {step === "error" && (
          <>
            <div style={{ textAlign: "center", marginBottom: "2rem" }}>
              <div style={{ fontSize: "4rem", marginBottom: "1rem" }}>❌</div>
              <SectionHeader
                level="h3"
                style={{ margin: "0 0 0.5rem 0", color: "#dc3545" }}
              >
                Failed to Create App
              </SectionHeader>
            </div>

            <Section
              style={{
                padding: "1rem",
                background: "#fee",
                border: "1px solid #fcc",
                borderRadius: "8px",
              }}
            >
              <div style={{ fontSize: "0.875rem", color: "#c33" }}>
                <strong>Error:</strong> {error}
              </div>
            </Section>

            <div style={{ display: "flex", gap: "0.75rem" }}>
              <button
                type="button"
                onClick={() => {
                  setStep("token");
                  setError(null);
                }}
                style={{
                  flex: 1,
                  padding: "0.875rem",
                  background: "#007a5a",
                  color: "white",
                  border: "none",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontSize: "0.9375rem",
                  fontWeight: "bold",
                }}
              >
                Try Again
              </button>
              <button
                type="button"
                onClick={onCancel}
                style={{
                  padding: "0.875rem 1.5rem",
                  background: "white",
                  color: "#616061",
                  border: "2px solid #e1e1e1",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontSize: "0.9375rem",
                }}
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </Dialog>
  );
}
