import { sanitizeErrorMessage } from "@/lib/sanitize";
import React, { Component, ReactNode } from "react";

export default class ErrorBoundary extends Component<
  { children: ReactNode; fallback?: ReactNode | ((error: Error) => ReactNode) },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: {
    children: ReactNode;
    fallback?: ReactNode | ((error: Error) => ReactNode);
  }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    // Always log uncaught render errors. Without this, production
    // failures show only the generic fallback UI with no signal — even
    // the developer-tools console is empty unless DEV mode was set
    // at build time. console.error survives in prod (the browser
    // captures it) and lets us correlate user reports with stack
    // traces. Wire a Sentry / Datadog hook here later if the volume
    // warrants it.
    console.error("ErrorBoundary caught:", error, errorInfo);

    // Optional integration point: window.__talosOnRenderError can be
    // attached at startup (e.g. from observability bootstrap) without
    // forcing every consumer to import a reporter.
    type RenderErrorReporter = (
      error: Error,
      info: React.ErrorInfo,
    ) => void;
    const reporter = (
      window as unknown as { __talosOnRenderError?: RenderErrorReporter }
    ).__talosOnRenderError;
    if (typeof reporter === "function") {
      try {
        reporter(error, errorInfo);
      } catch (e) {
        console.error("ErrorBoundary reporter threw:", e);
      }
    }
  }

  render() {
    if (this.state.hasError) {
      if (typeof this.props.fallback === "function") {
        return this.props.fallback(this.state.error!);
      }
      return (
        <div className="p-4 text-destructive overflow-hidden text-ellipsis">
          Something went wrong:{" "}
          {this.state.error?.message
            ? sanitizeErrorMessage(this.state.error.message)
            : "Unknown error"}
        </div>
      );
    }
    return this.props.children;
  }
}
