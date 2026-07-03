import * as React from "react";
import { cn } from "@/lib/utils";
import { SectionHeader } from "@/components/ui/SectionHeader";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { AlertTriangle } from "lucide-react";

export interface ErrorMessageProps {
  title?: string;
  message: string;
  technicalDetails?: string;
  error?: Error;
  onRetry?: () => void;
  onDismiss?: () => void;
  className?: string;
}

// Map common errors to user-friendly messages
const errorMappings: Record<string, { title: string; suggestion: string }> = {
  "401": {
    title: "Authentication Required",
    suggestion: "Your session may have expired. Try logging in again.",
  },
  "403": {
    title: "Access Denied",
    suggestion: "You don't have permission to perform this action.",
  },
  "404": {
    title: "Not Found",
    suggestion: "The requested resource could not be found.",
  },
  "500": {
    title: "Server Error",
    suggestion: "Something went wrong on our end. Please try again later.",
  },
  network: {
    title: "Connection Error",
    suggestion: "Please check your internet connection and try again.",
  },
  timeout: {
    title: "Request Timed Out",
    suggestion: "The request took too long. Please try again.",
  },
};

function getErrorInfo(
  message: string,
  _error?: Error,
): { title: string; suggestion: string } {
  // Check for HTTP status codes
  const statusMatch = message.match(/status (\d+)/i);
  if (statusMatch) {
    const status = statusMatch[1];
    if (errorMappings[status]) {
      return errorMappings[status];
    }
  }

  // Check for network errors
  if (
    message.toLowerCase().includes("network") ||
    message.toLowerCase().includes("fetch")
  ) {
    return errorMappings.network;
  }

  // Check for timeout errors
  if (message.toLowerCase().includes("timeout")) {
    return errorMappings.timeout;
  }

  // Default
  return {
    title: "Error",
    suggestion: "An unexpected error occurred. Please try again.",
  };
}

export function ErrorMessage({
  title,
  message,
  technicalDetails,
  error,
  onRetry,
  onDismiss,
  className,
}: ErrorMessageProps) {
  const [showDetails, setShowDetails] = React.useState(false);

  const errorInfo = getErrorInfo(message, error);
  const displayTitle = title || errorInfo.title;
  const displaySuggestion = errorInfo.suggestion;

  const displayTechnicalDetails =
    technicalDetails || error?.stack || error?.message || message;

  return (
    <div
      className={cn(
        "rounded-lg border border-destructive/50 bg-destructive/10 p-4",
        className,
      )}
      role="alert"
    >
      {/* Icon and Title */}
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0">
          <AlertTriangle className="h-5 w-5 text-destructive" />
        </div>

        <div className="flex-1 space-y-2">
          <SectionHeader level="h3" className="font-semibold text-foreground">
            {displayTitle}
          </SectionHeader>
          <p className="text-sm text-muted-foreground">{displaySuggestion}</p>

          {/* Technical Details - Collapsible */}
          {displayTechnicalDetails && (
            <Collapsible open={showDetails} onOpenChange={setShowDetails}>
              <CollapsibleTrigger asChild>
                <button
                  type="button"
                  className="text-xs text-primary hover:underline focus:outline-none"
                >
                  {showDetails ? "Hide" : "Show"} Technical Details ▼
                </button>
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-2">
                <pre className="rounded bg-muted p-2 text-xs overflow-x-auto">
                  <code>{displayTechnicalDetails}</code>
                </pre>
              </CollapsibleContent>
            </Collapsible>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            {onRetry && (
              <button
                onClick={onRetry}
                className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-primary-foreground bg-primary rounded hover:bg-primary/90 transition-premium"
              >
                Retry
              </button>
            )}
            {onDismiss && (
              <button
                onClick={onDismiss}
                className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-foreground border border-input rounded hover:bg-accent transition-premium"
              >
                Dismiss
              </button>
            )}
            <a
              href="https://github.com/anthropics/talos/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-foreground border border-input rounded hover:bg-accent transition-premium"
            >
              Contact Support
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

// Hook for using error messages
export function useErrorHandler() {
  const [error, setError] = React.useState<Error | null>(null);

  const handleError = React.useCallback((err: Error | string) => {
    if (typeof err === "string") {
      setError(new Error(err));
    } else {
      setError(err);
    }
  }, []);

  const clearError = React.useCallback(() => {
    setError(null);
  }, []);

  return { error, handleError, clearError };
}
