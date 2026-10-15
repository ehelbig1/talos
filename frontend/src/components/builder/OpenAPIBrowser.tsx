import React, { useState } from "react";
import type { OpenAPISpec } from "@/lib/openapi";
import { discoverOpenAPISpec, parseOpenAPIEndpoints } from "@/lib/openapi";
import type { Endpoint } from "./EndpointSelector";
import { EndpointSelector } from "./EndpointSelector";
import { Search, X, Loader2, Globe, Activity, Zap } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui";

interface OpenAPIBrowserProps {
  baseUrl: string;
  onSelectEndpoint: (config: Record<string, unknown>) => void;
}

export function OpenAPIBrowser({
  baseUrl,
  onSelectEndpoint,
}: OpenAPIBrowserProps) {
  const [loading, setLoading] = useState(false);
  const [, setSpec] = useState<OpenAPISpec | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showBrowser, setShowBrowser] = useState(false);
  const [useSelector, setUseSelector] = useState(false);

  const discoverAPI = async () => {
    setLoading(true);
    setError(null);

    try {
      const discoveredSpec = await discoverOpenAPISpec(baseUrl);

      if (!discoveredSpec) {
        setError("No OpenAPI/Swagger specification found at this URL");
        setLoading(false);
        return;
      }

      setSpec(discoveredSpec);
      const parsedEndpoints = parseOpenAPIEndpoints(discoveredSpec);
      setEndpoints(parsedEndpoints as Endpoint[]);
      setShowBrowser(true);
      setUseSelector(true);
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          "Failed to discover API: " +
            (err instanceof Error ? err.message : "Unknown error"),
        ),
      );
    } finally {
      setLoading(false);
    }
  };

  const handleConfigured = (config: {
    method: string;
    url: string;
    headers: Array<{ key: string; value: string }>;
    body?: string;
  }) => {
    onSelectEndpoint({
      METHOD: config.method,
      URL: config.url,
      HEADERS: config.headers,
      BODY: config.body || "",
    });
    setShowBrowser(false);
    setUseSelector(false);
  };

  if (!showBrowser) {
    return (
      <div className="space-y-4">
        <Button
          type="button"
          onClick={discoverAPI}
          disabled={loading || !baseUrl}
          className={cn(
            "h-10 px-6 text-sm font-semibold rounded-xl transition-ui",
            baseUrl
              ? "bg-primary hover:bg-primary/90 text-white"
              : "bg-surface-3 text-muted-foreground/70 grayscale",
          )}
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin mr-2" /> Deciphering
              Schema...
            </>
          ) : (
            <>
              <Search className="h-4 w-4 mr-2" /> Discovery Scan
            </>
          )}
        </Button>

        {error && (
          <div className="p-3 bg-destructive/5 border border-destructive/20 rounded-xl flex items-center gap-2 text-destructive">
            <X className="h-3.5 w-3.5" />
            <p className="m-0 text-2xs font-semibold leading-none">{error}</p>
          </div>
        )}
      </div>
    );
  }

  if (useSelector && endpoints.length > 0) {
    return (
      <div>
        <EndpointSelector
          endpoints={endpoints}
          baseUrl={baseUrl}
          onConfigure={handleConfigured}
        />
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden p-8 bg-surface-2/40 border border-white/5 rounded-2xl space-y-8">
      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20">
            <Globe className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-white">
              API Schema Deciphered
            </h4>
            <p className="text-xs font-medium text-muted-foreground/50">
              Found {endpoints.length} endpoint
              {endpoints.length !== 1 ? "s" : ""}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowBrowser(false)}
          className="p-1.5 rounded-lg hover:bg-white/5 text-muted-foreground/50 hover:text-white transition-ui"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex flex-col items-center justify-center py-10 px-6 bg-surface-4 rounded-2xl border-2 border-dashed border-white/5">
        <Activity className="w-12 h-12 text-muted-foreground/30 mb-4" />
        <p className="text-xs font-semibold text-muted-foreground/50">
          No endpoints found
        </p>
      </div>

      <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
        <div className="shrink-0 p-2 rounded-xl bg-primary/10 border border-primary/20">
          <Zap className="w-4 h-4 text-primary" />
        </div>
        <p className="text-xs text-primary/60 leading-relaxed">
          The URL must serve a valid OpenAPI/Swagger document (JSON or YAML) so
          endpoints can be read from it.
        </p>
      </div>
    </div>
  );
}
