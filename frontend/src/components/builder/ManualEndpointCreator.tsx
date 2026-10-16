import React, { useState } from "react";
import { Plus, X, Check, Target, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { EndpointSelector } from "./EndpointSelector";
import { Button, Badge } from "@/components/ui";

interface Parameter {
  name: string;
  in: "path" | "query" | "header";
  required: boolean;
  type: string;
  description: string;
}

interface CustomEndpoint {
  path: string;
  method: string;
  summary: string;
  parameters: Parameter[];
}

interface ManualEndpointCreatorProps {
  baseUrl: string;
  onConfigure: (config: Record<string, unknown>) => void;
}

export function ManualEndpointCreator({
  baseUrl,
  onConfigure,
}: ManualEndpointCreatorProps) {
  const [showCreator, setShowCreator] = useState(false);
  const [customEndpoints, setCustomEndpoints] = useState<CustomEndpoint[]>([]);
  const [currentEndpoint, setCurrentEndpoint] = useState({
    path: "",
    method: "GET",
    summary: "",
  });
  const [parameters, setParameters] = useState<Parameter[]>([]);

  const addParameter = (type: "path" | "query" | "header") => {
    setParameters([
      ...parameters,
      {
        name: "",
        in: type,
        required: false,
        type: "string",
        description: "",
      },
    ]);
  };

  const updateParameter = (index: number, field: string, value: unknown) => {
    const updated = [...parameters];
    updated[index] = { ...updated[index], [field]: value } as Parameter;
    setParameters(updated);
  };

  const removeParameter = (index: number) => {
    setParameters(parameters.filter((_, i) => i !== index));
  };

  const saveEndpoint = () => {
    if (!currentEndpoint.path) return;

    const endpoint: CustomEndpoint = {
      ...currentEndpoint,
      parameters: parameters.filter((p) => p.name),
    };

    setCustomEndpoints([...customEndpoints, endpoint]);
    setCurrentEndpoint({ path: "", method: "GET", summary: "" });
    setParameters([]);
    setShowCreator(false);
  };

  const handleConfigured = (config: Record<string, unknown>) => {
    onConfigure({
      METHOD: config.method,
      URL: config.url,
      HEADERS: config.headers,
      BODY: config.body || "",
    });
    setCustomEndpoints([]);
  };

  if (customEndpoints.length > 0) {
    return (
      <div>
        <EndpointSelector
          endpoints={customEndpoints}
          baseUrl={baseUrl}
          onConfigure={handleConfigured}
        />
      </div>
    );
  }

  if (!showCreator) {
    return (
      <Button
        type="button"
        onClick={() => setShowCreator(true)}
        disabled={!baseUrl}
        className={cn(
          "h-10 px-6 text-sm font-semibold rounded-xl transition-ui",
          baseUrl
            ? "bg-emerald-500 hover:bg-emerald-400 text-white shadow-emerald-500/20"
            : "bg-surface-3 text-muted-foreground/70 grayscale",
        )}
      >
        <Plus className="h-4 w-4 mr-2" /> Define endpoint manually
      </Button>
    );
  }

  return (
    <div className="bg-surface-2/60 border border-emerald-500/20 rounded-2xl p-8 space-y-8 relative overflow-hidden">
      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <Target className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-white">
              Custom endpoint
            </h4>
            <p className="text-xs font-medium text-muted-foreground/50">
              Define the request by hand
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowCreator(false)}
          aria-label="Close"
          className="p-1.5 rounded-lg hover:bg-white/5 text-muted-foreground/50 hover:text-white transition-ui"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-6 relative z-10">
        {/* Method and Path */}
        <div className="flex gap-4">
          <div className="w-32 space-y-2">
            <label className="text-xs font-medium text-white/70 px-1">
              Method
            </label>
            <select
              value={currentEndpoint.method}
              onChange={(e) =>
                setCurrentEndpoint({
                  ...currentEndpoint,
                  method: e.target.value,
                })
              }
              className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-sm font-semibold text-white outline-none focus:border-emerald-500/40 transition-ui"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div className="flex-1 space-y-2">
            <label className="text-xs font-medium text-white/70 px-1">
              Path <span className="text-emerald-400">*</span>
            </label>
            <input
              type="text"
              value={currentEndpoint.path}
              onChange={(e) =>
                setCurrentEndpoint({ ...currentEndpoint, path: e.target.value })
              }
              placeholder="/API/V1/RESOURCES/{ID}"
              className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-sm font-mono font-semibold text-white placeholder-white/10 outline-none focus:border-emerald-500/40 transition-ui"
            />
          </div>
        </div>

        {/* Summary */}
        <div className="space-y-2">
          <label className="text-xs font-medium text-white/70 px-1">
            Description
          </label>
          <input
            type="text"
            value={currentEndpoint.summary}
            onChange={(e) =>
              setCurrentEndpoint({
                ...currentEndpoint,
                summary: e.target.value,
              })
            }
            placeholder="e.g. Get a user by ID"
            className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-sm font-semibold text-white placeholder-white/10 outline-none focus:border-emerald-500/40 transition-ui"
          />
        </div>

        {/* Parameters */}
        <div className="space-y-4 pt-4 border-t border-white/5">
          <div className="flex justify-between items-center px-1">
            <h5 className="text-xs font-semibold text-white/60">Parameters</h5>
            <div className="flex gap-2">
              {(["path", "query", "header"] as const).map((type) => (
                <Button
                  variant="outline"
                  size="sm"
                  className="capitalize"
                  key={type}
                  onClick={() => addParameter(type)}
                >
                  <Plus className="h-3 w-3 mr-1.5 inline" /> {type}
                </Button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {parameters.length === 0 ? (
              <div className="py-10 text-center bg-surface-4 border border-white/5 rounded-2xl">
                <p className="text-xs font-medium text-muted-foreground/50">
                  No parameters
                </p>
              </div>
            ) : (
              <div className="space-y-3 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                {parameters.map((param, index) => (
                  <div
                    key={index}
                    className="flex gap-3 p-4 bg-surface-3/60 border border-white/5 rounded-2xl group/param items-center transition-ui hover:bg-surface-4"
                  >
                    <Badge
                      className={cn(
                        "w-16 h-8 text-2xs font-semibold uppercase tracking-wider border",
                        param.in === "path"
                          ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                          : param.in === "query"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-purple-500/10 text-purple-400 border-purple-500/20",
                      )}
                    >
                      {param.in}
                    </Badge>
                    <input
                      type="text"
                      value={param.name}
                      onChange={(e) =>
                        updateParameter(index, "name", e.target.value)
                      }
                      placeholder="KEY"
                      className="flex-1 h-8 bg-surface-4 border border-white/5 rounded-lg px-3 text-sm font-semibold text-white outline-none focus:border-emerald-500/40"
                    />
                    <input
                      type="text"
                      value={param.description}
                      onChange={(e) =>
                        updateParameter(index, "description", e.target.value)
                      }
                      placeholder="Description"
                      className="flex-[2] h-8 bg-surface-4 border border-white/5 rounded-lg px-3 text-sm font-semibold text-white outline-none focus:border-emerald-500/40"
                    />
                    <label className="flex items-center gap-2 cursor-pointer group/check">
                      <input
                        type="checkbox"
                        checked={param.required}
                        onChange={(e) =>
                          updateParameter(index, "required", e.target.checked)
                        }
                        className="w-4 h-4 rounded border-white/10 bg-surface-4 text-emerald-500 focus:ring-emerald-500/40"
                      />
                      <span className="text-2xs font-semibold text-muted-foreground/50 uppercase tracking-wider group-hover/check:text-white transition-ui">
                        Req
                      </span>
                    </label>
                    <button
                      type="button"
                      onClick={() => removeParameter(index)}
                      aria-label="Remove parameter"
                      className="p-1.5 rounded-lg hover:bg-destructive/10 text-muted-foreground/50 hover:text-destructive transition-ui"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-4 pt-6">
          <Button
            type="button"
            onClick={saveEndpoint}
            disabled={!currentEndpoint.path}
            className={cn(
              "flex-1 h-12 text-sm font-semibold rounded-2xl transition-ui flex items-center justify-center gap-3",
              currentEndpoint.path
                ? "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20"
                : "bg-surface-3 text-muted-foreground/70",
            )}
          >
            <Check className="h-4 w-4" /> Save endpoint
          </Button>
          <Button
            type="button"
            onClick={() => setShowCreator(false)}
            variant="ghost"
            className="h-12 px-8 bg-surface-3 hover:bg-surface-4 text-muted-foreground/70 hover:text-white text-sm font-semibold rounded-2xl border border-white/5 transition-ui"
          >
            Cancel
          </Button>
        </div>

        <div className="p-6 bg-emerald-500/5 border border-emerald-500/10 rounded-2xl flex items-start gap-4">
          <div className="shrink-0 p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-xs text-emerald-400/60 leading-relaxed">
            Tip: use {`{variable_name}`} in the path for values that change per
            request.
          </p>
        </div>
      </div>
    </div>
  );
}
