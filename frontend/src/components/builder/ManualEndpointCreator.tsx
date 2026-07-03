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
      <div className="animate-in fade-in slide-in-from-top-4 duration-700">
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
          "h-10 px-6 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium active:scale-95",
          baseUrl
            ? "bg-emerald-500 hover:bg-emerald-400 text-white shadow-lg shadow-emerald-500/20"
            : "bg-surface-3 text-muted-foreground/40 grayscale",
        )}
      >
        <Plus className="h-4 w-4 mr-2" /> Manual Vector Definition
      </Button>
    );
  }

  return (
    <div className="bg-surface-2/60 border border-emerald-500/20 rounded-[2.5rem] p-8 space-y-8 shadow-2xl animate-in zoom-in-95 duration-500 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 via-transparent to-transparent opacity-50 pointer-events-none" />

      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <Target className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h4 className="text-[11px] font-black text-white uppercase tracking-[0.2em]">
              Custom Vector Synthesis
            </h4>
            <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-widest">
              Manual Protocol Definition
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowCreator(false)}
          className="p-1.5 rounded-lg hover:bg-white/5 text-muted-foreground/20 hover:text-white transition-premium"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-6 relative z-10">
        {/* Method and Path */}
        <div className="flex gap-4">
          <div className="w-32 space-y-2">
            <label className="text-[9px] font-black text-white/40 uppercase tracking-widest px-1">
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
              className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-xs font-black uppercase tracking-widest text-white outline-none focus:border-emerald-500/40 transition-premium"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div className="flex-1 space-y-2">
            <label className="text-[9px] font-black text-white/40 uppercase tracking-widest px-1">
              Path <span className="text-emerald-400">*</span>
            </label>
            <input
              type="text"
              value={currentEndpoint.path}
              onChange={(e) =>
                setCurrentEndpoint({ ...currentEndpoint, path: e.target.value })
              }
              placeholder="/API/V1/RESOURCES/{ID}"
              className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-xs font-mono font-black uppercase tracking-widest text-white placeholder-white/10 outline-none focus:border-emerald-500/40 transition-premium"
            />
          </div>
        </div>

        {/* Summary */}
        <div className="space-y-2">
          <label className="text-[9px] font-black text-white/40 uppercase tracking-widest px-1">
            Operational Description
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
            placeholder="RETRIEVE TARGET RESOURCE BY IDENTIFIER"
            className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-xs font-black uppercase tracking-widest text-white placeholder-white/10 outline-none focus:border-emerald-500/40 transition-premium"
          />
        </div>

        {/* Parameters */}
        <div className="space-y-4 pt-4 border-t border-white/5">
          <div className="flex justify-between items-center px-1">
            <h5 className="text-[10px] font-black text-white/60 uppercase tracking-[0.2em]">
              Operational Parameters
            </h5>
            <div className="flex gap-2">
              {(["path", "query", "header"] as const).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => addParameter(type)}
                  className="h-7 px-3 bg-white/5 hover:bg-white/10 text-[8px] font-black text-white uppercase tracking-widest rounded-lg border border-white/5 transition-premium"
                >
                  <Plus className="h-3 w-3 mr-1.5 inline" /> {type}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {parameters.length === 0 ? (
              <div className="py-10 text-center bg-surface-4 border border-white/5 rounded-[2rem]">
                <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.3em]">
                  Null Parameters Defined
                </p>
              </div>
            ) : (
              <div className="space-y-3 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                {parameters.map((param, index) => (
                  <div
                    key={index}
                    className="flex gap-3 p-4 bg-surface-3/60 border border-white/5 rounded-2xl group/param items-center transition-premium hover:bg-surface-4"
                  >
                    <Badge
                      className={cn(
                        "w-16 h-8 text-[7px] font-black uppercase tracking-widest border",
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
                      className="flex-1 h-8 bg-surface-4 border border-white/5 rounded-lg px-3 text-[10px] font-black uppercase tracking-widest text-white outline-none focus:border-emerald-500/40"
                    />
                    <input
                      type="text"
                      value={param.description}
                      onChange={(e) =>
                        updateParameter(index, "description", e.target.value)
                      }
                      placeholder="DESCRIPTION"
                      className="flex-[2] h-8 bg-surface-4 border border-white/5 rounded-lg px-3 text-[10px] font-black uppercase tracking-widest text-white outline-none focus:border-emerald-500/40"
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
                      <span className="text-[8px] font-black text-muted-foreground/20 uppercase tracking-widest group-hover/check:text-white transition-premium">
                        Req
                      </span>
                    </label>
                    <button
                      type="button"
                      onClick={() => removeParameter(index)}
                      className="p-1.5 rounded-lg hover:bg-destructive/10 text-muted-foreground/20 hover:text-destructive transition-premium"
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
              "flex-1 h-12 text-[10px] font-black uppercase tracking-widest rounded-2xl transition-premium shadow-2xl active:scale-95 flex items-center justify-center gap-3",
              currentEndpoint.path
                ? "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20"
                : "bg-surface-3 text-muted-foreground/40",
            )}
          >
            <Check className="h-4 w-4" /> Synthesize & Lock Vector
          </Button>
          <Button
            type="button"
            onClick={() => setShowCreator(false)}
            variant="ghost"
            className="h-12 px-8 bg-surface-3 hover:bg-surface-4 text-muted-foreground/40 hover:text-white text-[10px] font-black uppercase tracking-widest rounded-2xl border border-white/5 transition-premium"
          >
            Abort
          </Button>
        </div>

        <div className="p-6 bg-emerald-500/5 border border-emerald-500/10 rounded-[2rem] flex items-start gap-4">
          <div className="shrink-0 p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-[10px] text-emerald-400/60 font-bold uppercase tracking-widest leading-relaxed">
            Strategic Insight: Manual vector synthesis requires precise path
            variable identification. Use {`{variable_name}`} syntax for dynamic
            path injection.
          </p>
        </div>
      </div>
    </div>
  );
}
