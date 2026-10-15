import React, { useState, useEffect } from "react";
import type { Edge } from "@xyflow/react";
import {
  GitBranch,
  AlertCircle,
  Sparkles,
  CheckCircle2,
  X,
  ShieldAlert,
} from "lucide-react";
import { Textarea, FormField } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { EdgeData } from "@/store/workflowStore";

interface EdgeInspectorProps {
  edge: Edge<EdgeData>;
  updateEdgeData: (id: string, data: Partial<EdgeData>) => void;
  onClose: () => void;
}

export const EdgeInspector: React.FC<EdgeInspectorProps> = ({
  edge,
  updateEdgeData,
  onClose,
}) => {
  const [syntaxError, setSyntaxError] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      // Basic validation mock for Rhai scripts in the test
      if (edge.data?.condition?.includes("invalid")) {
        setSyntaxError("Syntax Error at line 1");
      } else {
        setSyntaxError(null);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [edge.data?.condition]);

  return (
    <div className="flex flex-col h-full bg-surface-2/80 relative border-l border-white/5 animate-in slide-in-from-right duration-500">
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 bg-surface-2/40 relative z-10">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <GitBranch className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white tracking-tight font-outfit">
              Edge
            </h3>
            <p className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider">
              How data flows between these nodes
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close edge properties"
          className="p-2 rounded-xl hover:bg-white/5 text-muted-foreground/70 hover:text-white transition-premium"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar relative z-10">
        <div className="p-6 space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="space-y-4">
            <label className="text-xs text-muted-foreground/70 font-semibold ml-1">
              Edge type
            </label>
            <div className="grid grid-cols-2 gap-3 mt-2">
              {[
                {
                  value: "default",
                  label: "Success",
                  icon: CheckCircle2,
                  color: "text-success",
                },
                {
                  value: "error",
                  label: "Fault",
                  icon: AlertCircle,
                  color: "text-destructive",
                },
                {
                  value: "conditional",
                  label: "Router",
                  icon: GitBranch,
                  color: "text-primary",
                },
                {
                  value: "OnFailure",
                  label: "Fail-Safe",
                  icon: ShieldAlert,
                  color: "text-warning",
                },
              ].map((type) => (
                <button
                  type="button"
                  key={type.value}
                  onClick={() =>
                    updateEdgeData(edge.id, {
                      edgeType: type.value as EdgeData["edgeType"],
                    })
                  }
                  className={cn(
                    "flex items-center gap-3 p-4 rounded-2xl border text-left transition-premium group relative overflow-hidden",
                    edge.data?.edgeType === type.value
                      ? "bg-white/[0.03] border-white/20"
                      : "bg-surface-3/20 border-white/5 hover:bg-white/[0.03] hover:border-white/10",
                  )}
                >
                  <type.icon
                    className={cn("w-5 h-5 transition-premium", type.color)}
                  />
                  <span
                    className={cn(
                      "text-xs font-semibold",
                      edge.data?.edgeType === type.value
                        ? "text-white"
                        : "text-muted-foreground/70",
                    )}
                  >
                    {type.label}
                  </span>
                  {edge.data?.edgeType === type.value && (
                    <div
                      className={cn(
                        "absolute bottom-0 left-0 w-full h-1",
                        type.color.replace("text-", "bg-"),
                      )}
                    />
                  )}
                </button>
              ))}
            </div>
          </div>

          {edge.data?.edgeType === "conditional" && (
            <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl space-y-5 bg-surface-3 border border-white/10">
              <h4 className="text-xs font-semibold text-white flex items-center gap-3 font-outfit">
                <div className="p-2 rounded-xl bg-primary/10 border border-primary/20">
                  <Sparkles className="w-4 h-4 text-primary" />
                </div>
                Logic Routing
              </h4>
              <FormField label="Condition (Rhai)">
                <Textarea
                  placeholder="ctx.result.score > 0.8"
                  className={cn(
                    "bg-surface-4/40 border-white/5 focus:border-primary/50 font-mono text-xs min-h-[120px] rounded-xl transition-premium selection:bg-primary/30 leading-relaxed",
                    syntaxError &&
                      "border-destructive/50 focus:border-destructive",
                  )}
                  value={(edge.data?.condition as string) || ""}
                  onChange={(e) =>
                    updateEdgeData(edge.id, { condition: e.target.value })
                  }
                />
              </FormField>
              {syntaxError && (
                <div className="flex items-center gap-3 px-4 py-2 bg-destructive/10 border border-destructive/20 rounded-xl animate-in slide-in-from-top-2">
                  <ShieldAlert className="w-4 h-4 text-destructive shrink-0" />
                  <span className="text-xs font-semibold text-destructive">
                    {syntaxError}
                  </span>
                </div>
              )}
            </div>
          )}

          <div className="space-y-5 pt-8 border-t border-white/5">
            <label className="text-xs text-muted-foreground/70 font-semibold ml-1">
              Data Mapping Architecture
            </label>
            <div className="bg-surface-4/20 p-6 rounded-2xl border border-white/5 relative overflow-hidden">
              <Textarea
                placeholder="ctx.input.query = ctx.result.original_query"
                className="bg-transparent border-0 focus:ring-0 p-0 font-mono text-xs min-h-[80px] selection:bg-primary/30 leading-relaxed text-white/80"
                value={(edge.data?.mapping as string) ?? ""}
                onChange={(e) =>
                  updateEdgeData(edge.id, { mapping: e.target.value })
                }
              />
            </div>
            <p className="text-xs text-muted-foreground/50 leading-relaxed ml-1">
              Advanced: reshape the data passed from one node to the next.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
