import React, { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { z } from "zod";
import { Input, Textarea, Button } from "@/components/ui";
import { analyzeRhai } from "@/lib/graphqlApi";
import { TestRhaiModal } from "./TestRhaiModal";

import {
  ChevronDown,
  Info,
  AlertCircle,
  Clock,
  IterationCcw,
  Loader2,
} from "lucide-react";

/**
 * Render a configuration UI for node config.
 * Shows a JSON editor for all configurations.
 */
export const NodeConfigForm = React.memo(
  ({
    type,
    config,
    onChange,
  }: {
    type: string;
    config: Record<string, unknown>;
    onChange: (newConfig: Record<string, unknown>) => void;
  }) => {
    const [jsonError, setJsonError] = React.useState<string | null>(null);
    const [jsonText, setJsonText] = React.useState(() =>
      JSON.stringify(config, null, 2),
    );

    const [rhaiError, setRhaiError] = useState<string | null>(null);
    const [validating, setValidating] = useState(false);
    const [testModalOpen, setTestModalOpen] = useState(false);

    // Rhai validation for conditions/paths
    useEffect(() => {
      const scriptToValidate =
        (type === "foreach" && (config.input_path as string)) ||
        ((type === "WhileLoop" || type === "Loop") &&
          (config.loopCondition as string)) ||
        (type === "FanIn" && (config.aggregationExpr as string)) ||
        null;

      if (!scriptToValidate) {
        setRhaiError(null);
        return;
      }

      const timer = setTimeout(async () => {
        setValidating(true);
        try {
          const result = await analyzeRhai({ script: scriptToValidate });
          if (!result.success && result.errors.length > 0) {
            setRhaiError(result.errors[0].message);
          } else {
            setRhaiError(null);
          }
        } catch {
          // Rhai validation endpoint unreachable — skip validation silently.
          // The script will be validated server-side when the workflow is saved.
          setRhaiError(null);
        } finally {
          setValidating(false);
        }
      }, 500);

      return () => clearTimeout(timer);
    }, [type, config.input_path, config.loopCondition, config.aggregationExpr]);

    // Update jsonText when config changes externally
    React.useEffect(() => {
      setJsonText(JSON.stringify(config, null, 2));
    }, [config]);

    const handleJsonChange = React.useCallback(
      (newText: string) => {
        setJsonText(newText);
        const schema = z.record(z.unknown()); // generic object schema
        try {
          const parsed = JSON.parse(newText);
          schema.parse(parsed); // throws if not an object
          onChange(parsed);
          setJsonError(null);
        } catch (e: unknown) {
          setJsonError(e instanceof Error ? e.message : String(e));
        }
      },
      [onChange],
    );

    // Helper to update a single field inside the config object.
    const setField = React.useCallback(
      (field: string, value: unknown) => {
        onChange({ ...config, [field]: value });
      },
      [config, onChange],
    );

    const handleMethodChange = React.useCallback(
      (e: React.ChangeEvent<HTMLSelectElement>) =>
        setField("method", e.target.value),
      [setField],
    );
    const handleUrlChange = React.useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) =>
        setField("url", e.target.value),
      [setField],
    );
    const handleHeadersChange = React.useCallback(
      (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        try {
          const parsed = JSON.parse(e.target.value);
          setField("headers", parsed);
        } catch {
          // ignore invalid JSON
        }
      },
      [setField],
    );
    const handleBodyChange = React.useCallback(
      (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        try {
          const parsed = JSON.parse(e.target.value);
          setField("body", parsed);
        } catch {
          // ignore parse error
        }
      },
      [setField],
    );
    const handleModelChange = React.useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) =>
        setField("model", e.target.value),
      [setField],
    );
    const handlePromptChange = React.useCallback(
      (e: React.ChangeEvent<HTMLTextAreaElement>) =>
        setField("prompt", e.target.value),
      [setField],
    );
    const handlePathChange = React.useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) =>
        setField("path", e.target.value),
      [setField],
    );
    const handleInputPathChange = React.useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) =>
        setField("input_path", e.target.value),
      [setField],
    );
    const handleOutputHandleChange = React.useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) =>
        setField("output_handle", e.target.value),
      [setField],
    );
    const handleTextareaChange = React.useCallback(
      (e: React.ChangeEvent<HTMLTextAreaElement>) =>
        handleJsonChange(e.target.value),
      [handleJsonChange],
    );

    const inputBase =
      "w-full px-5 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium selection:bg-primary/30 placeholder:text-muted-foreground/20";
    const selectBase =
      "w-full h-12 px-5 py-3 text-[11px] font-bold bg-surface-4/40 border border-white/5 rounded-2xl text-foreground focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:outline-none transition-premium cursor-pointer hover:bg-surface-4/60 appearance-none selection:bg-primary/30";
    const textareaBase =
      "w-full px-5 py-4 text-[11px] font-mono bg-black/40 border border-white/5 rounded-[2rem] text-foreground/80 focus:border-primary/40 focus:outline-none transition-premium resize-none leading-relaxed selection:bg-primary/30 custom-scrollbar";

    // Render specialized UI per node type (legacy support for hardcoded types).
    switch (type) {
      case "http-request":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Request Method
              </label>
              <div className="relative">
                <select
                  id="method-select"
                  className={selectBase}
                  value={(config.method as string) ?? "GET"}
                  onChange={handleMethodChange}
                >
                  {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
                    <option key={m} value={m} className="bg-surface-3">
                      {m}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/40 pointer-events-none" />
              </div>
            </div>

            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Target Endpoint URL
              </label>
              <Input
                id="url-input"
                placeholder="https://api.example.com/v1/resource"
                value={(config.url as string) ?? ""}
                onChange={handleUrlChange}
                className={inputBase}
              />
            </div>

            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Protocol Headers (JSON)
              </label>
              <Textarea
                rows={4}
                placeholder='{"Authorization": "Bearer ...", "Content-Type": "application/json"}'
                value={JSON.stringify(config.headers ?? {}, null, 2)}
                onChange={handleHeadersChange}
                className={textareaBase}
              />
            </div>

            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Payload Body (JSON)
              </label>
              <Textarea
                rows={4}
                placeholder='{"key": "value"}'
                value={JSON.stringify(config.body ?? {}, null, 2)}
                onChange={handleBodyChange}
                className={textareaBase}
              />
            </div>
          </div>
        );
      case "llm-inference":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Compute Model Architecture
              </label>
              <Input
                id="model-input"
                placeholder="gpt-4o-pro-2025"
                value={(config.model as string) ?? ""}
                onChange={handleModelChange}
                className={inputBase}
              />
            </div>
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Prompt Directive
              </label>
              <Textarea
                id="prompt-textarea"
                rows={6}
                placeholder="Synthesize input data into a structured report..."
                value={(config.prompt as string) ?? ""}
                onChange={handlePromptChange}
                className={textareaBase}
              />
            </div>
          </div>
        );
      case "json-parse":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                JSONPath Data Extraction
              </label>
              <Input
                id="path-input"
                placeholder="$.results[*].identity.identifier"
                value={(config.path as string) ?? ""}
                onChange={handlePathChange}
                className={inputBase}
              />
            </div>
            <div className="flex items-center gap-4 px-5 py-4 bg-primary/5 border border-primary/10 rounded-2xl shadow-inner">
              <div className="p-2 bg-primary/10 rounded-xl text-primary shadow-[0_0_15px_hsla(var(--primary),0.1)]">
                <Info className="w-4 h-4" />
              </div>
              <p className="text-[10px] text-primary/60 font-bold uppercase tracking-wider leading-relaxed">
                Utilize standard JSONPath syntax to traverse and isolate nested
                values from the protocol stream.
              </p>
            </div>
          </div>
        );
      case "foreach":
        return (
          <div className="space-y-8 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-4">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Collection Source (Rhai)
              </label>
              <div className="flex gap-3">
                <div className="relative flex-1 group/input">
                  <div
                    className={cn(
                      "absolute -inset-0.5 rounded-2xl blur opacity-0 transition-premium",
                      rhaiError
                        ? "bg-destructive/20 group-hover/input:opacity-100"
                        : "bg-primary/10 group-hover/input:opacity-100",
                    )}
                  />
                  <Input
                    id="input-path-input"
                    placeholder="ctx.results['QUERY_ID'].items"
                    value={(config.input_path as string) ?? ""}
                    onChange={handleInputPathChange}
                    className={cn(
                      inputBase,
                      "relative",
                      rhaiError &&
                        "border-destructive/40 text-destructive placeholder:text-destructive/20",
                    )}
                  />
                  {validating && (
                    <div className="absolute top-1/2 -translate-y-1/2 right-4">
                      <Loader2 className="w-4 h-4 text-primary animate-spin" />
                    </div>
                  )}
                </div>
                <Button
                  onClick={() => setTestModalOpen(true)}
                  className="h-11 px-6 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl bg-white/5 border border-white/5 text-white/40 hover:text-white hover:bg-white/10 transition-premium active:scale-95 shadow-xl"
                >
                  TEST_EXP
                </Button>
              </div>
              {rhaiError && (
                <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-2xl animate-in slide-in-from-top-2">
                  <p className="text-[11px] text-destructive flex items-center gap-2 font-bold">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    FAULT: {rhaiError}
                  </p>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Iteration Memory Handle
              </label>
              <Input
                id="output-handle-input"
                placeholder="element_instance"
                value={(config.output_handle as string) ?? "item"}
                onChange={handleOutputHandleChange}
                className={inputBase}
              />
              <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest px-1">
                The local scope identifier for individual collection members.
              </p>
            </div>

            <div className="flex items-center gap-4 px-5 py-4 bg-surface-3/60 border border-white/5 rounded-2xl shadow-2xl">
              <div className="p-2.5 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400">
                <IterationCcw className="w-4 h-4" />
              </div>
              <div className="flex flex-col gap-1">
                <p className="text-[10px] text-white/60 font-black uppercase tracking-widest">
                  Parallel Stream Processor
                </p>
                <p className="text-[9px] text-muted-foreground/40 font-medium">
                  Automatic async fan-out enabled for high-throughput iteration.
                </p>
              </div>
            </div>

            <TestRhaiModal
              open={testModalOpen}
              onOpenChange={setTestModalOpen}
              script={(config.input_path as string) ?? ""}
            />
          </div>
        );
      case "WhileLoop":
      case "Loop":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-4">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Termination Condition (Rhai)
              </label>
              <Textarea
                id="loop-condition"
                placeholder="ctx.results['SCAN_NODE'].count < 10"
                value={(config.loopCondition as string) ?? ""}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                  setField("loopCondition", e.target.value)
                }
                className={cn(
                  textareaBase,
                  "min-h-[120px]",
                  rhaiError && "border-destructive/40",
                )}
              />
              {rhaiError && (
                <p className="text-[10px] text-destructive font-black uppercase tracking-widest px-2">
                  {rhaiError}
                </p>
              )}
            </div>

            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Iteration Limit
              </label>
              <Input
                type="number"
                id="max-iterations"
                value={(config.maxIterations as number) ?? 100}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setField("maxIterations", parseInt(e.target.value, 10) || 100)
                }
                className={inputBase}
              />
            </div>
          </div>
        );
      case "RepeatLoop":
        return (
          <div className="space-y-4 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Static Cycle Count
              </label>
              <Input
                type="number"
                id="repeat-count"
                value={(config.repeatCount as number) ?? 1}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setField("repeatCount", parseInt(e.target.value, 10) || 1)
                }
                className={inputBase}
              />
            </div>
          </div>
        );
      case "FanIn":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Aggregation Mode
              </label>
              <div className="relative">
                <select
                  id="join-mode"
                  className={selectBase}
                  value={(config.joinMode as string) ?? "All"}
                  onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                    setField("joinMode", e.target.value)
                  }
                >
                  <option value="All">RESOLVE_ALL_NODES</option>
                  <option value="Any">FIRST_SUCCESSFUL_WINNER</option>
                  <option value="Majority">MAJORITY_CONSENSUS_(50%+)</option>
                  <option value="N">EXACT_COUNT_THRESHOLD_(N)</option>
                </select>
                <ChevronDown className="absolute right-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/40 pointer-events-none" />
              </div>
            </div>
            {config.joinMode === "N" && (
              <div className="space-y-3 animate-in fade-in zoom-in-95">
                <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                  Threshold Count (N)
                </label>
                <Input
                  type="number"
                  id="join-n"
                  value={(config.joinN as number) ?? 1}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    setField("joinN", parseInt(e.target.value, 10) || 1)
                  }
                  className={inputBase}
                />
              </div>
            )}
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Consolidation Logic (Rhai)
              </label>
              <Textarea
                id="agg-expr"
                placeholder="ctx.results.collect().filter(|r| r.success)"
                value={(config.aggregationExpr as string) ?? ""}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                  setField("aggregationExpr", e.target.value)
                }
                className={cn(
                  textareaBase,
                  "min-h-[140px]",
                  rhaiError && "border-destructive/40",
                )}
              />
            </div>
          </div>
        );
      case "ErrorHandler":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Exception Pattern (Regex)
              </label>
              <Input
                id="error-pattern"
                placeholder=".*(timeout|connection_refused).*"
                value={(config.errorPattern as string) ?? ""}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setField("errorPattern", e.target.value)
                }
                className={inputBase}
              />
              <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest px-1 leading-relaxed">
                Matched against incoming error telemetry to activate this
                recovery branch.
              </p>
            </div>
          </div>
        );
      case "SubWorkflow":
        return (
          <div className="space-y-6 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Nested Protocol Identifier
              </label>
              <Input
                id="sub-wf"
                placeholder="workflow-0000-0000-0000"
                value={(config.subWorkflowId as string) ?? ""}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setField("subWorkflowId", e.target.value)
                }
                className={inputBase}
              />
            </div>
          </div>
        );
      case "Wait":
        return (
          <div className="space-y-8 animate-in slide-in-from-top-4 duration-500">
            <div className="space-y-3">
              <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                Manual Intervention Label
              </label>
              <Input
                placeholder="Awaiting Executive Override..."
                value={(config.message as string) ?? ""}
                onChange={(e) => setField("message", e.target.value)}
                className={inputBase}
              />
            </div>
            <div className="flex items-center gap-4 px-6 py-5 bg-amber-500/5 border border-amber-500/20 rounded-[2rem] shadow-2xl relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-br from-amber-500/5 to-transparent opacity-50" />
              <div className="p-3 bg-amber-500/10 rounded-2xl text-amber-500 shadow-[0_0_20px_hsla(var(--warning),0.2)] group-hover:scale-110 transition-premium relative z-10">
                <Clock className="w-5 h-5" />
              </div>
              <div className="flex flex-col gap-1 relative z-10">
                <p className="text-[11px] text-amber-400 font-black uppercase tracking-widest">
                  Protocol Suspension
                </p>
                <p className="text-[10px] text-amber-300/40 font-medium leading-relaxed">
                  Workflow state will be persisted. Execution resumes only upon
                  manual signal.
                </p>
              </div>
            </div>
          </div>
        );
      default:
        // Fallback: generic JSON editor with error handling
        return (
          <div className="space-y-4 animate-in slide-in-from-top-4 duration-500">
            <label className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Advanced Object Configuration
            </label>
            <div className="relative group/json">
              <div
                className={cn(
                  "absolute -inset-1 rounded-[2.5rem] blur opacity-0 transition-premium",
                  jsonError
                    ? "bg-destructive/10 group-hover/json:opacity-100"
                    : "bg-primary/5 group-hover/json:opacity-100",
                )}
              />
              <textarea
                id="config-json"
                rows={12}
                className={cn(
                  textareaBase,
                  "relative border-white/10 group-hover/json:border-white/20 h-96 p-8",
                  jsonError &&
                    "border-destructive/40 text-destructive shadow-[0_0_30px_hsla(var(--destructive),0.05)]",
                )}
                value={jsonText}
                onChange={handleTextareaChange}
              />
              <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.05)_50%),linear-gradient(90deg,rgba(255,0,0,0.01),rgba(0,255,0,0.005),rgba(0,0,255,0.01))] bg-[length:100%_4px,3px_100%]" />
            </div>

            {jsonError && (
              <div className="p-5 bg-destructive/5 border border-destructive/20 rounded-2xl animate-in slide-in-from-top-2">
                <p className="text-[11px] text-destructive flex items-center gap-3 font-bold">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  SCHEMA_VIOLATION: {jsonError}
                </p>
              </div>
            )}
            {!jsonError && Object.keys(config).length === 0 && (
              <div className="mt-4 p-8 border border-dashed border-white/5 rounded-[2rem] bg-black/10 text-center">
                <p className="text-[11px] text-muted-foreground/20 font-black uppercase tracking-[0.4em] italic leading-relaxed">
                  NULL_CONFIG_REQUIRED
                </p>
              </div>
            )}
          </div>
        );
    }
  },
);
