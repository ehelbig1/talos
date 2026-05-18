import React, { useState, useEffect } from "react";
import { FlexContainer } from "@/components/ui/FlexContainer";
import { analyzeURL, applySuggestions, validateField } from "@/lib/smartConfig";
import { OpenAPIBrowser } from "./OpenAPIBrowser";
import { ManualEndpointCreator } from "./ManualEndpointCreator";
import { SlackBrowser } from "./SlackBrowser";
import { SlackAppSelector } from "./SlackAppSelector";
import { GoogleCalendarSelector } from "./GoogleCalendarSelector";
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@/components/ui/accordion";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import {
  Link,
  Lightbulb,
  AlertTriangle,
  Check,
  CheckCircle,
  ChevronDown,
  X,
  ArrowLeft,
  FileText,
  Calendar,
  Search,
  Mail,
  Target,
  Plus,
  Loader2,
  Settings,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface JSONSchemaProperty {
  type: string;
  title?: string;
  description?: string;
  enum?: string[];
  placeholder?: string;
  default?: unknown;
  helpText?: string;
  "x-hidden"?: boolean;
  readOnly?: boolean;
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
  presets?: Array<{ label: string; value: unknown; description?: string }>;
  slackApiEndpoint?: string;
  pattern?: string;
}

interface SmartSuggestion {
  field: string;
  value: unknown;
  reason: string;
}

export interface JSONSchema {
  type: string;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}

export const ConfigForm = React.memo(function ConfigForm({
  schema,
  value,
  onChange,
  category,
  templateName,
}: {
  schema: JSONSchema;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  category?: string;
  templateName?: string;
}) {
  const [validationErrors, setValidationErrors] = useState<
    Record<string, string>
  >({});
  const [suggestions, setSuggestions] = useState<SmartSuggestion[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggestionsAnalyzed, setSuggestionsAnalyzed] = useState<string | null>(
    null,
  );

  const handleChange = React.useCallback(
    (field: string, fieldValue: unknown) => {
      const newValue = { ...value, [field]: fieldValue };
      onChange(newValue);

      // Validate the field
      const fieldSchema = schema.properties?.[field];
      if (fieldSchema) {
        const validation = validateField(field, fieldValue, {
          ...fieldSchema,
          required: schema.required?.includes(field),
        });

        setValidationErrors((prev) => {
          const next = { ...prev };
          if (validation.valid) {
            delete next[field];
          } else if (validation.message) {
            next[field] = validation.message;
          }
          return next;
        });
      }

      // Smart URL analysis
      if (field === "URL" && fieldValue && fieldValue !== suggestionsAnalyzed) {
        const analysis = analyzeURL(fieldValue as string);
        if (analysis.isValid && analysis.suggestions.length > 0) {
          const hasNewSuggestions = analysis.suggestions.some((s) => {
            const currentValue = value[s.field];
            return JSON.stringify(currentValue) !== JSON.stringify(s.value);
          });

          if (hasNewSuggestions) {
            setSuggestions(analysis.suggestions);
            setSuggestionsAnalyzed(fieldValue as string);
          }
        }
      }
    },
    [value, onChange, schema, suggestionsAnalyzed],
  );

  const applySmartSuggestions = React.useCallback(() => {
    const newConfig = applySuggestions(value, suggestions);
    onChange(newConfig);
    setShowSuggestions(false);
  }, [value, suggestions, onChange]);

  if (!schema.properties) {
    return (
      <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-xl text-destructive text-[10px] font-black uppercase tracking-widest">
        Invalid Blueprint Schema
      </div>
    );
  }

  const allFieldEntries = Object.entries(schema.properties);
  const commonFields = ["URL", "METHOD", "NAME", "LABEL", "MESSAGE", "TEXT", "CHANNEL"];

  const requiredFields = allFieldEntries.filter(
    ([field]) =>
      schema.required?.includes(field) &&
      !["HEADERS", "BODY", "TIMEOUT"].includes(field),
  );

  const commonOptionalFields = allFieldEntries.filter(
    ([field]) =>
      !schema.required?.includes(field) && commonFields.includes(field),
  );

  const advancedFields = allFieldEntries.filter(
    ([field]) =>
      !requiredFields.some(([f]) => f === field) &&
      !commonOptionalFields.some(([f]) => f === field),
  );

  if (category === "http") {
    requiredFields.sort(([keyA], [keyB]) => {
      if (keyA === "URL") return -1;
      if (keyB === "URL") return 1;
      if (keyA === "METHOD") return -1;
      if (keyB === "METHOD") return 1;
      return 0;
    });
  }

  const hasServiceIntegration =
    templateName &&
    (templateName.toLowerCase().includes("slack") ||
      (templateName.toLowerCase().includes("google") &&
        templateName.toLowerCase().includes("calendar")) ||
      templateName.toLowerCase().includes("gmail") ||
      templateName.toLowerCase().includes("google-mail"));

  return (
    <div className="space-y-6">
      {/* Service Integration */}
      {hasServiceIntegration && (
        <Collapsible defaultOpen={!value || Object.keys(value).length === 0} className="group/collapsible">
          <CollapsibleTrigger asChild>
            <button
              type="button"
              className="w-full p-4 bg-surface-3 hover:bg-surface-4 border border-white/5 rounded-2xl cursor-pointer text-[10px] font-black text-white uppercase tracking-widest flex items-center justify-between transition-premium shadow-xl group-hover/collapsible:border-primary/20"
            >
              <div className="flex items-center gap-3">
                <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                    <Link className="h-4 w-4" />
                </div>
                <span>Configure Unified Integration</span>
              </div>
              <ChevronDown className="h-4 w-4 text-muted-foreground/40 group-data-[state=open]/collapsible:rotate-180 transition-transform duration-500" />
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-4 space-y-4 animate-in fade-in slide-in-from-top-2 duration-500">
            {templateName && templateName.toLowerCase().includes("slack") && (
              <SlackAppSelector
                onSelect={(slackConfig) => onChange({ ...value, ...slackConfig })}
                currentConfig={value}
              />
            )}

            {templateName &&
              templateName.toLowerCase().includes("google") &&
              templateName.toLowerCase().includes("calendar") && (
                <GoogleCalendarSelector
                  onSelect={(calendarConfig) => onChange({ ...value, ...calendarConfig })}
                  currentConfig={value}
                />
              )}

            {templateName &&
              (templateName.toLowerCase().includes("gmail") ||
                templateName.toLowerCase().includes("google-mail")) && (
                <div className="p-6 bg-surface-2/60 border border-white/5 rounded-2xl">
                  <div className="text-[10px] font-black text-primary uppercase tracking-[0.2em] mb-3 flex items-center gap-3">
                    <Mail className="h-4 w-4" /> Gmail Integration Vector
                  </div>
                  <p className="m-0 text-[11px] font-bold text-muted-foreground/40 leading-relaxed uppercase tracking-widest">
                    Direct Gmail binding coming soon. Manually configure labels in primary settings.
                  </p>
                </div>
              )}
          </CollapsibleContent>
        </Collapsible>
      )}

      {/* Smart Suggestions */}
      {suggestions.length > 0 && (
        <div className={cn(
            "relative group/suggestions p-6 rounded-[2rem] border transition-premium overflow-hidden",
            showSuggestions ? "bg-primary/5 border-primary/20 shadow-2xl" : "bg-primary/5 border-primary/10 hover:border-primary/30"
        )}>
            <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
                <Lightbulb className="w-12 h-12 text-primary" />
            </div>
            <div className="flex items-center justify-between mb-4 relative z-10">
                <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-lg bg-primary/20 text-primary animate-pulse">
                        <Zap className="h-4 w-4" />
                    </div>
                    <span className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
                        {suggestions.length} Structural Insight{suggestions.length > 1 ? "s" : ""} detected
                    </span>
                </div>
                {!showSuggestions ? (
                    <button
                        onClick={() => setShowSuggestions(true)}
                        className="text-[9px] font-black text-primary uppercase tracking-widest hover:text-white transition-premium"
                    >
                        Review Analysis
                    </button>
                ) : (
                    <button
                        onClick={() => setShowSuggestions(false)}
                        className="p-1.5 rounded-lg hover:bg-white/5 text-muted-foreground/20 hover:text-white transition-premium"
                    >
                        <X className="h-4 w-4" />
                    </button>
                )}
            </div>

            {showSuggestions && (
                <div className="space-y-6 relative z-10 animate-in fade-in slide-in-from-top-2">
                    <ul className="space-y-3">
                        {suggestions.map((s) => (
                            <li key={s.field} className="flex gap-4 items-start group/s">
                                <div className="mt-1 w-1.5 h-1.5 rounded-full bg-primary/40 group-hover/s:bg-primary transition-premium" />
                                <div className="space-y-1">
                                    <p className="text-[11px] font-bold text-white/60">
                                        Override <span className="text-primary">{s.field}</span> with <code className="px-1.5 py-0.5 bg-white/5 rounded font-mono text-primary/80">{JSON.stringify(s.value)}</code>
                                    </p>
                                    <p className="text-[9px] font-black uppercase tracking-widest text-muted-foreground/20">
                                        Reason: {s.reason}
                                    </p>
                                </div>
                            </li>
                        ))}
                    </ul>
                    <div className="flex items-center gap-3 pt-4 border-t border-white/5">
                        <button
                            onClick={applySmartSuggestions}
                            className="px-6 h-9 bg-primary hover:bg-primary/90 text-white text-[9px] font-black uppercase tracking-widest rounded-xl transition-premium shadow-lg shadow-primary/20"
                        >
                            Apply Optimization
                        </button>
                        <button
                            onClick={() => setSuggestions([])}
                            className="px-6 h-9 bg-surface-3 hover:bg-surface-4 text-muted-foreground/40 hover:text-white text-[9px] font-black uppercase tracking-widest rounded-xl transition-premium border border-white/5"
                        >
                            Discard
                        </button>
                    </div>
                </div>
            )}
        </div>
      )}

      {/* Form Fields */}
      <div className="space-y-6">
          {requiredFields
            .filter(([field, fieldSchema]) => !fieldSchema["x-hidden"] && !fieldSchema.readOnly)
            .map(([field, fieldSchema]) => (
              <div key={field} className="space-y-3">
                <div className="flex items-center justify-between px-1">
                    <label
                      htmlFor={`field-${field}`}
                      className="text-[10px] font-black text-white/40 uppercase tracking-[0.2em]"
                    >
                      {fieldSchema.title || field}
                      {schema.required?.includes(field) && (
                        <span className="text-primary ml-1.5">*</span>
                      )}
                    </label>
                    {fieldSchema.description && (
                        <div className="group/info relative">
                            <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground/20 cursor-help hover:text-primary transition-premium" />
                            <div className="absolute bottom-full right-0 mb-3 w-64 p-3 bg-surface-4 border border-white/10 rounded-xl shadow-2xl opacity-0 group-hover/info:opacity-100 transition-premium pointer-events-none z-50">
                                <p className="text-[10px] font-bold text-white/60 leading-relaxed uppercase tracking-widest">
                                    {fieldSchema.description}
                                </p>
                            </div>
                        </div>
                    )}
                </div>

                {renderField(
                  field,
                  fieldSchema,
                  value[field],
                  (v) => handleChange(field, v),
                  validationErrors[field]
                    ? false
                    : field === "URL" && value[field]
                      ? true
                      : undefined,
                )}

                {validationErrors[field] && (
                  <p className="px-2 py-2 bg-destructive/5 border border-destructive/10 rounded-lg text-[9px] font-black text-destructive uppercase tracking-widest flex items-center gap-2 animate-in slide-in-from-top-1">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {validationErrors[field]}
                  </p>
                )}

                {field === "URL" && !!value[field] && !validationErrors[field] && (
                    <div className="bg-surface-2 border border-white/5 rounded-2xl p-6 space-y-6 shadow-inner relative overflow-hidden group/http">
                      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />
                      <div className="flex items-center justify-between relative z-10">
                        <div className="flex items-center gap-3">
                            <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400">
                                <CheckCircle className="h-4 w-4" />
                            </div>
                            <span className="text-[10px] font-black text-white/40 uppercase tracking-[0.2em]">Protocol Endpoint Authenticated</span>
                        </div>
                        {suggestions.length > 0 && !showSuggestions && (
                            <button
                                onClick={() => setShowSuggestions(true)}
                                className="text-[9px] font-black text-primary uppercase tracking-widest animate-pulse"
                            >
                                {suggestions.length} Optimizations Ready
                            </button>
                        )}
                      </div>
                      
                      {category === "http" && (
                        <div className="space-y-4 relative z-10 pt-4 border-t border-white/5">
                            <p className="text-[9px] font-black text-white/20 uppercase tracking-[0.3em] flex items-center gap-2">
                                <Target className="h-3.5 w-3.5 text-primary" />
                                Deep Ingress Configuration
                            </p>
                            <div className="flex gap-3 flex-wrap">
                                <OpenAPIBrowser
                                    baseUrl={value[field] as string}
                                    onSelectEndpoint={(endpointConfig) => onChange({ ...value, ...endpointConfig })}
                                />
                                <ManualEndpointCreator
                                    baseUrl={value[field] as string}
                                    onConfigure={(endpointConfig) => onChange({ ...value, ...endpointConfig })}
                                />
                            </div>
                        </div>
                      )}
                    </div>
                  )}
              </div>
            ))}

          {/* Advanced Section */}
          {advancedFields.filter(([f, s]) => !s["x-hidden"] && !s.readOnly).length > 0 && (
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="advanced" className="border-white/5">
                <AccordionTrigger className="text-[10px] font-black text-white/40 uppercase tracking-[0.3em] hover:text-white hover:no-underline px-1 transition-premium">
                  <div className="flex items-center gap-3">
                    <Settings className="h-3.5 w-3.5" />
                    Extended Configuration Vector
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pt-8 pb-4 space-y-8 animate-in fade-in slide-in-from-top-4">
                  {advancedFields
                    .filter(([field, fieldSchema]) => !fieldSchema["x-hidden"] && !fieldSchema.readOnly)
                    .map(([field, fieldSchema]) => (
                      <div key={field} className="space-y-3">
                        <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.2em] px-1">
                          {fieldSchema.title || field}
                        </label>
                        {renderField(
                          field,
                          fieldSchema,
                          value[field],
                          (v) => handleChange(field, v),
                          validationErrors[field] ? false : undefined,
                        )}
                        {validationErrors[field] && (
                          <p className="text-[9px] font-black text-destructive uppercase tracking-widest px-2">
                            {validationErrors[field]}
                          </p>
                        )}
                      </div>
                    ))}
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          )}
      </div>
    </div>
  );
});

function renderField(
  field: string,
  schema: JSONSchemaProperty,
  value: unknown,
  onChange: (value: unknown) => void,
  isValid?: boolean,
) {
  const baseClassName = cn(
    "w-full px-4 h-12 bg-surface-2 border border-white/5 rounded-xl text-xs font-black uppercase tracking-widest text-white placeholder-white/10 outline-none transition-premium shadow-inner",
    isValid === false && "border-destructive/40 ring-1 ring-destructive/20 bg-destructive/5 text-destructive",
    isValid === true && "border-emerald-500/40 ring-1 ring-emerald-500/20 bg-emerald-500/5",
    "focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:bg-surface-3"
  );

  switch (schema.type) {
    case "string":
      if (schema.enum) {
        return (
          <select
            id={`field-${field}`}
            value={(value as string) || (schema.default as string) || ""}
            onChange={(e) => onChange(e.target.value)}
            className={baseClassName}
          >
            <option value="" className="bg-surface-4 text-white/20">SELECT OPTION...</option>
            {schema.enum?.map((opt: string) => (
              <option key={opt} value={opt} className="bg-surface-4 text-white">{opt.toUpperCase()}</option>
            ))}
          </select>
        );
      }
      return (
        <input
          id={`field-${field}`}
          type="text"
          value={(value as string) || ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={schema.placeholder?.toUpperCase() || (schema.default as string | undefined)?.toUpperCase()}
          className={baseClassName}
        />
      );

    case "number":
      return (
        <input
          id={`field-${field}`}
          type="number"
          value={value !== undefined ? (value as number) : ""}
          onChange={(e) => onChange(e.target.value ? Number(e.target.value) : undefined)}
          placeholder={schema.default ? String(schema.default) : undefined}
          className={baseClassName}
        />
      );

    case "boolean":
      return (
        <div className="flex items-center gap-3 px-1">
            <input
              id={`field-${field}`}
              type="checkbox"
              checked={value !== undefined ? (value as boolean) : (schema.default as boolean) || false}
              onChange={(e) => onChange(e.target.checked)}
              className="w-5 h-5 rounded-lg border-white/10 bg-surface-2 text-primary focus:ring-primary/40 transition-premium cursor-pointer"
            />
            <label htmlFor={`field-${field}`} className="text-[10px] font-black text-white/40 uppercase tracking-widest cursor-pointer">
                Activate {field.replace(/_/g, " ")}
            </label>
        </div>
      );

    case "array":
      if (schema.items?.type === "object") {
        const arrayValue = (value as unknown[]) || [];
        const itemsSchema = schema.items as JSONSchemaProperty;
        return (
          <div className="space-y-3">
            {arrayValue.map((item, index: number) => (
              <div key={index} className="flex gap-3 group/item">
                {Object.keys(itemsSchema.properties || {}).map((key) => (
                  <input
                    key={key}
                    type="text"
                    placeholder={key.toUpperCase()}
                    value={(item as Record<string, string>)[key] || ""}
                    onChange={(e) => {
                      const newArray = [...arrayValue];
                      newArray[index] = {
                        ...(item as Record<string, unknown>),
                        [key]: e.target.value,
                      };
                      onChange(newArray);
                    }}
                    className={cn(baseClassName, "flex-1")}
                  />
                ))}
                <button
                  type="button"
                  onClick={() => onChange(arrayValue.filter((_, i) => i !== index))}
                  className="shrink-0 w-12 h-12 flex items-center justify-center bg-destructive/5 border border-destructive/20 text-destructive rounded-xl hover:bg-destructive/10 transition-premium active:scale-90"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
            <button
              type="button"
              onClick={() => {
                const newItem: Record<string, unknown> = {};
                Object.keys(schema.items?.properties || {}).forEach((key) => {
                  newItem[key] = "";
                });
                onChange([...arrayValue, newItem]);
              }}
              className="h-11 px-6 bg-surface-2 hover:bg-surface-3 border border-white/5 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] text-primary transition-premium flex items-center gap-2"
            >
              <Plus className="h-4 w-4" /> Add Protocol Entry
            </button>
          </div>
        );
      }

      if (schema.presets && Array.isArray(schema.presets)) {
        const arrayValue = value || schema.default || [];
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {schema.presets.map((preset) => {
                const isSelected = JSON.stringify(arrayValue) === JSON.stringify(preset.value);
                return (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => onChange(preset.value)}
                    className={cn(
                        "p-4 rounded-2xl border text-left transition-premium group/preset relative overflow-hidden",
                        isSelected ? "bg-primary/10 border-primary shadow-xl" : "bg-surface-2 border-white/5 hover:border-white/20 hover:bg-surface-3"
                    )}
                  >
                    <div className="flex flex-col relative z-10">
                        <span className={cn("text-[10px] font-black uppercase tracking-[0.2em] mb-1 transition-premium", isSelected ? "text-white" : "text-white/40 group-hover/preset:text-white")}>
                            {preset.label}
                        </span>
                        <span className="text-[9px] font-bold text-muted-foreground/40 leading-relaxed uppercase tracking-widest">
                            {preset.description}
                        </span>
                    </div>
                    {isSelected && <div className="absolute top-2 right-2"><Check className="w-3 h-3 text-primary" /></div>}
                  </button>
                );
              })}
            </div>
            <Collapsible>
              <CollapsibleTrigger className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.3em] hover:text-white transition-premium ml-1">
                Deep Protocol Editor (JSON)
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-3 animate-in fade-in slide-in-from-top-2">
                  <textarea
                    value={JSON.stringify(arrayValue, null, 2)}
                    onChange={(e) => {
                      try { onChange(JSON.parse(e.target.value)); } catch { /* Ignore invalid JSON */ }
                    }}
                    rows={4}
                    className={cn(baseClassName, "h-auto py-4 font-mono text-[10px] normal-case tracking-normal")}
                  />
              </CollapsibleContent>
            </Collapsible>
          </div>
        );
      }

      if (schema.items?.type === "string") {
        const arrayValue = (value as string[]) || (schema.default as string[]) || [];
        return (
          <div className="space-y-3">
            {arrayValue.map((item, index: number) => (
              <div key={index} className="flex gap-3">
                <input
                  type="text"
                  value={item as string}
                  onChange={(e) => {
                    const newArray = [...arrayValue];
                    newArray[index] = e.target.value;
                    onChange(newArray);
                  }}
                  placeholder={`IDENTIFIER ${index + 1}`}
                  className={cn(baseClassName, "flex-1")}
                />
                <button
                  type="button"
                  onClick={() => onChange(arrayValue.filter((_, i) => i !== index))}
                  className="shrink-0 w-12 h-12 flex items-center justify-center bg-destructive/5 border border-destructive/20 text-destructive rounded-xl hover:bg-destructive/10 transition-premium"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
            <button
              type="button"
              onClick={() => onChange([...arrayValue, ""])}
              className="h-11 px-6 bg-surface-2 hover:bg-surface-3 border border-white/5 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] text-primary transition-premium flex items-center gap-2"
            >
              <Plus className="h-4 w-4" /> Add Vector
            </button>
          </div>
        );
      }
      return null;

    default:
      return null;
  }
}
