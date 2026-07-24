import React, { useState } from "react";
import { analyzeURL, applySuggestions, validateField } from "@/lib/smartConfig";
import { OpenAPIBrowser } from "./OpenAPIBrowser";
import { ManualEndpointCreator } from "./ManualEndpointCreator";
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@/components/ui/accordion";
import { AlertTriangle, CheckCircle, Target, Settings } from "lucide-react";
import type { JSONSchema, SmartSuggestion } from "./config-form/types";
import { renderField } from "./config-form/renderField";
import { ServiceIntegrationSection } from "./config-form/ServiceIntegrationSection";
import { SuggestionsBanner } from "./config-form/SuggestionsBanner";

export type { JSONSchema, JSONSchemaProperty } from "./config-form/types";

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
  const commonFields = [
    "URL",
    "METHOD",
    "NAME",
    "LABEL",
    "MESSAGE",
    "TEXT",
    "CHANNEL",
  ];

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
        <ServiceIntegrationSection
          templateName={templateName}
          value={value}
          onChange={onChange}
        />
      )}

      {/* Smart Suggestions */}
      {suggestions.length > 0 && (
        <SuggestionsBanner
          suggestions={suggestions}
          showSuggestions={showSuggestions}
          onShow={() => setShowSuggestions(true)}
          onHide={() => setShowSuggestions(false)}
          onApply={applySmartSuggestions}
          onDiscard={() => setSuggestions([])}
        />
      )}

      {/* Form Fields */}
      <div className="space-y-6">
        {requiredFields
          .filter(
            ([_field, fieldSchema]) =>
              !fieldSchema["x-hidden"] && !fieldSchema.readOnly,
          )
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

              {field === "URL" &&
                !!value[field] &&
                !validationErrors[field] && (
                  <div className="bg-surface-2 border border-white/5 rounded-2xl p-6 space-y-6 shadow-inner relative overflow-hidden group/http">
                    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />
                    <div className="flex items-center justify-between relative z-10">
                      <div className="flex items-center gap-3">
                        <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400">
                          <CheckCircle className="h-4 w-4" />
                        </div>
                        <span className="text-[10px] font-black text-white/40 uppercase tracking-[0.2em]">
                          Protocol Endpoint Authenticated
                        </span>
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
                            onSelectEndpoint={(endpointConfig) =>
                              onChange({ ...value, ...endpointConfig })
                            }
                          />
                          <ManualEndpointCreator
                            baseUrl={value[field] as string}
                            onConfigure={(endpointConfig) =>
                              onChange({ ...value, ...endpointConfig })
                            }
                          />
                        </div>
                      </div>
                    )}
                  </div>
                )}
            </div>
          ))}

        {/* Advanced Section */}
        {advancedFields.filter(([_f, s]) => !s["x-hidden"] && !s.readOnly)
          .length > 0 && (
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
                  .filter(
                    ([_field, fieldSchema]) =>
                      !fieldSchema["x-hidden"] && !fieldSchema.readOnly,
                  )
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
