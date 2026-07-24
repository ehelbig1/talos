/**
 * Per-field input renderer for the workflow-builder node ConfigForm.
 * Pure function of (field, schema, value, onChange, isValid) — no state.
 * Handles string / enum / number / boolean / array-of-object /
 * preset-array / array-of-string field shapes.
 */

import React from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { Check, X, Plus } from "lucide-react";
import { cn } from "@/lib/utils";
import type { JSONSchemaProperty } from "./types";

export function renderField(
  field: string,
  schema: JSONSchemaProperty,
  value: unknown,
  onChange: (value: unknown) => void,
  isValid?: boolean,
) {
  const baseClassName = cn(
    "w-full px-4 h-12 bg-surface-2 border border-white/5 rounded-xl text-xs font-black uppercase tracking-widest text-white placeholder-white/10 outline-none transition-premium shadow-inner",
    isValid === false &&
      "border-destructive/40 ring-1 ring-destructive/20 bg-destructive/5 text-destructive",
    isValid === true &&
      "border-emerald-500/40 ring-1 ring-emerald-500/20 bg-emerald-500/5",
    "focus:border-primary/40 focus:ring-1 focus:ring-primary/20 focus:bg-surface-3",
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
            <option value="" className="bg-surface-4 text-white/20">
              SELECT OPTION...
            </option>
            {schema.enum?.map((opt: string) => (
              <option key={opt} value={opt} className="bg-surface-4 text-white">
                {opt.toUpperCase()}
              </option>
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
          placeholder={
            schema.placeholder?.toUpperCase() ||
            (schema.default as string | undefined)?.toUpperCase()
          }
          className={baseClassName}
        />
      );

    case "number":
      return (
        <input
          id={`field-${field}`}
          type="number"
          value={value !== undefined ? (value as number) : ""}
          onChange={(e) =>
            onChange(e.target.value ? Number(e.target.value) : undefined)
          }
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
            checked={
              value !== undefined
                ? (value as boolean)
                : (schema.default as boolean) || false
            }
            onChange={(e) => onChange(e.target.checked)}
            className="w-5 h-5 rounded-lg border-white/10 bg-surface-2 text-primary focus:ring-primary/40 transition-premium cursor-pointer"
          />
          <label
            htmlFor={`field-${field}`}
            className="text-[10px] font-black text-white/40 uppercase tracking-widest cursor-pointer"
          >
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
                  onClick={() =>
                    onChange(arrayValue.filter((_, i) => i !== index))
                  }
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
                const isSelected =
                  JSON.stringify(arrayValue) === JSON.stringify(preset.value);
                return (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => onChange(preset.value)}
                    className={cn(
                      "p-4 rounded-2xl border text-left transition-premium group/preset relative overflow-hidden",
                      isSelected
                        ? "bg-primary/10 border-primary shadow-xl"
                        : "bg-surface-2 border-white/5 hover:border-white/20 hover:bg-surface-3",
                    )}
                  >
                    <div className="flex flex-col relative z-10">
                      <span
                        className={cn(
                          "text-[10px] font-black uppercase tracking-[0.2em] mb-1 transition-premium",
                          isSelected
                            ? "text-white"
                            : "text-white/40 group-hover/preset:text-white",
                        )}
                      >
                        {preset.label}
                      </span>
                      <span className="text-[9px] font-bold text-muted-foreground/40 leading-relaxed uppercase tracking-widest">
                        {preset.description}
                      </span>
                    </div>
                    {isSelected && (
                      <div className="absolute top-2 right-2">
                        <Check className="w-3 h-3 text-primary" />
                      </div>
                    )}
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
                    try {
                      onChange(JSON.parse(e.target.value));
                    } catch {
                      /* Ignore invalid JSON */
                    }
                  }}
                  rows={4}
                  className={cn(
                    baseClassName,
                    "h-auto py-4 font-mono text-[10px] normal-case tracking-normal",
                  )}
                />
              </CollapsibleContent>
            </Collapsible>
          </div>
        );
      }

      if (schema.items?.type === "string") {
        const arrayValue =
          (value as string[]) || (schema.default as string[]) || [];
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
                  onClick={() =>
                    onChange(arrayValue.filter((_, i) => i !== index))
                  }
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
