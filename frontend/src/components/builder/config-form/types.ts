/**
 * Schema + suggestion types for the workflow-builder node ConfigForm.
 * Re-exported from ConfigForm.tsx so existing import paths keep resolving.
 */

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

export interface SmartSuggestion {
  field: string;
  value: unknown;
  reason: string;
}

export interface JSONSchema {
  type: string;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}
