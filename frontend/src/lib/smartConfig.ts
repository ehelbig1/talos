/**
 * Smart configuration helpers for node creation
 * Provides intelligent defaults and validation based on URL patterns and node types
 */

interface SmartSuggestion {
  field: string;
  value: unknown;
  reason: string;
}

export interface Schema {
  type?: string;
  format?: string;
  title?: string;
  required?: boolean;
  minimum?: number;
  maximum?: number;
  enum?: unknown[]; // enum values can be many things
  pattern?: string;
  uniqueItems?: boolean;
  items?: {
    pattern?: string;
  };
}

interface URLAnalysis {
  isValid: boolean;
  protocol?: string;
  hostname?: string;
  apiType?: "rest" | "graphql" | "unknown";
  suggestions: SmartSuggestion[];
  knownService?: string;
}

/**
 * Analyze a URL and provide smart suggestions
 */
export function analyzeURL(url: string): URLAnalysis {
  if (!url) {
    return {
      isValid: false,
      suggestions: [],
    };
  }

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const pathname = urlObj.pathname;
    const suggestions: SmartSuggestion[] = [];
    let apiType: "rest" | "graphql" | "unknown" = "unknown";
    let knownService: string | undefined;

    // Detect GraphQL endpoints
    if (pathname.includes("graphql") || pathname.includes("gql")) {
      apiType = "graphql";
      suggestions.push({
        field: "METHOD",
        value: "POST",
        reason: "GraphQL APIs typically use POST",
      });
      suggestions.push({
        field: "HEADERS",
        value: [{ key: "Content-Type", value: "application/json" }],
        reason: "GraphQL requires JSON content type",
      });
    }

    // Detect known services and suggest configurations
    if (hostname.includes("api.github.com")) {
      knownService = "GitHub API";
      suggestions.push({
        field: "HEADERS",
        value: [
          { key: "Accept", value: "application/vnd.github+json" },
          { key: "X-GitHub-Api-Version", value: "2022-11-28" },
        ],
        reason: "GitHub API recommended headers",
      });
      apiType = "rest";
    } else if (
      hostname.includes("api.openai.com") ||
      hostname.includes("api.anthropic.com")
    ) {
      knownService = hostname.includes("openai")
        ? "OpenAI API"
        : "Anthropic API";
      suggestions.push({
        field: "HEADERS",
        value: [{ key: "Content-Type", value: "application/json" }],
        reason: "LLM APIs require JSON",
      });
      suggestions.push({
        field: "METHOD",
        value: "POST",
        reason: "LLM APIs use POST for inference",
      });
      apiType = "rest";
    } else if (hostname.includes("jsonplaceholder.typicode.com")) {
      knownService = "JSONPlaceholder (Test API)";
      suggestions.push({
        field: "HEADERS",
        value: [{ key: "Content-Type", value: "application/json" }],
        reason: "REST API standard headers",
      });
      apiType = "rest";
    } else if (pathname.match(/\/api\//)) {
      // Generic REST API detection
      apiType = "rest";
      suggestions.push({
        field: "HEADERS",
        value: [{ key: "Content-Type", value: "application/json" }],
        reason: "Common REST API header",
      });
    }

    // Suggest method based on endpoint pattern
    if (apiType === "rest" && !suggestions.some((s) => s.field === "METHOD")) {
      if (pathname.match(/\/(create|add|new)/i)) {
        suggestions.push({
          field: "METHOD",
          value: "POST",
          reason: "Endpoint suggests resource creation",
        });
      } else if (pathname.match(/\/(update|edit|modify)/i)) {
        suggestions.push({
          field: "METHOD",
          value: "PUT",
          reason: "Endpoint suggests resource update",
        });
      } else if (pathname.match(/\/(delete|remove)/i)) {
        suggestions.push({
          field: "METHOD",
          value: "DELETE",
          reason: "Endpoint suggests resource deletion",
        });
      } else {
        suggestions.push({
          field: "METHOD",
          value: "GET",
          reason: "Default for data retrieval",
        });
      }
    }

    // Suggest reasonable timeout
    if (!suggestions.some((s) => s.field === "TIMEOUT_MS")) {
      const timeout =
        knownService === "OpenAI API" || knownService === "Anthropic API"
          ? 30000
          : 5000;
      suggestions.push({
        field: "TIMEOUT_MS",
        value: timeout,
        reason: knownService?.includes("API")
          ? "LLM APIs may take longer"
          : "Standard timeout",
      });
    }

    return {
      isValid: true,
      protocol: urlObj.protocol,
      hostname,
      apiType,
      suggestions,
      knownService,
    };
  } catch {
    return {
      isValid: false,
      suggestions: [],
    };
  }
}

/**
 * Validate field values based on schema and context
 */
export function validateField(
  field: string,
  value: unknown,
  schema: Schema,
): { valid: boolean; message?: string } {
  // URL validation
  if (field === "URL" || schema.format === "uri") {
    if (!value) {
      return { valid: false, message: "URL is required" };
    }
    if (typeof value !== "string") {
      return { valid: false, message: "Invalid URL format" };
    }
    try {
      new URL(value);
      return { valid: true };
    } catch {
      return { valid: false, message: "Invalid URL format" };
    }
  }

  // Required field validation
  if (schema.required && !value) {
    return { valid: false, message: `${schema.title || field} is required` };
  }

  // Number range validation
  if (schema.type === "number" && typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return { valid: false, message: `Must be at least ${schema.minimum}` };
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return { valid: false, message: `Must be at most ${schema.maximum}` };
    }
  }

  // Enum validation
  if (schema.enum && !schema.enum.includes(value)) {
    return { valid: false, message: "Invalid value" };
  }

  // Pattern validation for strings
  if (schema.type === "string" && schema.pattern && typeof value === "string") {
    try {
      if (schema.pattern.length > 250) {
        return { valid: false, message: "Regex pattern too complex" };
      }
      const regex = new RegExp(schema.pattern);
      if (!regex.test(value)) {
        return {
          valid: false,
          message: `Invalid format (expected pattern: ${schema.pattern})`,
        };
      }
    } catch {
      // Invalid regex pattern in schema, skip validation
    }
  }

  // Array validation
  if (schema.type === "array" && value && Array.isArray(value)) {
    // Validate uniqueItems constraint
    if (schema.uniqueItems) {
      const seen = new Set();
      for (const item of value) {
        const key = JSON.stringify(item);
        if (seen.has(key)) {
          return { valid: false, message: "Array items must be unique" };
        }
        seen.add(key);
      }
    }

    // Validate array items if they have patterns
    if (schema.items?.pattern) {
      try {
        if (schema.items.pattern.length > 250) {
          return { valid: false, message: "Regex pattern too complex" };
        }
        const regex = new RegExp(schema.items.pattern);
        for (const item of value) {
          if (typeof item === "string" && !regex.test(item)) {
            return {
              valid: false,
              message: `Invalid item format (expected pattern: ${schema.items.pattern})`,
            };
          }
        }
      } catch {
        // Invalid regex pattern in schema, skip validation
      }
    }
  }

  return { valid: true };
}

/**
 * Apply smart suggestions to config
 */
export function applySuggestions(
  currentConfig: Record<string, unknown>,
  suggestions: SmartSuggestion[],
): Record<string, unknown> {
  const newConfig = { ...currentConfig };

  for (const suggestion of suggestions) {
    // Only apply if the field is empty or has default value
    if (!newConfig[suggestion.field] || newConfig[suggestion.field] === "") {
      newConfig[suggestion.field] = suggestion.value;
    } else if (
      suggestion.field === "HEADERS" &&
      Array.isArray(suggestion.value)
    ) {
      // Merge headers instead of replacing
      const existingHeaders =
        (newConfig[suggestion.field] as { key: string; value: string }[]) || [];
      const suggestedHeaders = suggestion.value as {
        key: string;
        value: string;
      }[];

      // Only add headers that don't already exist
      for (const suggestedHeader of suggestedHeaders) {
        const exists = existingHeaders.some(
          (h) => h.key === suggestedHeader.key,
        );
        if (!exists) {
          existingHeaders.push(suggestedHeader);
        }
      }
      newConfig[suggestion.field] = existingHeaders;
    }
  }

  return newConfig;
}

/**
 * Get smart defaults for a template category
 */
export function getTemplateDefaults(
  category: string,
  templateName: string,
): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};

  switch (category) {
    case "http":
      defaults.METHOD = "GET";
      defaults.HEADERS = [];
      defaults.TIMEOUT_MS = 5000;
      break;

    case "llm":
      defaults.MAX_TOKENS = 1000;
      defaults.SYSTEM_PROMPT = "You are a helpful assistant.";
      break;

    case "transform":
      if (templateName.includes("JSON")) {
        defaults.SELECTOR = "data";
      }
      break;

    case "debug":
      defaults.LOG_TO_CONSOLE = true;
      defaults.UPPERCASE = false;
      break;

    case "webhook":
      if (templateName.includes("slack")) {
        return getSlackSmartDefaults();
      }
      break;
  }

  return defaults;
}

/**
 * Get smart defaults for Slack webhook configuration
 */
export function getSlackSmartDefaults(_url?: string): Record<string, unknown> {
  return {
    EVENT_TYPES: ["message.channels", "message.im", "app_mention"],
    MESSAGE_FILTERS: {
      exclude_bots: true,
      min_length: 1,
      keywords: [],
      exclude_keywords: [],
      require_mention: false,
      threads_only: false,
      exclude_threads: false,
      has_attachments: false,
      has_links: false,
      max_length: 0,
    },
    OUTPUT_FORMAT: "simplified",
    CHANNEL_FILTER: [],
    USER_FILTER: [],
    ENRICH_EVENTS: {
      include_user_profile: false,
      include_channel_info: false,
      include_thread_context: false,
      resolve_mentions: false,
    },
    RATE_LIMIT: {
      enabled: false,
      max_per_minute: 60,
      max_per_channel: 10,
    },
  };
}
