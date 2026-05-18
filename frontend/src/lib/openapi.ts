/**
 * OpenAPI/Swagger integration for auto-discovering API configurations
 */

interface OpenAPIEndpoint {
  path: string;
  method: string;
  summary?: string;
  description?: string;
  parameters?: unknown[];
  requestBody?: {
    content?: Record<string, { schema?: Record<string, unknown> }>;
  };
  responses?: Record<
    string,
    { content?: Record<string, { schema?: Record<string, unknown> }> }
  >;
  security?: unknown[];
}

interface OpenAPIOperation {
  summary?: string;
  description?: string;
  parameters?: unknown[];
  requestBody?: {
    content?: Record<string, { schema?: Record<string, unknown> }>;
  };
  responses?: Record<
    string,
    { content?: Record<string, { schema?: Record<string, unknown> }> }
  >;
  security?: unknown[];
}

export interface OpenAPISpec {
  openapi?: string;
  swagger?: string;
  info?: {
    title: string;
    version: string;
    description?: string;
  };
  servers?: Array<{ url: string; description?: string }>;
  paths?: Record<string, Record<string, unknown>>;
  components?: Record<string, unknown>;
}

/**
 * Common OpenAPI spec URL patterns
 */
const OPENAPI_PATTERNS = [
  "/openapi.json",
  "/openapi.yaml",
  "/swagger.json",
  "/swagger.yaml",
  "/api-docs",
  "/api/openapi.json",
  "/api/swagger.json",
  "/v1/openapi.json",
  "/v2/openapi.json",
  "/v3/openapi.json",
  "/.well-known/openapi.json",
];

/**
 * Try to discover OpenAPI spec for a given base URL
 */
export async function discoverOpenAPISpec(
  baseUrl: string,
): Promise<OpenAPISpec | null> {
  try {
    const url = new URL(baseUrl);
    const baseOrigin = `${url.protocol}//${url.host}`;

    // Try common patterns
    for (const pattern of OPENAPI_PATTERNS) {
      try {
        const specUrl = baseOrigin + pattern;
        // if (import.meta.env.DEV) console.log("Trying OpenAPI spec URL:", specUrl);

        const response = await fetch(specUrl, {
          method: "GET",
          headers: {
            Accept: "application/json, application/yaml",
          },
        });

        if (response.ok) {
          const contentType = response.headers.get("content-type") || "";
          let spec: OpenAPISpec;

          if (contentType.includes("yaml") || specUrl.endsWith(".yaml")) {
            // For YAML, we'd need a YAML parser
            // For now, skip YAML files
            continue;
          } else {
            spec = await response.json();
          }

          // Validate it's actually an OpenAPI spec
          if (spec.openapi || spec.swagger) {
            // if (import.meta.env.DEV) console.log("Found OpenAPI spec:", spec);
            return spec;
          }
        }
      } catch {
        // Try next pattern
        continue;
      }
    }

    return null;
  } catch {
    // if (import.meta.env.DEV) console.error("Error discovering OpenAPI spec:", error);
    return null;
  }
}

/**
 * Parse OpenAPI spec and extract endpoints
 */
export function parseOpenAPIEndpoints(spec: OpenAPISpec): OpenAPIEndpoint[] {
  const endpoints: OpenAPIEndpoint[] = [];

  if (!spec.paths) {
    return endpoints;
  }

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    const methods = [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "options",
      "head",
    ];

    for (const method of methods) {
      const operation = pathItem[method] as OpenAPIOperation | undefined;
      if (operation) {
        endpoints.push({
          path,
          method: method.toUpperCase(),
          summary: operation.summary,
          description: operation.description,
          parameters: operation.parameters,
          requestBody: operation.requestBody,
          responses: operation.responses,
          security: operation.security,
        });
      }
    }
  }

  return endpoints;
}

/**
 * Convert OpenAPI endpoint to node configuration
 */
export function endpointToNodeConfig(
  endpoint: OpenAPIEndpoint,
  baseUrl: string,
  spec?: OpenAPISpec,
): Record<string, unknown> {
  const config: Record<string, unknown> = {
    METHOD: endpoint.method,
    URL: baseUrl + endpoint.path,
    HEADERS: [] as Array<{ key: string; value: string }>,
    TIMEOUT_MS: 5000,
  };

  // Add Content-Type header if request body is expected
  if (endpoint.requestBody) {
    const contentTypes = Object.keys(endpoint.requestBody.content || {});
    if (contentTypes.length > 0) {
      (config.HEADERS as Array<{ key: string; value: string }>).push({
        key: "Content-Type",
        value: contentTypes[0], // Use the first content type
      });
    }
  }

  // Add Accept header based on responses
  if (endpoint.responses) {
    const response200 = endpoint.responses["200"] || endpoint.responses["201"];
    if (response200 && response200.content) {
      const contentTypes = Object.keys(response200.content);
      if (contentTypes.length > 0) {
        (config.HEADERS as Array<{ key: string; value: string }>).push({
          key: "Accept",
          value: contentTypes[0],
        });
      }
    }
  }

  // Handle authentication
  if (endpoint.security || spec?.components?.securitySchemes) {
    const securitySchemes =
      (spec?.components?.securitySchemes as Record<string, unknown>) || {};
    const firstScheme = Object.values(securitySchemes)[0] as
      | Record<string, unknown>
      | undefined;

    if (firstScheme) {
      if (firstScheme.type === "http" && firstScheme.scheme === "bearer") {
        (config.HEADERS as Array<{ key: string; value: string }>).push({
          key: "Authorization",
          value: "Bearer YOUR_TOKEN_HERE",
        });
      } else if (firstScheme.type === "apiKey") {
        (config.HEADERS as Array<{ key: string; value: string }>).push({
          key: (firstScheme.name as string) || "X-API-Key",
          value: "YOUR_API_KEY_HERE",
        });
      }
    }
  }

  // Handle path parameters
  const pathParams =
    (endpoint.parameters as Array<{ in: string; name: string }>)?.filter(
      (p) => p.in === "path",
    ) || [];
  if (pathParams.length > 0) {
    // Replace path parameters with placeholders
    let url = config.URL as string;
    for (const param of pathParams) {
      url = url.replace(`{${param.name}}`, `{{${param.name}}}`);
    }
    config.URL = url;
  }

  return config;
}

/**
 * Generate example request body from OpenAPI schema
 */
export function generateExampleBody(requestBody: {
  content?: Record<string, { schema?: Record<string, unknown> }>;
}): string | undefined {
  if (!requestBody || !requestBody.content) {
    return undefined;
  }

  const contentTypes = Object.keys(requestBody.content);
  if (contentTypes.length === 0) {
    return undefined;
  }

  const schema = requestBody.content[contentTypes[0]]?.schema;
  if (!schema) {
    return undefined;
  }

  // Generate a simple example based on schema
  const example = generateExampleFromSchema(schema);
  return JSON.stringify(example, null, 2);
}

function generateExampleFromSchema(schema: Record<string, unknown>): unknown {
  if (schema.example) {
    return schema.example;
  }

  if (schema.type === "object" && schema.properties) {
    const obj: Record<string, unknown> = {};
    for (const [key, prop] of Object.entries(
      schema.properties as Record<string, unknown>,
    )) {
      obj[key] = generateExampleFromSchema(prop as Record<string, unknown>);
    }
    return obj;
  }

  if (schema.type === "array" && schema.items) {
    return [generateExampleFromSchema(schema.items as Record<string, unknown>)];
  }

  if (schema.type === "string") {
    return schema.format === "email" ? "user@example.com" : "example";
  }

  if (schema.type === "number" || schema.type === "integer") {
    return 0;
  }

  if (schema.type === "boolean") {
    return false;
  }

  return null;
}
