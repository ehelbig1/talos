import React, { useState } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Link,
  Search,
  Clipboard,
  FileText,
  X,
  Target,
  Settings,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button, Badge } from "@/components/ui";

export interface Parameter {
  name: string;
  in: "path" | "query" | "header" | "body";
  required?: boolean;
  type?: string;
  description?: string;
  schema?: Record<string, unknown>;
  example?: unknown;
}

interface BodySchema {
  properties?: Record<
    string,
    {
      type?: string;
      description?: string;
      example?: unknown;
      default?: unknown;
    }
  >;
  required?: string[];
}

export interface Endpoint {
  path: string;
  method: string;
  summary?: string;
  description?: string;
  parameters?: Parameter[];
  requestBody?: {
    content?: Record<string, { schema?: BodySchema }>;
  };
}

interface EndpointSelectorProps {
  endpoints: Endpoint[];
  onConfigure: (config: {
    method: string;
    url: string;
    headers: Array<{ key: string; value: string }>;
    body?: string;
  }) => void;
  baseUrl: string;
}

export function EndpointSelector({
  endpoints,
  onConfigure,
  baseUrl,
}: EndpointSelectorProps) {
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(
    null,
  );
  const [pathParams, setPathParams] = useState<Record<string, string>>({});
  const [queryParams, setQueryParams] = useState<Record<string, string>>({});
  const [headerParams, setHeaderParams] = useState<Record<string, string>>({});
  const [bodyData, setBodyData] = useState<Record<string, unknown>>({});
  const [activeTab, setActiveTab] = useState<"params" | "body">("params");

  const handleSelectEndpoint = (endpoint: Endpoint) => {
    setSelectedEndpoint(endpoint);
    setPathParams({});
    setQueryParams({});
    setHeaderParams({});
    setBodyData({});

    const pathParameters =
      endpoint.parameters?.filter((p) => p.in === "path") || [];
    const queryParameters =
      endpoint.parameters?.filter((p) => p.in === "query") || [];
    const headerParameters =
      endpoint.parameters?.filter((p) => p.in === "header") || [];

    const initialPath: Record<string, string> = {};
    pathParameters.forEach((p) => {
      if (p.example) initialPath[p.name] = String(p.example);
    });
    setPathParams(initialPath);

    const initialQuery: Record<string, string> = {};
    queryParameters.forEach((p) => {
      if (p.example) initialQuery[p.name] = String(p.example);
    });
    setQueryParams(initialQuery);

    const initialHeaders: Record<string, string> = {};
    headerParameters.forEach((p) => {
      if (p.example) initialHeaders[p.name] = String(p.example);
    });
    setHeaderParams(initialHeaders);
  };

  const handleApplyConfiguration = () => {
    if (!selectedEndpoint) return;

    let url = baseUrl + selectedEndpoint.path;
    Object.entries(pathParams).forEach(([key, value]) => {
      url = url.replace(`{${key}}`, encodeURIComponent(value));
    });

    const queryString = Object.entries(queryParams)
      .filter(([_, value]) => value)
      .map(
        ([key, value]) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
      )
      .join("&");

    if (queryString) url += "?" + queryString;

    const headers: Array<{ key: string; value: string }> = [];
    Object.entries(headerParams).forEach(([key, value]) => {
      if (value) headers.push({ key, value });
    });

    if (selectedEndpoint.requestBody && Object.keys(bodyData).length > 0) {
      const contentType =
        Object.keys(selectedEndpoint.requestBody.content || {})[0] ||
        "application/json";
      if (!headers.some((h) => h.key.toLowerCase() === "content-type")) {
        headers.push({ key: "Content-Type", value: contentType });
      }
    }

    const body =
      Object.keys(bodyData).length > 0
        ? JSON.stringify(bodyData, null, 2)
        : undefined;

    onConfigure({
      method: selectedEndpoint.method,
      url,
      headers,
      body,
    });

    setSelectedEndpoint(null);
  };

  if (!selectedEndpoint) {
    return (
      <div className="bg-surface-2/40 border border-white/5 rounded-2xl p-8 space-y-6 relative overflow-hidden">
        <div className="flex items-center gap-3 relative z-10 mb-2">
          <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
            <Target className="h-4 w-4" />
          </div>
          <h4 className="text-xs font-semibold text-white">
            Choose an endpoint
          </h4>
        </div>
        <div className="max-h-96 overflow-y-auto flex flex-col gap-3 pr-2 custom-scrollbar relative z-10">
          {endpoints.map((endpoint) => (
            <button
              key={`${endpoint.method}-${endpoint.path}`}
              onClick={() => handleSelectEndpoint(endpoint)}
              className="p-5 bg-surface-3/60 hover:bg-surface-4 border border-white/5 hover:border-primary/40 rounded-2xl text-left transition-ui group"
            >
              <div className="flex items-center gap-4 mb-3">
                <span
                  className={cn(
                    "px-2.5 py-1 rounded-lg text-2xs font-semibold uppercase tracking-wider border transition-ui",
                    getMethodStyles(endpoint.method),
                  )}
                >
                  {endpoint.method}
                </span>
                <code className="text-xs font-mono text-white/80 group-hover:text-primary transition-ui truncate">
                  {endpoint.path}
                </code>
              </div>
              {endpoint.summary && (
                <p className="text-xs text-muted-foreground/70 line-clamp-1 leading-relaxed">
                  {endpoint.summary}
                </p>
              )}
            </button>
          ))}
        </div>
      </div>
    );
  }

  const pathParameters =
    selectedEndpoint.parameters?.filter((p) => p.in === "path") || [];
  const queryParameters =
    selectedEndpoint.parameters?.filter((p) => p.in === "query") || [];
  const headerParameters =
    selectedEndpoint.parameters?.filter((p) => p.in === "header") || [];
  const hasBody = !!selectedEndpoint.requestBody;
  const bodySchema = selectedEndpoint.requestBody?.content?.["application/json"]
    ?.schema as BodySchema | undefined;

  const totalParams =
    pathParameters.length + queryParameters.length + headerParameters.length;

  return (
    <div className="bg-surface-2/60 border border-primary/20 rounded-2xl p-8 space-y-10 relative overflow-hidden">
      <div className="relative z-10">
        <div className="flex justify-between items-start mb-6">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <span
                className={cn(
                  "px-3 py-1.5 rounded-xl text-xs font-semibold border",
                  getMethodStyles(selectedEndpoint.method),
                )}
              >
                {selectedEndpoint.method}
              </span>
              <code className="text-xl font-mono font-semibold text-white tracking-tight">
                {selectedEndpoint.path}
              </code>
            </div>
            {selectedEndpoint.summary && (
              <p className="m-0 text-xs text-muted-foreground/70 leading-relaxed">
                {selectedEndpoint.summary}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setSelectedEndpoint(null)}
            aria-label="Clear selection"
            className="p-2 rounded-xl hover:bg-white/5 text-muted-foreground/50 hover:text-white transition-ui"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="relative z-10 border-b border-white/5">
        <div className="flex gap-8">
          <button
            type="button"
            onClick={() => setActiveTab("params")}
            className={cn(
              "pb-4 text-xs font-semibold transition-ui relative",
              activeTab === "params"
                ? "text-primary"
                : "text-muted-foreground/70 hover:text-white",
            )}
          >
            Parameters
            {totalParams > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-primary/10 border border-primary/20 rounded-full text-2xs">
                {totalParams}
              </span>
            )}
            {activeTab === "params" && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary rounded-full" />
            )}
          </button>
          {hasBody && (
            <button
              type="button"
              onClick={() => setActiveTab("body")}
              className={cn(
                "pb-4 text-xs font-semibold transition-ui relative",
                activeTab === "body"
                  ? "text-primary"
                  : "text-muted-foreground/70 hover:text-white",
              )}
            >
              Request Manifest
              {activeTab === "body" && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary rounded-full" />
              )}
            </button>
          )}
        </div>
      </div>

      {/* Tab Content */}
      <div className="relative z-10 min-h-[300px]">
        {activeTab === "params" && (
          <div className="space-y-10">
            {pathParameters.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1">
                  <Link className="h-3.5 w-3.5 text-primary" />
                  <h5 className="text-2xs font-semibold text-white/70 uppercase tracking-wider">
                    Path variables
                  </h5>
                </div>
                <div className="grid gap-6">
                  {pathParameters.map((param) => (
                    <ParameterInput
                      key={param.name}
                      parameter={param}
                      value={pathParams[param.name] || ""}
                      onChange={(value) =>
                        setPathParams({ ...pathParams, [param.name]: value })
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {queryParameters.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1">
                  <Search className="h-3.5 w-3.5 text-primary" />
                  <h5 className="text-2xs font-semibold text-white/70 uppercase tracking-wider">
                    Query parameters
                  </h5>
                </div>
                <div className="grid gap-6">
                  {queryParameters.map((param) => (
                    <ParameterInput
                      key={param.name}
                      parameter={param}
                      value={queryParams[param.name] || ""}
                      onChange={(value) =>
                        setQueryParams({ ...queryParams, [param.name]: value })
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {headerParameters.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1">
                  <Clipboard className="h-3.5 w-3.5 text-primary" />
                  <h5 className="text-2xs font-semibold text-white/70 uppercase tracking-wider">
                    Headers
                  </h5>
                </div>
                <div className="grid gap-6">
                  {headerParameters.map((param) => (
                    <ParameterInput
                      key={param.name}
                      parameter={param}
                      value={headerParams[param.name] || ""}
                      onChange={(value) =>
                        setHeaderParams({
                          ...headerParams,
                          [param.name]: value,
                        })
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {totalParams === 0 && (
              <div className="py-12 text-center bg-surface-4 border-2 border-dashed border-white/5 rounded-2xl">
                <p className="text-xs font-semibold text-muted-foreground/50">
                  Zero Parameters Required for Operation
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === "body" && hasBody && (
          <div className="space-y-6">
            <div className="flex items-center gap-3 px-1">
              <FileText className="h-4 w-4 text-primary" />
              <h5 className="text-xs font-semibold text-white/60">
                Payload Manifest Construction
              </h5>
            </div>
            {bodySchema?.properties ? (
              <div className="grid gap-8">
                {Object.entries(bodySchema.properties).map(([key, prop]) => (
                  <div key={key} className="space-y-3">
                    <div className="flex items-center justify-between px-1">
                      <label className="text-xs font-semibold text-white/70">
                        {key}
                        {(
                          bodySchema.required as string[] | undefined
                        )?.includes(key) && (
                          <span className="text-primary ml-1.5">*</span>
                        )}
                      </label>
                    </div>
                    {prop.description && (
                      <p className="text-2xs font-medium text-muted-foreground/50 leading-relaxed px-1">
                        {prop.description}
                      </p>
                    )}
                    <Input
                      type={
                        prop.type === "number" || prop.type === "integer"
                          ? "number"
                          : "text"
                      }
                      value={(bodyData[key] as string) || ""}
                      onChange={(e) =>
                        setBodyData({ ...bodyData, [key]: e.target.value })
                      }
                      placeholder={String(
                        prop.example || prop.default || `Enter ${key}...`,
                      ).toUpperCase()}
                    />
                  </div>
                ))}
              </div>
            ) : (
              <div className="relative group">
                <Textarea
                  value={JSON.stringify(bodyData, null, 2)}
                  onChange={(e) => {
                    try {
                      setBodyData(JSON.parse(e.target.value));
                    } catch {
                      /* Ignore */
                    }
                  }}
                  placeholder='{ "PAYLOAD": "METADATA" }'
                  rows={10}
                  className="relative text-xs font-mono text-primary custom-scrollbar"
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="relative z-10 flex gap-4 pt-10 border-t border-white/5">
        <Button
          onClick={handleApplyConfiguration}
          className="flex-1 h-14 bg-primary hover:bg-primary/90 text-white text-sm font-semibold rounded-2xl transition-ui flex items-center justify-center gap-3"
        >
          <Zap className="h-4 w-4" /> Finalize Configuration
        </Button>
        <Button
          onClick={() => setSelectedEndpoint(null)}
          variant="ghost"
          className="h-14 px-10 bg-surface-3 hover:bg-surface-4 text-muted-foreground/70 hover:text-white text-sm font-semibold rounded-2xl border border-white/5 transition-ui"
        >
          Cancel
        </Button>
      </div>

      <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
        <div className="shrink-0 p-2 rounded-xl bg-primary/10 border border-primary/20">
          <Settings className="w-4 h-4 text-primary" />
        </div>
        <p className="text-xs text-primary/60 leading-relaxed">
          Check the parameters carefully. A wrong path variable or body shape
          will make the node fail at run time.
        </p>
      </div>
    </div>
  );
}

function ParameterInput({
  parameter,
  value,
  onChange,
}: {
  parameter: Parameter;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between px-1">
        <label
          htmlFor={`param-${parameter.name}`}
          className="flex items-center gap-2 text-xs font-semibold text-white"
        >
          <code className="text-primary font-bold">{parameter.name}</code>
          {parameter.required && <span className="text-primary">*</span>}
        </label>
        <Badge className="bg-white/5 text-muted-foreground/50 border-white/10 text-2xs font-semibold uppercase tracking-wider">
          {parameter.in.toUpperCase()}
        </Badge>
      </div>
      {parameter.description && (
        <p className="text-2xs font-medium text-muted-foreground/50 leading-relaxed px-1">
          {parameter.description}
        </p>
      )}
      <Input
        id={`param-${parameter.name}`}
        type={
          parameter.schema?.type === "number" ||
          parameter.schema?.type === "integer"
            ? "number"
            : "text"
        }
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={String(
          parameter.example ||
            parameter.schema?.default ||
            `IDENTIFIER VALUE...`,
        ).toUpperCase()}
        required={parameter.required}
      />
    </div>
  );
}

function getMethodStyles(method: string): string {
  const styles: Record<string, string> = {
    GET: "bg-success/10 text-success border-success/20",
    POST: "bg-primary/10 text-primary border-primary/20",
    PUT: "bg-warning/10 text-warning border-warning/20",
    PATCH: "bg-primary/10 text-primary border-primary/20",
    DELETE: "bg-destructive/10 text-destructive border-destructive/20",
  };
  return styles[method] || "bg-white/5 text-muted-foreground border-white/10";
}
