import React, { useState } from "react";
import {
  MapPin,
  Link,
  Search,
  Clipboard,
  FileText,
  Check,
  X,
  Target,
  ArrowRight,
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
      <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-8 space-y-6 shadow-2xl animate-in zoom-in-95 duration-500 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />
        <div className="flex items-center gap-3 relative z-10 mb-2">
          <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
            <Target className="h-4 w-4" />
          </div>
          <h4 className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
            Select Isolated Vector
          </h4>
        </div>
        <div className="max-h-96 overflow-y-auto flex flex-col gap-3 pr-2 custom-scrollbar relative z-10">
          {endpoints.map((endpoint) => (
            <button
              key={`${endpoint.method}-${endpoint.path}`}
              onClick={() => handleSelectEndpoint(endpoint)}
              className="p-5 bg-surface-3/60 hover:bg-surface-4 border border-white/5 hover:border-primary/40 rounded-2xl text-left transition-premium group shadow-lg active:scale-[0.98]"
            >
              <div className="flex items-center gap-4 mb-3">
                <span
                  className={cn(
                    "px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border transition-premium",
                    getMethodStyles(endpoint.method),
                  )}
                >
                  {endpoint.method}
                </span>
                <code className="text-xs font-mono text-white/80 group-hover:text-primary transition-premium truncate">
                  {endpoint.path}
                </code>
              </div>
              {endpoint.summary && (
                <p className="text-[10px] font-bold text-muted-foreground/40 uppercase tracking-widest line-clamp-1 leading-relaxed">
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
    <div className="bg-surface-2/60 border border-primary/20 rounded-[2.5rem] p-8 space-y-10 shadow-2xl animate-in zoom-in-95 duration-500 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />

      <div className="relative z-10">
        <div className="flex justify-between items-start mb-6">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <span
                className={cn(
                  "px-3 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-widest border shadow-lg",
                  getMethodStyles(selectedEndpoint.method),
                )}
              >
                {selectedEndpoint.method}
              </span>
              <code className="text-xl font-mono font-black text-white tracking-tight">
                {selectedEndpoint.path}
              </code>
            </div>
            {selectedEndpoint.summary && (
              <p className="m-0 text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest leading-relaxed">
                {selectedEndpoint.summary}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setSelectedEndpoint(null)}
            className="p-2 rounded-xl hover:bg-white/5 text-muted-foreground/20 hover:text-white transition-premium"
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
              "pb-4 text-[10px] font-black uppercase tracking-[0.2em] transition-premium relative",
              activeTab === "params"
                ? "text-primary"
                : "text-muted-foreground/40 hover:text-white",
            )}
          >
            Parameters
            {totalParams > 0 && (
              <span className="ml-2 px-2 py-0.5 bg-primary/10 border border-primary/20 rounded-full text-[8px] animate-pulse">
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
                "pb-4 text-[10px] font-black uppercase tracking-[0.2em] transition-premium relative",
                activeTab === "body"
                  ? "text-primary"
                  : "text-muted-foreground/40 hover:text-white",
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
          <div className="space-y-10 animate-in fade-in slide-in-from-left-4 duration-500">
            {pathParameters.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1">
                  <Link className="h-3.5 w-3.5 text-primary" />
                  <h5 className="text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
                    Isolated Path Variables
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
                  <h5 className="text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
                    Query Injection Vectors
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
                  <h5 className="text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
                    Header Metadata Streams
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
              <div className="py-20 text-center bg-surface-4 border-2 border-dashed border-white/5 rounded-[2rem] animate-in fade-in">
                <p className="text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.4em]">
                  Zero Parameters Required for Operation
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === "body" && hasBody && (
          <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-500">
            <div className="flex items-center gap-3 px-1">
              <FileText className="h-4 w-4 text-primary" />
              <h5 className="text-[10px] font-black text-white/60 uppercase tracking-[0.2em]">
                Payload Manifest Construction
              </h5>
            </div>
            {bodySchema?.properties ? (
              <div className="grid gap-8">
                {Object.entries(bodySchema.properties).map(([key, prop]) => (
                  <div key={key} className="space-y-3">
                    <div className="flex items-center justify-between px-1">
                      <label className="text-[10px] font-black text-white/40 uppercase tracking-widest">
                        {key}
                        {(
                          bodySchema.required as string[] | undefined
                        )?.includes(key) && (
                          <span className="text-primary ml-1.5">*</span>
                        )}
                      </label>
                    </div>
                    {prop.description && (
                      <p className="text-[9px] font-bold text-muted-foreground/20 uppercase tracking-widest leading-relaxed px-1">
                        {prop.description}
                      </p>
                    )}
                    <input
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
                      className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-xs font-black uppercase tracking-widest text-white placeholder-white/10 focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-premium shadow-inner"
                    />
                  </div>
                ))}
              </div>
            ) : (
              <div className="relative group">
                <div className="absolute -inset-1 bg-primary/10 rounded-3xl blur opacity-50 group-focus-within:opacity-100 transition-premium" />
                <textarea
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
                  className="relative w-full p-6 bg-surface-4 border border-white/5 rounded-[2rem] text-xs font-mono text-primary placeholder-primary/20 focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-premium outline-none shadow-2xl custom-scrollbar"
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
          className="flex-1 h-14 bg-primary hover:bg-primary/90 text-white text-[11px] font-black uppercase tracking-[0.3em] rounded-2xl transition-premium shadow-2xl shadow-primary/20 active:scale-95 flex items-center justify-center gap-3"
        >
          <Zap className="h-4 w-4" /> Finalize Configuration
        </Button>
        <Button
          onClick={() => setSelectedEndpoint(null)}
          variant="ghost"
          className="h-14 px-10 bg-surface-3 hover:bg-surface-4 text-muted-foreground/40 hover:text-white text-[10px] font-black uppercase tracking-widest rounded-2xl border border-white/5 transition-premium active:scale-95"
        >
          Abort
        </Button>
      </div>

      <div className="p-6 bg-primary/5 border border-primary/10 rounded-[2rem] flex items-start gap-4">
        <div className="shrink-0 p-2 rounded-xl bg-primary/10 border border-primary/20">
          <Settings className="w-4 h-4 text-primary" />
        </div>
        <p className="text-[10px] text-primary/60 font-bold uppercase tracking-widest leading-relaxed">
          Deployment Insight: Review all parameters carefully. Incorrect path
          variables or payload manifests may cause execution instability across
          the workflow core.
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
          className="flex items-center gap-2 text-[10px] font-black text-white uppercase tracking-widest"
        >
          <code className="text-primary font-bold">{parameter.name}</code>
          {parameter.required && <span className="text-primary">*</span>}
        </label>
        <Badge className="bg-white/5 text-muted-foreground/20 border-white/10 text-[7px] font-black uppercase tracking-widest">
          {parameter.in.toUpperCase()}
        </Badge>
      </div>
      {parameter.description && (
        <p className="text-[9px] font-bold text-muted-foreground/20 uppercase tracking-widest leading-relaxed px-1">
          {parameter.description}
        </p>
      )}
      <input
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
        className="w-full h-12 bg-surface-3 border border-white/5 rounded-xl px-4 text-xs font-black uppercase tracking-widest text-white placeholder-white/10 focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-premium shadow-inner"
      />
    </div>
  );
}

function getMethodStyles(method: string): string {
  const styles: Record<string, string> = {
    GET: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.1)]",
    POST: "bg-primary/10 text-primary border-primary/20 shadow-[0_0_15px_rgba(99,102,241,0.1)]",
    PUT: "bg-amber-500/10 text-amber-400 border-amber-500/20 shadow-[0_0_15px_rgba(245,158,11,0.1)]",
    PATCH:
      "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/20 shadow-[0_0_15px_rgba(168,85,247,0.1)]",
    DELETE:
      "bg-destructive/10 text-destructive border-destructive/20 shadow-[0_0_15px_rgba(239,68,68,0.1)]",
  };
  return styles[method] || "bg-white/5 text-muted-foreground border-white/10";
}
