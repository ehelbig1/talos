import React, { useState, useCallback } from "react";
import { cn } from "@/lib/utils";

const MAX_STRING_LENGTH = 200;

interface NodeDataViewerProps {
  data: unknown;
  depth?: number;
}

/**
 * Recursive JSON viewer with syntax highlighting and collapsible nodes.
 * Dark-themed, monospace font. No external dependencies.
 */
export const NodeDataViewer: React.FC<NodeDataViewerProps> = ({
  data,
  depth = 0,
}) => {
  if (data === null || data === undefined) {
    return <span className="text-muted-foreground italic">null</span>;
  }

  if (typeof data === "boolean") {
    return <span className="text-yellow-400">{data ? "true" : "false"}</span>;
  }

  if (typeof data === "number") {
    return <span className="text-cyan-400">{String(data)}</span>;
  }

  if (typeof data === "string") {
    return <StringValue value={data} />;
  }

  if (Array.isArray(data)) {
    return <ArrayValue items={data} depth={depth} />;
  }

  if (typeof data === "object") {
    return <ObjectValue obj={data as Record<string, unknown>} depth={depth} />;
  }

  // Fallback for anything else
  return <span className="text-foreground/80">{String(data)}</span>;
};

const StringValue: React.FC<{ value: string }> = ({ value }) => {
  const [expanded, setExpanded] = useState(false);
  const isTruncated = value.length > MAX_STRING_LENGTH;

  const displayValue =
    isTruncated && !expanded
      ? value.slice(0, MAX_STRING_LENGTH) + "..."
      : value;

  return (
    <span className="text-green-400">
      &quot;{displayValue}&quot;
      {isTruncated && (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="ml-1 text-[9px] text-violet-400 hover:text-violet-300 underline underline-offset-2 transition-premium"
        >
          {expanded ? "collapse" : "expand"}
        </button>
      )}
    </span>
  );
};

const ArrayValue: React.FC<{
  items: unknown[];
  depth: number;
}> = ({ items, depth }) => {
  const [collapsed, setCollapsed] = useState(depth > 2);

  const toggle = useCallback(() => setCollapsed((c) => !c), []);

  if (items.length === 0) {
    return <span className="text-muted-foreground">[]</span>;
  }

  return (
    <span>
      <button
        type="button"
        onClick={toggle}
        className="text-muted-foreground hover:text-foreground/80 transition-premium select-none"
      >
        {collapsed ? "[ ... ]" : "["}
      </button>
      {collapsed && (
        <span className="text-[9px] text-muted-foreground/50 ml-1">
          {items.length} items
        </span>
      )}
      {!collapsed && (
        <>
          <div className="pl-4 border-l border-white/5">
            {items.map((item, i) => (
              <div key={i} className="py-0.5">
                <NodeDataViewer data={item} depth={depth + 1} />
                {i < items.length - 1 && (
                  <span className="text-muted-foreground/50">,</span>
                )}
              </div>
            ))}
          </div>
          <span className="text-muted-foreground">]</span>
        </>
      )}
    </span>
  );
};

const ObjectValue: React.FC<{
  obj: Record<string, unknown>;
  depth: number;
}> = ({ obj, depth }) => {
  const keys = Object.keys(obj);
  const [collapsed, setCollapsed] = useState(depth > 2);

  const toggle = useCallback(() => setCollapsed((c) => !c), []);

  if (keys.length === 0) {
    return <span className="text-muted-foreground">{"{}"}</span>;
  }

  return (
    <span>
      <button
        type="button"
        onClick={toggle}
        className="text-muted-foreground hover:text-foreground/80 transition-premium select-none"
      >
        {collapsed ? "{ ... }" : "{"}
      </button>
      {collapsed && (
        <span className="text-[9px] text-muted-foreground/50 ml-1">
          {keys.length} keys
        </span>
      )}
      {!collapsed && (
        <>
          <div className="pl-4 border-l border-white/5">
            {keys.map((key, i) => (
              <div key={key} className="py-0.5">
                <span className="text-violet-300">&quot;{key}&quot;</span>
                <span className="text-muted-foreground">: </span>
                <NodeDataViewer data={obj[key]} depth={depth + 1} />
                {i < keys.length - 1 && (
                  <span className="text-muted-foreground/50">,</span>
                )}
              </div>
            ))}
          </div>
          <span className="text-muted-foreground">{"}"}</span>
        </>
      )}
    </span>
  );
};
