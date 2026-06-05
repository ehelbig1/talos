import React from "react";
import { cn } from "@/lib/utils";

interface ToolbarGroupProps {
  label: string;
  children: React.ReactNode;
  className?: string;
  hoverColor?: string;
}

export function ToolbarGroup({
  label,
  children,
  className,
  hoverColor = "group-hover:text-primary",
}: ToolbarGroupProps) {
  return (
    <div
      className={cn(
        "relative flex items-center gap-3 pt-5 group/toolbar-group",
        className,
      )}
    >
      <span
        className={cn(
          "absolute top-0 left-0.5 text-[8px] font-black text-muted-foreground/40 uppercase tracking-[0.4em] select-none pointer-events-none transition-premium",
          hoverColor,
        )}
      >
        {label}
      </span>
      <div className="flex items-center gap-2.5">{children}</div>
    </div>
  );
}
