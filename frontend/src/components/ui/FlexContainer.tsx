import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Generic flex container allowing optional customization via props.
 * Provides sensible defaults (row direction, center alignment).
 */
export const FlexContainer: React.FC<{
  children: React.ReactNode;
  gap?: string;
  justify?: "start" | "end" | "center" | "between" | "around" | "evenly";
  align?: "start" | "end" | "center" | "baseline" | "stretch";
  style?: React.CSSProperties;
  className?: string;
}> = ({ children, gap, justify, align, style, className }) => {
  const justifyMap = {
    start: "justify-start",
    end: "justify-end",
    center: "justify-center",
    between: "justify-between",
    around: "justify-around",
    evenly: "justify-evenly",
  };

  const alignMap = {
    start: "items-start",
    end: "items-end",
    center: "items-center",
    baseline: "items-baseline",
    stretch: "items-stretch",
  };

  return (
    <div
      className={cn(
        "flex flex-row",
        justify && justifyMap[justify],
        align && alignMap[align],
        className,
      )}
      style={{
        ...(gap ? { gap } : {}),
        ...style,
      }}
    >
      {children}
    </div>
  );
};
