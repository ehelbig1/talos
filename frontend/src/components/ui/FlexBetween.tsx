import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple flex container that spaces children horizontally with `space-between`
 * alignment.
 */
export const FlexBetween: React.FC<{
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}> = ({ children, className, style }) => (
  <div
    className={cn("flex justify-between items-center", className)}
    style={style}
  >
    {children}
  </div>
);
