import React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple flex container that aligns items in a row.
 */
export const FlexRow: React.FC<{
  className?: string;
  children: React.ReactNode;
}> = ({ className, children }) => (
  <div className={cn("flex items-center", className)}>{children}</div>
);
