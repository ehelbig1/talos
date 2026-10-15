import React from "react";
import { DarkSurfaceDiv } from "./DarkSurfaceDiv";
import { cn } from "@/lib/utils";

/**
 * Simple informational banner used throughout the UI.
 * Standardized to use theme variables and consistent padding/border.
 */
export const InfoBanner: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <DarkSurfaceDiv
    className={cn(
      "border border-primary/20 rounded-xl p-4 bg-primary/5 relative overflow-hidden",
      className,
    )}
  >
    {children}
  </DarkSurfaceDiv>
);
