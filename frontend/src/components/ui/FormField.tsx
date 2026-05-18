import React from "react";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

/**
 * Simple wrapper that pairs a label with a form control.
 * Standardized to use theme variables and consistent spacing.
 */
export const FormField = ({
  label,
  children,
  id,
  className,
  description,
}: {
  label: string;
  children: React.ReactNode;
  id?: string;
  className?: string;
  description?: string;
}) => (
  <div className={cn("space-y-2", className)}>
    <div className="space-y-1">
      <Label
        htmlFor={id}
        className="block text-sm font-semibold text-foreground/90"
      >
        {label}
      </Label>
      {description && (
        <p className="text-[11px] text-muted-foreground font-medium leading-relaxed">
          {description}
        </p>
      )}
    </div>
    {children}
  </div>
);
