import React from "react";
import { cn } from "@/lib/utils";
import { Check } from "lucide-react";

interface StepIndicatorProps {
  steps: { label: string }[];
  currentStep: number;
  className?: string;
}

/**
 * Horizontal step indicator for multi-step wizards.
 * Shows completed steps with a check, current step highlighted, future steps dimmed.
 */
export const StepIndicator: React.FC<StepIndicatorProps> = ({
  steps,
  currentStep,
  className,
}) => (
  <div className={cn("flex items-center gap-1", className)}>
    {steps.map((step, idx) => {
      const isCompleted = idx < currentStep;
      const isCurrent = idx === currentStep;
      return (
        <React.Fragment key={idx}>
          {/* Connector line (skip before first step) */}
          {idx > 0 && (
            <div
              className={cn(
                "flex-1 h-px max-w-[40px]",
                isCompleted ? "bg-primary" : "bg-white/10",
              )}
            />
          )}
          {/* Step circle + label */}
          <div className="flex items-center gap-1.5">
            <div
              className={cn(
                "w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-premium",
                isCompleted && "bg-primary text-white",
                isCurrent &&
                  "bg-primary/20 text-primary border border-primary/50 ring-2 ring-primary/20",
                !isCompleted &&
                  !isCurrent &&
                  "bg-white/5 text-muted-foreground/70 border border-white/5",
              )}
            >
              {isCompleted ? <Check className="h-3 w-3" /> : idx + 1}
            </div>
            <span
              className={cn(
                "text-xs font-medium",
                isCurrent ? "text-foreground" : "text-muted-foreground",
              )}
            >
              {step.label}
            </span>
          </div>
        </React.Fragment>
      );
    })}
  </div>
);
