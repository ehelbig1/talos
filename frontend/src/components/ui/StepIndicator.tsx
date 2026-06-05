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
                isCompleted ? "bg-violet-500" : "bg-white/10",
              )}
            />
          )}
          {/* Step circle + label */}
          <div className="flex items-center gap-1.5">
            <div
              className={cn(
                "w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold transition-premium",
                isCompleted && "bg-violet-500 text-white",
                isCurrent &&
                  "bg-violet-500/20 text-violet-300 border border-violet-500/50 ring-2 ring-violet-500/20",
                !isCompleted &&
                  !isCurrent &&
                  "bg-white/5 text-muted-foreground/40 border border-white/5",
              )}
            >
              {isCompleted ? <Check className="h-3 w-3" /> : idx + 1}
            </div>
            <span
              className={cn(
                "text-[10px] uppercase tracking-wider font-medium",
                isCurrent ? "text-foreground/80" : "text-muted-foreground/40",
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
