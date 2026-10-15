import React from "react";
import { cn } from "@/lib/utils";

export interface DialogWrapperProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

/**
 * Standard container for dialog content: a raised surface with even padding.
 */
export const DialogWrapper: React.FC<DialogWrapperProps> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div
      {...props}
      className={cn(
        "bg-surface-3/80 backdrop-blur-2xl border border-white/10 rounded-3xl p-8 shadow-2xl w-full max-w-3xl overflow-hidden relative pointer-events-auto nodrag nopan",
        className,
      )}
    >
      <div className="relative z-10">{children}</div>
    </div>
  );
};
