import React from "react";
import { cn } from "@/lib/utils";

export interface DialogWrapperProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

/**
 * Standard container for dialog content.
 * Provides the glassmorphism aesthetic and consistent padding.
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
        "bg-surface-3/40 backdrop-blur-3xl border border-white/10 rounded-[3rem] p-10 shadow-2xl w-full max-w-3xl overflow-hidden relative glass pointer-events-auto nodrag nopan gpu optimize-blur",
        className,
      )}
    >
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
      <div className="relative z-10">{children}</div>
    </div>
  );
};
