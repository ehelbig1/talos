import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?:
    "default" | "destructive" | "outline" | "ghost" | "premium" | "secondary";
  size?: "default" | "sm" | "lg" | "xl" | "icon";
}

/**
 * The one button. Sentence-case label at a readable size; emphasis comes from
 * the variant's fill, not from weight, caps or glow.
 */
const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    const base =
      "inline-flex items-center justify-center gap-2 rounded-xl font-semibold transition-premium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30 disabled:opacity-40 disabled:pointer-events-none active:scale-[0.98] select-none leading-none whitespace-nowrap";

    const variants = {
      default:
        "bg-primary text-primary-foreground hover:bg-primary/90 border border-primary/20",
      destructive:
        "bg-destructive text-destructive-foreground hover:bg-destructive/90 border border-destructive/20",
      outline:
        "border border-white/10 bg-white/5 text-foreground hover:bg-white/10 hover:border-white/20",
      secondary:
        "bg-surface-4 text-foreground border border-white/5 hover:bg-white/5",
      ghost: "hover:bg-white/5 text-muted-foreground hover:text-foreground",
      premium:
        "bg-gradient-to-br from-primary to-indigo-600 text-white border border-white/10 hover:brightness-110",
    };

    const sizes = {
      default: "h-10 px-4 text-sm",
      sm: "h-8 px-3 text-xs",
      lg: "h-12 px-6 text-sm",
      xl: "h-14 px-8 text-base",
      icon: "h-10 w-10 p-0",
    };

    return (
      <button
        className={cn(base, variants[variant], sizes[size], className)}
        ref={ref}
        {...props}
      />
    );
  },
);

Button.displayName = "Button";
export { Button };
