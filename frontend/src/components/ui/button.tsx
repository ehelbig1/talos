import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?:
    | "default"
    | "destructive"
    | "outline"
    | "ghost"
    | "premium"
    | "glass"
    | "secondary";
  size?: "default" | "sm" | "lg" | "xl" | "icon";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    const base =
      "inline-flex items-center justify-center rounded-xl font-black uppercase tracking-widest transition-premium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 disabled:opacity-30 disabled:pointer-events-none active:scale-95 select-none leading-none";

    const variants = {
      default:
        "bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20 border border-primary/20",
      destructive:
        "bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-lg shadow-destructive/20 border border-destructive/20",
      outline:
        "border border-white/10 bg-white/5 text-foreground hover:bg-white/10 hover:border-white/20",
      secondary:
        "bg-surface-4 text-foreground border border-white/5 hover:bg-white/5",
      ghost: "hover:bg-white/5 text-muted-foreground hover:text-foreground",
      premium:
        "bg-gradient-to-br from-primary to-indigo-600 text-white shadow-xl shadow-primary/20 border border-white/10 hover:brightness-110",
      glass:
        "bg-white/5 backdrop-blur-md border border-white/10 text-white hover:bg-white/10 hover:border-white/20 shadow-xl",
    };

    const sizes = {
      default: "h-11 px-6 text-[10px]",
      sm: "h-9 px-4 text-[9px]",
      lg: "h-14 px-8 text-xs",
      xl: "h-16 px-10 text-sm",
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
