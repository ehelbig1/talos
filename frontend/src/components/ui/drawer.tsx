import * as React from "react";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";

export interface DrawerProps {
  children: React.ReactNode;
  position?: "bottom" | "right" | "left";
  height?: string;
  width?: string;
  className?: string;
  isOpen?: boolean;
  onClose?: () => void;
}

const Drawer = React.forwardRef<HTMLDivElement, DrawerProps>(
  (
    {
      children,
      position = "bottom",
      height = "300px",
      width = "400px",
      className,
      isOpen = true,
    },
    ref,
  ) => {
    const positionClasses = {
      bottom: "bottom-0 left-0 right-0",
      right: "right-0 top-0 bottom-0",
      left: "left-0 top-0 bottom-0",
    };

    const sizeStyle = position === "bottom" ? { height } : { width };

    return (
      <div
        ref={ref}
        className={cn(
          "fixed bg-surface-3/90 backdrop-blur-xl border-white/5 shadow-2xl transition-transform duration-200 ease-in-out",
          positionClasses[position],
          position === "bottom" && "border-t",
          position === "right" && "border-l",
          position === "left" && "border-r",
          !isOpen &&
            (position === "bottom"
              ? "translate-y-full"
              : position === "right"
                ? "translate-x-full"
                : "-translate-x-full"),
          className,
        )}
        style={sizeStyle}
      >
        {children}
      </div>
    );
  },
);

Drawer.displayName = "Drawer";

export interface DrawerHeaderProps {
  children: React.ReactNode;
  className?: string;
  onClose?: () => void;
}

const DrawerHeader = React.forwardRef<HTMLDivElement, DrawerHeaderProps>(
  ({ children, className, onClose }, ref) => (
    <div
      ref={ref}
      className={cn(
        "flex items-center justify-between px-4 py-3 border-b border-white/5",
        className,
      )}
    >
      <div className="flex-1">{children}</div>
      {onClose && (
        <button
          onClick={onClose}
          className="ml-4 p-1.5 rounded-xl hover:bg-white/10 transition-premium text-muted-foreground hover:text-foreground"
          aria-label="Close drawer"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  ),
);

DrawerHeader.displayName = "DrawerHeader";

export interface DrawerContentProps {
  children: React.ReactNode;
  className?: string;
}

const DrawerContent = React.forwardRef<HTMLDivElement, DrawerContentProps>(
  ({ children, className }, ref) => (
    <div ref={ref} className={cn("flex-1 overflow-auto p-4", className)}>
      {children}
    </div>
  ),
);

DrawerContent.displayName = "DrawerContent";

export { Drawer, DrawerHeader, DrawerContent };
