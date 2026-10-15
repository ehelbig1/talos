import React from "react";
import { cn } from "@/lib/utils";

interface PageContainerProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * The width and gutters every page shares. A page is a scroll container
 * around one of these; the header and the content sit inside it.
 */
export const PageContainer: React.FC<PageContainerProps> = ({
  children,
  className,
}) => (
  <div
    className={cn(
      "w-full max-w-7xl mx-auto px-6 md:px-8 py-8 md:py-10 relative z-10",
      className,
    )}
  >
    {children}
  </div>
);
