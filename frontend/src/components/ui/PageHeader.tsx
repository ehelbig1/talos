import React from "react";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  /** The page's name, as a plain noun. */
  title: React.ReactNode;
  /** One sentence on what the page is for, or a live summary ("3 workflows"). */
  description?: React.ReactNode;
  /** Primary actions, right-aligned. */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * Every page starts the same way: a title, one line under it, actions on
 * the right. Nothing else goes here; filters and tabs belong to the page.
 */
export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  actions,
  className,
}) => (
  <header
    className={cn(
      "flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-8",
      className,
    )}
  >
    <div className="min-w-0">
      <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight font-outfit">
        {title}
      </h1>
      {description && (
        <div className="text-sm text-muted-foreground mt-1">{description}</div>
      )}
    </div>
    {actions && (
      <div className="flex items-center gap-2 shrink-0 flex-wrap">
        {actions}
      </div>
    )}
  </header>
);
