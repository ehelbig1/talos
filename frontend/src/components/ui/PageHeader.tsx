import React from "react";
import { Link } from "react-router";
import { ChevronLeft } from "lucide-react";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  /** The page's name, as a plain noun. */
  title: React.ReactNode;
  /** One sentence on what the page is for, or a live summary ("3 workflows"). */
  description?: React.ReactNode;
  /** Primary actions, right-aligned. */
  actions?: React.ReactNode;
  /** A detail page names the list it came from. */
  backTo?: { to: string; label: string };
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
  backTo,
  className,
}) => (
  <header className={cn("mb-8", className)}>
    {backTo && (
      <Link
        to={backTo.to}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-white transition-premium mb-3 -ml-1"
      >
        <ChevronLeft className="w-4 h-4" />
        {backTo.label}
      </Link>
    )}
    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight font-outfit">
          {title}
        </h1>
        {description && (
          <div className="text-sm text-muted-foreground mt-1">
            {description}
          </div>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          {actions}
        </div>
      )}
    </div>
  </header>
);
