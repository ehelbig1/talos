import React from "react";
import { Button } from "@/components/ui/button";
import { FormField } from "@/components/ui/FormField";
import { cn } from "@/lib/utils";

/**
 * Displays a read-only value with a copy-to-clipboard button.
 * Standardized to use theme variables and consistent styling.
 */
export const CopyField = ({
  label,
  value,
  copied,
  onCopy,
  className,
}: {
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
  className?: string;
}) => (
  <FormField label={label}>
    <div
      className={cn(
        "flex items-center gap-2 bg-surface-4/60 border border-white/5 rounded-xl p-1.5 transition-premium focus-within:border-primary/40",
        className,
      )}
    >
      <code className="text-[10px] font-mono text-muted-foreground bg-transparent px-2 py-1 flex-1 truncate">
        {value}
      </code>
      <Button
        size="sm"
        variant="ghost"
        onClick={onCopy}
        className="text-[10px] font-black uppercase tracking-widest h-7 px-3 text-primary hover:text-primary/80 hover:bg-primary/10 rounded-lg transition-premium active:scale-[0.95]"
      >
        {copied ? "✓ Copied" : "Copy"}
      </Button>
    </div>
  </FormField>
);
