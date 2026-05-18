import React from "react";
import { AlertCircle } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";

interface NodeErrorOverlayProps {
  error?: string;
  fixSuggestion?: string;
}

export const NodeErrorOverlay: React.FC<NodeErrorOverlayProps> = ({
  error,
  fixSuggestion,
}) => {
  if (!error) return null;

  return (
    <div className="mt-3 pt-2.5 border-t border-border/50 space-y-1.5 group/error">
      <div className="flex items-start gap-2">
        <AlertCircle className="w-3.5 h-3.5 text-destructive shrink-0 mt-0.5" />
        <p className="text-[11px] text-destructive/90 leading-relaxed line-clamp-2">
          {sanitizeErrorMessage(error).slice(0, 120)}
        </p>
      </div>
      {fixSuggestion && (
        <p className="text-[11px] text-warning font-bold tracking-tight pl-5">
          PROPOSAL: {fixSuggestion}
        </p>
      )}
    </div>
  );
};
