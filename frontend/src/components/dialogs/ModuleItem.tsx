import React from "react";
import type { WasmModule } from "@/hooks/useAddExistingNode";
import { Badge } from "@/components/ui/badge";
import { formatSize, formatDate } from "@/lib/format";
import { getCapabilityVisuals } from "@/lib/capabilityBadge";
import { cn } from "@/lib/utils";
import { HardDrive, Calendar, Fingerprint, Check } from "lucide-react";

type Props = {
  module: WasmModule;
  selected: boolean;
  onSelect: (id: string) => void;
};

export const ModuleItem: React.FC<Props> = ({ module, selected, onSelect }) => {
  // Use shared format helpers

  return (
    <div
      key={module.id}
      onClick={() => onSelect(module.id)}
      className={cn(
        "group cursor-pointer p-5 rounded-2xl border transition-ui relative overflow-hidden",
        selected
          ? "bg-primary/10 border-primary/40"
          : "bg-surface-4/40 border-white/5 hover:border-white/20 hover:bg-surface-4/60",
      )}
    >
      <div className="flex justify-between items-start">
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                "w-5 h-5 rounded-full border flex items-center justify-center transition-ui",
                selected
                  ? "border-primary bg-primary"
                  : "border-white/10 bg-surface-4",
              )}
            >
              {selected && <Check className="w-3 h-3 text-white" />}
            </div>
            <span
              className={cn(
                "font-semibold text-xs transition-ui font-outfit leading-none",
                selected
                  ? "text-white"
                  : "text-muted-foreground/60 group-hover:text-white",
              )}
            >
              {module.name}
            </span>
          </div>

          <div className="ml-7 mt-2 flex flex-col gap-2">
            {module.capabilityWorld &&
              (() => {
                const vis = getCapabilityVisuals(module.capabilityWorld);
                return (
                  <div className="flex items-center gap-1.5">
                    <span
                      className={cn(
                        "text-2xs px-2 py-0.5 rounded-lg font-semibold border uppercase tracking-wider shadow-sm",
                        vis.bgColor,
                        vis.color,
                        vis.borderColor,
                      )}
                    >
                      {vis.tierLabel} {vis.label}
                    </span>
                  </div>
                );
              })()}

            <div className="flex items-center gap-5 text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60">
              <div className="flex items-center gap-2 group/meta">
                <HardDrive className="h-3.5 w-3.5 opacity-40 group-hover/meta:text-primary transition-ui" />
                <span className="group-hover/meta:text-muted-foreground/60 transition-ui">
                  {formatSize(module.sizeBytes)}
                </span>
              </div>
              <div className="flex items-center gap-2 group/meta">
                <Calendar className="h-3.5 w-3.5 opacity-40 group-hover/meta:text-primary transition-ui" />
                <span className="group-hover/meta:text-muted-foreground/60 transition-ui">
                  {formatDate(module.compiledAt)}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <Badge
            variant="outline"
            className="text-2xs font-mono font-bold text-muted-foreground/50 border-white/5 bg-surface-4/60 px-2 py-0.5 flex items-center gap-1.5 rounded-lg group-hover:border-primary/20 transition-ui"
          >
            <Fingerprint className="w-3 h-3 opacity-40" />
            {module.id.slice(0, 8).toUpperCase()}
          </Badge>
        </div>
      </div>
    </div>
  );
};
