import React from "react";
import { Box, Zap } from "lucide-react";

interface ResourceStatsProps {
  nodeCount: number;
  edgeCount: number;
}

export function ResourceStats({ nodeCount, edgeCount }: ResourceStatsProps) {
  return (
    <div className="flex items-center gap-4 h-11 rounded-2xl bg-surface-4/40 border border-white/5">
      <div className="flex items-center gap-2 group/node-stat px-4">
        <Box className="w-3 h-3 text-primary transition-transform" />
        <div className="flex flex-col items-start">
          <span className="text-xs font-semibold text-white leading-none">
            {nodeCount}
          </span>
          <span className="text-2xs font-semibold text-muted-foreground/70 uppercase tracking-wider mt-0.5">
            Nodes
          </span>
        </div>
      </div>
      <div className="w-[1px] h-4 bg-white/5" />
      <div className="flex items-center gap-2 group/edge-stat px-4">
        <Zap className="w-3 h-3 text-indigo-400 transition-transform" />
        <div className="flex flex-col items-start">
          <span className="text-xs font-semibold text-white leading-none">
            {edgeCount}
          </span>
          <span className="text-2xs font-semibold text-muted-foreground/70 uppercase tracking-wider mt-0.5">
            Edges
          </span>
        </div>
      </div>
    </div>
  );
}
