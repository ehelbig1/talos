import React from "react";
import { Box, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

interface ResourceStatsProps {
  nodeCount: number;
  edgeCount: number;
}

export function ResourceStats({ nodeCount, edgeCount }: ResourceStatsProps) {
  return (
    <div className="flex items-center gap-4 h-11 rounded-2xl bg-surface-4/40 border border-white/5">
      <div className="flex items-center gap-2 group/node-stat px-4">
        <Box className="w-3 h-3 text-primary group-hover:scale-110 transition-transform" />
        <div className="flex flex-col items-start">
          <span className="text-[10px] font-black text-white leading-none">{nodeCount}</span>
          <span className="text-[7px] font-black text-muted-foreground/40 uppercase tracking-widest mt-0.5">Nodes</span>
        </div>
      </div>
      <div className="w-[1px] h-4 bg-white/5" />
      <div className="flex items-center gap-2 group/edge-stat px-4">
        <Zap className="w-3 h-3 text-indigo-400 group-hover:scale-110 transition-transform" />
        <div className="flex flex-col items-start">
          <span className="text-[10px] font-black text-white leading-none">{edgeCount}</span>
          <span className="text-[7px] font-black text-muted-foreground/40 uppercase tracking-widest mt-0.5">Edges</span>
        </div>
      </div>
    </div>
  );
}
