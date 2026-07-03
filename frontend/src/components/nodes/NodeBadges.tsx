import React from "react";
import { cn } from "@/lib/utils";
import { getCapabilityVisuals } from "@/lib/capabilityBadge";
import type { LucideIcon } from "lucide-react";
import {
  RotateCw,
  Shuffle,
  Repeat,
  Hash,
  Package,
  Shield,
  Clock,
  Zap,
  Lock,
  Globe,
  Key,
  Database,
} from "lucide-react";

export function getSystemNodeStyle(kind?: string): {
  icon: LucideIcon;
  color: string;
  bg: string;
} {
  switch (kind) {
    case "ForEach":
      return {
        icon: RotateCw,
        color: "text-blue-400",
        bg: "border-blue-500/30",
      };
    case "FanIn":
      return {
        icon: Shuffle,
        color: "text-purple-400",
        bg: "border-purple-500/30",
      };
    case "WhileLoop":
      return {
        icon: Repeat,
        color: "text-cyan-400",
        bg: "border-cyan-500/30",
      };
    case "RepeatLoop":
      return {
        icon: Hash,
        color: "text-teal-400",
        bg: "border-teal-500/30",
      };
    case "SubWorkflow":
      return {
        icon: Package,
        color: "text-primary",
        bg: "border-primary/30",
      };
    case "ErrorHandler":
      return {
        icon: Shield,
        color: "text-destructive",
        bg: "border-destructive/30",
      };
    case "Wait":
      return {
        icon: Clock,
        color: "text-warning",
        bg: "border-warning/30",
      };
    case "Loop":
      return {
        icon: RotateCw,
        color: "text-cyan-400",
        bg: "border-cyan-500/30",
      };
    case "Collect":
      return {
        icon: Package,
        color: "text-indigo-400",
        bg: "border-indigo-500/30",
      };
    case "DynamicDispatch":
      return {
        icon: Shuffle,
        color: "text-orange-400",
        bg: "border-orange-500/30",
      };
    case "CapabilityDispatch":
      return {
        icon: Shield,
        color: "text-emerald-400",
        bg: "border-emerald-500/30",
      };
    default:
      return {
        icon: Zap,
        color: "text-primary",
        bg: "border-primary/30",
      };
  }
}

interface NodeBadgesProps {
  systemNodeKind?: string;
  capabilityWorld?: string;
  joinMode?: string;
}

export const NodeBadges: React.FC<NodeBadgesProps> = ({
  systemNodeKind,
  capabilityWorld,
  joinMode,
}) => {
  const systemStyle = systemNodeKind
    ? getSystemNodeStyle(systemNodeKind)
    : null;

  return (
    <>
      {systemNodeKind && systemStyle && (
        <div
          className={cn(
            "text-[9px] font-bold mt-2 px-1.5 py-0.5 rounded-md inline-flex items-center gap-1 border",
            systemStyle.color,
            "bg-black/40 border-current/20 backdrop-blur-sm",
          )}
        >
          <systemStyle.icon className="w-2.5 h-2.5" />
          {systemNodeKind.toUpperCase()}
          {systemNodeKind === "FanIn" && joinMode ? ` (${joinMode})` : ""}
        </div>
      )}

      {!systemNodeKind &&
        capabilityWorld &&
        (() => {
          const vis = getCapabilityVisuals(capabilityWorld);
          return (
            <div className="flex gap-1 mt-2">
              {vis.tier === 0 && (
                <div
                  title="Sandboxed"
                  className="w-4 h-4 flex items-center justify-center rounded bg-success/10 text-success border border-success/20"
                >
                  <Lock className="w-2.5 h-2.5" />
                </div>
              )}
              {vis.tier >= 1 && (
                <div
                  title="HTTP Access"
                  className="w-4 h-4 flex items-center justify-center rounded bg-blue-500/10 text-blue-400 border border-blue-500/20"
                >
                  <Globe className="w-2.5 h-2.5" />
                </div>
              )}
              {vis.tier >= 3 && (
                <div
                  title="Secrets"
                  className="w-4 h-4 flex items-center justify-center rounded bg-warning/10 text-warning border border-warning/20"
                >
                  <Key className="w-2.5 h-2.5" />
                </div>
              )}
              {vis.tier >= 4 && (
                <div
                  title="Database"
                  className="w-4 h-4 flex items-center justify-center rounded bg-destructive/10 text-destructive border border-destructive/20"
                >
                  <Database className="w-2.5 h-2.5" />
                </div>
              )}
            </div>
          );
        })()}
    </>
  );
};
