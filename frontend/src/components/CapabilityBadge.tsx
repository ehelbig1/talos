import { cn } from "@/lib/utils";
import { getCapabilityConfig } from "@/lib/capabilityConfig";

/**
 * The one chip that names a capability world — on an actor card, an actor's
 * summary, a module row and a node's inspector. It shows the world's plain
 * label ("Network access"), never the wire name ("network-node").
 */
export function CapabilityBadge({
  world,
  size = "sm",
  count,
  className,
}: {
  world: string;
  size?: "sm" | "md";
  /** A trailing count, e.g. the interfaces a node imports. Hidden when 0. */
  count?: number;
  className?: string;
}) {
  const cfg = getCapabilityConfig(world);
  return (
    <span
      title={cfg.tooltipDetail}
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border font-semibold",
        size === "sm" ? "text-2xs px-2 py-0.5" : "text-xs px-2.5 py-0.5",
        cfg.textColor,
        cfg.bgColor,
        cfg.borderColor,
        className,
      )}
    >
      {cfg.label}
      {count !== undefined && count > 0 && (
        <span className="opacity-60 tabular-nums">· {count}</span>
      )}
    </span>
  );
}
