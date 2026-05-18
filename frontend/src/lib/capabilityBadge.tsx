/**
 * WASM Capability World visual configuration.
 *
 * Maps each `CapabilityWorld` string (as serialized by the backend's
 * `wit_inspector::CapabilityWorld`) to an icon, accent color, human-readable
 * label, tier level, and short description.
 */
import {
  Shield,
  Globe,
  Network,
  Lock,
  HardDrive,
  Mail,
  Layers,
  Database,
  Scale,
  Bot,
  Crown,
  HelpCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export interface CapabilityVisuals {
  /** Lucide icon component */
  icon: LucideIcon;
  /** Tailwind text color class */
  color: string;
  /** Tailwind bg color class (low opacity) */
  bgColor: string;
  /** Tailwind border color class */
  borderColor: string;
  /** Human-readable label */
  label: string;
  /** Privilege tier (T0 = sandboxed, T5 = full access) */
  tier: number;
  /** Tier label string */
  tierLabel: string;
  /** Short description of what this world can do */
  description: string;
}

const CAPABILITY_MAP: Record<string, CapabilityVisuals> = {
  minimal: {
    icon: Shield,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/20",
    label: "Minimal",
    tier: 0,
    tierLabel: "T0",
    description:
      "Pure computation — logging, JSON, datetime, crypto. No outbound I/O.",
  },
  http: {
    icon: Globe,
    color: "text-sky-400",
    bgColor: "bg-sky-500/10",
    borderColor: "border-sky-500/20",
    label: "HTTP",
    tier: 1,
    tierLabel: "T1",
    description: "Outbound HTTP, webhooks, GraphQL, email, state, templates.",
  },
  network: {
    icon: Network,
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/20",
    label: "Network",
    tier: 2,
    tierLabel: "T2",
    description: "All HTTP capabilities plus raw TCP/UDP sockets.",
  },
  secrets: {
    icon: Lock,
    color: "text-amber-400",
    bgColor: "bg-amber-500/10",
    borderColor: "border-amber-500/20",
    label: "Secrets Vault",
    tier: 3,
    tierLabel: "T3",
    description: "Network access + read-only secrets vault.",
  },
  filesystem: {
    icon: HardDrive,
    color: "text-orange-400",
    bgColor: "bg-orange-500/10",
    borderColor: "border-orange-500/20",
    label: "Filesystem",
    tier: 3,
    tierLabel: "T3",
    description: "Network access + sandboxed file I/O.",
  },
  messaging: {
    icon: Mail,
    color: "text-pink-400",
    bgColor: "bg-pink-500/10",
    borderColor: "border-pink-500/20",
    label: "Messaging",
    tier: 3,
    tierLabel: "T3",
    description: "Network access + NATS pub/sub messaging.",
  },
  cache: {
    icon: Layers,
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/10",
    borderColor: "border-cyan-500/20",
    label: "Cache",
    tier: 3,
    tierLabel: "T3",
    description: "Network access + Redis distributed cache.",
  },
  database: {
    icon: Database,
    color: "text-violet-400",
    bgColor: "bg-violet-500/10",
    borderColor: "border-violet-500/20",
    label: "Database",
    tier: 4,
    tierLabel: "T4",
    description: "Network + secrets + direct PostgreSQL access.",
  },
  governance: {
    icon: Scale,
    color: "text-indigo-400",
    bgColor: "bg-indigo-500/10",
    borderColor: "border-indigo-500/20",
    label: "Governance",
    tier: 3,
    tierLabel: "T3",
    description: "Network + human-in-the-loop approvals.",
  },
  agent: {
    icon: Bot,
    color: "text-fuchsia-400",
    bgColor: "bg-fuchsia-500/10",
    borderColor: "border-fuchsia-500/20",
    label: "Agent",
    tier: 4,
    tierLabel: "T4",
    description: "Secrets + LLM + memory + governance + orchestration.",
  },
  trusted: {
    icon: Crown,
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/20",
    label: "Full Access",
    tier: 5,
    tierLabel: "T5",
    description:
      "Full platform capabilities — secrets, files, cache, messaging, DB.",
  },
  unknown: {
    icon: HelpCircle,
    color: "text-gray-400",
    bgColor: "bg-gray-500/10",
    borderColor: "border-gray-500/20",
    label: "Unknown",
    tier: -1,
    tierLabel: "?",
    description: "Not a recognised Talos component.",
  },
};

/** Default fallback for unrecognised world strings. */
const FALLBACK: CapabilityVisuals = CAPABILITY_MAP.unknown;

/**
 * Look up visual configuration for a given capability world string.
 *
 * The `world` parameter is the `capabilityWorld` string from the backend
 * (e.g. "minimal", "http", "trusted").
 */
export function getCapabilityVisuals(world?: string): CapabilityVisuals {
  if (!world || typeof world !== "string") return FALLBACK;

  // 1. Clean the string (lowercase + trim)
  let key = world.toLowerCase().trim();

  // 2. Strip common suffixes like "-node" or "-world"
  key = key.replace(/-(node|world|world-node)$/, "");

  // 3. Map common aliases to our internal keys
  const aliases: Record<string, string> = {
    automation: "trusted",
    full: "trusted",
    all: "trusted",
    rest: "http",
    web: "http",
  };

  const finalKey = aliases[key] || key;

  return CAPABILITY_MAP[finalKey] ?? FALLBACK;
}

/**
 * Returns the tier color ring class for embedding in a node.
 * Uses a ring instead of background to layer nicely over the node surface.
 */
export function getTierRingColor(world?: string): string {
  const v = getCapabilityVisuals(world);
  return v.borderColor;
}
