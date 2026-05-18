/**
 * Capability world configuration for the Actor system.
 * A "capability world" defines the maximum WASM host interface an Actor's
 * workflows may use — it is the primary security boundary for Actors.
 */

export interface CapabilityConfig {
  /** Short, plain-English label shown on badges */
  label: string;
  /** One-liner shown in capability ladder (Create Actor step 2) */
  description: string;
  /** Full tooltip explaining trade-offs */
  tooltipDetail: string;
  /** What this world unlocks vs the one below it */
  unlocks: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  /** Privilege level 0 (lowest) → 5 (highest) */
  level: number;
}

export const CAPABILITY_WORLDS: Record<string, CapabilityConfig> = {
  "minimal-node": {
    label: "Compute only",
    description: "Pure logic — no network or I/O",
    tooltipDetail:
      "minimal-node: Can execute code, perform computations, and transform data. Cannot make any network requests, read vault secrets, or access external resources.",
    unlocks: "Rhai scripting, data transformation, JSON processing",
    textColor: "text-muted-foreground",
    bgColor: "bg-white/5",
    borderColor: "border-white/10",
    level: 0,
  },
  "http-node": {
    label: "HTTP requests",
    description: "Can make outbound HTTP calls",
    tooltipDetail:
      "http-node: Can make outbound HTTP requests, emit structured domain events, and consume SSE streams. Cannot read vault secrets, write to databases, or send autonomous messages.",
    unlocks: "Outbound HTTP, REST APIs, webhooks, events, SSE streams",
    textColor: "text-blue-400",
    bgColor: "bg-blue-400/10",
    borderColor: "border-blue-400/20",
    level: 1,
  },
  // Legacy alias — kept for backward compatibility with stored actor configs.
  // The canonical name is "http-node"; this alias renders identically.
  "standard-node": {
    label: "HTTP requests",
    description: "Can make outbound HTTP calls",
    tooltipDetail:
      "standard-node (alias for http-node): Can make outbound HTTP requests to external APIs.",
    unlocks: "Outbound HTTP, REST APIs, webhooks",
    textColor: "text-blue-400",
    bgColor: "bg-blue-400/10",
    borderColor: "border-blue-400/20",
    level: 1,
  },
  "network-node": {
    label: "Network access",
    description: "Full TCP/UDP network access",
    tooltipDetail:
      "network-node: Full TCP/UDP network access beyond HTTP. Cannot access vault secrets or write to external databases.",
    unlocks: "Raw TCP/UDP sockets, custom protocols",
    textColor: "text-teal-400",
    bgColor: "bg-teal-400/10",
    borderColor: "border-teal-400/20",
    level: 2,
  },
  "secrets-node": {
    label: "Vault access",
    description: "Can read encrypted vault secrets",
    tooltipDetail:
      "secrets-node: Can read encrypted vault secrets and supply them to modules at runtime. Cannot write to external databases.",
    unlocks: "Vault secrets, API key injection",
    textColor: "text-amber-400",
    bgColor: "bg-amber-400/10",
    borderColor: "border-amber-400/20",
    level: 3,
  },
  "governance-node": {
    label: "Governance",
    description: "Approval workflows and audit",
    tooltipDetail:
      "governance-node: Can trigger human-in-the-loop approval gates, write audit events, and manage governance policies.",
    unlocks: "Approval gates, audit trail, governance policies",
    textColor: "text-purple-400",
    bgColor: "bg-purple-400/10",
    borderColor: "border-purple-400/20",
    level: 3,
  },
  "messaging-node": {
    label: "Messaging",
    description: "NATS pub/sub messaging",
    tooltipDetail:
      "messaging-node: Can publish and subscribe to NATS message queues for async communication between workflows.",
    unlocks: "NATS pub/sub, async messaging",
    textColor: "text-indigo-400",
    bgColor: "bg-indigo-400/10",
    borderColor: "border-indigo-400/20",
    level: 3,
  },
  "filesystem-node": {
    label: "File I/O",
    description: "Read and write files",
    tooltipDetail:
      "filesystem-node: Can read and write files within the sandboxed filesystem. Cannot escape the WASM sandbox.",
    unlocks: "File read/write, temp storage",
    textColor: "text-cyan-400",
    bgColor: "bg-cyan-400/10",
    borderColor: "border-cyan-400/20",
    level: 3,
  },
  "cache-node": {
    label: "Cache access",
    description: "Redis and in-memory cache",
    tooltipDetail:
      "cache-node: Can read/write to Redis cache and in-memory cache stores for performance optimization.",
    unlocks: "Redis cache, in-memory KV store",
    textColor: "text-emerald-400",
    bgColor: "bg-emerald-400/10",
    borderColor: "border-emerald-400/20",
    level: 3,
  },
  "database-node": {
    label: "Database writes",
    description: "Can write to external databases",
    tooltipDetail:
      "database-node: Can read vault secrets and write to external databases. High privilege — scope this Actor's workflows carefully.",
    unlocks: "External DB reads and writes",
    textColor: "text-orange-400",
    bgColor: "bg-orange-400/10",
    borderColor: "border-orange-400/20",
    level: 4,
  },
  "agent-node": {
    label: "Agent",
    description: "LLM + secrets + memory + governance + orchestration",
    tooltipDetail:
      "agent-node: The recommended world for autonomous agents. Provides LLM tool use, secrets, vector embeddings, persistent agent memory, human approval gates, multi-agent orchestration, structured events, and SSE streaming — without filesystem, cache, messaging, database, or object storage access.",
    unlocks: "Agent memory, governance, orchestration, embeddings",
    textColor: "text-fuchsia-400",
    bgColor: "bg-fuchsia-400/10",
    borderColor: "border-fuchsia-400/20",
    level: 4,
  },
  "automation-node": {
    label: "Full access",
    description: "No capability restrictions",
    tooltipDetail:
      "automation-node: Full platform access — all host interfaces available. Use only for fully trusted automation workloads.",
    unlocks: "Everything — no restrictions",
    textColor: "text-red-400",
    bgColor: "bg-red-400/10",
    borderColor: "border-red-400/20",
    level: 5,
  },
  // Legacy alias — kept for backward compatibility with stored actor configs.
  // The canonical name is "automation-node"; this alias renders identically.
  "full-node": {
    label: "Full access",
    description: "No capability restrictions",
    tooltipDetail:
      "full-node (alias for automation-node): Full platform access — all host interfaces available.",
    unlocks: "Everything — no restrictions",
    textColor: "text-red-400",
    bgColor: "bg-red-400/10",
    borderColor: "border-red-400/20",
    level: 5,
  },
};

/**
 * The ordered capability ladder shown in the Create Actor flow.
 * Each step is a superset of the previous.
 */
export const CAPABILITY_LADDER: readonly string[] = [
  "minimal-node",
  "http-node",
  "network-node",
  "secrets-node",
  "governance-node",
  "messaging-node",
  "filesystem-node",
  "cache-node",
  "database-node",
  "agent-node",
  "automation-node",
];

export function getCapabilityConfig(world: string): CapabilityConfig {
  return (
    CAPABILITY_WORLDS[world] ?? {
      label: world.replace(/-node$/, ""),
      description: world,
      tooltipDetail: world,
      unlocks: "",
      textColor: "text-muted-foreground",
      bgColor: "bg-white/5",
      borderColor: "border-white/10",
      level: 0,
    }
  );
}

/**
 * Detect whether a workflow graph JSON contains an LLM node
 * with INJECT_CONTEXT enabled — making the owning Actor an "AI Actor".
 */
export function isAiWorkflow(graphJson: string): boolean {
  try {
    const graph = JSON.parse(graphJson);
    const nodes: unknown[] = graph?.nodes ?? [];
    return nodes.some((n) => {
      const node = n as Record<string, unknown>;
      const data = node.data as Record<string, unknown> | undefined;
      const nodeType = String(data?.type ?? node.type ?? "").toLowerCase();
      const isLlm =
        nodeType.includes("llm") ||
        nodeType.includes("claude") ||
        nodeType.includes("anthropic") ||
        nodeType.includes("llm_inference") ||
        nodeType.includes("inference");
      if (!isLlm) return false;
      // Check config for INJECT_CONTEXT flag
      const config = data?.config as Record<string, unknown> | undefined;
      return (
        config?.INJECT_CONTEXT === true ||
        config?.inject_context === true ||
        String(config?.INJECT_CONTEXT) === "true"
      );
    });
  } catch {
    return false;
  }
}
