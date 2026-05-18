/**
 * Capability worlds — match the worlds defined in wit/talos.wit.
 */
export const WORLD_MINIMAL = "minimal-node" as const;
export const WORLD_HTTP = "http-node" as const;
export const WORLD_LLM = "llm-node" as const;
export const WORLD_NETWORK = "network-node" as const;
export const WORLD_SECRETS = "secrets-node" as const;
export const WORLD_FILESYSTEM = "filesystem-node" as const;
export const WORLD_MESSAGING = "messaging-node" as const;
export const WORLD_CACHE = "cache-node" as const;
export const WORLD_GOVERNANCE = "governance-node" as const;
export const WORLD_DATABASE = "database-node" as const;
export const WORLD_AGENT = "agent-node" as const;
export const WORLD_AUTOMATION = "automation-node" as const;

export type CapabilityWorld =
  | typeof WORLD_MINIMAL
  | typeof WORLD_HTTP
  | typeof WORLD_LLM
  | typeof WORLD_NETWORK
  | typeof WORLD_SECRETS
  | typeof WORLD_FILESYSTEM
  | typeof WORLD_MESSAGING
  | typeof WORLD_CACHE
  | typeof WORLD_GOVERNANCE
  | typeof WORLD_DATABASE
  | typeof WORLD_AGENT
  | typeof WORLD_AUTOMATION;

/**
 * Parsed input to a Talos module.
 */
export interface TalosInput {
  /** Node configuration from the workflow graph. */
  config?: Record<string, unknown>;
  /** Upstream node output (inter-node data flow). */
  input?: unknown;
  /** Original trigger payload, available to all nodes. */
  __trigger_input__?: Record<string, unknown>;
  /** Top-level fields (config values merged to root). */
  [key: string]: unknown;
}

/**
 * Output from a Talos module.
 */
export type TalosOutput = Record<string, unknown>;

/**
 * Configuration for a Talos module definition.
 */
export interface TalosModuleConfig {
  /** Capability world for this module. */
  world: CapabilityWorld;
  /** The module entry point. Receives parsed JSON, returns output. */
  run: (data: TalosInput) => TalosOutput | Promise<TalosOutput>;
}
