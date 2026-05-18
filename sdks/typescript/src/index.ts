/**
 * Talos TypeScript SDK — build WASM workflow modules in TypeScript.
 *
 * Modules are compiled to WebAssembly via ComponentizeJS and executed inside
 * Talos's capability-gated WASM sandbox with the same security guarantees as
 * Rust modules: fuel limits, memory caps, per-module secret scoping, and
 * tiered capability worlds.
 *
 * @example
 * ```ts
 * import { talosModule } from "@talos/sdk";
 *
 * export default talosModule({
 *   world: "http-node",
 *   run: async (data) => {
 *     return { greeting: `Hello, ${data.name ?? "World"}!` };
 *   },
 * });
 * ```
 */

export { talosModule } from "./module.js";
export type { TalosModuleConfig, TalosInput, TalosOutput } from "./types.js";
export {
  WORLD_MINIMAL,
  WORLD_HTTP,
  WORLD_LLM,
  WORLD_SECRETS,
  WORLD_DATABASE,
  WORLD_AUTOMATION,
  type CapabilityWorld,
} from "./types.js";
