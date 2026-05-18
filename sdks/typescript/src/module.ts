/**
 * Core module wrapper for Talos TypeScript modules.
 *
 * The `talosModule` function wraps a TypeScript handler as a Talos WASM
 * module entry point. It handles JSON serialization, error wrapping, and
 * world metadata embedding — mirroring the Rust `#[talos_module]` proc macro
 * and the Python `@talos_module` decorator.
 *
 * At compile time, `ComponentizeJS` reads the WIT world from the exported
 * `__TALOS_WORLD__` variable and links only the permitted capabilities.
 */

import type { TalosModuleConfig, TalosInput, TalosOutput } from "./types.js";

/**
 * Define a Talos module.
 *
 * @example
 * ```ts
 * import { talosModule } from "@talos/sdk";
 *
 * export default talosModule({
 *   world: "http-node",
 *   run: (data) => {
 *     const url = data.url ?? data.config?.url ?? "https://example.com";
 *     return { status: "ok", url };
 *   },
 * });
 * ```
 */
export function talosModule(config: TalosModuleConfig): {
  __TALOS_WORLD__: string;
  run: (inputJson: string) => string;
} {
  return {
    // Metadata for ComponentizeJS and the Talos compilation service
    __TALOS_WORLD__: config.world,

    // WASM entry point: run(input: string) -> result<string, string>
    run(inputJson: string): string {
      try {
        const data: TalosInput = inputJson ? JSON.parse(inputJson) : {};
        const resultOrPromise = config.run(data);

        // Handle sync and async results
        if (resultOrPromise instanceof Promise) {
          // Note: in the WASM sandbox, top-level await is not supported.
          // Async modules should use the async runtime provided by the host.
          throw new Error(
            "Async run() is not yet supported in the WASM sandbox. " +
              "Use synchronous code or wrap async calls with the host runtime.",
          );
        }

        return JSON.stringify(resultOrPromise);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : String(err);
        return JSON.stringify({
          __error: true,
          error: message,
        });
      }
    },
  };
}
