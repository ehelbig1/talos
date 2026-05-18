/**
 * Hello World — minimal Talos module in TypeScript.
 *
 * Compile: talos compile --language typescript --world minimal-node hello-world.ts
 */
import { talosModule } from "@talos/sdk";

export default talosModule({
  world: "minimal-node",
  run: (data) => {
    const name = (data.name as string) ?? data.input?.toString() ?? "World";
    return {
      greeting: `Hello, ${name}!`,
      source: "typescript-sdk",
    };
  },
});
