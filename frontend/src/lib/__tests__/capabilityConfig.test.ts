import { describe, expect, it } from "vitest";
import { ceilingOptions, getCapabilityConfig } from "../capabilityConfig";

// Shaped like the backend's `capabilityWorldHierarchy`: the ceilings are a
// lattice, so a later world in the list is NOT necessarily permitted by an
// earlier-listed ceiling's successor. `talos-api`'s
// `capability_world_permits_tests` pins the real lists.
const hierarchy = [
  { name: "minimal-node", permits: ["minimal-node"] },
  { name: "http-node", permits: ["minimal-node", "http-node"] },
  { name: "llm-node", permits: ["minimal-node", "http-node", "llm-node"] },
  {
    name: "governance-node",
    permits: ["minimal-node", "http-node", "governance-node"],
  },
  {
    name: "database-node",
    permits: ["minimal-node", "http-node", "network-node", "database-node"],
  },
  {
    name: "network-node",
    permits: ["minimal-node", "http-node", "network-node"],
  },
];

const permittedOf = (ceiling: string | undefined) =>
  ceilingOptions(hierarchy, ceiling)
    .filter((o) => o.permitted)
    .map((o) => o.world);

describe("ceilingOptions", () => {
  it("reads the ceiling's own permits, not its position in the list", () => {
    // database-node is listed after governance-node and does not cover it.
    expect(permittedOf("database-node")).not.toContain("governance-node");
    expect(permittedOf("database-node")).toContain("network-node");
    // llm-node covers nothing listed after it.
    expect(permittedOf("llm-node")).toEqual([
      "minimal-node",
      "http-node",
      "llm-node",
    ]);
  });

  it("offers every served world, in the served order", () => {
    expect(ceilingOptions(hierarchy, "http-node").map((o) => o.world)).toEqual(
      hierarchy.map((n) => n.name),
    );
  });

  it("permits nothing for an unknown or not-yet-loaded ceiling", () => {
    expect(permittedOf("full-node")).toEqual([]);
    expect(permittedOf(undefined)).toEqual([]);
    expect(ceilingOptions([], "automation-node")).toEqual([]);
  });
});

describe("getCapabilityConfig", () => {
  it("has a label for llm-node and none for the retired aliases", () => {
    expect(getCapabilityConfig("llm-node").label).toBe("LLM inference");
    // Retired aliases fall through to the generic rendering.
    expect(getCapabilityConfig("full-node").label).toBe("full");
    expect(getCapabilityConfig("standard-node").label).toBe("standard");
  });
});
