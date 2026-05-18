import { describe, it, expect } from "vitest";
import { formatSize, formatDate } from "../format";
import { getCategoryIcon, getCategoryColor } from "../categoryIcons";
import { getCapabilityVisuals, getTierRingColor } from "../capabilityBadge";
import {
  Database,
  Cpu,
  HardDrive,
  Network,
  Box,
  Shield,
  Globe,
  Crown,
  HelpCircle,
} from "lucide-react";

describe("format utilities", () => {
  it("formatSize should format bytes correctly", () => {
    expect(formatSize(500)).toBe("500 B");
    expect(formatSize(1024)).toBe("1.0 KB");
    expect(formatSize(1024 * 1024)).toBe("1.00 MB");
    expect(formatSize(1024 * 1024 * 1.5)).toBe("1.50 MB");
  });

  it("formatDate should format dates correctly", () => {
    expect(formatDate("")).toBe("");
    const date = "2024-01-01T12:00:00Z";
    const formatted = formatDate(date);
    expect(formatted).toContain("2024");
    // We don't check exact string due to locale differences in CI
    expect(typeof formatted).toBe("string");
    expect(formatted.length).toBeGreaterThan(0);
  });
});

describe("categoryIcons utilities", () => {
  it("getCategoryIcon returns correct icons", () => {
    expect(getCategoryIcon("data")).toBe(Database);
    expect(getCategoryIcon("AI")).toBe(Cpu);
    expect(getCategoryIcon("storage")).toBe(HardDrive);
    expect(getCategoryIcon("NETWORK")).toBe(Network);
    expect(getCategoryIcon("unknown")).toBe(Box);
    expect(getCategoryIcon()).toBe(Box);
  });

  it("getCategoryColor returns correct colors", () => {
    expect(getCategoryColor("data")).toBe("text-blue-400");
    expect(getCategoryColor("AI")).toBe("text-purple-400");
    expect(getCategoryColor("storage")).toBe("text-amber-400");
    expect(getCategoryColor("NETWORK")).toBe("text-green-400");
    expect(getCategoryColor("unknown")).toBe("text-gray-400");
    expect(getCategoryColor()).toBe("text-gray-400");
  });
});

describe("capabilityBadge utilities", () => {
  it("getCapabilityVisuals returns correct visuals", () => {
    expect(getCapabilityVisuals("minimal").label).toBe("Minimal");
    expect(getCapabilityVisuals("minimal").icon).toBe(Shield);

    expect(getCapabilityVisuals("http").label).toBe("HTTP");
    expect(getCapabilityVisuals("http").icon).toBe(Globe);

    expect(getCapabilityVisuals("trusted").label).toBe("Full Access");
    expect(getCapabilityVisuals("trusted").icon).toBe(Crown);

    // Aliases
    expect(getCapabilityVisuals("automation").label).toBe("Full Access");
    expect(getCapabilityVisuals("web").label).toBe("HTTP");

    // Suffix stripping
    expect(getCapabilityVisuals("http-node").label).toBe("HTTP");
    expect(getCapabilityVisuals("minimal-world").label).toBe("Minimal");

    // Fallback
    expect(getCapabilityVisuals("unknown").icon).toBe(HelpCircle);
    expect(getCapabilityVisuals(undefined).icon).toBe(HelpCircle);
  });

  it("getTierRingColor returns correct border color", () => {
    expect(getTierRingColor("minimal")).toBe("border-emerald-500/20");
    expect(getTierRingColor("trusted")).toBe("border-yellow-500/20");
    expect(getTierRingColor()).toBe("border-gray-500/20");
  });
});
