import { describe, it, expect } from "vitest";
import {
  SEVERITY_STYLE,
  ASSIGNABLE_SEVERITIES,
  severityStyle,
} from "./alertSeverity";

describe("alertSeverity", () => {
  it("returns the matching style for a known severity", () => {
    expect(severityStyle("critical")).toBe(SEVERITY_STYLE.critical);
    expect(severityStyle("noise")).toBe(SEVERITY_STYLE.noise);
  });

  it("falls back to the unclassified style for unknown/null/undefined input", () => {
    expect(severityStyle("bogus")).toBe(SEVERITY_STYLE.unclassified);
    expect(severityStyle(null)).toBe(SEVERITY_STYLE.unclassified);
    expect(severityStyle(undefined)).toBe(SEVERITY_STYLE.unclassified);
  });

  it("excludes unclassified from the assignable list", () => {
    expect(ASSIGNABLE_SEVERITIES).toHaveLength(6);
    expect(ASSIGNABLE_SEVERITIES).not.toContain("unclassified");
  });
});
