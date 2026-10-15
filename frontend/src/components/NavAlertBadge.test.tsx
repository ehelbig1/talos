import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "../test-utils";
import { NavAlertBadge } from "./NavAlertBadge";

let digest: Array<{ severity: string; count: number }> = [];
vi.mock("@/generated/graphql", () => ({
  useOpsAlertsDigestQuery: vi.fn(() => ({
    data: {
      opsAlertsDigest: {
        activeBySeverity: digest,
        activeBySource: [],
        newLast24H: 0,
        reopenedActive: 0,
      },
    },
  })),
}));

describe("NavAlertBadge", () => {
  beforeEach(() => {
    digest = [];
  });

  it("draws nothing when no alert is active", () => {
    render(<NavAlertBadge />);
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("draws nothing when only noise is active", () => {
    digest = [{ severity: "noise", count: 7 }];
    render(<NavAlertBadge />);
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("counts active alerts, noise excluded, and links to the alerts page", () => {
    digest = [
      { severity: "high", count: 2 },
      { severity: "low", count: 1 },
      { severity: "noise", count: 9 },
    ];
    render(<NavAlertBadge />);
    const link = screen.getByRole("link", { name: "3 active alerts" });
    expect(link).toHaveAttribute("href", "/alerts");
    expect(link).toHaveTextContent("3");
    // the most urgent severity present colours the badge
    expect(link.className).toContain("text-warning");
  });

  it("takes the colour of a critical alert over the rest", () => {
    digest = [
      { severity: "critical", count: 1 },
      { severity: "medium", count: 4 },
    ];
    render(<NavAlertBadge />);
    expect(
      screen.getByRole("link", { name: "5 active alerts" }).className,
    ).toContain("text-destructive");
  });
});
