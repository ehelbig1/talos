import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NodeBadges, getSystemNodeStyle } from "./NodeBadges";
import { RotateCw, Zap } from "lucide-react";

describe("NodeBadges", () => {
  it("renders system node badge correctly", () => {
    const { container } = render(<NodeBadges systemNodeKind="ForEach" />);
    // Implementation uses .toUpperCase() on the kind string
    expect(screen.getByText("FOREACH")).toBeInTheDocument();
    // Check for the Lucide icon SVG presence
    expect(container.querySelector("svg")).toBeInTheDocument();
  });

  it("renders join mode for FanIn", () => {
    render(<NodeBadges systemNodeKind="FanIn" joinMode="wait_all" />);
    expect(screen.getByText(/FANIN \(wait_all\)/)).toBeInTheDocument();
  });

  it("renders capability badges for WASM modules", () => {
    render(<NodeBadges capabilityWorld="http" />);
    expect(screen.getByTitle("HTTP Access")).toBeInTheDocument();
  });

  it("returns correct system style", () => {
    const forEachStyle = getSystemNodeStyle("ForEach");
    expect(forEachStyle.color).toBe("text-blue-400");
    expect(forEachStyle.icon).toBe(RotateCw);

    const defaultStyle = getSystemNodeStyle("Unknown");
    expect(defaultStyle.icon).toBe(Zap);
  });
});
