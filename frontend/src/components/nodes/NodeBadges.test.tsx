import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NodeBadges, getSystemNodeStyle } from "./NodeBadges";
import { RotateCw, Zap } from "lucide-react";

describe("NodeBadges", () => {
  it("renders system node badge correctly", () => {
    const { container } = render(<NodeBadges systemNodeKind="ForEach" />);
    // The badge says the kind in words, never the wire name
    expect(screen.getByText("For each item")).toBeInTheDocument();
    // Check for the Lucide icon SVG presence
    expect(container.querySelector("svg")).toBeInTheDocument();
  });

  it("renders join mode for FanIn", () => {
    render(<NodeBadges systemNodeKind="FanIn" joinMode="wait_all" />);
    expect(screen.getByText("Join branches · wait_all")).toBeInTheDocument();
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

  it("does not repeat a title that already says the kind", () => {
    const { container } = render(
      <NodeBadges systemNodeKind="ForEach" nodeLabel="For each item" />,
    );
    expect(container.querySelector("div")).toBeNull();
    render(<NodeBadges systemNodeKind="ForEach" nodeLabel="Per customer" />);
    expect(screen.getByText("For each item")).toBeInTheDocument();
  });

  it("shows a kind the editor cannot add by its wire name", () => {
    render(<NodeBadges systemNodeKind="Loop" />);
    expect(screen.getByText("Loop")).toBeInTheDocument();
  });
});
