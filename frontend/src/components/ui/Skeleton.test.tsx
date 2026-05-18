import React from "react";
import { render, screen } from "../../test-utils";
import {
  SkeletonLine,
  SkeletonBlock,
  SkeletonCard,
  SkeletonInspector,
} from "./Skeleton";
import { describe, it, expect } from "vitest";

describe("Skeleton Components", () => {
  it("renders SkeletonLine with default props", () => {
    render(<SkeletonLine />);
    const skeleton = document.querySelector(".animate-shimmer");
    expect(skeleton).toBeInTheDocument();
    expect(skeleton).toHaveClass("w-full");
  });

  it("renders SkeletonLine with custom width", () => {
    render(<SkeletonLine width="w-1/2" />);
    const skeleton = document.querySelector(".animate-shimmer");
    expect(skeleton).toHaveClass("w-1/2");
  });

  it("renders SkeletonBlock with custom height", () => {
    render(<SkeletonBlock height="h-32" />);
    const skeleton = document.querySelector(".animate-shimmer");
    expect(skeleton).toHaveClass("h-32");
  });

  it("renders SkeletonCard", () => {
    const { container } = render(<SkeletonCard />);
    const elements = container.querySelectorAll(".animate-shimmer");
    expect(elements.length).toBeGreaterThan(0);
  });

  it("renders SkeletonInspector and is findable by test-id", () => {
    render(<SkeletonInspector />);
    expect(screen.getByTestId("skeleton-inspector")).toBeInTheDocument();
  });
});
