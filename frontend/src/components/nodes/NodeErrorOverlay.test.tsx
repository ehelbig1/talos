import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NodeErrorOverlay } from "./NodeErrorOverlay";

describe("NodeErrorOverlay", () => {
  it("renders nothing when no error is provided", () => {
    const { container } = render(<NodeErrorOverlay />);
    expect(container.firstChild).toBeNull();
  });

  it("renders error message and proposal when provided", () => {
    render(
      <NodeErrorOverlay
        error="Test error message"
        fixSuggestion="Test suggestion"
      />,
    );

    expect(screen.getByText("Test error message")).toBeInTheDocument();
    expect(screen.getByText("PROPOSAL: Test suggestion")).toBeInTheDocument();
  });

  it("truncates long error messages", () => {
    const longError = "a".repeat(200);
    render(<NodeErrorOverlay error={longError} />);

    const errorText = screen.getByText(/a{50,}/);
    expect(errorText.textContent?.length).toBeLessThanOrEqual(123); // 120 + potential padding/slop
  });
});
