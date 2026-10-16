import { describe, it, expect } from "vitest";
import { render, screen } from "@/test-utils";
import { StatusDot, STATUS_BORDER } from "./NodeStatus";

describe("NodeStatus", () => {
  it("renders correctly for idle status", () => {
    render(<StatusDot status="idle" />);
    const dot = screen.getByLabelText("Status: idle");
    expect(dot).toBeInTheDocument();
    expect(dot).toHaveClass("bg-muted-foreground/30");
    expect(dot).not.toHaveClass("animate-status-pulse");
  });

  it("renders with pulse for running status", () => {
    const { container } = render(<StatusDot status="running" />);
    const dot = container.querySelector(".animate-status-pulse");
    expect(dot).toBeInTheDocument();
    expect(dot).toHaveClass("bg-info");
  });

  it("renders correctly for failed status", () => {
    const { container } = render(<StatusDot status="failed" />);
    const dot = container.querySelector(".bg-destructive");
    expect(dot).toBeInTheDocument();
  });

  it("exports correct border styles", () => {
    expect(STATUS_BORDER.running).toBe("border-l-info");
    expect(STATUS_BORDER.failed).toBe("border-l-destructive");
  });
});
