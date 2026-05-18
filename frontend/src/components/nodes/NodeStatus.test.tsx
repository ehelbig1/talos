import { describe, it, expect } from "vitest";
import { render, screen } from "@/test-utils";
import { StatusDot, STATUS_BORDER } from "./NodeStatus";

describe("NodeStatus", () => {
  it("renders correctly for idle status", () => {
    const { container } = render(<StatusDot status="idle" />);
    const dot = container.querySelector(".bg-\\[\\#4A4D5E\\]");
    expect(dot).toBeInTheDocument();
    expect(dot).not.toHaveClass("animate-status-pulse");
  });

  it("renders with pulse for running status", () => {
    const { container } = render(<StatusDot status="running" />);
    const dot = container.querySelector(".animate-status-pulse");
    expect(dot).toBeInTheDocument();
    expect(dot).toHaveClass("bg-blue-500");
  });

  it("renders correctly for failed status", () => {
    const { container } = render(<StatusDot status="failed" />);
    const dot = container.querySelector(".bg-red-500");
    expect(dot).toBeInTheDocument();
  });

  it("exports correct border styles", () => {
    expect(STATUS_BORDER.running).toBe("border-l-blue-500");
    expect(STATUS_BORDER.failed).toBe("border-l-red-500");
  });
});
