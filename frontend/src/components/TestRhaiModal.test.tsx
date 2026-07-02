import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { TestRhaiModal } from "./TestRhaiModal";

// Mock testRhaiExpression
vi.mock("@/lib/graphqlApi", () => ({
  testRhaiExpression: vi.fn(),
}));

describe("TestRhaiModal", () => {
  const mockOnOpenChange = vi.fn();

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("renders when open is true", () => {
    render(
      <TestRhaiModal
        open={true}
        onOpenChange={mockOnOpenChange}
        script="ctx.value"
      />,
    );

    expect(screen.getByText(/Protocol Evaluation/i)).toBeInTheDocument();
    expect(screen.getByText(/ctx.value/i)).toBeInTheDocument();
  });

  it("calls testRhaiExpression and shows result", async () => {
    const { testRhaiExpression } = await import("@/lib/graphqlApi");
    vi.mocked(testRhaiExpression).mockResolvedValueOnce({
      success: true,
      output: "42",
    });

    render(
      <TestRhaiModal open={true} onOpenChange={mockOnOpenChange} script="42" />,
    );

    const runButton = screen.getByRole("button", {
      name: /Initiate Logic Test/i,
    });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(screen.getByText(/Execution Successful/i)).toBeInTheDocument();
      // The output is rendered inside a <pre> element
      const outputs = screen.getAllByText("42");
      const output = outputs.find((el) => el.tagName === "PRE");
      expect(output).toBeInTheDocument();
    });
  });

  it("shows error when test fails", async () => {
    const { testRhaiExpression } = await import("@/lib/graphqlApi");
    vi.mocked(testRhaiExpression).mockResolvedValueOnce({
      success: false,
      error: "Syntax Error",
    });

    render(
      <TestRhaiModal
        open={true}
        onOpenChange={mockOnOpenChange}
        script="invalid"
      />,
    );

    const runButton = screen.getByRole("button", {
      name: /Initiate Logic Test/i,
    });
    fireEvent.click(runButton);

    await waitFor(() => {
      // The failure state shows a "Critical Evaluation Failure" label
      expect(
        screen.getByText(/Critical Evaluation Failure/i),
      ).toBeInTheDocument();

      const errorDiv = screen.getByText(/Syntax Error/i);
      expect(errorDiv).toBeInTheDocument();
    });
  });
});
