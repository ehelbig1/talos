import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { TestRhaiModal } from "./TestRhaiModal";

// Mock testRhaiExpression
vi.mock("@/lib/graphqlClient", () => ({
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

    expect(screen.getByText(/Test Rhai Expression/i)).toBeInTheDocument();
    expect(screen.getByText(/ctx.value/i)).toBeInTheDocument();
  });

  it("calls testRhaiExpression and shows result", async () => {
    const { testRhaiExpression } = await import("@/lib/graphqlClient");
    vi.mocked(testRhaiExpression).mockResolvedValueOnce({
      success: true,
      output: "42",
    });

    render(
      <TestRhaiModal open={true} onOpenChange={mockOnOpenChange} script="42" />,
    );

    const runButton = screen.getByRole("button", { name: /Run Test/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(screen.getByText(/Output/i)).toBeInTheDocument();
      // Use test ID or specific element type for output
      const outputs = screen.getAllByText("42");
      const output = outputs.find((el) => el.tagName === "PRE");
      expect(output).toBeInTheDocument();
    });
  });

  it("shows error when test fails", async () => {
    const { testRhaiExpression } = await import("@/lib/graphqlClient");
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

    const runButton = screen.getByRole("button", { name: /Run Test/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      // Find the "Error" label specifically
      const errorLabels = screen.getAllByText(/Error/i);
      const errorLabel = errorLabels.find((el) => el.textContent === "Error");
      expect(errorLabel).toBeInTheDocument();

      const errorDiv = screen.getByText(/Syntax Error/i);
      expect(errorDiv).toBeInTheDocument();
    });
  });
});
