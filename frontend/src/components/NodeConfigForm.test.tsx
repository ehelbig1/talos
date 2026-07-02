import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NodeConfigForm } from "./NodeConfigForm";
import { analyzeRhai } from "@/lib/graphqlApi";

// Mock analyzeRhai
vi.mock("@/lib/graphqlApi", () => ({
  analyzeRhai: vi.fn(),
}));

describe("NodeConfigForm", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("renders HTTP request form fields", () => {
    const config = { method: "POST", url: "https://api.test.com" };
    const onChange = vi.fn();

    render(
      <NodeConfigForm
        type="http-request"
        config={config}
        onChange={onChange}
      />,
    );

    // Labels were reworded in the redesign; assert on the new copy + controls.
    expect(screen.getByText(/Request Method/i)).toBeInTheDocument();
    expect(screen.getByText(/Target Endpoint URL/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue("POST")).toBeInTheDocument();
    expect(
      screen.getByDisplayValue("https://api.test.com"),
    ).toBeInTheDocument();
  });

  it("calls onChange when URL is changed", () => {
    const config = { method: "GET", url: "" };
    const onChange = vi.fn();

    render(
      <NodeConfigForm
        type="http-request"
        config={config}
        onChange={onChange}
      />,
    );

    const urlInput = screen.getByPlaceholderText(/api\.example\.com/i);
    fireEvent.change(urlInput, { target: { value: "https://new.url" } });

    expect(onChange).toHaveBeenCalledWith({
      ...config,
      url: "https://new.url",
    });
  });

  it("renders LLM inference form fields", () => {
    const config = { model: "gpt-4", prompt: "Hello world" };
    const onChange = vi.fn();

    render(
      <NodeConfigForm
        type="llm-inference"
        config={config}
        onChange={onChange}
      />,
    );

    expect(screen.getByText(/Compute Model Architecture/i)).toBeInTheDocument();
    expect(screen.getByText(/Prompt Directive/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue("gpt-4")).toBeInTheDocument();
    expect(screen.getByDisplayValue("Hello world")).toBeInTheDocument();
  });

  it("renders ForEach form and handles Rhai validation", async () => {
    const config = { input_path: "items", output_handle: "item" };
    const onChange = vi.fn();

    vi.mocked(analyzeRhai).mockResolvedValue({
      success: true,
      errors: [],
      warnings: [],
    });

    const { rerender } = render(
      <NodeConfigForm type="foreach" config={config} onChange={onChange} />,
    );

    expect(screen.getByText(/Collection Source \(Rhai\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Iteration Memory Handle/i)).toBeInTheDocument();

    // input_path = "items" → its current value identifies the Collection Source input.
    const inputPath = screen.getByDisplayValue("items");
    fireEvent.change(inputPath, { target: { value: "ctx.results" } });

    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ input_path: "ctx.results" }),
    );

    // Rerender with new config to trigger useEffect
    rerender(
      <NodeConfigForm
        type="foreach"
        config={{ ...config, input_path: "ctx.results" }}
        onChange={onChange}
      />,
    );

    // Check for validation trigger (debounced 500ms)
    await waitFor(
      () => {
        expect(analyzeRhai).toHaveBeenCalledWith({ script: "ctx.results" });
      },
      { timeout: 2000 },
    );
  });

  it("shows error when Rhai validation fails", async () => {
    const config = { input_path: "invalid[" };
    const onChange = vi.fn();

    vi.mocked(analyzeRhai).mockResolvedValue({
      success: false,
      errors: [
        {
          message: "Syntax error",
          line: 1,
          column: 8,
          endLine: 1,
          endColumn: 9,
          severity: "error",
        },
      ],
      warnings: [],
    });

    render(
      <NodeConfigForm type="foreach" config={config} onChange={onChange} />,
    );

    await waitFor(
      () => {
        expect(screen.getByText(/Syntax error/i)).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
  });

  it("renders fallback JSON editor for unknown types", () => {
    const config = { custom: "value" };
    const onChange = vi.fn();

    render(
      <NodeConfigForm type="unknown" config={config} onChange={onChange} />,
    );

    // Fallback editor's label was reworded to "Advanced Object Configuration".
    expect(
      screen.getByText(/Advanced Object Configuration/i),
    ).toBeInTheDocument();
    const textarea = screen.getByRole("textbox") as HTMLTextAreaElement;
    expect(textarea).toBeInTheDocument();
    expect(textarea.value).toContain("custom");
  });

  it("shows JSON parse error in fallback editor", () => {
    const config = {};
    const onChange = vi.fn();

    render(
      <NodeConfigForm type="unknown" config={config} onChange={onChange} />,
    );

    const textarea = screen.getByRole("textbox");
    fireEvent.change(textarea, { target: { value: "{ invalid json }" } });

    // Parse failures now surface under the "SCHEMA_VIOLATION" banner.
    expect(screen.getByText(/SCHEMA_VIOLATION/i)).toBeInTheDocument();
  });
});
