import React from "react";
import { render, screen, fireEvent } from "../../../test-utils";
import { ConfigForm } from "../ConfigForm";
import { describe, it, expect, vi } from "vitest";

describe("ConfigForm", () => {
  const mockSchema = {
    type: "object",
    properties: {
      URL: { type: "string", title: "Endpoint URL" },
      METHOD: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
      RETRIES: { type: "number", minimum: 0, maximum: 5, title: "RETRIES" },
      ENABLED: { type: "boolean", title: "Active" },
    },
    required: ["URL"],
  };

  it("renders fields correctly based on schema", () => {
    const onChange = vi.fn();
    render(<ConfigForm schema={mockSchema} value={{}} onChange={onChange} />);

    expect(screen.getByText(/Endpoint URL/i)).toBeInTheDocument();
    expect(screen.getByText(/Advanced Settings/i)).toBeInTheDocument();
  });

  it("calls onChange when values change", () => {
    const onChange = vi.fn();
    render(<ConfigForm schema={mockSchema} value={{}} onChange={onChange} />);

    const urlInput = screen.getByRole("textbox");
    fireEvent.change(urlInput, {
      target: { value: "https://api.example.com" },
    });

    expect(onChange).toHaveBeenCalledWith({ URL: "https://api.example.com" });
  });

  it("shows validation error for invalid URL", async () => {
    const onChange = vi.fn();
    render(
      <ConfigForm
        schema={mockSchema}
        value={{ URL: "not-a-url" }}
        onChange={onChange}
      />,
    );

    const urlInput = screen.getByRole("textbox");
    fireEvent.change(urlInput, { target: { value: "invalid" } });

    expect(await screen.findByText(/Invalid URL format/i)).toBeInTheDocument();
  });

  it("displays smart suggestions when a known URL is entered", async () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <ConfigForm schema={mockSchema} value={{}} onChange={onChange} />,
    );

    const urlInput = screen.getByRole("textbox");
    fireEvent.change(urlInput, { target: { value: "https://api.github.com" } });

    rerender(
      <ConfigForm
        schema={mockSchema}
        value={{ URL: "https://api.github.com" }}
        onChange={onChange}
      />,
    );

    // Initial analysis happens on change.
    const viewSuggestions = await screen.findByText(/Smart Suggestion/i);
    expect(viewSuggestions).toBeInTheDocument();
  });
});
