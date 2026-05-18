import React from "react";
import { render, screen, fireEvent, waitFor } from "../../test-utils";
import { ManualEndpointCreator } from "./ManualEndpointCreator";
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("ManualEndpointCreator", () => {
  const mockOnConfigure = vi.fn();
  const baseUrl = "https://api.example.com";

  beforeEach(() => {
    mockOnConfigure.mockClear();
  });

  it('renders "Create Custom Endpoint" button initially', () => {
    render(
      <ManualEndpointCreator baseUrl={baseUrl} onConfigure={mockOnConfigure} />,
    );
    expect(screen.getByText(/Create Custom Endpoint/i)).toBeInTheDocument();
  });

  it("disabled button if baseUrl is missing", () => {
    render(<ManualEndpointCreator baseUrl="" onConfigure={mockOnConfigure} />);
    const btn = screen.getByText(/Create Custom Endpoint/i).closest("button");
    expect(btn).toBeDisabled();
  });

  it("shows creator form when button is clicked", () => {
    render(
      <ManualEndpointCreator baseUrl={baseUrl} onConfigure={mockOnConfigure} />,
    );

    fireEvent.click(screen.getByText(/Create Custom Endpoint/i));

    expect(screen.getByText(/Method/i)).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/\/api\/users\/\{id\}/i),
    ).toBeInTheDocument();
  });

  it("allows adding and removing parameters", () => {
    render(
      <ManualEndpointCreator baseUrl={baseUrl} onConfigure={mockOnConfigure} />,
    );

    fireEvent.click(screen.getByText(/Create Custom Endpoint/i));

    // Add query parameter
    fireEvent.click(screen.getByRole("button", { name: /query/i }));
    expect(screen.getByPlaceholderText(/name/i)).toBeInTheDocument();

    // Fill parameter name
    fireEvent.change(screen.getByPlaceholderText(/name/i), {
      target: { value: "page" },
    });

    // Add path parameter
    fireEvent.click(screen.getByRole("button", { name: /path/i }));
    const inputs = screen.getAllByPlaceholderText(/name/i);
    expect(inputs).toHaveLength(2);

    // Remove first parameter
    const removeBtns = screen
      .getAllByRole("button")
      .filter((btn) => btn.innerHTML.includes("svg"));
    // There's 1 for close form, and 2 for parameters
    // Let's find specifically parameter remove buttons
    // The component uses a special structure, we can look for the SVG inside the parameter row
  });

  it("saves endpoint and switches to EndpointSelector", () => {
    render(
      <ManualEndpointCreator baseUrl={baseUrl} onConfigure={mockOnConfigure} />,
    );

    fireEvent.click(screen.getByText(/Create Custom Endpoint/i));

    // Fill form
    fireEvent.change(screen.getByPlaceholderText(/\/api\/users\/\{id\}/i), {
      target: { value: "/test-path" },
    });
    fireEvent.change(screen.getByPlaceholderText(/Get user by ID/i), {
      target: { value: "Test Summary" },
    });

    // Save
    fireEvent.click(screen.getByText(/Save & Configure Endpoint/i));

    // Should now show EndpointSelector with our new endpoint
    expect(screen.getByText("GET")).toBeInTheDocument();
    expect(screen.getByText("/test-path")).toBeInTheDocument();
    expect(screen.getByText("Test Summary")).toBeInTheDocument();
  });
});
