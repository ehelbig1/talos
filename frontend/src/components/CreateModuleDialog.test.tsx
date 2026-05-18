import React from "react";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import { CreateModuleDialog } from "./CreateModuleDialog";
import { describe, it, expect, vi } from "vitest";

describe("CreateModuleDialog", () => {
  const mockOnModuleCreated = vi.fn();
  const mockOnClose = vi.fn();

  it("renders loading state initially", async () => {
    render(
      <CreateModuleDialog
        onModuleCreated={mockOnModuleCreated}
        onClose={mockOnClose}
      />,
    );
    expect(screen.getByText(/Loading templates.../i)).toBeInTheDocument();
  });

  it("renders template list after loading", async () => {
    render(
      <CreateModuleDialog
        onModuleCreated={mockOnModuleCreated}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("HTTP Request")).toBeInTheDocument();
    });

    expect(screen.getByText("Send an HTTP request")).toBeInTheDocument();
  });

  it("navigates to configuration step when a template is selected", async () => {
    render(
      <CreateModuleDialog
        onModuleCreated={mockOnModuleCreated}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("HTTP Request")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("HTTP Request"));

    expect(screen.getByText("Configure Module")).toBeInTheDocument();
    expect(screen.getByLabelText("Module Name")).toBeInTheDocument();
    expect(screen.getByDisplayValue("HTTP Request")).toBeInTheDocument(); // Auto-suggested name
  });

  it("calls onModuleCreated and onClose after successful creation", async () => {
    render(
      <CreateModuleDialog
        onModuleCreated={mockOnModuleCreated}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      fireEvent.click(screen.getByText("HTTP Request"));
    });

    const createButton = screen.getByText("Create Module");
    fireEvent.click(createButton);

    await waitFor(() => {
      expect(mockOnModuleCreated).toHaveBeenCalledWith(
        "new-module-id",
        "HTTP Request",
        expect.objectContaining({ url: "https://api.example.com" }),
        "http",
      );
      expect(mockOnClose).toHaveBeenCalled();
    });
  });

  it("allows filtering templates by search query", async () => {
    render(
      <CreateModuleDialog
        onModuleCreated={mockOnModuleCreated}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("HTTP Request")).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText("Search templates...");
    fireEvent.change(searchInput, { target: { value: "Non-existent" } });

    expect(
      screen.getByText(/No templates found matching your search/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("HTTP Request")).not.toBeInTheDocument();
  });
});
