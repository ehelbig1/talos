import React from "react";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import { AddExistingNodeDialog } from "./AddExistingNodeDialog";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "../../vitest.setup";
import { handlers } from "../mocks/handlers";

describe("AddExistingNodeDialog", () => {
  const mockOnNodeAdded = vi.fn();
  const mockOnClose = vi.fn();

  beforeEach(() => {
    mockOnNodeAdded.mockClear();
    mockOnClose.mockClear();
    server.use(...handlers);
  });

  it("renders loading state initially", async () => {
    render(
      <AddExistingNodeDialog
        onNodeAdded={mockOnNodeAdded}
        onClose={mockOnClose}
      />,
    );
    expect(screen.getByText(/Synchronizing Registry.../i)).toBeInTheDocument();
  });

  it("renders module list after loading", async () => {
    render(
      <AddExistingNodeDialog
        onNodeAdded={mockOnNodeAdded}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("Existing Module")).toBeInTheDocument();
    });
  });

  it("calls onNodeAdded and onClose when module is selected and added", async () => {
    render(
      <AddExistingNodeDialog
        onNodeAdded={mockOnNodeAdded}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("Existing Module")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Existing Module"));

    const addButton = screen.getByText("Initialize Node");
    fireEvent.click(addButton);

    await waitFor(() => {
      expect(mockOnNodeAdded).toHaveBeenCalledWith(
        "module-1",
        "Existing Module",
        expect.any(Object),
        "http",
        undefined,
        undefined,
        expect.arrayContaining(["wasi:http/types"]),
      );
      expect(mockOnClose).toHaveBeenCalled();
    });
  });

  it("filters modules by search query", async () => {
    render(
      <AddExistingNodeDialog
        onNodeAdded={mockOnNodeAdded}
        onClose={mockOnClose}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("Existing Module")).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(
      "FILTER OPERATIONAL BLUEPRINTS...",
    );
    fireEvent.change(searchInput, { target: { value: "Something Else" } });

    expect(screen.getByText(/No Blueprint Matches/i)).toBeInTheDocument();
    expect(screen.queryByText("Existing Module")).not.toBeInTheDocument();
  });
});
