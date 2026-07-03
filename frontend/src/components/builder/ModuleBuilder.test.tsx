import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@/test-utils";
import { ModuleBuilder } from "./ModuleBuilder";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

describe("ModuleBuilder", () => {
  const mockOnClose = vi.fn();
  const mockOnModuleCreated = vi.fn();

  it("renders correctly when open", () => {
    render(
      <ModuleBuilder
        open={true}
        onClose={mockOnClose}
        onModuleCreated={mockOnModuleCreated}
      />,
    );
    expect(screen.getByText("Strategic Module Architect")).toBeInTheDocument();
  });

  it("calls onClose when close button is clicked", async () => {
    // Setup MSW to return an empty template library
    server.use(
      http.post("/graphql", () => {
        return HttpResponse.json({
          data: {
            nodeTemplates: [],
          },
        });
      }),
    );

    render(
      <ModuleBuilder
        open={true}
        onClose={mockOnClose}
        onModuleCreated={mockOnModuleCreated}
      />,
    );

    const closeButton = screen.getByTitle(/close/i);
    fireEvent.click(closeButton);
    expect(mockOnClose).toHaveBeenCalled();
  });

  it("displays template library initially", async () => {
    render(
      <ModuleBuilder
        open={true}
        onClose={mockOnClose}
        onModuleCreated={mockOnModuleCreated}
      />,
    );

    expect(screen.getByText(/Initializing Library.../i)).toBeInTheDocument();
  });
});
