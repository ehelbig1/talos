import { render, screen, fireEvent } from "@testing-library/react";
import { Dialog } from "../dialog";
import { vi } from "vitest";

describe("Dialog Component", () => {
  it("renders when open", () => {
    render(
      <Dialog open={true} onClose={() => {}} title="Test Dialog">
        <div>Content</div>
      </Dialog>,
    );
    expect(screen.getByText("Test Dialog")).toBeInTheDocument();
    expect(screen.getByText("Content")).toBeInTheDocument();
  });

  it("does not render when closed", () => {
    const { container } = render(
      <Dialog open={false} onClose={() => {}}>
        <div>Content</div>
      </Dialog>,
    );
    expect(container.firstChild).toBeNull();
  });

  it("calls onClose when clicking backdrop", () => {
    const onClose = vi.fn();
    render(
      <Dialog open={true} onClose={onClose}>
        <div>Content</div>
      </Dialog>,
    );

    // The dialog backdrop is the outermost div with role="dialog"
    fireEvent.click(screen.getByRole("dialog"));
    expect(onClose).toHaveBeenCalled();
  });

  it("calls onClose when clicking close button", () => {
    const onClose = vi.fn();
    render(
      <Dialog open={true} onClose={onClose} title="Title">
        <div>Content</div>
      </Dialog>,
    );

    fireEvent.click(screen.getByTitle("Close"));
    expect(onClose).toHaveBeenCalled();
  });

  it("calls onClose when pressing Escape", () => {
    const onClose = vi.fn();
    render(
      <Dialog open={true} onClose={onClose}>
        <div>Content</div>
      </Dialog>,
    );

    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});
