import { render, screen, fireEvent } from "@testing-library/react";
import { KeyboardShortcutsHelp } from "../KeyboardShortcutsHelp";

describe("KeyboardShortcutsHelp", () => {
  it("opens and displays shortcut categories", () => {
    render(<KeyboardShortcutsHelp />);
    // Initial button should be present
    const openBtn = screen.getByRole("button", { name: /keyboard shortcuts/i });
    expect(openBtn).toBeInTheDocument();
    fireEvent.click(openBtn);

    // After opening, dialog overlay should appear
    const dialogTitle = screen.getByText(/keyboard shortcuts/i);
    expect(dialogTitle).toBeInTheDocument();

    // Verify category headings are rendered
    expect(screen.getAllByText(/navigation/i)).toHaveLength(1);
    expect(screen.getAllByText(/actions/i)).toHaveLength(1);

    // Ensure the dialog can be closed by clicking the backdrop
    const dialogElement = screen.getByRole("dialog");
    fireEvent.click(dialogElement);

    expect(screen.queryByText(/navigation/i)).toBeNull();
  });
});
