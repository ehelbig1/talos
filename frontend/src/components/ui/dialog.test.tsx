import { render, screen, fireEvent } from "@testing-library/react";
import { Dialog } from "./dialog";

describe("Dialog", () => {
  it("renders nothing while closed", () => {
    render(
      <Dialog open={false} onClose={() => {}} title="Hidden">
        body
      </Dialog>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("is named by its title and closes on Escape and on the close button", () => {
    const onClose = vi.fn();
    render(
      <Dialog open onClose={onClose} title="Delete this secret?">
        <p>body</p>
      </Dialog>,
    );
    expect(
      screen.getByRole("dialog", { name: "Delete this secret?" }),
    ).toBeInTheDocument();
    fireEvent.keyDown(document.activeElement ?? document.body, {
      key: "Escape",
    });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("is still named without a title", () => {
    render(
      <Dialog open onClose={() => {}}>
        <p>body</p>
      </Dialog>,
    );
    expect(screen.getByRole("dialog", { name: "Dialog" })).toBeInTheDocument();
  });
});
