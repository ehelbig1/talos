import { render, screen } from "@testing-library/react";
import { LoadingState, Spinner } from "./spinner";

describe("Spinner", () => {
  it("is decorative unless it has a label", () => {
    const { container, rerender } = render(<Spinner />);
    expect(container.querySelector("svg")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    rerender(<Spinner label="Saving" />);
    expect(screen.getByRole("status", { name: "Saving" })).toBeInTheDocument();
  });
});

describe("LoadingState", () => {
  it("announces one plain line", () => {
    render(<LoadingState label="Loading secrets…" />);
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("Loading secrets…");
    expect(status.querySelector("svg")).toBeTruthy();
  });

  it("passes attributes through", () => {
    render(<LoadingState data-panel-loading />);
    expect(document.querySelector("[data-panel-loading]")).toBeTruthy();
  });
});
