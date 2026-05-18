import { render, screen } from "@testing-library/react";
import { LoadingSpinner } from "../LoadingSpinner";

describe("LoadingSpinner", () => {
  it("renders spinner with accessible label", () => {
    render(<LoadingSpinner />);
    const container = screen.getByLabelText(/loading/i);
    expect(container).toBeInTheDocument();
    // Ensure an SVG element exists inside the container
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
  });
});
