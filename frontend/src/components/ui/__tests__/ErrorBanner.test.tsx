import { render, screen } from "@testing-library/react";
import { ErrorBanner } from "../ErrorBanner";

describe("ErrorBanner", () => {
  it("renders the provided message", () => {
    const msg = "Something went wrong";
    render(<ErrorBanner message={msg} />);
    expect(screen.getByRole("alert")).toHaveTextContent(msg);
  });
});
