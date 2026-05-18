import { render, screen, fireEvent } from "@testing-library/react";
import { RadioGroup, RadioGroupItem } from "../radio-group";
import { vi } from "vitest";

describe("RadioGroup", () => {
  it("renders and handles value changes", () => {
    const onValueChange = vi.fn();
    render(
      <RadioGroup value="option-1" onValueChange={onValueChange}>
        <RadioGroupItem value="option-1" id="r1" />
        <RadioGroupItem value="option-2" id="r2" />
        {"Just text child"}
      </RadioGroup>,
    );

    const radios = screen.getAllByRole("radio");

    expect(radios[0]).toHaveAttribute("aria-checked", "true");
    expect(radios[1]).toHaveAttribute("aria-checked", "false");

    fireEvent.click(radios[1]);
    expect(onValueChange).toHaveBeenCalledWith("option-2");
  });

  it("renders checked state with SVG", () => {
    render(
      <RadioGroup value="option-1" onValueChange={() => {}}>
        <RadioGroupItem value="option-1" />
      </RadioGroup>,
    );

    // The SVG only renders when checked
    expect(document.querySelector("svg")).toBeInTheDocument();
  });
});
