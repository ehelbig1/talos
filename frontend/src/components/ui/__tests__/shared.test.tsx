import { render, screen, fireEvent } from "@testing-library/react";
import { Badge } from "../badge";
import { IconButton } from "../IconButton";
import { NoteBox } from "../NoteBox";
import { Section } from "../Section";
import { vi } from "vitest";

describe("Shared UI Components", () => {
  describe("Badge", () => {
    it("renders children and custom class", () => {
      render(<Badge className="custom-class">Test Badge</Badge>);
      const badge = screen.getByText("Test Badge");
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass("custom-class");
    });
  });

  describe("IconButton", () => {
    it("renders and handles clicks", () => {
      const onClick = vi.fn();
      render(
        <IconButton onClick={onClick} title="Test Button">
          <span>Icon</span>
        </IconButton>,
      );
      const button = screen.getByTitle("Test Button");
      expect(button).toBeInTheDocument();
      fireEvent.click(button);
      expect(onClick).toHaveBeenCalled();
    });
  });

  describe("NoteBox", () => {
    it("renders children", () => {
      render(<NoteBox>Important note</NoteBox>);
      expect(screen.getByText("Important note")).toBeInTheDocument();
    });
  });

  describe("Section", () => {
    it("renders children", () => {
      render(
        <Section>
          <div>Section Content</div>
        </Section>,
      );
      expect(screen.getByText("Section Content")).toBeInTheDocument();
    });
  });
});
