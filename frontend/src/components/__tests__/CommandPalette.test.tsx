import { describe, it, expect } from "vitest";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { useLocation } from "react-router";
import { http, HttpResponse } from "msw";
import { server } from "@/../vitest.setup";
import { CommandPalette, matchScore } from "../CommandPalette";

function Where() {
  const { pathname, hash } = useLocation();
  return <div data-testid="where">{pathname + hash}</div>;
}

const WORKFLOW_ID = "0b2f7a1c-5e0e-4c3b-9d1a-2f6c8e4b7a90";
const ACTOR_ID = "6d1e9c2a-7b4f-4a8e-b3c5-1f0d2e3a4b5c";

function stubLists() {
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as { query: string };
      if (body.query.includes("query Workflows")) {
        return HttpResponse.json({
          data: {
            workflows: [
              {
                id: WORKFLOW_ID,
                name: "Nightly digest",
                graphJson: "{}",
                actorId: null,
                maxConcurrentExecutions: 1,
                intent: null,
              },
            ],
          },
        });
      }
      if (body.query.includes("query ListActors")) {
        return HttpResponse.json({
          data: {
            actors: [
              {
                id: ACTOR_ID,
                name: "Scout",
                status: "active",
                executionCount: 0,
              },
            ],
          },
        });
      }
      return HttpResponse.json({ data: {} });
    }),
  );
}

function openWithKeyboard() {
  fireEvent.keyDown(window, { key: "k", metaKey: true });
  return screen.getByRole("dialog", { name: "Jump to" });
}

describe("CommandPalette", () => {
  it("opens on ⌘K, filters, and goes where Enter points", async () => {
    stubLists();
    render(
      <>
        <CommandPalette />
        <Where />
      </>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    openWithKeyboard();
    const box = screen.getByRole("combobox");
    fireEvent.change(box, { target: { value: "sched" } });
    expect(screen.getByRole("option", { name: /Schedules/ })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    fireEvent.keyDown(box, { key: "Enter" });
    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent(
        "/settings#schedules",
      ),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("lists the user's workflows and actors while open", async () => {
    stubLists();
    render(
      <>
        <CommandPalette />
        <Where />
      </>,
    );
    openWithKeyboard();
    const workflow = await screen.findByRole("option", {
      name: /Nightly digest/,
    });
    expect(await screen.findByRole("option", { name: /Scout/ })).toBeTruthy();
    fireEvent.click(workflow);
    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent(
        `/editor/${WORKFLOW_ID}`,
      ),
    );
  });

  it("goes to a page on g then a letter, but not from inside a text field", async () => {
    render(
      <>
        <CommandPalette />
        <Where />
        <input aria-label="field" />
      </>,
    );
    const field = screen.getByLabelText("field");
    fireEvent.keyDown(field, { key: "g" });
    fireEvent.keyDown(field, { key: "a" });
    expect(screen.getByTestId("where")).toHaveTextContent("/");
    fireEvent.keyDown(window, { key: "g" });
    fireEvent.keyDown(window, { key: "a" });
    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent("/actors"),
    );
  });

  it("scores a prefix over a word start over a substring", () => {
    expect(matchScore("Failed deliveries", "fail")).toBe(3);
    expect(matchScore("Failed deliveries", "deliv")).toBe(2);
    expect(matchScore("Failed deliveries", "iver")).toBe(1);
    expect(matchScore("Failed deliveries", "xyz")).toBe(0);
    expect(matchScore("Anything", "")).toBe(1);
  });
});
