/**
 * The terminal renders a window of the newest rows, not all 5000.
 */
import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import Terminal, { TERMINAL_WINDOW } from "../Terminal";
import { useUIStore } from "@/store/uiStore";
import {
  flushExecutionUpdates,
  useEphemeralExecutionStore,
} from "@/store/executionStore";

describe("Terminal", () => {
  beforeEach(() => {
    useEphemeralExecutionStore.getState().clearEvents();
    useUIStore.setState({ terminalState: "full" });
  });

  it("renders only the newest window and reveals earlier rows on request", () => {
    act(() => {
      const store = useEphemeralExecutionStore.getState();
      for (let i = 0; i < TERMINAL_WINDOW + 50; i++) {
        store.addEvent({
          executionId: "e",
          status: "RUNNING",
          logMessage: `line-${i}`,
          elapsedMs: i,
        } as never);
      }
      flushExecutionUpdates();
    });
    render(<Terminal />);
    expect(screen.queryByText("LINE-0")).toBeNull();
    expect(screen.getByText(`LINE-${TERMINAL_WINDOW + 49}`)).toBeTruthy();
    fireEvent.click(screen.getByText(/Show 50 earlier/));
    expect(screen.getByText("LINE-0")).toBeTruthy();
  });
});
