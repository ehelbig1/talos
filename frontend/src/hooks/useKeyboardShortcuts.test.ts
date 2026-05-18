import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useKeyboardShortcuts } from "./useKeyboardShortcuts";

describe("useKeyboardShortcuts", () => {
  const handler = vi.fn();
  const shortcuts = [
    { key: "k", metaKey: true, handler, description: "Search" },
    { key: "s", ctrlKey: true, handler, description: "Save" },
  ];

  beforeEach(() => {
    handler.mockClear();
    // Polyfill closest for JSDOM in tests if needed, but JSDOM should have it
    // The error "target.closest is not a function" suggests target is not an Element
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call handler when shortcut is pressed", () => {
    renderHook(() => useKeyboardShortcuts(shortcuts));

    // Ensure we're dispatching to window but the target is an element
    const event = new KeyboardEvent("keydown", {
      key: "k",
      metaKey: true,
      bubbles: true,
      cancelable: true,
    });

    // In JSDOM, event.target might be null if not dispatched from an element
    // Let's dispatch from document.body to ensure target is an HTMLElement
    document.body.dispatchEvent(event);

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("should call handler when ctrl shortcut is pressed", () => {
    renderHook(() => useKeyboardShortcuts(shortcuts));

    const event = new KeyboardEvent("keydown", {
      key: "s",
      ctrlKey: true,
      bubbles: true,
      cancelable: true,
    });
    document.body.dispatchEvent(event);

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("should ignore shortcuts when typing in an input", () => {
    renderHook(() => useKeyboardShortcuts(shortcuts));

    const input = document.createElement("input");
    document.body.appendChild(input);
    input.focus();

    const event = new KeyboardEvent("keydown", {
      key: "k",
      metaKey: true,
      bubbles: true,
      cancelable: true,
    });
    input.dispatchEvent(event);

    expect(handler).not.toHaveBeenCalled();
    document.body.removeChild(input);
  });

  it("should ignore shortcuts when in a monaco editor", () => {
    renderHook(() => useKeyboardShortcuts(shortcuts));

    const monaco = document.createElement("div");
    monaco.className = "monaco-editor";
    document.body.appendChild(monaco);

    const event = new KeyboardEvent("keydown", {
      key: "k",
      metaKey: true,
      bubbles: true,
      cancelable: true,
    });
    monaco.dispatchEvent(event);

    expect(handler).not.toHaveBeenCalled();
    document.body.removeChild(monaco);
  });

  it("should cleanup event listener on unmount", () => {
    const removeEventListenerSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() => useKeyboardShortcuts(shortcuts));

    unmount();

    expect(removeEventListenerSpy).toHaveBeenCalledWith(
      "keydown",
      expect.any(Function),
    );
  });
});
