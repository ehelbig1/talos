import { useEffect } from "react";

export interface KeyboardShortcut {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  shiftKey?: boolean;
  altKey?: boolean;
  handler: () => void;
  description: string;
}

export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[]) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Ignore keypresses originating from inputs, textareas, or contenteditables
      const target = event.target as HTMLElement;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable ||
          target.closest(".monaco-editor"))
      ) {
        return;
      }

      for (const shortcut of shortcuts) {
        const matchesKey =
          event.key.toLowerCase() === shortcut.key.toLowerCase();
        const matchesCtrl =
          shortcut.ctrlKey === undefined || event.ctrlKey === shortcut.ctrlKey;
        const matchesMeta =
          shortcut.metaKey === undefined || event.metaKey === shortcut.metaKey;
        const matchesShift =
          shortcut.shiftKey === undefined ||
          event.shiftKey === shortcut.shiftKey;
        const matchesAlt =
          shortcut.altKey === undefined || event.altKey === shortcut.altKey;

        if (
          matchesKey &&
          matchesCtrl &&
          matchesMeta &&
          matchesShift &&
          matchesAlt
        ) {
          event.preventDefault();
          shortcut.handler();
          break;
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [shortcuts]);
}

// Common keyboard shortcuts
export const SHORTCUTS = {
  TOGGLE_TOOLBOX: {
    key: "b",
    metaKey: true,
    description: "Toggle Toolbox",
  },
  TOGGLE_INSPECTOR: {
    key: "i",
    metaKey: true,
    description: "Toggle Inspector",
  },
  TOGGLE_TERMINAL: {
    key: "j",
    metaKey: true,
    description: "Toggle Terminal",
  },
  SEARCH: {
    key: "k",
    metaKey: true,
    description: "Search Templates",
  },
  SAVE: {
    key: "s",
    metaKey: true,
    description: "Save Workflow",
  },
};
