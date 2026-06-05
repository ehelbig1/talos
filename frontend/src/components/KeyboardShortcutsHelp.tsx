import React, { useState, useEffect } from "react";
import { Dialog, SectionHeader } from "@/components/ui";
import { Keyboard } from "lucide-react";

export interface Shortcut {
  key: string;
  description: string;
  category: string;
}

const shortcuts: Shortcut[] = [
  { key: "⌘ + I", description: "Toggle Inspector", category: "Navigation" },
  { key: "⌘ + J", description: "Cycle Terminal State", category: "Navigation" },
  { key: "?", description: "Show This Help", category: "Navigation" },
  { key: "⌘ + S", description: "Save Workflow", category: "Actions" },
  { key: "⌘ + D", description: "Duplicate Selected Node", category: "Actions" },
  { key: "Del / ⌫", description: "Delete Selected Node", category: "Actions" },
];

export function KeyboardShortcutsHelp() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "?" && !e.metaKey && !e.ctrlKey) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (
          tag === "INPUT" ||
          tag === "TEXTAREA" ||
          (e.target as HTMLElement)?.isContentEditable
        )
          return;
        setIsOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 p-2 bg-primary text-primary-foreground rounded-full shadow-lg hover:bg-primary/90 transition-premium z-50 flex items-center justify-center border border-border/50"
        title="Keyboard Shortcuts (?)"
      >
        <Keyboard size={20} />
      </button>
    );
  }

  const categories = Array.from(new Set(shortcuts.map((s) => s.category)));

  return (
    <Dialog
      open={isOpen}
      onClose={() => setIsOpen(false)}
      title="Keyboard Shortcuts"
    >
      <div className="p-4 space-y-6 max-h-[60vh] overflow-y-auto custom-scrollbar">
        {categories.map((category) => (
          <div key={category}>
            <SectionHeader
              level="h3"
              className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3"
            >
              {category}
            </SectionHeader>
            <div className="space-y-2">
              {shortcuts
                .filter((s) => s.category === category)
                .map((shortcut, idx) => (
                  <div key={idx} className="flex items-center justify-between">
                    <span className="text-sm text-foreground">
                      {shortcut.description}
                    </span>
                    <kbd className="px-2 py-1 text-xs font-mono bg-muted border border-border rounded text-primary">
                      {shortcut.key}
                    </kbd>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
      <div className="p-4 border-t border-border bg-muted/40 rounded-b-xl">
        <p className="text-xs text-muted-foreground">
          Press{" "}
          <kbd className="px-1 py-0.5 text-xs font-mono bg-background border border-border rounded">
            ?
          </kbd>{" "}
          to toggle this help
        </p>
      </div>
    </Dialog>
  );
}
