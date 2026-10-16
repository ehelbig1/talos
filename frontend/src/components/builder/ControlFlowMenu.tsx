/**
 * Dropdown menu for adding control-flow nodes to the workflow canvas. The
 * kinds and their words live in `@/lib/systemNodes`.
 */
import React, { useState, useEffect, useRef, useCallback } from "react";
import { Code2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";
import { SYSTEM_NODES, type SystemNodeKind } from "@/lib/systemNodes";

interface ControlFlowMenuProps {
  onClose: () => void;
}

export function ControlFlowMenu({ onClose }: ControlFlowMenuProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);

  const { addNode, updateNodeData } = useWorkflowStore(
    useShallow((s) => ({
      addNode: s.addNode,
      updateNodeData: s.updateNodeData,
    })),
  );

  const addSystemNode = useCallback(
    (kind: SystemNodeKind, label: string) => {
      const position = {
        x: 250 + Math.random() * 100,
        y: 200 + Math.random() * 100,
      };
      addNode(
        `system:${kind}`,
        label,
        position,
        {},
        undefined,
        undefined,
        "control-flow",
        [],
      );
      const storeNodes = useWorkflowStore.getState().nodes;
      const newNode = storeNodes[storeNodes.length - 1];
      if (newNode) updateNodeData(newNode.id, { systemNodeKind: kind });
      setIsOpen(false);
      onClose();
    },
    [addNode, updateNodeData, onClose],
  );

  // Toggle the menu. Resetting the keyboard-nav highlight lives here in
  // the open path (an event) rather than in the open effect, so the
  // effect stays a pure external-listener subscription
  // (react-hooks/set-state-in-effect). Resetting on close too is a
  // harmless no-op since the list is hidden.
  const toggleOpen = useCallback(() => {
    setIsOpen((v) => !v);
    setActiveIndex(-1);
  }, []);

  // Close on outside click
  useEffect(() => {
    if (!isOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen]);

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((i) => (i + 1) % SYSTEM_NODES.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex(
          (i) => (i - 1 + SYSTEM_NODES.length) % SYSTEM_NODES.length,
        );
      } else if (e.key === "Enter" && activeIndex >= 0) {
        e.preventDefault();
        const sn = SYSTEM_NODES[activeIndex];
        addSystemNode(sn.kind, sn.label);
      } else if (e.key === "Escape") {
        setIsOpen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, activeIndex, addSystemNode]);

  return (
    <div className="relative" ref={containerRef}>
      <button
        onClick={toggleOpen}
        aria-label="Open control flow menu"
        aria-expanded={isOpen}
        aria-haspopup="true"
        className={cn(
          "h-8 px-3 flex items-center gap-2 text-xs font-semibold rounded-xl transition-ui border whitespace-nowrap",
          isOpen
            ? "bg-white/10 text-white border-white/20"
            : "bg-white/5 hover:bg-white/10 text-foreground border-white/10",
        )}
      >
        <Code2 className="w-3.5 h-3.5" />
        Control flow
      </button>

      {isOpen && (
        <div
          className="absolute top-full left-0 mt-2 z-50 bg-surface-3 border border-white/10 rounded-2xl py-2 min-w-[240px] max-h-[min(70vh,32rem)] overflow-y-auto custom-scrollbar origin-top-left"
          role="menu"
          aria-label="Control flow nodes"
        >
          <div className="relative z-10 px-3 py-1.5 mb-1.5 border-b border-white/5">
            <span className="text-2xs font-semibold text-muted-foreground/70 uppercase tracking-wider">
              Control flow
            </span>
          </div>
          {SYSTEM_NODES.map((sn, idx) => (
            <button
              key={sn.kind}
              onClick={() => addSystemNode(sn.kind, sn.label)}
              onMouseEnter={() => setActiveIndex(idx)}
              onFocus={() => setActiveIndex(idx)}
              role="menuitem"
              className={cn(
                "w-full text-left px-4 py-2.5 transition-ui group outline-none relative z-10",
                activeIndex === idx ? "bg-white/5" : "hover:bg-white/[0.02]",
              )}
            >
              <div
                className={cn(
                  "text-xs font-semibold",
                  activeIndex === idx
                    ? "text-info"
                    : "text-white group-hover:text-info",
                )}
              >
                {sn.label}
              </div>
              <div
                className={cn(
                  "text-2xs font-medium leading-relaxed",
                  activeIndex === idx
                    ? "text-muted-foreground"
                    : "text-muted-foreground/60 group-hover:text-muted-foreground",
                )}
              >
                {sn.desc}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
