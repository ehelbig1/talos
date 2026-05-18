/**
 * Dropdown menu for adding control-flow nodes (ForEach, FanIn, Loop, etc.)
 * to the workflow canvas. Extracted from WorkflowToolbar.
 */
import React, { useState, useEffect, useRef, useCallback } from "react";
import { Code2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";

const SYSTEM_NODES = [
  { kind: "ForEach" as const,          label: "For Each",           desc: "Iterate over array items" },
  { kind: "FanIn" as const,            label: "Fan-In",             desc: "Merge parallel branches" },
  { kind: "WhileLoop" as const,        label: "While Loop",         desc: "Loop while condition is true" },
  { kind: "RepeatLoop" as const,       label: "Repeat",             desc: "Repeat N times" },
  { kind: "SubWorkflow" as const,      label: "Sub-Workflow",       desc: "Run another workflow" },
  { kind: "ErrorHandler" as const,     label: "Error Handler",      desc: "Catch and handle errors" },
  { kind: "Wait" as const,             label: "Wait",               desc: "Pause for approval" },
  { kind: "Collect" as const,          label: "Collect",            desc: "Aggregate multiple inputs" },
  { kind: "DynamicDispatch" as const,  label: "Dynamic Dispatch",   desc: "Route to module by name" },
  { kind: "CapabilityDispatch" as const, label: "Capability Dispatch", desc: "Route to module by capability" },
] as const;

export type SystemNodeKind = (typeof SYSTEM_NODES)[number]["kind"];

interface ControlFlowMenuProps {
  onClose: () => void;
}

export function ControlFlowMenu({ onClose }: ControlFlowMenuProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);

  const { addNode, updateNodeData } = useWorkflowStore(
    useShallow((s) => ({ addNode: s.addNode, updateNodeData: s.updateNodeData })),
  );

  const addSystemNode = useCallback(
    (kind: SystemNodeKind, label: string) => {
      const position = {
        x: 250 + Math.random() * 100,
        y: 200 + Math.random() * 100,
      };
      addNode(`system:${kind}`, label, position, {}, undefined, undefined, "control-flow", []);
      const storeNodes = useWorkflowStore.getState().nodes;
      const newNode = storeNodes[storeNodes.length - 1];
      if (newNode) updateNodeData(newNode.id, { systemNodeKind: kind });
      setIsOpen(false);
      onClose();
    },
    [addNode, updateNodeData, onClose],
  );

  // Close on outside click
  useEffect(() => {
    if (!isOpen) return;
    setActiveIndex(-1);
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
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
        setActiveIndex((i) => (i - 1 + SYSTEM_NODES.length) % SYSTEM_NODES.length);
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
        onClick={() => setIsOpen((v) => !v)}
        aria-label="Open control flow menu"
        aria-expanded={isOpen}
        aria-haspopup="true"
        className={cn(
          "h-8 px-3 flex items-center gap-1.5 text-xs font-medium rounded-md transition-premium active:scale-95 border shadow-sm",
          isOpen
            ? "bg-cyan-500/25 text-cyan-200 border-cyan-500/50 shadow-cyan-500/20"
            : "bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border-cyan-500/30 shadow-cyan-500/10",
        )}
      >
        <Code2 className="w-3.5 h-3.5" />
        Control Flow
      </button>

      {isOpen && (
        <div
          className="absolute top-full left-0 mt-2 z-50 glass-dark rounded-2xl py-2 min-w-[240px] overflow-hidden animate-in fade-in slide-in-from-top-2 duration-300 origin-top-left"
          role="menu"
          aria-label="Control flow nodes"
        >
          <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/10 via-transparent to-transparent opacity-30 pointer-events-none" />
          <div className="relative z-10 px-3 py-1.5 mb-1.5 border-b border-white/5">
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.2em]">Logic Primitives</span>
          </div>
          {SYSTEM_NODES.map((sn, idx) => (
            <button
              key={sn.kind}
              onClick={() => addSystemNode(sn.kind, sn.label)}
              onMouseEnter={() => setActiveIndex(idx)}
              onFocus={() => setActiveIndex(idx)}
              role="menuitem"
              className={cn(
                "w-full text-left px-4 py-2.5 transition-premium group outline-none relative z-10",
                activeIndex === idx ? "bg-white/5" : "hover:bg-white/[0.02]",
              )}
            >
              <div className={cn(
                "text-xs font-black uppercase tracking-widest",
                activeIndex === idx ? "text-cyan-400" : "text-white group-hover:text-cyan-400",
              )}>
                {sn.label}
              </div>
              <div className={cn(
                "text-[9px] font-medium leading-relaxed",
                activeIndex === idx ? "text-muted-foreground" : "text-muted-foreground/60 group-hover:text-muted-foreground",
              )}>
                {sn.desc}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
