import React, { useRef, useEffect } from "react";
import ReactDOM from "react-dom";
import { Copy, Trash2, ClipboardCopy } from "lucide-react";
import { toast } from "sonner";

interface NodeContextMenuProps {
  pos: { x: number; y: number };
  nodeId?: string;
  onClose: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}

export const NodeContextMenu: React.FC<NodeContextMenuProps> = ({
  pos,
  nodeId,
  onClose,
  onDuplicate,
  onDelete,
}) => {
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [onClose]);

  const handleCopyId = async () => {
    if (!nodeId) return;
    try {
      await navigator.clipboard.writeText(nodeId);
      toast.success("Node ID copied");
    } catch {
      // Clipboard API unavailable (non-HTTPS or denied permission) — fail silently
    }
    onClose();
  };

  return ReactDOM.createPortal(
    <div
      ref={menuRef}
      style={{ position: "fixed", top: pos.y, left: pos.x }}
      className="z-[9999] glass-dark rounded-xl shadow-2xl py-1.5 min-w-[190px] border border-white/10 overflow-hidden
        animate-in fade-in zoom-in-95 duration-150 origin-top-left"
      role="menu"
      aria-label="Node context menu"
    >
      {/* Duplicate */}
      <button
        type="button"
        className="w-full text-left px-3 py-2 text-xs font-semibold text-foreground hover:bg-white/10 transition-premium flex items-center justify-between gap-2 group"
        onClick={() => {
          onDuplicate();
          onClose();
        }}
        role="menuitem"
      >
        <span className="flex items-center gap-2">
          <Copy className="w-3.5 h-3.5 text-muted-foreground group-hover:text-indigo-400 transition-premium" />
          Duplicate
        </span>
        <kbd className="text-[10px] text-muted-foreground font-mono bg-white/5 px-1.5 py-0.5 rounded border border-white/5">
          ⌘D
        </kbd>
      </button>

      {/* Copy Node ID */}
      {nodeId && (
        <button
          type="button"
          className="w-full text-left px-3 py-2 text-xs font-semibold text-foreground hover:bg-white/10 transition-premium flex items-center justify-between gap-2 group"
          onClick={handleCopyId}
          role="menuitem"
        >
          <span className="flex items-center gap-2">
            <ClipboardCopy className="w-3.5 h-3.5 text-muted-foreground group-hover:text-violet-400 transition-premium" />
            Copy Node ID
          </span>
        </button>
      )}

      <div className="mx-2 my-1 border-t border-white/5" />

      {/* Delete */}
      <button
        type="button"
        className="w-full text-left px-3 py-2 text-xs font-semibold text-red-400 hover:bg-red-500/10 transition-premium flex items-center justify-between gap-2 group"
        onClick={() => {
          onDelete();
          onClose();
        }}
        role="menuitem"
      >
        <span className="flex items-center gap-2">
          <Trash2 className="w-3.5 h-3.5 opacity-70 group-hover:opacity-100 transition-opacity" />
          Remove Node
        </span>
        <kbd className="text-[10px] text-red-500/50 font-mono bg-red-500/5 px-1.5 py-0.5 rounded border border-red-500/10">
          ⌫
        </kbd>
      </button>
    </div>,
    document.body,
  );
};
