import React from "react";
import { Handle, Position } from "@xyflow/react";

export const NodeHandles: React.FC = () => {
  return (
    <>
      <Handle
        type="target"
        position={Position.Top}
        aria-label="Input handle"
        className="!bg-primary !border-background !border-4 !w-3.5 !h-3.5 hover:!scale-125 !transition-premium hover:!ring-4 hover:!ring-primary/20"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        aria-label="Output handle"
        className="!bg-success !border-background !border-4 !w-3.5 !h-3.5 hover:!scale-125 !transition-premium hover:!ring-4 hover:!ring-success/20"
      />
    </>
  );
};
