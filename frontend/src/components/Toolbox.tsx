import React, { useState } from "react";
import { Button, IconButton, SectionHeader } from "@/components/ui";
import { ModuleBuilder } from "@/components/builder/ModuleBuilder";
import { useUIStore } from "@/store/uiStore";
import { Menu, Plus, Star, ChevronsLeft, LayoutGrid } from "lucide-react";

interface ToolboxProps {
  onAddNode: (
    moduleId: string,
    moduleName: string,
    position: { x: number; y: number },
    category?: string,
  ) => void;
}

export default function Toolbox({ onAddNode }: ToolboxProps) {
  const [builderOpen, setBuilderOpen] = useState(false);
  const { toolboxMode, setToolboxMode, favoriteTemplates, recentTemplates } =
    useUIStore();

  const handleAdd = (
    moduleId: string,
    moduleName: string,
    category?: string,
  ) => {
    const position = { x: 100, y: 100 };
    onAddNode(moduleId, moduleName, position, category);
  };

  // Icon mode - show only icons
  if (toolboxMode === "icon") {
    return (
      <div className="h-full flex flex-col items-center p-2 space-y-4">
        <IconButton
          onClick={() => setToolboxMode("full")}
          title="Expand Toolbox"
        >
          <Menu className="h-5 w-5" />
        </IconButton>

        <IconButton onClick={() => setBuilderOpen(true)} title="Add Node">
          <Plus className="h-5 w-5" />
        </IconButton>

        <IconButton title="Favorites">
          <Star className="h-5 w-5" />
        </IconButton>

        <ModuleBuilder
          open={builderOpen}
          onClose={() => setBuilderOpen(false)}
          onModuleCreated={(
            moduleId: string,
            moduleName: string,
            _: string,
            category: string,
          ) => {
            handleAdd(moduleId, moduleName, category);
          }}
        />
      </div>
    );
  }

  // Full mode - show complete toolbox
  return (
    <div className="h-full flex flex-col p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <LayoutGrid className="h-4 w-4 text-primary" />
          <SectionHeader level="h3" className="text-sm font-semibold">
            Toolbox
          </SectionHeader>
        </div>
        <IconButton
          onClick={() => setToolboxMode("icon")}
          title="Collapse Toolbox"
          className="p-1"
        >
          <ChevronsLeft className="h-4 w-4" />
        </IconButton>
      </div>

      <Button size="sm" onClick={() => setBuilderOpen(true)} className="w-full">
        <Plus className="h-3.5 w-3.5 mr-2" />
        Create Node
      </Button>

      {favoriteTemplates.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground flex items-center">
            <Star className="h-3 w-3 mr-1 fill-warning text-warning" />
            Favorites
          </p>
          <div className="space-y-1">
            {favoriteTemplates.slice(0, 3).map((template) => (
              <Button
                key={template}
                size="sm"
                variant="outline"
                onClick={() => handleAdd(template, template)}
                className="w-full justify-start text-xs"
              >
                {template}
              </Button>
            ))}
          </div>
        </div>
      )}

      {recentTemplates.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">Recent</p>
          <div className="space-y-1">
            {recentTemplates.slice(0, 3).map((template) => (
              <Button
                key={template}
                size="sm"
                variant="outline"
                onClick={() => handleAdd(template, template)}
                className="w-full justify-start text-xs"
              >
                {template}
              </Button>
            ))}
          </div>
        </div>
      )}

      <div className="border-t border-border pt-2 mt-auto">
        <p className="text-[10px] text-muted-foreground italic leading-relaxed">
          💡 Use the "Create Node" button above to compile and add nodes from
          templates
        </p>
      </div>

      <ModuleBuilder
        open={builderOpen}
        onClose={() => setBuilderOpen(false)}
        onModuleCreated={(
          moduleId: string,
          moduleName: string,
          configJson: string,
          category: string,
        ) => {
          handleAdd(moduleId, moduleName, category);
        }}
      />
    </div>
  );
}
