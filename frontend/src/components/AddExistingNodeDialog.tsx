import React, { memo, useState } from "react";
import { ErrorBanner, Dialog, Button, DarkInput } from "@/components/ui";
import { ModuleItem } from "@/components/dialogs/ModuleItem";
import { useAddExistingNode } from "@/hooks/useAddExistingNode";
import { Search, Library } from "lucide-react";

interface AddExistingNodeDialogProps {
  onNodeAdded: (
    moduleId: string,
    moduleName: string,
    config: Record<string, unknown>,
    capabilityWorld?: string,
    capabilityDescription?: string,
    category?: string,
    importedInterfaces?: string[],
  ) => void;
  onClose: () => void;
}

export const AddExistingNodeDialog = memo(function AddExistingNodeDialog({
  onNodeAdded,
  onClose,
}: AddExistingNodeDialogProps) {
  const {
    modules,
    loading,
    error,
    selectedModuleId,
    setSelectedModuleId,
    getSelectedModule,
    parseConfig,
  } = useAddExistingNode();
  const [searchQuery, setSearchQuery] = useState("");

  const handleAdd = () => {
    if (!selectedModuleId) return;
    const selectedModule = getSelectedModule();
    if (!selectedModule) return;

    const config = parseConfig(selectedModule);
    onNodeAdded(
      selectedModule.id,
      selectedModule.name,
      config,
      selectedModule.capabilityWorld,
      undefined,
      undefined,
      selectedModule.importedInterfaces,
    );
    onClose();
  };

  const filteredModules = modules.filter((m) =>
    m.name.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <Dialog open={true} onClose={onClose} title="Add existing module">
      <div className="space-y-8">
        <div className="relative overflow-hidden p-6 bg-primary/5 border border-white/5 rounded-2xl bg-white/[0.03] border border-white/5 group">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-ui">
            <Library className="w-12 h-12 text-primary" />
          </div>
          <div className="flex items-start gap-5 relative z-10">
            <div className="shrink-0 w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Library className="w-6 h-6 text-primary" />
            </div>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-white tracking-tight font-outfit">
                Reuse a module
              </p>
              <p className="text-xs text-muted-foreground/60 leading-relaxed">
                Add a module you already have to this workflow. Nothing needs to
                be compiled.
              </p>
            </div>
          </div>
        </div>

        <div className="relative group/search">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60 group-focus-within/search:text-primary transition-ui z-10" />
          <DarkInput
            type="text"
            placeholder="Search modules…"
            value={searchQuery}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setSearchQuery(e.target.value)
            }
            className="pl-11 h-14"
          />
        </div>

        <div className="min-h-[300px] flex flex-col">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/50">
              <div className="w-10 h-10 border-4 border-primary/10 border-t-primary rounded-full animate-spin" />
              <p className="text-xs font-semibold">Loading…</p>
            </div>
          ) : error ? (
            <div>
              <ErrorBanner message={error} />
            </div>
          ) : filteredModules.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-20 px-8 text-center border-2 border-dashed border-white/5 rounded-2xl bg-surface-1/10 grayscale opacity-20">
              <Search className="w-12 h-12 text-muted-foreground/70 mb-6" />
              <p className="text-xs font-semibold text-muted-foreground mb-2">
                No modules match
              </p>
              <p className="text-xs text-muted-foreground/60 leading-relaxed max-w-[240px]">
                Try a different search, or create a module from the Catalog.
              </p>
            </div>
          ) : (
            <div className="max-h-[400px] overflow-y-auto pr-2 space-y-2 custom-scrollbar">
              {filteredModules.map((module) => (
                <ModuleItem
                  key={module.id}
                  module={module}
                  selected={selectedModuleId === module.id}
                  onSelect={setSelectedModuleId}
                />
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between pt-8 border-t border-white/5 relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-1.5 h-1.5 rounded-full bg-primary/40" />
            <p className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
              {filteredModules.length} module
              {filteredModules.length !== 1 ? "s" : ""}
            </p>
          </div>
          <div className="flex gap-4">
            <Button
              variant="ghost"
              onClick={onClose}
              className="h-12 px-8 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5"
            >
              Abort
            </Button>
            <Button
              onClick={handleAdd}
              disabled={!selectedModuleId || loading}
              variant="premium"
              className="h-12 px-10"
            >
              Add node
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
});

export default AddExistingNodeDialog;
