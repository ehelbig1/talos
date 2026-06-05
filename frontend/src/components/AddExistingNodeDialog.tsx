import React, { memo, useState } from "react";
import {
  ErrorBanner,
  Dialog,
  InfoTip,
  Button,
  DarkInput,
  InfoBanner,
} from "@/components/ui";
import { ModuleItem } from "@/components/dialogs/ModuleItem";
import { useAddExistingNode } from "@/hooks/useAddExistingNode";
import { Search, Library } from "lucide-react";
import type { WasmModule } from "@/hooks/useAddExistingNode";

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
    <Dialog open={true} onClose={onClose} title="Operational Resource Library">
      <div className="space-y-8">
        <div className="relative overflow-hidden p-6 bg-primary/5 border border-white/5 rounded-[2.5rem] shadow-inner glass-light group">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-premium">
            <Library className="w-12 h-12 text-primary" />
          </div>
          <div className="flex items-start gap-5 relative z-10">
            <div className="shrink-0 w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-xl">
              <Library className="w-6 h-6 text-primary" />
            </div>
            <div className="space-y-1">
              <p className="text-[11px] font-black text-white tracking-tight font-outfit uppercase">
                Provisioning Accelerator
              </p>
              <p className="text-[10px] text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed">
                Deploy pre-validated execution modules to bypass synthesis
                latencies. These protocols are ready for immediate
                instantiation.
              </p>
            </div>
          </div>
        </div>

        <div className="relative group/search">
          <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within/search:opacity-100 transition-premium" />
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/30 group-focus-within/search:text-primary transition-premium z-10" />
          <DarkInput
            type="text"
            placeholder="FILTER OPERATIONAL BLUEPRINTS..."
            value={searchQuery}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setSearchQuery(e.target.value)
            }
            className="pl-11 h-14"
          />
        </div>

        <div className="min-h-[300px] flex flex-col">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground/20 animate-status-pulse">
              <div className="w-10 h-10 border-4 border-primary/10 border-t-primary rounded-full animate-spin shadow-[0_0_15px_hsla(var(--primary),0.2)]" />
              <p className="text-[10px] font-black uppercase tracking-[0.3em]">
                Synchronizing Registry...
              </p>
            </div>
          ) : error ? (
            <div className="animate-in fade-in slide-in-from-top-2">
              <ErrorBanner message={error} />
            </div>
          ) : filteredModules.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-20 px-8 text-center border-2 border-dashed border-white/5 rounded-[3rem] bg-surface-1/10 grayscale opacity-20">
              <Search className="w-12 h-12 text-muted-foreground/40 mb-6" />
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.3em] mb-2">
                No Blueprint Matches
              </p>
              <p className="text-[10px] text-muted-foreground/60 uppercase tracking-widest leading-relaxed max-w-[240px] font-bold">
                Adjust query parameters or synthesize new modules from the
                Catalog.
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
            <div className="w-1.5 h-1.5 rounded-full bg-primary/40 shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
            <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.3em]">
              {filteredModules.length} Operational Protocol
              {filteredModules.length !== 1 ? "s" : ""} Online
            </p>
          </div>
          <div className="flex gap-4">
            <Button
              variant="ghost"
              onClick={onClose}
              className="h-12 px-8 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95"
            >
              Abort
            </Button>
            <Button
              onClick={handleAdd}
              disabled={!selectedModuleId || loading}
              variant="premium"
              className="h-12 px-10"
            >
              Initialize Node
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
});

export default AddExistingNodeDialog;
