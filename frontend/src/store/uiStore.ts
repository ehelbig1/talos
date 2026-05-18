import { create } from "zustand";
import { persist } from "zustand/middleware";

export type TerminalState = "collapsed" | "compact" | "full";
export type ToolboxMode = "icon" | "full";

export interface UIState {
  // Panel visibility
  showToolbox: boolean;
  toolboxMode: ToolboxMode;
  showInspector: boolean;
  terminalState: TerminalState;

  // Selected node for Inspector
  selectedNodeId: string | null;

  // Debug panel — node ID to show in the debug inspector
  debugNodeId: string | null;

  // Cross-component toolbar modal trigger (used by Workspace empty state)
  toolbarModal: "addExisting" | "create" | null;
  setToolbarModal: (modal: "addExisting" | "create" | null) => void;

  // Actions
  toggleToolbox: () => void;
  setToolboxMode: (mode: ToolboxMode) => void;
  setShowInspector: (show: boolean) => void;
  setTerminalState: (state: TerminalState) => void;
  setSelectedNodeId: (id: string | null) => void;
  setDebugNodeId: (id: string | null) => void;

  // Template favorites and recent
  favoriteTemplates: string[];
  recentTemplates: string[];
  toggleFavorite: (templateId: string) => void;
  addRecentTemplate: (templateId: string) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set, get) => ({
      // Default state
      showToolbox: true,
      toolboxMode: "full",
      showInspector: false,
      terminalState: "collapsed",
      selectedNodeId: null,
      debugNodeId: null,
      toolbarModal: null,
      favoriteTemplates: [],
      recentTemplates: [],

      // Actions
      toggleToolbox: () => set({ showToolbox: !get().showToolbox }),

      setToolboxMode: (mode) => set({ toolboxMode: mode }),

      setShowInspector: (show) => set({ showInspector: show }),

      setTerminalState: (state) => set({ terminalState: state }),

      setToolbarModal: (modal) => set({ toolbarModal: modal }),

      setSelectedNodeId: (id) => {
        set({ selectedNodeId: id });
        // Auto-open inspector when node is selected
        if (id) {
          set({ showInspector: true });
        }
      },

      setDebugNodeId: (id) => {
        set({ debugNodeId: id });
        // Auto-open inspector when debug node is selected
        if (id) {
          set({ showInspector: true });
        }
      },

      toggleFavorite: (templateId) => {
        const favorites = get().favoriteTemplates;
        if (favorites.includes(templateId)) {
          set({
            favoriteTemplates: favorites.filter((id) => id !== templateId),
          });
        } else {
          set({ favoriteTemplates: [...favorites, templateId] });
        }
      },

      addRecentTemplate: (templateId) => {
        const recent = get().recentTemplates;
        // Remove if already exists
        const filtered = recent.filter((id) => id !== templateId);
        // Add to front and keep max 5
        set({ recentTemplates: [templateId, ...filtered].slice(0, 5) });
      },
    }),
    {
      name: "talos_panel_state",
      partialize: (state) => ({
        toolboxMode: state.toolboxMode,
        terminalState: state.terminalState,
        favoriteTemplates: state.favoriteTemplates,
        recentTemplates: state.recentTemplates,
      }),
    },
  ),
);
