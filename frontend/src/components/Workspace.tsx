import React, {
  useCallback,
  Suspense,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useNavigate } from "react-router";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import ErrorBoundary from "@/components/ErrorBoundary";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  Panel,
} from "@xyflow/react";
import type { Connection } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { TalosNode } from "@/components/TalosNode";
import { ConditionEdge } from "@/components/ConditionEdge";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";
import { useUIStore } from "@/store/uiStore";
import { WorkflowToolbar } from "@/components/WorkflowToolbar";
const Inspector = React.lazy(() => import("@/components/Inspector"));
const Terminal = React.lazy(() => import("@/components/Terminal"));
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { cn } from "@/lib/utils";
import { useKeyboardShortcuts, SHORTCUTS } from "@/hooks/useKeyboardShortcuts";
import { Zap, FolderPlus, BookOpen } from "lucide-react";

const proOptions = { hideAttribution: true };
const nodeTypes = { talosNode: TalosNode };
const edgeTypes = { conditionEdge: ConditionEdge };

function Workspace() {
  const navigate = useNavigate();
  const nodes = useWorkflowStore(useShallow((s) => s.nodes));
  const edges = useWorkflowStore(useShallow((s) => s.edges));
  const onNodesChange = useWorkflowStore((s) => s.onNodesChange);
  const onEdgesChange = useWorkflowStore((s) => s.onEdgesChange);
  const connectNodes = useWorkflowStore((s) => s.connectNodes);
  const deleteNode = useWorkflowStore((s) => s.deleteNode);
  const nodeCount = nodes.length;

  const { showInspector, terminalState, setShowInspector, setTerminalState } =
    useUIStore(
      useShallow((s) => ({
        showInspector: s.showInspector,
        terminalState: s.terminalState,
        setShowInspector: s.setShowInspector,
        setTerminalState: s.setTerminalState,
      })),
    );

  const onConnect = useCallback(
    (connection: Connection) => {
      connectNodes(connection);
    },
    [connectNodes],
  );

  const handleDeleteSelected = useCallback(() => {
    const activeElement = document.activeElement as HTMLElement;
    const isInput =
      activeElement &&
      (activeElement.tagName === "INPUT" ||
        activeElement.tagName === "TEXTAREA" ||
        activeElement.isContentEditable ||
        activeElement.closest(".monaco-editor"));

    if (isInput) return;

    const selectedNode = useWorkflowStore
      .getState()
      .nodes.find((n) => n.selected);
    if (selectedNode) {
      deleteNode(selectedNode.id);
      setShowInspector(false);
    }
  }, [deleteNode, setShowInspector]);

  const keyboardShortcuts = useMemo(
    () => [
      {
        ...SHORTCUTS.TOGGLE_INSPECTOR,
        handler: () => setShowInspector(!showInspector),
      },
      {
        ...SHORTCUTS.TOGGLE_TERMINAL,
        handler: () => {
          if (terminalState === "collapsed") setTerminalState("compact");
          else if (terminalState === "compact") setTerminalState("full");
          else setTerminalState("collapsed");
        },
      },
      {
        key: "Delete",
        handler: handleDeleteSelected,
        description: "Terminate & Remove Node",
      },
      {
        key: "Backspace",
        handler: handleDeleteSelected,
        description: "Terminate & Remove Node",
      },
    ],
    [
      showInspector,
      terminalState,
      handleDeleteSelected,
      setShowInspector,
      setTerminalState,
    ],
  );
  useKeyboardShortcuts(keyboardShortcuts);

  // Subscribe to window resize for terminal height calculation
  const windowHeight = useSyncExternalStore(
    (cb) => {
      window.addEventListener("resize", cb);
      return () => window.removeEventListener("resize", cb);
    },
    () => window.innerHeight,
  );

  const terminalHeight =
    terminalState === "collapsed"
      ? 24
      : terminalState === "compact"
        ? 240
        : windowHeight * 0.45;

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-background relative overflow-hidden h-full">
      {/* Dynamic Background Glows */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden select-none z-0">
        <div
          className="absolute top-[-10%] left-[-5%] w-[50%] h-[50%] bg-primary/10 blur-[120px] rounded-full mix-blend-screen animate-pulse"
          style={{ animationDuration: "12s" }}
        />
        <div
          className="absolute bottom-[-10%] right-[-5%] w-[50%] h-[50%] bg-indigo-500/10 blur-[120px] rounded-full mix-blend-screen animate-pulse"
          style={{ animationDuration: "18s" }}
        />
      </div>

      <WorkflowToolbar />

      <div className="flex flex-1 overflow-hidden relative z-10">
        <div className="flex-1 relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            nodeOrigin={[0.5, 0.5]}
            snapToGrid
            snapGrid={[15, 15]}
            onlyRenderVisibleElements
            nodeDragThreshold={1}
            defaultEdgeOptions={{
              style: { strokeWidth: 3, stroke: "hsla(var(--primary), 0.5)" },
              animated: true,
            }}
            proOptions={proOptions}
            className="bg-transparent"
          >
            <Background
              color="hsla(var(--white), 0.05)"
              gap={40}
              size={1}
              variant={BackgroundVariant.Lines}
              className="opacity-50"
            />

            <div className="absolute bottom-8 left-8 z-20">
              <Controls
                showInteractive={false}
                className="!m-0 !bg-surface-3/40 !backdrop-blur-2xl !border-white/5 !shadow-2xl !rounded-2xl overflow-hidden [&>button]:!bg-transparent [&>button]:!border-white/10 [&>button]:!text-muted-foreground [&>button:hover]:!text-foreground [&>button:hover]:!bg-white/5 [&>button]:!transition-premium"
              />
            </div>

            <Panel position="bottom-right" className="!m-8 z-20">
              <MiniMap
                className="!bg-surface-3/40 !backdrop-blur-2xl !border-white/5 !rounded-[2rem] !shadow-2xl overflow-hidden glass"
                maskColor="hsla(var(--background), 0.8)"
                nodeColor={(n) => {
                  if (n.data?.category === "control-flow")
                    return "hsl(var(--info))";
                  return "hsl(var(--primary))";
                }}
                nodeStrokeWidth={4}
                zoomable
                pannable
              />
            </Panel>
          </ReactFlow>

          {nodeCount === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-30 px-6">
              <div className="text-center pointer-events-auto bg-surface-3/40 border border-white/10 p-16 rounded-[4rem] shadow-[0_32px_120px_rgba(0,0,0,0.5)] max-w-xl w-full backdrop-blur-3xl glass relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-primary/20 via-transparent to-transparent opacity-50" />

                <div className="relative z-10">
                  <div className="w-24 h-24 mx-auto mb-10 rounded-[2.5rem] bg-surface-4/60 border border-white/10 flex items-center justify-center shadow-2xl group-hover:scale-110 group-hover:rotate-6 transition-premium duration-700">
                    <Zap className="w-12 h-12 text-primary fill-primary/10 drop-shadow-[0_0_20px_hsla(var(--primary),0.6)]" />
                  </div>

                  <h3 className="text-4xl font-black text-white tracking-tighter mb-4 font-outfit">
                    Mission Control
                  </h3>
                  <p className="text-sm text-muted-foreground/80 mb-2 leading-relaxed font-medium">
                    The platform is primed and awaiting protocol deployment.
                  </p>
                  <p className="text-[10px] font-black text-primary/40 uppercase tracking-[0.3em] mb-12">
                    Initialize Workspace &bull; Deploy Core Modules
                  </p>

                  <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                    <button
                      onClick={() =>
                        useUIStore.getState().setToolbarModal("addExisting")
                      }
                      className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-8 py-4 text-[10px] font-black uppercase tracking-widest bg-primary text-white rounded-2xl transition-premium shadow-xl shadow-primary/20 hover:scale-105 active:scale-95"
                    >
                      <FolderPlus className="w-4 h-4" />
                      Initialize Module
                    </button>
                    <button
                      onClick={() => navigate("/library#templates")}
                      className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-8 py-4 text-[10px] font-black uppercase tracking-widest bg-white/5 text-muted-foreground border border-white/10 hover:text-white hover:bg-white/10 rounded-2xl transition-premium active:scale-95"
                    >
                      <BookOpen className="w-4 h-4" />
                      Load Template
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Inspector - Slide in/out */}
        <div
          className={cn(
            "border-l border-white/5 bg-surface-1/60 backdrop-blur-3xl transition-premium z-20",
            showInspector ? "shadow-[-20px_0_60px_rgba(0,0,0,0.3)]" : "",
          )}
          style={{ width: showInspector ? "420px" : "0px" }}
        >
          <ErrorBoundary
            fallback={(e) => (
              <div className="p-4 text-destructive overflow-auto break-words text-xs font-mono">
                Failed to load inspector: {sanitizeErrorMessage(e.message)}
              </div>
            )}
          >
            <Suspense fallback={<LoadingSpinner />}>
              <Inspector />
            </Suspense>
          </ErrorBoundary>
        </div>
      </div>

      {/* Bottom Terminal - Drawer */}
      <div
        className={cn(
          "border-t border-white/5 bg-surface-1/60 backdrop-blur-3xl text-foreground transition-premium z-30",
          terminalState !== "collapsed"
            ? "shadow-[0_-20px_60px_rgba(0,0,0,0.3)]"
            : "",
        )}
        style={{ height: `${terminalHeight}px` }}
      >
        <ErrorBoundary
          fallback={
            <div className="p-4 text-xs text-destructive">
              Failed to load terminal.
            </div>
          }
        >
          <Suspense fallback={<LoadingSpinner />}>
            <Terminal />
          </Suspense>
        </ErrorBoundary>
      </div>

      <KeyboardShortcutsHelp />
    </div>
  );
}

export default Workspace;
