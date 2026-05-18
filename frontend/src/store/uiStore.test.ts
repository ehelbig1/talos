import { describe, it, expect, beforeEach } from "vitest";
import { useUIStore } from "./uiStore";

describe("uiStore", () => {
  beforeEach(() => {
    // Manually reset state because persist middleware can keep state between tests
    useUIStore.setState({
      showToolbox: true,
      toolboxMode: "full",
      showInspector: false,
      terminalState: "collapsed",
      selectedNodeId: null,
      favoriteTemplates: [],
      recentTemplates: [],
    });
  });

  it("toggles toolbox visibility", () => {
    expect(useUIStore.getState().showToolbox).toBe(true);
    useUIStore.getState().toggleToolbox();
    expect(useUIStore.getState().showToolbox).toBe(false);
  });

  it("updates toolbox mode", () => {
    useUIStore.getState().setToolboxMode("icon");
    expect(useUIStore.getState().toolboxMode).toBe("icon");
  });

  it("updates inspector visibility", () => {
    useUIStore.getState().setShowInspector(true);
    expect(useUIStore.getState().showInspector).toBe(true);
  });

  it("sets selected node and auto-opens inspector", () => {
    expect(useUIStore.getState().showInspector).toBe(false);
    useUIStore.getState().setSelectedNodeId("node-1");
    expect(useUIStore.getState().selectedNodeId).toBe("node-1");
    expect(useUIStore.getState().showInspector).toBe(true);
  });

  it("manages favorite templates", () => {
    useUIStore.getState().toggleFavorite("tpl-1");
    expect(useUIStore.getState().favoriteTemplates).toContain("tpl-1");

    useUIStore.getState().toggleFavorite("tpl-1");
    expect(useUIStore.getState().favoriteTemplates).not.toContain("tpl-1");
  });

  it("manages recent templates with a limit", () => {
    const store = useUIStore.getState();
    store.addRecentTemplate("tpl-1");
    store.addRecentTemplate("tpl-2");
    store.addRecentTemplate("tpl-3");
    store.addRecentTemplate("tpl-4");
    store.addRecentTemplate("tpl-5");
    store.addRecentTemplate("tpl-6");

    const recent = useUIStore.getState().recentTemplates;
    expect(recent).toHaveLength(5);
    expect(recent[0]).toBe("tpl-6");
    expect(recent).not.toContain("tpl-1");
  });

  it("moves existing recent template to front", () => {
    const store = useUIStore.getState();
    store.addRecentTemplate("tpl-1");
    store.addRecentTemplate("tpl-2");
    store.addRecentTemplate("tpl-1");

    const recent = useUIStore.getState().recentTemplates;
    expect(recent).toHaveLength(2);
    expect(recent[0]).toBe("tpl-1");
  });
});
