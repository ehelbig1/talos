import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useAddExistingNode } from "./useAddExistingNode";
import { graphqlRequest } from "@/lib/graphqlClient";

vi.mock("@/lib/graphqlClient", () => ({
  graphqlRequest: vi.fn(),
}));

describe("useAddExistingNode", () => {
  const mockModules = [
    {
      id: "1",
      name: "Module 1",
      config: '{"key": "val"}',
      sizeBytes: 100,
      contentHash: "abc",
      compiledAt: "2026-03-01",
    },
    {
      id: "2",
      name: "Module 2",
      config: "invalid-json",
      sizeBytes: 200,
      contentHash: "def",
      compiledAt: "2026-03-02",
    },
  ];

  beforeEach(() => {
    vi.mocked(graphqlRequest).mockResolvedValue({ myModules: mockModules });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("should fetch modules on mount", async () => {
    const { result } = renderHook(() => useAddExistingNode());

    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.modules).toEqual(mockModules);
    expect(graphqlRequest).toHaveBeenCalledTimes(1);
  });

  it("should handle fetch errors", async () => {
    vi.mocked(graphqlRequest).mockRejectedValue(new Error("Fetch failed"));

    const { result } = renderHook(() => useAddExistingNode());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe("Fetch failed");
    expect(result.current.modules).toEqual([]);
  });

  it("should allow selecting a module", async () => {
    const { result } = renderHook(() => useAddExistingNode());

    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.setSelectedModuleId("1");
    });

    expect(result.current.selectedModuleId).toBe("1");
    expect(result.current.getSelectedModule()).toEqual(mockModules[0]);
  });

  it("should parse module configuration JSON", async () => {
    const { result } = renderHook(() => useAddExistingNode());

    await waitFor(() => expect(result.current.loading).toBe(false));

    const config = result.current.parseConfig(mockModules[0]);
    expect(config).toEqual({ key: "val" });
  });

  it("should return empty object for invalid config JSON", async () => {
    const { result } = renderHook(() => useAddExistingNode());

    await waitFor(() => expect(result.current.loading).toBe(false));

    const config = result.current.parseConfig(mockModules[1]);
    expect(config).toEqual({});
  });
});
