import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import Dashboard from "./dashboard";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { loadWorkflowById } from "@/lib/workflowLoader";

const mockNavigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// Mock the modules that cause issues in test environment
vi.mock("@/lib/graphqlClient", () => ({
  graphqlRequest: vi.fn(),
  graphqlFetcher: vi.fn(() => vi.fn()),
  listAgents: vi.fn().mockResolvedValue([]),
  listActors: vi.fn().mockResolvedValue([]),
  subscribeExecution: vi.fn(() => vi.fn()),
  subscribeWorkflowExecutions: vi.fn(() => vi.fn()),
  gql: (strings: TemplateStringsArray, ..._values: unknown[]) =>
    strings.join(""),
}));

vi.mock("@/lib/workflowLoader", () => ({
  loadWorkflowById: vi.fn(),
}));

// Mock generated graphql hooks — Dashboard uses these, not graphqlRequest directly
let mockWorkflows: unknown[] = [];
let mockActors: unknown[] = [];
let mockLatestExecutions: unknown[] = [];
vi.mock("@/generated/graphql", () => ({
  useWorkflowsQuery: vi.fn(
    (_vars: unknown, opts?: { select?: (d: any) => any }) => {
      const raw = { workflows: mockWorkflows };
      return {
        data: opts?.select ? opts.select(raw) : raw,
        isLoading: false,
      };
    },
  ),
  useListActorsQuery: vi.fn(
    (_vars: unknown, opts?: { select?: (d: any) => any }) => {
      const raw = { actors: mockActors };
      return {
        data: opts?.select ? opts.select(raw) : raw,
        isLoading: false,
      };
    },
  ),
  useLatestWorkflowExecutionsQuery: vi.fn(
    (_vars: unknown, opts?: { select?: (d: any) => any }) => {
      const raw = { latestWorkflowExecutions: mockLatestExecutions };
      return {
        data: opts?.select ? opts.select(raw) : raw,
        isLoading: false,
      };
    },
  ),
  useGetAllWorkflowStatsQuery: vi.fn(() => ({
    data: null,
    isLoading: false,
  })),
  useDeleteWorkflowMutation: vi.fn(() => ({
    mutateAsync: vi.fn(),
  })),
  useTriggerWorkflowMutation: vi.fn(() => ({
    mutateAsync: vi.fn(),
  })),
  useGetApprovalsQuery: vi.fn(() => ({
    data: null,
    isLoading: false,
  })),
  useMySchedulesQuery: vi.fn(() => ({
    data: null,
    isLoading: false,
  })),
}));

vi.mock("@/store/workflowStore", () => ({
  useWorkflowStore: vi.fn(() => ({
    clearWorkflow: vi.fn(),
  })),
}));

vi.mock("@/store/executionStore", () => ({
  usePersistedExecutionStore: vi.fn((_selector) => {
    // Basic mock for execution store
    return {};
  }),
}));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

const renderWithProviders = (ui: React.ReactNode) => {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("Dashboard", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    queryClient.clear();
    mockWorkflows = [];
    mockActors = [];
    mockLatestExecutions = [];
  });

  it("renders loading state initially", async () => {
    // Override the hook to return loading state — import the mock dynamically
    const genGraphql = await import("@/generated/graphql");
    vi.mocked(genGraphql.useWorkflowsQuery).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as any);
    vi.mocked(genGraphql.useListActorsQuery).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as any);
    vi.mocked(genGraphql.useLatestWorkflowExecutionsQuery).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as any);

    renderWithProviders(<Dashboard />);

    // Loading state now renders skeleton cards instead of a spinner text.
    expect(
      document.querySelector('[data-testid="skeleton-stat-row"]'),
    ).toBeInTheDocument();
  });

  it("renders empty state when no workflows exist", async () => {
    mockWorkflows = [];

    renderWithProviders(<Dashboard />);

    // Empty state was redesigned: heading "Initialize Workflow" + CTA.
    const emptyMsg = await screen.findByText(/Initialize Workflow/i);
    expect(emptyMsg).toBeInTheDocument();
  });

  it("renders list of workflows", async () => {
    mockWorkflows = [
      {
        id: "1",
        name: "Workflow Alpha",
        graphJson: '{"nodes":[], "edges":[]}',
      },
      {
        id: "2",
        name: "Workflow Beta",
        graphJson: '{"nodes":[], "edges":[]}',
      },
    ];

    renderWithProviders(<Dashboard />);

    expect(await screen.findByText("Workflow Alpha")).toBeInTheDocument();
    expect(await screen.findByText("Workflow Beta")).toBeInTheDocument();
  });

  it("filters workflows by search term", async () => {
    mockWorkflows = [
      { id: "1", name: "Apple", graphJson: '{"nodes":[], "edges":[]}' },
      { id: "2", name: "Banana", graphJson: '{"nodes":[], "edges":[]}' },
    ];

    renderWithProviders(<Dashboard />);

    expect(await screen.findByText("Apple")).toBeInTheDocument();
    expect(await screen.findByText("Banana")).toBeInTheDocument();

    const searchInput = screen.getByPlaceholderText(
      /SEARCH AUTOMATED PIPELINES/i,
    );
    fireEvent.change(searchInput, { target: { value: "app" } });

    expect(screen.getByText("Apple")).toBeInTheDocument();
    expect(screen.queryByText("Banana")).not.toBeInTheDocument();
  });

  it("navigates to editor on edit click", async () => {
    mockWorkflows = [
      {
        id: "1",
        name: "Test Workflow",
        graphJson: '{"nodes":[], "edges":[]}',
      },
    ];
    vi.mocked(loadWorkflowById).mockResolvedValue({
      id: "1",
      name: "Test Workflow",
    } as any);

    renderWithProviders(<Dashboard />);

    // The edit action is now an icon button titled "Configure Architecture".
    const editButton = await screen.findByTitle(/Configure Architecture/i);
    await act(async () => {
      fireEvent.click(editButton);
    });

    expect(mockNavigate).toHaveBeenCalledWith("/editor/1");
  });
});
