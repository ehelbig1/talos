import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";
import {
  SmartClassifierConfig,
  isSmartClassifierModule,
} from "./SmartClassifierConfig";
import { useWorkflowStore } from "@/store/workflowStore";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

function mockGraphql(
  handlers: Record<string, (vars: Record<string, unknown>) => unknown>,
) {
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as GqlBody;
      for (const [needle, resolve] of Object.entries(handlers)) {
        if (body.query.includes(needle)) {
          const value = resolve(body.variables ?? {});
          if (value instanceof HttpResponse) return value;
          return HttpResponse.json(value as Record<string, unknown>);
        }
      }
      return HttpResponse.json({ data: {} });
    }),
  );
}

function actorsResponse() {
  return {
    data: {
      actors: [
        {
          id: "actor-1",
          name: "personal-assistant",
          description: null,
          status: "active",
          maxCapabilityWorld: "agent-node",
          totalBudgetUsd: null,
          spentBudgetUsd: 0,
          workflowCount: 1,
          executionCount: 0,
          createdAt: "2026-07-01",
          updatedAt: "2026-07-01",
        },
        {
          id: "actor-archived",
          name: "old-actor",
          description: null,
          status: "archived",
          maxCapabilityWorld: "agent-node",
          totalBudgetUsd: null,
          spentBudgetUsd: 0,
          workflowCount: 0,
          executionCount: 0,
          createdAt: "2026-07-01",
          updatedAt: "2026-07-01",
        },
      ],
    },
  };
}

describe("isSmartClassifierModule", () => {
  const contractSchema = {
    required: ["MODEL_NAME", "SYSTEM_PROMPT", "LABELS"],
    properties: {},
  };

  it("matches the catalog display name a loaded node actually carries", () => {
    // workflowLoader sets moduleName = module display name; catalog modules
    // surface "Smart Classifier", NOT the slug — this is the real load path.
    expect(isSmartClassifierModule("Smart Classifier")).toBe(true);
  });
  it("matches the slug and underscore/case variants", () => {
    expect(isSmartClassifierModule("smart-classifier")).toBe(true);
    expect(isSmartClassifierModule("smart_classifier")).toBe(true);
    expect(isSmartClassifierModule("SMART CLASSIFIER")).toBe(true);
  });
  it("does not match other modules or empty", () => {
    expect(isSmartClassifierModule("hybrid-classify-inbox")).toBe(false);
    expect(isSmartClassifierModule("LLM Inference")).toBe(false);
    expect(isSmartClassifierModule(undefined)).toBe(false);
    expect(isSmartClassifierModule("")).toBe(false);
  });
  it("identifies by config contract when a schema is present (rename-stable)", () => {
    // A renamed catalog module keeps its schema → keeps its panel.
    expect(isSmartClassifierModule("My Email Sorter", contractSchema)).toBe(
      true,
    );
  });
  it("refuses a name-alike module whose schema is NOT the contract", () => {
    // A user sandbox module named "smart_classifier" with different config
    // must get the raw JSON editor, not this panel (whose provisioning
    // side effects would be wrong for it).
    expect(
      isSmartClassifierModule("smart_classifier", {
        required: ["THRESHOLD", "WEBHOOK_URL"],
      }),
    ).toBe(false);
  });
  it("falls back to name matching only when no schema is declared", () => {
    expect(isSmartClassifierModule("Smart Classifier", undefined)).toBe(true);
    expect(isSmartClassifierModule("Smart Classifier", {})).toBe(true);
  });
});

describe("SmartClassifierConfig", () => {
  beforeEach(() => {
    // The workflow must be saved (have an id) for provisioning to bind to it.
    useWorkflowStore.setState({ workflowId: "wf-1" });
  });

  it("provisions the model and binds the workflow actor, stamping MODEL_NAME", async () => {
    let provisionVars: Record<string, unknown> | null = null;
    let bindVars: Record<string, unknown> | null = null;
    mockGraphql({
      ListActorSummaries: () => actorsResponse(),
      ProvisionMlClassifier: (vars) => {
        provisionVars = vars;
        return {
          data: {
            provisionMlClassifier: {
              modelName: "email-urgency",
              modelId: "model-1",
              datasetId: "ds-1",
              lifecycleState: "llm_only",
              alreadyExisted: false,
              localityWarning: null,
            },
          },
        };
      },
      SetWorkflowActorId: (vars) => {
        bindVars = vars;
        return { data: { setWorkflowActorId: true } };
      },
    });

    const updateNodeData = vi.fn();
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ LABELS: ["urgent", "normal"], SYSTEM_PROMPT: "Classify." }}
        updateNodeData={updateNodeData}
      />,
    );

    // Archived actors are filtered out of the picker.
    await screen.findByRole("option", { name: "personal-assistant" });
    expect(
      screen.queryByRole("option", { name: "old-actor" }),
    ).not.toBeInTheDocument();

    // Name + actor selection.
    fireEvent.change(screen.getByPlaceholderText("support-email-urgency"), {
      target: { value: "email-urgency" },
    });
    fireEvent.change(screen.getByRole("combobox"), {
      target: { value: "actor-1" },
    });

    const btn = screen.getByRole("button", { name: /set up classifier/i });
    await waitFor(() => expect(btn).not.toBeDisabled());
    fireEvent.click(btn);

    await waitFor(() => expect(bindVars).not.toBeNull());
    expect(provisionVars).toMatchObject({
      name: "email-urgency",
      labels: ["urgent", "normal"],
      actorId: "actor-1",
      allowExternalLlm: false,
    });
    expect(bindVars).toMatchObject({
      workflowId: "wf-1",
      actorId: "actor-1",
    });
    // MODEL_NAME stamped into the node config.
    await waitFor(() =>
      expect(updateNodeData).toHaveBeenCalledWith(
        "node-1",
        expect.objectContaining({
          config: expect.objectContaining({ MODEL_NAME: "email-urgency" }),
        }),
      ),
    );
  });

  it("disables setup until name, 2+ labels, and an actor are provided", async () => {
    mockGraphql({ ListActorSummaries: () => actorsResponse() });
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ LABELS: ["urgent"] }}
        updateNodeData={vi.fn()}
      />,
    );
    const btn = await screen.findByRole("button", {
      name: /set up classifier/i,
    });
    expect(btn).toBeDisabled();
    // With a valid name the reason advances to the missing-label requirement.
    fireEvent.change(screen.getByPlaceholderText("support-email-urgency"), {
      target: { value: "email-urgency" },
    });
    expect(screen.getByText(/at least 2 labels/i)).toBeInTheDocument();
    expect(btn).toBeDisabled();
  });

  it("blocks provisioning when the workflow is unsaved", async () => {
    useWorkflowStore.setState({ workflowId: null });
    mockGraphql({ ListActorSummaries: () => actorsResponse() });
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ LABELS: ["a", "b"] }}
        updateNodeData={vi.fn()}
      />,
    );
    expect(
      await screen.findByText(/save the workflow first/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /set up classifier/i }),
    ).toBeDisabled();
  });

  it("shows the lifecycle badge and review link once provisioned", async () => {
    mockGraphql({
      ListActorSummaries: () => actorsResponse(),
      MlModels: () => ({
        data: {
          mlModels: [
            {
              id: "model-1",
              name: "email-urgency",
              taskType: "classification",
              lifecycleState: "shadow",
              promotedVersion: null,
              promotedAccuracy: null,
              pendingDisagreements: 3,
            },
          ],
        },
      }),
    });
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ MODEL_NAME: "email-urgency", LABELS: ["a", "b"] }}
        updateNodeData={vi.fn()}
      />,
    );
    // Model name + "Learning" (shadow) badge.
    expect(await screen.findByText("email-urgency")).toBeInTheDocument();
    expect(await screen.findByText(/learning/i)).toBeInTheDocument();
    // Review link points at the ModelReview page.
    const link = await screen.findByRole("link", { name: /3 to review/i });
    expect(link).toHaveAttribute("href", "/models");
  });
});

describe("SmartClassifierConfig affordances", () => {
  beforeEach(() => {
    useWorkflowStore.setState({ workflowId: "wf-1" });
  });

  it("offers re-configure once provisioned, clearing MODEL_NAME", async () => {
    mockGraphql({
      ListActorSummaries: () => actorsResponse(),
      MlModels: () => ({ data: { mlModels: [] } }),
    });
    const updateNodeData = vi.fn();
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ MODEL_NAME: "clf", LABELS: ["a", "b"], MAX_TOKENS: 64 }}
        updateNodeData={updateNodeData}
      />,
    );
    const btn = await screen.findByRole("button", {
      name: /re-configure classifier/i,
    });
    fireEvent.click(btn);
    // MODEL_NAME removed; every OTHER key survives (the escape hatch must
    // not wipe the node's config).
    expect(updateNodeData).toHaveBeenCalledWith("node-1", {
      config: { LABELS: ["a", "b"], MAX_TOKENS: 64 },
    });
  });

  it("requires the explicit egress acknowledgment for an external provider", async () => {
    mockGraphql({ ListActorSummaries: () => actorsResponse() });
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ LABELS: ["a", "b"], PROVIDER: "anthropic" }}
        updateNodeData={vi.fn()}
      />,
    );
    fireEvent.change(
      await screen.findByPlaceholderText("support-email-urgency"),
      { target: { value: "clf" } },
    );
    // Wait for the async actors fetch before selecting — a change event on a
    // native select whose option hasn't rendered yet silently stays "".
    await screen.findByRole("option", { name: "personal-assistant" });
    fireEvent.change(screen.getAllByRole("combobox")[0], {
      target: { value: "actor-1" },
    });
    // Open the advanced section to reach the acknowledgment.
    fireEvent.click(screen.getByRole("button", { name: /llm fallback/i }));
    const setup = screen.getByRole("button", { name: /set up classifier/i });
    expect(setup).toBeDisabled();
    expect(
      screen.getByText(/confirm the external-provider data notice/i),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /acknowledge external provider data egress/i,
      }),
    );
    await waitFor(() => expect(setup).not.toBeDisabled());
  });

  it("exposes MAX_TOKENS in the advanced section", async () => {
    mockGraphql({
      ListActorSummaries: () => actorsResponse(),
      MlModels: () => ({ data: { mlModels: [] } }),
    });
    const updateNodeData = vi.fn();
    render(
      <SmartClassifierConfig
        nodeId="node-1"
        config={{ MODEL_NAME: "clf", LABELS: ["a", "b"] }}
        updateNodeData={updateNodeData}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /llm fallback/i }),
    );
    const field = screen.getByRole("spinbutton");
    expect(field).toHaveValue(256);
    fireEvent.change(field, { target: { value: "64" } });
    expect(updateNodeData).toHaveBeenCalledWith(
      "node-1",
      expect.objectContaining({
        config: expect.objectContaining({ MAX_TOKENS: 64 }),
      }),
    );
  });
});
