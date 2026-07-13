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
