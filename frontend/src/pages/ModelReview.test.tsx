import { render, screen, fireEvent, waitFor } from "@/test-utils";
import ModelReview from "./ModelReview";
import { describe, it, expect } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

function models() {
  return [
    {
      id: "m-1",
      name: "inbox-classifier-personal",
      taskType: "classification",
      lifecycleState: "shadow",
      promotedVersion: 7,
      promotedAccuracy: 0.9375,
      pendingDisagreements: 2,
    },
  ];
}

function feed() {
  return {
    modelId: "m-1",
    lifecycleState: "shadow",
    shadowAgreement: 0.942,
    shadowObservations: 121,
    shadowEpoch: 2,
    pending: [
      {
        id: "d-1",
        exampleKey: "k1",
        featuresText:
          "Subject: 50% off plants\nFrom: deals@x.com\nSnippet: sale",
        kind: "divergence",
        fastLabel: "to_read",
        fastConfidence: 0.9,
        llmLabel: "archive",
        createdAt: new Date("2026-07-12").toISOString(),
      },
    ],
  };
}

function mockGraphql(
  handlers: Record<string, (vars: Record<string, unknown>) => unknown>,
) {
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as GqlBody;
      // Order matters: match the most specific operation substrings first.
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

describe("ModelReview", () => {
  it("lists models and shows the selected model's disagreements", async () => {
    mockGraphql({
      resolveMlDisagreement: () => ({ data: {} }),
      mlModelDisagreements: () => ({ data: { mlModelDisagreements: feed() } }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    // Model card + pending badge.
    expect(
      await screen.findByText("inbox-classifier-personal"),
    ).toBeInTheDocument();
    // The disagreement's decrypted features render in the queue.
    expect(await screen.findByText(/50% off plants/)).toBeInTheDocument();
    // Both candidate labels are offered as correct-label buttons.
    expect(
      screen.getByRole("button", { name: /archive/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /to_read/i }),
    ).toBeInTheDocument();
  });

  it("posts a correction with the chosen label when a label button is clicked", async () => {
    let captured: Record<string, unknown> | null = null;
    mockGraphql({
      resolveMlDisagreement: (vars) => {
        captured = vars;
        return {
          data: {
            resolveMlDisagreement: {
              disagreementId: "d-1",
              status: "resolved",
              correctionAppended: true,
            },
          },
        };
      },
      mlModelDisagreements: () => ({ data: { mlModelDisagreements: feed() } }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);
    const archiveBtn = await screen.findByRole("button", { name: /archive/i });
    fireEvent.click(archiveBtn);

    await waitFor(() => expect(captured).not.toBeNull());
    expect(captured).toMatchObject({
      disagreementId: "d-1",
      correctLabel: "archive",
    });
  });
});
