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

function feed(teacherAudit: unknown = null) {
  return {
    modelId: "m-1",
    lifecycleState: "shadow",
    shadowAgreement: 0.942,
    shadowObservations: 121,
    shadowEpoch: 2,
    teacherAudit,
    // Server-supplied class list. `follow_up` appears NOWHERE in `pending` —
    // that is the point: it must still be offerable.
    labelVocabulary: ["archive", "follow_up", "to_read"],
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

  it("offers a class the feed never proposes, and posts it", async () => {
    // The reported bug: fast said to_read, the teacher said archive, and the
    // reviewer judged follow_up — but the buttons were derived from the feed,
    // so no follow_up button existed and the most informative correction
    // available (BOTH models wrong) could not be recorded at all.
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
    const followUpBtn = await screen.findByRole("button", {
      name: /follow_up/i,
    });
    fireEvent.click(followUpBtn);

    await waitFor(() => expect(captured).not.toBeNull());
    expect(captured).toMatchObject({
      disagreementId: "d-1",
      correctLabel: "follow_up",
    });
  });

  it("still renders label buttons when the server sends no vocabulary", async () => {
    // Back-compat: an older server omitting labelVocabulary must degrade to
    // the feed-derived labels, not to a card with no way to act on it.
    mockGraphql({
      mlModelDisagreements: () => ({
        data: {
          mlModelDisagreements: { ...feed(), labelVocabulary: [] },
        },
      }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);
    expect(
      await screen.findByRole("button", { name: /archive/i }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: /to_read/i }),
    ).toBeInTheDocument();
  });

  it("shows an error state (never 'all caught up') when the queue query fails", async () => {
    mockGraphql({
      // Feed query errors — e.g. schema/query version skew or a decrypt
      // failure. Pre-fix this rendered the same empty state as a
      // genuinely clear queue, hiding pending work behind "All caught
      // up" while the model list still showed a pending badge.
      mlModelDisagreements: () => new HttpResponse(null, { status: 500 }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    expect(
      await screen.findByText(/could not load the review queue/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/all caught up/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("shows 'not audited yet' when teacherAudit is null", async () => {
    mockGraphql({
      mlModelDisagreements: () => ({
        data: { mlModelDisagreements: feed(null) },
      }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    expect(await screen.findByText(/not audited yet/i)).toBeInTheDocument();
  });

  it("shows audit progress while the teacher audit is running", async () => {
    mockGraphql({
      mlModelDisagreements: () => ({
        data: {
          mlModelDisagreements: feed({
            status: "running",
            started_at: new Date("2026-07-19").toISOString(),
            done: 30,
            gold_rows: 80,
          }),
        },
      }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    expect(await screen.findByText(/auditing/i)).toBeInTheDocument();
    expect(screen.getByText("30/80")).toBeInTheDocument();
  });

  it("shows accuracy, per-class agreement, and parse_failed for a completed audit", async () => {
    mockGraphql({
      mlModelDisagreements: () => ({
        data: {
          mlModelDisagreements: feed({
            status: "complete",
            audited_at: new Date("2026-07-19T12:00:00Z").toISOString(),
            total: 40,
            compared: 40,
            agree: 34,
            parse_failed: 2,
            accuracy: 0.85,
            per_class: {
              archive: { n: 20, agree: 18 },
              follow_up: { n: 20, agree: 16 },
            },
            mismatches: [],
            teacher: { provider: "ollama", model: "qwen3.6", few_shot_used: 8 },
          }),
        },
      }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    expect(await screen.findByText("85.0%")).toBeInTheDocument();
    expect(screen.getByText(/parse failed/i)).toBeInTheDocument();
    // Per-class row label. Disambiguated from the correct-label BUTTON of the
    // same name, which now renders because `follow_up` is in the model's
    // vocabulary — assert a non-button node carries the text.
    expect(
      screen
        .getAllByText("follow_up")
        .some((n) => n.closest("button") === null),
    ).toBe(true);
    expect(screen.getByText("18/20")).toBeInTheDocument();
    expect(screen.getByText(/qwen3\.6/)).toBeInTheDocument();
  });

  it("shows a failure message when the teacher audit fails", async () => {
    mockGraphql({
      mlModelDisagreements: () => ({
        data: {
          mlModelDisagreements: feed({
            status: "failed",
            error: "teacher unavailable (repeated call failures)",
            failed_at: new Date("2026-07-19").toISOString(),
          }),
        },
      }),
      mlModels: () => ({ data: { mlModels: models() } }),
    });

    render(<ModelReview />);

    expect(await screen.findByText(/audit failed/i)).toBeInTheDocument();
    expect(
      screen.getByText(/teacher unavailable \(repeated call failures\)/i),
    ).toBeInTheDocument();
  });
});
