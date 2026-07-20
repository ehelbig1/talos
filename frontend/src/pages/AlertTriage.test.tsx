import { render, screen, fireEvent, waitFor } from "@/test-utils";
import AlertTriage from "./AlertTriage";
import { describe, it, expect } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

function digest() {
  return {
    activeBySeverity: [
      { severity: "critical", count: 2 },
      { severity: "medium", count: 5 },
    ],
    activeBySource: [{ source: "gcp_monitoring", count: 7 }],
    newLast24H: 3,
    reopenedActive: 1,
  };
}

function alerts() {
  return [
    {
      id: "a-1",
      source: "gcp_monitoring",
      externalId: "ext-1",
      dedupKey: "dk-1",
      title: "Cloud Run job failing",
      resource: "projects/x/jobs/y",
      severity: "medium",
      severityRaw: "WARNING",
      triageSource: "classifier",
      triageConfidence: 0.8,
      correctedSeverity: null,
      status: "new",
      occurrenceCount: 3,
      firstSeen: new Date("2026-07-19").toISOString(),
      lastSeen: new Date("2026-07-20").toISOString(),
      reopenedAt: null,
      resolvedSource: null,
    },
  ];
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

describe("AlertTriage", () => {
  it("renders the digest chips and alert rows from query data", async () => {
    mockGraphql({
      opsAlertsDigest: () => ({ data: { opsAlertsDigest: digest() } }),
      opsAlerts: () => ({ data: { opsAlerts: alerts() } }),
    });

    render(<AlertTriage />);

    expect(
      await screen.findByText("Cloud Run job failing"),
    ).toBeInTheDocument();
    expect(screen.getByText(/2 critical/i)).toBeInTheDocument();
    expect(screen.getByText(/5 medium/i)).toBeInTheDocument();
    expect(screen.getByText(/3 new in 24h/i)).toBeInTheDocument();
    expect(screen.getByText(/1 reopened/i)).toBeInTheDocument();
    expect(screen.getByText(/×3/)).toBeInTheDocument();
  });

  it("fires CorrectOpsAlertSeverity with the right variables when a non-current chip is clicked", async () => {
    let captured: Record<string, unknown> | null = null;
    mockGraphql({
      correctOpsAlertSeverity: (vars) => {
        captured = vars;
        return { data: { correctOpsAlertSeverity: true } };
      },
      opsAlertsDigest: () => ({ data: { opsAlertsDigest: digest() } }),
      opsAlerts: () => ({ data: { opsAlerts: alerts() } }),
    });

    render(<AlertTriage />);

    // The row's current severity is "medium" — click "critical" instead.
    const criticalChip = await screen.findByRole("button", {
      name: /^critical$/i,
    });
    fireEvent.click(criticalChip);

    await waitFor(() => expect(captured).not.toBeNull());
    expect(captured).toMatchObject({ alertId: "a-1", severity: "critical" });
  });

  it("shows the empty state when there are no alerts", async () => {
    mockGraphql({
      opsAlertsDigest: () => ({
        data: {
          opsAlertsDigest: {
            activeBySeverity: [],
            activeBySource: [],
            newLast24H: 0,
            reopenedActive: 0,
          },
        },
      }),
      opsAlerts: () => ({ data: { opsAlerts: [] } }),
    });

    render(<AlertTriage />);

    expect(
      await screen.findByText(/no active alerts — all quiet/i),
    ).toBeInTheDocument();
  });
});
