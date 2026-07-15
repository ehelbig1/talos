import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { GoogleCloudWatchChannels } from "./GoogleCloudWatchChannels";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

const ACTIVE_INTEGRATION = {
  id: "11111111-1111-1111-1111-111111111111",
  account_email: "owner@example.com",
  is_active: true,
  tier: "read",
};

const WRITE_TIER_INTEGRATION = {
  id: "22222222-2222-2222-2222-222222222222",
  account_email: "owner@example.com",
  is_active: true,
  tier: "write",
};

function mockIntegrations(list: unknown[]) {
  server.use(
    http.get("*/api/gcp/integrations", () =>
      HttpResponse.json({ success: true, data: list }),
    ),
  );
}

function mockWatches(list: unknown[]) {
  server.use(
    http.get("*/api/gcp/watch-channels", () =>
      HttpResponse.json({ success: true, data: list }),
    ),
  );
}

describe("GoogleCloudWatchChannels", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when there is no connected GCP integration", async () => {
    mockIntegrations([]);
    mockWatches([]);
    render(<GoogleCloudWatchChannels />);
    // The panel gates itself off entirely with no integration.
    await waitFor(() =>
      expect(
        screen.queryByText(/Google Cloud Watch Channels/i),
      ).not.toBeInTheDocument(),
    );
  });

  it("shows the empty-state CTA when connected but no watches exist", async () => {
    mockIntegrations([ACTIVE_INTEGRATION]);
    mockWatches([]);
    render(<GoogleCloudWatchChannels />);
    await waitFor(() =>
      expect(
        screen.getByText(/No Google Cloud watches yet/i),
      ).toBeInTheDocument(),
    );
  });

  it("creates a watch and surfaces the push endpoint once", async () => {
    mockIntegrations([ACTIVE_INTEGRATION]);
    mockWatches([]);
    const pushEndpoint =
      "https://talos.example.com/api/gcp/pubsub/tok-secret-123";
    server.use(
      http.post("*/api/gcp/watch-channels", async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        expect(body.integration_id).toBe(ACTIVE_INTEGRATION.id);
        expect(body.expected_sa_email).toBe(
          "pusher@my-proj.iam.gserviceaccount.com",
        );
        return HttpResponse.json({
          success: true,
          data: { channel_uuid: "c1", push_endpoint: pushEndpoint },
        });
      }),
    );

    render(<GoogleCloudWatchChannels />);

    // Open the create dialog (empty-state CTA — unambiguous vs the
    // header "Create" button).
    const createBtn = await screen.findByRole("button", {
      name: /Create your first GCP watch/i,
    });
    fireEvent.click(createBtn);

    // Fill the service-account email and submit.
    const saInput = await screen.findByPlaceholderText(/gserviceaccount\.com/i);
    fireEvent.change(saInput, {
      target: { value: "pusher@my-proj.iam.gserviceaccount.com" },
    });
    const submit = screen.getByRole("button", { name: /Create watch/i });
    fireEvent.click(submit);

    // The push endpoint is surfaced once, prominently, with a copy button.
    await waitFor(() =>
      expect(screen.getByText(pushEndpoint)).toBeInTheDocument(),
    );
    expect(screen.getByText(/copy your push endpoint/i)).toBeInTheDocument();
  });

  it("badges a write-tier (provisioning) integration distinctly from a read-tier one", async () => {
    // Phase C: the same Google account can hold both a read row and a write
    // row — both must render, each with its own tier badge.
    mockIntegrations([ACTIVE_INTEGRATION, WRITE_TIER_INTEGRATION]);
    mockWatches([]);
    render(<GoogleCloudWatchChannels />);

    await waitFor(() =>
      expect(
        screen.getByText(/No Google Cloud watches yet/i),
      ).toBeInTheDocument(),
    );

    expect(screen.getByText("Provisioning")).toBeInTheDocument();
    expect(screen.getByText("Read-only")).toBeInTheDocument();
  });

  it("labels the account chips as OAuth consents, distinct from watch channels", async () => {
    // Regression (2026-07-15): unlabeled account chips inside the Watch
    // Channels panel were read as "a watch channel was created" when the
    // channel table was in fact empty. The chip row must carry an explicit
    // caption saying these are consents, not channels.
    mockIntegrations([ACTIVE_INTEGRATION, WRITE_TIER_INTEGRATION]);
    mockWatches([]);
    render(<GoogleCloudWatchChannels />);

    await waitFor(() =>
      expect(screen.getByText(/Connected accounts/i)).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/OAuth consents only; not watch channels/i),
    ).toBeInTheDocument();
  });
});
