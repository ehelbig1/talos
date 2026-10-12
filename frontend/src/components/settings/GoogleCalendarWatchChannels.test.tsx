import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { GoogleCalendarWatchChannels } from "./GoogleCalendarWatchChannels";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

// The workflow picker on a watch channel's row. Until 2026-10-12 the table
// had no control for the binding and did not show one that existed, so a
// channel that started a workflow on every calendar change looked the same
// as one that started nothing.

const INTEGRATION = {
  id: "11111111-1111-4111-8111-111111111111",
  email: "owner@example.com",
  is_active: true,
};
const CHANNEL = "22222222-2222-4222-8222-222222222222";
const ON_INVITE = "33333333-3333-4333-8333-333333333333";
const DAILY = "44444444-4444-4444-8444-444444444444";
const GONE = "55555555-5555-4555-8555-555555555555";

function channel(workflowId?: string) {
  return {
    channel_uuid: CHANNEL,
    integration_id: INTEGRATION.id,
    calendar_id: "primary",
    google_channel_id: "google-channel-0001",
    webhook_url: "https://hooks.example.com/api/google-calendar/webhook",
    expiration: new Date(Date.now() + 5 * 24 * 3600 * 1000).toISOString(),
    has_sync_token: true,
    module_id: null,
    module_name: null,
    ...(workflowId ? { workflow_id: workflowId } : {}),
    last_message_number: 3,
    updated_at: new Date().toISOString(),
  };
}

/** The server's side of the panel: one channel whose binding a PUT changes. */
function serve(initial: string | undefined, refuse?: string) {
  let bound = initial;
  const puts: unknown[] = [];
  server.use(
    http.get("*/api/google-calendar/integrations", () =>
      HttpResponse.json({ success: true, data: [INTEGRATION] }),
    ),
    http.get("*/api/google-calendar/watch-channels", () =>
      HttpResponse.json({ success: true, data: [channel(bound)] }),
    ),
    http.put(
      `*/api/google-calendar/watch-channels/${CHANNEL}/workflow`,
      async ({ request }) => {
        const body = (await request.json()) as { workflow_id: string | null };
        puts.push(body);
        if (refuse) {
          return HttpResponse.json(
            { success: false, error: refuse },
            { status: 404 },
          );
        }
        bound = body.workflow_id ?? undefined;
        return HttpResponse.json({
          success: true,
          data: { channel_uuid: CHANNEL, workflow_id: body.workflow_id },
        });
      },
    ),
    http.post("*/graphql", () =>
      HttpResponse.json({
        data: {
          workflows: [
            { id: ON_INVITE, name: "on-invitation" },
            { id: DAILY, name: "daily-brief" },
          ],
        },
      }),
    ),
  );
  return puts;
}

async function picker(): Promise<HTMLSelectElement> {
  const select = (await screen.findByRole("combobox", {
    name: "Workflow started by primary",
  })) as HTMLSelectElement;
  // The list has loaded once the owner's workflows are offered.
  await waitFor(() =>
    expect(
      screen.getByRole("option", { name: "daily-brief" }),
    ).toBeInTheDocument(),
  );
  return select;
}

describe("GoogleCalendarWatchChannels workflow picker", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the workflow a channel is bound to, by name", async () => {
    serve(ON_INVITE);
    render(<GoogleCalendarWatchChannels />);
    const select = await picker();
    expect(select.value).toBe(ON_INVITE);
    expect(
      (
        screen.getByRole("option", {
          name: "on-invitation",
        }) as HTMLOptionElement
      ).selected,
    ).toBe(true);
  });

  it("shows an unbound channel as bound to nothing", async () => {
    serve(undefined);
    render(<GoogleCalendarWatchChannels />);
    const select = await picker();
    expect(select.value).toBe("");
  });

  it("binds the workflow picked, and clears the binding on None", async () => {
    const puts = serve(undefined);
    render(<GoogleCalendarWatchChannels />);
    const select = await picker();

    fireEvent.change(select, { target: { value: DAILY } });
    await waitFor(() => expect(puts).toEqual([{ workflow_id: DAILY }]));
    await waitFor(() => expect(select.value).toBe(DAILY));

    fireEvent.change(select, { target: { value: "" } });
    await waitFor(() =>
      expect(puts).toEqual([{ workflow_id: DAILY }, { workflow_id: null }]),
    );
    await waitFor(() => expect(select.value).toBe(""));
  });

  it("puts the picker back when the server refuses", async () => {
    const said = vi.spyOn(toast, "error");
    const puts = serve(ON_INVITE, "No such workflow.");
    render(<GoogleCalendarWatchChannels />);
    const select = await picker();

    fireEvent.change(select, { target: { value: DAILY } });
    await waitFor(() => expect(puts).toEqual([{ workflow_id: DAILY }]));
    // What the server holds is what is shown, and why is said.
    await waitFor(() => expect(select.value).toBe(ON_INVITE));
    await waitFor(() => expect(said).toHaveBeenCalledWith("No such workflow."));
  });

  it("does not show a bound channel as unbound when its workflow is not in the list", async () => {
    serve(GONE);
    render(<GoogleCalendarWatchChannels />);
    const select = await picker();
    expect(select.value).toBe(GONE);
    expect(
      screen.getByRole("option", { name: /^Not found \(55555555/ }),
    ).toBeInTheDocument();
  });
});
