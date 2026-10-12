import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { GmailWatchChannels } from "./GmailWatchChannels";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

// The workflow picker on a Gmail watch's row. The list has always carried
// `workflow_id`; until 2026-10-12 the table did not show it and had no
// control for it.

const INTEGRATION = {
  id: "11111111-1111-4111-8111-111111111111",
  email_address: "owner@example.com",
  is_active: true,
};
const WATCH = "22222222-2222-4222-8222-222222222222";
const ON_MAIL = "33333333-3333-4333-8333-333333333333";
const TRIAGE = "44444444-4444-4444-8444-444444444444";

function serve(initial: string | null, moduleName: string | null = null) {
  let bound = initial;
  const puts: unknown[] = [];
  server.use(
    http.get("*/api/gmail/integrations", () =>
      HttpResponse.json({ success: true, data: [INTEGRATION] }),
    ),
    http.get("*/api/gmail/watch-channels", () =>
      HttpResponse.json({
        success: true,
        data: [
          {
            channel_uuid: WATCH,
            integration_id: INTEGRATION.id,
            email_address: INTEGRATION.email_address,
            topic_name: "projects/example/topics/gmail",
            history_id: 1001,
            label_ids: ["INBOX"],
            expiration: new Date(
              Date.now() + 5 * 24 * 3600 * 1000,
            ).toISOString(),
            module_id: moduleName
              ? "55555555-5555-4555-8555-555555555555"
              : null,
            module_name: moduleName,
            module_binding: moduleName ? "bound" : "none",
            workflow_id: bound,
            updated_at: new Date().toISOString(),
          },
        ],
      }),
    ),
    http.put(
      `*/api/gmail/watch-channels/${WATCH}/workflow`,
      async ({ request }) => {
        const body = (await request.json()) as { workflow_id: string | null };
        puts.push(body);
        bound = body.workflow_id;
        return HttpResponse.json({
          success: true,
          data: { channel_uuid: WATCH, workflow_id: body.workflow_id },
        });
      },
    ),
    http.post("*/graphql", () =>
      HttpResponse.json({
        data: {
          workflows: [
            { id: ON_MAIL, name: "on-new-mail" },
            { id: TRIAGE, name: "inbox-triage" },
          ],
        },
      }),
    ),
  );
  return puts;
}

async function picker(): Promise<HTMLSelectElement> {
  const select = (await screen.findByRole("combobox", {
    name: "Workflow started by owner@example.com",
  })) as HTMLSelectElement;
  await waitFor(() =>
    expect(
      screen.getByRole("option", { name: "inbox-triage" }),
    ).toBeInTheDocument(),
  );
  return select;
}

describe("GmailWatchChannels workflow picker", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the workflow a watch is bound to, and that its module is not run", async () => {
    serve(ON_MAIL, "label-new-mail");
    render(<GmailWatchChannels />);
    const select = await picker();
    expect(select.value).toBe(ON_MAIL);
    // On a Gmail watch the workflow is started INSTEAD of the module.
    expect(
      screen.getByText("not run while a workflow is bound"),
    ).toBeInTheDocument();
  });

  it("says nothing about the module when no workflow is bound", async () => {
    serve(null, "label-new-mail");
    render(<GmailWatchChannels />);
    const select = await picker();
    expect(select.value).toBe("");
    expect(
      screen.queryByText("not run while a workflow is bound"),
    ).not.toBeInTheDocument();
  });

  it("binds the workflow picked on this watch, and clears it on None", async () => {
    const puts = serve(null);
    render(<GmailWatchChannels />);
    const select = await picker();

    fireEvent.change(select, { target: { value: TRIAGE } });
    await waitFor(() => expect(puts).toEqual([{ workflow_id: TRIAGE }]));
    await waitFor(() => expect(select.value).toBe(TRIAGE));

    fireEvent.change(select, { target: { value: "" } });
    await waitFor(() =>
      expect(puts).toEqual([{ workflow_id: TRIAGE }, { workflow_id: null }]),
    );
  });
});
