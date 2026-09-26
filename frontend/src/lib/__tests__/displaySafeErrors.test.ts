/**
 * Server errors marked user-facing (`extensions.safe`) are shown as written;
 * the production whitelist reduced "Invalid 2FA code" and a delete refusal
 * naming its referencing workflows to a generic string.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { graphql, http, HttpResponse } from "msw";
import { server } from "../../../vitest.setup";
import { graphqlRequest } from "../graphqlClient";
import { DisplaySafeError, userFacingErrorMessage } from "../sanitize";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function respondWith(
  errors: Array<{ message: string; extensions?: Record<string, unknown> }>,
) {
  vi.stubGlobal("document", { cookie: "talos_csrf_token=t" });
  server.use(
    http.get("*/auth/csrf", () => HttpResponse.text("ok")),
    graphql.mutation("DeleteWorkflow", () =>
      HttpResponse.json({ data: null, errors }),
    ),
  );
}

describe("server-marked safe errors", () => {
  it("a marked refusal reaches the user verbatim in production", async () => {
    vi.stubEnv("PROD", true);
    const reason =
      "Workflow is referenced as a sub-workflow by: pa-chief-of-staff";
    respondWith([{ message: reason, extensions: { safe: true } }]);
    const err = await graphqlRequest(
      "mutation DeleteWorkflow { deleteWorkflow(id: 1) }",
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DisplaySafeError);
    expect(userFacingErrorMessage(err, "Failed")).toBe(reason);
  });

  it("control: an unmarked message is still collapsed in production", async () => {
    vi.stubEnv("PROD", true);
    respondWith([{ message: 'relation "workflows" does not exist' }]);
    const err = await graphqlRequest(
      "mutation DeleteWorkflow { deleteWorkflow(id: 1) }",
    ).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(DisplaySafeError);
    expect(userFacingErrorMessage(err, "Failed")).toBe(
      "An error occurred. Please try again.",
    );
  });

  it("one unmarked error in the batch disqualifies the whole message", async () => {
    vi.stubEnv("PROD", true);
    respondWith([
      { message: "Invalid 2FA code", extensions: { safe: true } },
      { message: "internal detail" },
    ]);
    const err = await graphqlRequest(
      "mutation DeleteWorkflow { deleteWorkflow(id: 1) }",
    ).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(DisplaySafeError);
  });

  it("a marked message is stripped of control characters and capped", () => {
    const e = new DisplaySafeError("a\u001b[31mb" + "x".repeat(600));
    expect(e.message).not.toContain("\u001b");
    expect(e.message.length).toBeLessThanOrEqual(501);
  });
});
