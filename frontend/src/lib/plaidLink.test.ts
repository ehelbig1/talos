import { afterEach, describe, expect, it, vi } from "vitest";
import { openPlaidLink, PLAID_LINK_SCRIPT } from "./plaidLink";

type Config = {
  token: string;
  onSuccess: (
    t: string,
    m: { institution?: { name?: string; institution_id?: string } | null },
  ) => void;
  onExit?: (
    err: { error_code?: string; display_message?: string | null } | null,
  ) => void;
};

/** A stand-in for Plaid's global that runs `behaviour` when Link opens. */
function fakePlaid(behaviour: (c: Config) => void) {
  const destroy = vi.fn();
  const created: Config[] = [];
  window.Plaid = {
    create: (config: Config) => {
      created.push(config);
      return { open: () => behaviour(config), destroy };
    },
  };
  return { created, destroy };
}

afterEach(() => {
  delete window.Plaid;
});

describe("openPlaidLink", () => {
  it("resolves with the public token and the bank Plaid named", async () => {
    const { created, destroy } = fakePlaid((c) =>
      c.onSuccess("public-sandbox-1", {
        institution: { name: "Wells Fargo", institution_id: "ins_127991" },
      }),
    );
    await expect(openPlaidLink("link-sandbox-1")).resolves.toEqual({
      publicToken: "public-sandbox-1",
      institution: { name: "Wells Fargo", institution_id: "ins_127991" },
    });
    expect(created[0].token).toBe("link-sandbox-1");
    expect(destroy).toHaveBeenCalled();
  });

  it("resolves null when the window is closed without connecting", async () => {
    fakePlaid((c) => c.onExit?.(null));
    await expect(openPlaidLink("link-sandbox-1")).resolves.toBeNull();
  });

  it("rejects with Plaid's own message when the sign-in fails", async () => {
    fakePlaid((c) =>
      c.onExit?.({
        error_code: "INVALID_CREDENTIALS",
        display_message: "The credentials were not correct.",
      }),
    );
    await expect(openPlaidLink("link-sandbox-1")).rejects.toThrow(
      "The credentials were not correct.",
    );
  });

  it("opens one window at a time: a second call while one is open is refused", async () => {
    let finish: (() => void) | undefined;
    const { created } = fakePlaid((c) => {
      finish = () => c.onExit?.(null);
    });
    const first = openPlaidLink("link-sandbox-1");
    await Promise.resolve(); // let the first reach Plaid.create
    await expect(openPlaidLink("link-sandbox-2")).rejects.toThrow(
      "already open",
    );
    expect(created).toHaveLength(1);
    finish?.();
    await expect(first).resolves.toBeNull();
    // Once it has closed, a new sign-in can start.
    fakePlaid((c) => c.onExit?.(null));
    await expect(openPlaidLink("link-sandbox-3")).resolves.toBeNull();
  });

  it("loads the script from Plaid's CDN, never a bundled copy", () => {
    expect(PLAID_LINK_SCRIPT).toBe(
      "https://cdn.plaid.com/link/v2/stable/link-initialize.js",
    );
  });
});
