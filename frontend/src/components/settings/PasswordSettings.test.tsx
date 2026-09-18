import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import PasswordSettings, { passwordFormProblem } from "./PasswordSettings";
import { describe, it, expect } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

/** Answers changePassword with `reply` and records every request sent. */
function captureChangePassword(reply: () => Record<string, unknown>) {
  const sent: GqlBody[] = [];
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as GqlBody;
      if (body.query.includes("changePassword")) {
        sent.push(body);
        return HttpResponse.json(reply());
      }
      return HttpResponse.json({ data: {} });
    }),
  );
  return sent;
}

function fill(current: string, next: string, confirm: string) {
  fireEvent.change(screen.getByLabelText("Current password"), {
    target: { value: current },
  });
  fireEvent.change(screen.getByLabelText("New password"), {
    target: { value: next },
  });
  fireEvent.change(screen.getByLabelText("Confirm new password"), {
    target: { value: confirm },
  });
  fireEvent.click(screen.getByRole("button", { name: "Change password" }));
}

describe("passwordFormProblem", () => {
  const good = "Rotated-Passphrase-2026";
  it("accepts a complete, matching, different new password", () => {
    expect(passwordFormProblem("old-password-1", good, good)).toBeNull();
  });
  it("names each problem", () => {
    expect(passwordFormProblem("", good, good)).toMatch(/current password/);
    expect(passwordFormProblem("x", "short", "short")).toMatch(/at least 12/);
    expect(passwordFormProblem("x", good, good + "!")).toMatch(/do not match/);
    expect(passwordFormProblem(good, good, good)).toMatch(/different/);
  });
  it("measures the upper bound in bytes, as bcrypt does", () => {
    // 36 two-byte characters: 36 characters, 72 bytes — allowed; 37 is not.
    const at = "é".repeat(36);
    const over = "é".repeat(37);
    expect(passwordFormProblem("x", at, at)).toBeNull();
    expect(passwordFormProblem("x", over, over)).toMatch(/72 bytes/);
  });
});

describe("PasswordSettings", () => {
  it("sends the current and new password and clears the form", async () => {
    const sent = captureChangePassword(() => ({
      data: { changePassword: true },
    }));
    render(<PasswordSettings />);
    fill(
      "old-password-1",
      "Rotated-Passphrase-2026",
      "Rotated-Passphrase-2026",
    );

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].variables).toEqual({
      input: {
        currentPassword: "old-password-1",
        newPassword: "Rotated-Passphrase-2026",
      },
    });
    await waitFor(() =>
      expect(screen.getByLabelText("Current password")).toHaveValue(""),
    );
  });

  it("refuses a mismatched confirmation without sending anything", async () => {
    const sent = captureChangePassword(() => ({
      data: { changePassword: true },
    }));
    render(<PasswordSettings />);
    fill(
      "old-password-1",
      "Rotated-Passphrase-2026",
      "Rotated-Passphrase-2027",
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The new passwords do not match.",
    );
    expect(sent).toHaveLength(0);
  });

  it("keeps the form after a server refusal", async () => {
    const sent = captureChangePassword(() => ({
      errors: [{ message: "Current password is incorrect." }],
      data: null,
    }));
    render(<PasswordSettings />);
    fill(
      "wrong-password-1",
      "Rotated-Passphrase-2026",
      "Rotated-Passphrase-2026",
    );

    await waitFor(() => expect(sent).toHaveLength(1));
    // Nothing was cleared, so the user can correct the current password.
    expect(screen.getByLabelText("New password")).toHaveValue(
      "Rotated-Passphrase-2026",
    );
  });
});
