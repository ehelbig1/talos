/**
 * The briefings fold: a failed chunk is reported, never rendered as "no
 * briefings" (it was `.catch(() => [])`), and an actor that returned the
 * per-actor row cap is flagged as possibly missing older `/latest` rows.
 */
import { describe, expect, it } from "vitest";
import { MEMORIES_PER_ACTOR_CAP, summarizeBriefings } from "./Briefings";

const mem = (key: string, updatedAt = "2026-09-25T00:00:00Z") =>
  ({ key, value: '"x"', updatedAt }) as never;

describe("summarizeBriefings", () => {
  it("reports a failed chunk's actors instead of dropping them silently", () => {
    const out = summarizeBriefings(
      [
        { id: "a", name: "Alpha" },
        { id: "b", name: "Beta" },
      ],
      [
        {
          ids: ["a"],
          result: {
            status: "fulfilled",
            value: [{ actorId: "a", memories: [mem("daily_brief/latest")] }],
          },
        },
        { ids: ["b"], result: { status: "rejected", reason: new Error("x") } },
      ],
    );
    expect(out.briefings.map((b) => b.key)).toEqual(["daily_brief/latest"]);
    expect(out.unreadableActors).toEqual(["Beta"]);
    expect(out.possiblyTruncatedActors).toEqual([]);
  });

  it("flags an actor whose read hit the per-actor cap", () => {
    const memories = Array.from({ length: MEMORIES_PER_ACTOR_CAP }, (_, i) =>
      mem(`note/${i}`),
    );
    const out = summarizeBriefings(
      [{ id: "a", name: "Alpha" }],
      [
        {
          ids: ["a"],
          result: { status: "fulfilled", value: [{ actorId: "a", memories }] },
        },
      ],
    );
    expect(out.briefings).toEqual([]);
    expect(out.possiblyTruncatedActors).toEqual(["Alpha"]);
  });
});
