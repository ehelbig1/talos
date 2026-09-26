/**
 * The briefings fold: a failed chunk is reported, never rendered as "no
 * briefings" (it was `.catch(() => [])`), and an actor that returned the
 * per-actor row cap is flagged as possibly missing older `/latest` rows.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/graphqlApi", () => ({
  listActors: vi.fn(),
  listActorsMemories: vi.fn(),
}));

import { listActors, listActorsMemories } from "@/lib/graphqlApi";
import {
  BRIEFING_KEY_SUFFIX,
  MEMORIES_PER_ACTOR_CAP,
  loadBriefings,
  summarizeBriefings,
} from "./Briefings";

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

describe("loadBriefings", () => {
  it("asks the server for `/latest` keys only, chunked at 100 actors", async () => {
    const actors = Array.from({ length: 101 }, (_, i) => ({
      id: `a${i}`,
      name: `A${i}`,
    }));
    vi.mocked(listActors).mockResolvedValue(actors as never);
    vi.mocked(listActorsMemories).mockImplementation(async (ids) =>
      ids.map((actorId) => ({
        actorId,
        memories: [mem("daily_brief/latest")],
      })),
    );
    const out = await loadBriefings();
    expect(BRIEFING_KEY_SUFFIX).toBe("/latest");
    expect(vi.mocked(listActorsMemories).mock.calls).toEqual([
      [actors.slice(0, 100).map((a) => a.id), "episodic", "/latest"],
      [["a100"], "episodic", "/latest"],
    ]);
    expect(out.briefings).toHaveLength(101);
    expect(out.unreadableActors).toEqual([]);
  });
});
