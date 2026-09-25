/**
 * The shared-socket hub (package DV), driven through the PRODUCTION helpers
 * in `graphqlClient.ts` against a scripted fake `WebSocket`. On the pre-DV
 * tree the first case fails by construction: three subscriptions opened
 * three sockets.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/session", () => ({
  currentRefreshEpoch: vi.fn(() => 7),
  isAuthErrorMessage: (m: unknown) =>
    String(m ?? "").includes("Authentication required") ||
    String(m ?? "").includes("Not authenticated") ||
    String(m ?? "").includes("expired"),
  recoverSession: vi.fn(async () => true),
  seedCsrfCookie: vi.fn(async () => {}),
  ensureCsrfCookie: vi.fn(async () => {}),
}));

import { recoverSession } from "@/lib/session";
import {
  subscribeDlqUpdates,
  subscribeExecution,
  subscribeWorkflowExecutions,
} from "../graphqlClient";
import { resetSubscriptionHubForTests } from "../wsHub";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readyState = 0;
  sent: Array<Record<string, unknown>> = [];
  closes: Array<{ code?: number; reason?: string }> = [];
  onopen: ((e: unknown) => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  constructor(
    public url: string,
    public protocol: string,
  ) {
    FakeWebSocket.instances.push(this);
  }
  send(text: string) {
    this.sent.push(JSON.parse(text));
  }
  close(code?: number, reason?: string) {
    this.readyState = 3;
    this.closes.push({ code, reason });
  }
  // ── test-side controls ──
  open() {
    this.readyState = 1;
    this.onopen?.({});
  }
  ack() {
    this.onmessage?.({ data: JSON.stringify({ type: "connection_ack" }) });
  }
  emit(frame: Record<string, unknown>) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
  serverClose(code: number) {
    this.readyState = 3;
    this.onclose?.({ code });
  }
  starts() {
    return this.sent.filter((f) => f.type === "start");
  }
  stops() {
    return this.sent.filter((f) => f.type === "stop");
  }
}

function frames(ws: FakeWebSocket, type: string) {
  return ws.sent.filter((f) => f.type === type);
}

describe("one shared WebSocket for every subscription", () => {
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
    vi.stubGlobal("window", {
      location: { protocol: "http:", host: "localhost:3000" },
    });
    resetSubscriptionHubForTests();
    vi.mocked(recoverSession).mockClear();
    vi.mocked(recoverSession).mockResolvedValue(true);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("three subscriptions open ONE socket, start with distinct ids after the ack, and route data by id", () => {
    const seen: Record<string, unknown[]> = { exec: [], wf: [], dlq: [] };
    const unExec = subscribeExecution("e1", (ev) => seen.exec.push(ev));
    const unWf = subscribeWorkflowExecutions((ev) => seen.wf.push(ev));
    const unDlq = subscribeDlqUpdates((ev) => seen.dlq.push(ev));
    expect(FakeWebSocket.instances).toHaveLength(1);
    const ws = FakeWebSocket.instances[0];
    expect(ws.protocol).toBe("graphql-ws");

    ws.open();
    expect(frames(ws, "connection_init")).toHaveLength(1);
    expect(ws.starts()).toHaveLength(0);
    ws.ack();
    const starts = ws.starts();
    expect(starts).toHaveLength(3);
    const ids = starts.map((s) => s.id as string);
    expect(new Set(ids).size).toBe(3);

    // Data for the workflow subscription reaches ONLY its handler.
    const wfId = starts.find((s) =>
      String((s.payload as { query: string }).query).includes(
        "workflowExecutionUpdates",
      ),
    )!.id as string;
    ws.emit({
      type: "data",
      id: wfId,
      payload: { data: { workflowExecutionUpdates: { executionId: "x" } } },
    });
    expect(seen.wf).toEqual([{ executionId: "x" }]);
    expect(seen.exec).toEqual([]);
    expect(seen.dlq).toEqual([]);

    // Unsubscribing one sends `stop` for its id and leaves the socket up.
    unWf();
    expect(ws.stops().map((s) => s.id)).toEqual([wfId]);
    expect(ws.closes).toHaveLength(0);
    ws.emit({
      type: "data",
      id: wfId,
      payload: { data: { workflowExecutionUpdates: { executionId: "late" } } },
    });
    expect(seen.wf).toHaveLength(1);

    // The last one out closes the socket, once, cleanly.
    unExec();
    unDlq();
    expect(ws.closes).toEqual([{ code: 1000, reason: "idle" }]);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("two subscriptions of the SAME document are routed by id, not by data key", () => {
    // The execution monitor and the test modal both subscribe to
    // `executionUpdates` (same dataKey) for different executions: only the
    // id decides who gets an event.
    const a: unknown[] = [];
    const b: unknown[] = [];
    subscribeExecution("e-a", (ev) => a.push(ev));
    subscribeExecution("e-b", (ev) => b.push(ev));
    const ws = FakeWebSocket.instances[0];
    ws.open();
    ws.ack();
    const starts = ws.starts();
    expect(starts).toHaveLength(2);
    const idB = starts.find(
      (s) =>
        (s.payload as { variables: { execId: string } }).variables.execId ===
        "e-b",
    )!.id as string;
    ws.emit({
      type: "data",
      id: idB,
      payload: { data: { executionUpdates: { executionId: "e-b" } } },
    });
    expect(b).toEqual([{ executionId: "e-b" }]);
    expect(a).toEqual([]);
  });

  it("a subscription added while the socket is live starts immediately; one added after idle close reopens", () => {
    const un1 = subscribeDlqUpdates(() => {});
    const ws = FakeWebSocket.instances[0];
    ws.open();
    ws.ack();
    expect(ws.starts()).toHaveLength(1);
    const un2 = subscribeWorkflowExecutions(() => {});
    expect(ws.starts()).toHaveLength(2);
    expect(FakeWebSocket.instances).toHaveLength(1);
    un1();
    un2();
    expect(ws.closes).toHaveLength(1);
    subscribeDlqUpdates(() => {});
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it("an abnormal close reconnects with backoff and replays EVERY live subscription", () => {
    vi.useFakeTimers();
    subscribeDlqUpdates(() => {});
    subscribeWorkflowExecutions(() => {});
    const first = FakeWebSocket.instances[0];
    first.open();
    first.ack();
    expect(first.starts()).toHaveLength(2);
    first.serverClose(1006);
    expect(FakeWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);
    const second = FakeWebSocket.instances[1];
    second.open();
    second.ack();
    expect(second.starts()).toHaveLength(2);
    expect(second.starts().map((s) => s.id)).toEqual(
      first.starts().map((s) => s.id),
    );
  });

  it("an auth failure recovers the session ONCE through the connect-time epoch and reconnects on success", async () => {
    subscribeDlqUpdates(() => {});
    subscribeWorkflowExecutions(() => {});
    const first = FakeWebSocket.instances[0];
    first.open();
    first.ack();
    first.emit({
      type: "error",
      id: "1",
      payload: [{ message: "Authentication required" }],
    });
    expect(first.closes).toEqual([{ code: 4403, reason: "Forbidden" }]);
    expect(recoverSession).toHaveBeenCalledTimes(1);
    expect(recoverSession).toHaveBeenCalledWith(7);
    await Promise.resolve();
    await Promise.resolve();
    expect(FakeWebSocket.instances).toHaveLength(2);
    const second = FakeWebSocket.instances[1];
    second.open();
    second.ack();
    expect(second.starts()).toHaveLength(2);
  });

  it("a failed recovery leaves the subscriptions dormant rather than looping", async () => {
    vi.mocked(recoverSession).mockResolvedValue(false);
    subscribeDlqUpdates(() => {});
    const first = FakeWebSocket.instances[0];
    first.open();
    first.emit({ type: "connection_error", payload: { message: "nope" } });
    await Promise.resolve();
    await Promise.resolve();
    expect(recoverSession).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("a non-auth server refusal for one id does not touch the socket or the other subscriptions", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    subscribeDlqUpdates(() => {});
    const ws = FakeWebSocket.instances[0];
    ws.open();
    ws.ack();
    ws.emit({
      type: "error",
      id: "1",
      payload: [{ message: "Too many open subscriptions on this connection." }],
    });
    expect(ws.closes).toHaveLength(0);
    expect(recoverSession).not.toHaveBeenCalled();
    expect(err).toHaveBeenCalled();
    err.mockRestore();
  });

  it("after the 24 h lifetime the socket is closed and replaced through the ordinary reconnect", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-22T10:00:00Z"));
    subscribeDlqUpdates(() => {});
    const first = FakeWebSocket.instances[0];
    first.open();
    first.ack();
    vi.setSystemTime(new Date("2026-09-23T10:00:01Z"));
    first.emit({
      type: "data",
      id: "1",
      payload: { data: { dlqUpdates: {} } },
    });
    expect(first.closes).toEqual([
      { code: 1000, reason: "Max connection lifetime exceeded" },
    ]);
    first.serverClose(1000);
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it("a socket that opens and is closed before any ack stops after the pre-ack cap (no reset on open)", () => {
    // A disallowed Origin: the upgrade succeeds, then the server closes
    // with no `connection_error` (1005). Resetting the counter on `open`
    // made this reconnect every second forever.
    vi.useFakeTimers();
    subscribeDlqUpdates(() => {});
    for (let i = 0; i < 20; i++) {
      const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
      ws.open();
      ws.serverClose(1005);
      vi.advanceTimersByTime(60_000);
    }
    // The first socket plus MAX_ATTEMPTS_BEFORE_FIRST_ACK (5) reconnects.
    expect(FakeWebSocket.instances).toHaveLength(6);
  });

  it("an ack resets the attempt counter, so a later drop gets the full budget again", () => {
    vi.useFakeTimers();
    subscribeDlqUpdates(() => {});
    for (let i = 0; i < 4; i++) {
      const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
      ws.open();
      ws.serverClose(1005);
      vi.advanceTimersByTime(60_000);
    }
    const acked = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
    acked.open();
    acked.ack();
    acked.serverClose(1006);
    // Backoff restarts at 1 s rather than continuing at 16 s.
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(6);
  });

  it("a socket still refused after a successful recovery is rate-limited and then abandoned", async () => {
    vi.useFakeTimers();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    subscribeDlqUpdates(() => {});
    const flush = async () => {
      for (let i = 0; i < 4; i++) await Promise.resolve();
    };
    const refuseLatest = async () => {
      const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
      ws.open();
      ws.emit({ type: "connection_error", payload: { message: "nope" } });
      await flush();
    };
    await refuseLatest(); // refused → immediate recovery → reconnect
    expect(recoverSession).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    await refuseLatest(); // refused again: the next recovery waits
    expect(recoverSession).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(29_000);
    await flush();
    expect(recoverSession).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1_000);
    await flush();
    expect(recoverSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(3);
    await refuseLatest(); // second refusal after a successful recovery: stop
    vi.advanceTimersByTime(10 * 60_000);
    await flush();
    // Refusal → recovery → refusal → one more (rate-limited) recovery →
    // refusal → stop. Never a tight refresh loop.
    expect(recoverSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(3);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });
});
