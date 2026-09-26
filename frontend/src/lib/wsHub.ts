/**
 * ONE WebSocket per page for every GraphQL subscription (package DV,
 * 2026-09-22).
 *
 * Before this, `createSubscription` opened its OWN socket per subscription:
 * a dashboard load authenticated three sockets in 400 ms, each with its own
 * cookie handshake, its own reconnect backoff and its own 15-minute
 * token-expiry close — three times the controller sessions and three times
 * the reconnect storm for one page. The graphql-ws protocol multiplexes
 * many operations over one connection by `id`; the server lane does so
 * since the same package (each `start` is its own task, `stop` aborts it,
 * a per-socket cap bounds the count).
 *
 * The hub owns: the lazily opened socket, the registry of live
 * subscriptions keyed by a page-unique id, replay of every live `start`
 * after each `connection_ack` (so a reconnect resubscribes everything), a
 * `stop` on unsubscribe, an idle close when the last subscription leaves,
 * ONE auth-recovery site through the session's refresh epoch (DS's rule:
 * a refresh that succeeded since this socket was opened is reused, not
 * repeated), the reconnect backoff (5 attempts before a first ack, 30
 * after — MCP-865's numbers), and the 24 h maximum connection lifetime.
 *
 * The attempt counter resets on `connection_ack` ONLY, never on `open`: the
 * server closes a disallowed-Origin socket after the upgrade with no
 * `connection_error`, so an `open` proves nothing and resetting there made
 * the pre-ack cap unreachable (a reconnect every second, forever). Auth
 * recovery shares that counter, runs at most once per
 * `AUTH_RECOVERY_MIN_INTERVAL_MS`, and stops after the second refusal that
 * follows a successful recovery — a refreshed cookie the socket still does
 * not carry (different WS host, a proxy stripping `Cookie`) must not turn
 * into a refresh-token rotation loop.
 *
 * Imports only `config` and `session`, never a request wrapper, so it cannot
 * form a cycle with the callers it serves.
 */

import { config } from "@/config";
import {
  currentRefreshEpoch,
  isAuthErrorMessage,
  recoverSession,
} from "@/lib/session";

type Handler = (event: unknown) => void;

interface LiveSubscription {
  query: string;
  variables: Record<string, unknown>;
  onEvent: Handler;
  dataKey: string;
}

/** Close codes after which the hub never reconnects on its own: the
 *  auth-recovery path (which the hub itself initiates) decides instead. */
const AUTH_CLOSE_CODES = new Set([4403, 4401, 1008]);
const MAX_CONNECTION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_ATTEMPTS_BEFORE_FIRST_ACK = 5;
const MAX_ATTEMPTS_AFTER_ACK = 30;
const MAX_BACKOFF_MS = 30_000;
const AUTH_RECOVERY_MIN_INTERVAL_MS = 30_000;
/** Refusals after a SUCCESSFUL recovery (with no ack in between) before the
 *  hub gives up: the fresh cookie is evidently not reaching the socket. */
const MAX_REFUSALS_AFTER_RECOVERY = 2;

function wsBaseUrl(): string {
  // MCP-900: explicit VITE_WS_URL > derived from VITE_API_URL > page origin.
  const apiUrl = config.apiUrl || "";
  if (config.wsUrl) return config.wsUrl;
  if (apiUrl) {
    return apiUrl.replace("http://", "ws://").replace("https://", "wss://");
  }
  return `${window.location.protocol === "https:" ? "wss" : "ws"}://${
    window.location.host
  }`;
}

export class SubscriptionHub {
  private ws: WebSocket | null = null;
  private readonly subs = new Map<string, LiveSubscription>();
  private nextId = 1;
  /** `connection_ack` seen on the CURRENT socket. */
  private acked = false;
  /** ids whose `start` went out on the current socket. */
  private readonly started = new Set<string>();
  /** The hub closed the socket itself (idle, auth recovery, lifetime). */
  private closedByHub = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private connectedAt = 0;
  private epochAtConnect = 0;
  private lastRecoveryAt = Number.NEGATIVE_INFINITY;
  /** A recovery succeeded and no socket has been acked since. */
  private recoveredSinceAck = false;
  private refusalsAfterRecovery = 0;

  subscribe<T>(
    query: string,
    variables: Record<string, unknown>,
    onEvent: (event: T) => void,
    dataKey: string,
  ): () => void {
    const id = String(this.nextId++);
    this.subs.set(id, {
      query,
      variables,
      onEvent: onEvent as Handler,
      dataKey,
    });
    if (!this.ws) {
      this.connect();
    } else if (this.acked) {
      this.sendStart(id);
    }
    return () => this.unsubscribe(id);
  }

  /** Live subscriptions — for tests and diagnostics. */
  get size(): number {
    return this.subs.size;
  }

  private unsubscribe(id: string): void {
    if (!this.subs.delete(id)) return;
    if (
      this.ws &&
      this.acked &&
      this.ws.readyState === WebSocket.OPEN &&
      this.started.has(id)
    ) {
      this.ws.send(JSON.stringify({ id, type: "stop" }));
    }
    this.started.delete(id);
    if (this.subs.size === 0) this.closeIdle();
  }

  private closeIdle(): void {
    this.clearReconnect();
    const ws = this.ws;
    this.detach();
    this.reconnectAttempts = 0;
    if (ws) {
      this.closedByHub = true;
      ws.close(1000, "idle");
    }
  }

  private detach(): void {
    this.ws = null;
    this.acked = false;
    this.started.clear();
  }

  private clearReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private connect(): void {
    this.clearReconnect();
    const ws = new WebSocket(`${wsBaseUrl()}/ws`, "graphql-ws");
    this.ws = ws;
    this.acked = false;
    this.started.clear();
    this.closedByHub = false;
    this.connectedAt = Date.now();
    // DS's rule, at the connection: a refresh that succeeds after this
    // socket opened is what a later auth failure needs, not another one.
    this.epochAtConnect = currentRefreshEpoch();

    ws.onopen = () => {
      if (ws !== this.ws) return;
      ws.send(JSON.stringify({ type: "connection_init", payload: {} }));
    };
    ws.onmessage = (msg) => this.onMessage(ws, msg);
    ws.onclose = (event) => this.onClose(ws, event);
  }

  private sendStart(id: string): void {
    const sub = this.subs.get(id);
    if (!sub || !this.ws) return;
    this.ws.send(
      JSON.stringify({
        id,
        type: "start",
        payload: { query: sub.query, variables: sub.variables },
      }),
    );
    this.started.add(id);
  }

  private onMessage(ws: WebSocket, msg: MessageEvent): void {
    if (ws !== this.ws) return; // a socket the hub already replaced
    if (Date.now() - this.connectedAt > MAX_CONNECTION_LIFETIME_MS) {
      // Reconnect through the ordinary close path (not an auth code, not
      // closedByHub), which replays every live subscription.
      ws.close(1000, "Max connection lifetime exceeded");
      return;
    }
    let data: {
      type?: string;
      id?: string;
      payload?: {
        data?: Record<string, unknown> | null;
        errors?: Array<{ message?: unknown }>;
      } & Array<{ message?: unknown }>;
    };
    try {
      data = JSON.parse(msg.data as string);
    } catch {
      return;
    }
    switch (data.type) {
      case "connection_ack": {
        if (this.acked) return;
        this.acked = true;
        this.reconnectAttempts = 0;
        this.recoveredSinceAck = false;
        this.refusalsAfterRecovery = 0;
        for (const id of this.subs.keys()) this.sendStart(id);
        return;
      }
      case "data": {
        const sub = data.id ? this.subs.get(data.id) : undefined;
        if (!sub) return;
        // Surface GraphQL errors instead of swallowing them: a selection
        // the schema rejects returns `{data: null, errors}` and every event
        // would otherwise vanish with no signal.
        const payloadData = data.payload?.data;
        if (payloadData && payloadData[sub.dataKey] != null) {
          sub.onEvent(payloadData[sub.dataKey]);
        } else if (data.payload?.errors?.length) {
          console.error(
            `[subscription:${sub.dataKey}] server returned errors:`,
            data.payload.errors,
          );
        }
        return;
      }
      case "connection_error": {
        this.recoverAuth(ws);
        return;
      }
      case "error": {
        const errors = Array.isArray(data.payload) ? data.payload : [];
        if (errors.some((e) => isAuthErrorMessage(e?.message))) {
          this.recoverAuth(ws);
          return;
        }
        const sub = data.id ? this.subs.get(data.id) : undefined;
        console.error(
          `[subscription:${sub?.dataKey ?? data.id ?? "?"}] server refused:`,
          errors,
        );
        return;
      }
      default:
        return;
    }
  }

  /** The ONE auth-recovery site (MCP-864's parity with the REST 401 path):
   *  close, recover the session through the epoch, reconnect on success —
   *  bounded by the shared attempt counter and a minimum interval. */
  private recoverAuth(ws: WebSocket): void {
    this.closedByHub = true;
    this.detach();
    ws.close(4403, "Forbidden");
    if (this.recoveredSinceAck) {
      this.refusalsAfterRecovery++;
      if (this.refusalsAfterRecovery >= MAX_REFUSALS_AFTER_RECOVERY) {
        console.warn(
          "[subscriptions] still refused after a successful session refresh; not retrying",
        );
        return;
      }
    }
    if (this.reconnectAttempts >= MAX_ATTEMPTS_BEFORE_FIRST_ACK) return;
    this.reconnectAttempts++;
    const run = () => {
      this.reconnectTimer = null;
      if (this.subs.size === 0 || this.ws) return;
      this.lastRecoveryAt = Date.now();
      recoverSession(this.epochAtConnect).then((recovered) => {
        if (!recovered) return;
        this.recoveredSinceAck = true;
        if (this.subs.size > 0 && !this.ws) this.connect();
      });
      // Not recovered: the subscriptions stay registered and dormant; the
      // next `subscribe()` (or a page that signs in again) opens a socket.
    };
    const wait =
      this.lastRecoveryAt + AUTH_RECOVERY_MIN_INTERVAL_MS - Date.now();
    this.clearReconnect();
    if (wait > 0) this.reconnectTimer = setTimeout(run, wait);
    else run();
  }

  private onClose(ws: WebSocket, event: CloseEvent): void {
    if (ws !== this.ws) return;
    const wasAcked = this.acked;
    this.detach();
    if (this.closedByHub) return;
    if (AUTH_CLOSE_CODES.has(event.code)) return;
    if (this.subs.size === 0) return;

    // MCP-865: bounded backoff. Pre-ack failures suggest auth or proxy
    // misconfiguration — give up faster; a live session that dropped is
    // usually a network blip — retry more generously.
    const maxAttempts = wasAcked
      ? MAX_ATTEMPTS_AFTER_ACK
      : MAX_ATTEMPTS_BEFORE_FIRST_ACK;
    if (this.reconnectAttempts >= maxAttempts) return;
    const delay = Math.min(1000 * 2 ** this.reconnectAttempts, MAX_BACKOFF_MS);
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.subs.size > 0 && !this.ws) this.connect();
    }, delay);
  }
}

let hub = new SubscriptionHub();

/** Every subscription helper goes through this one socket. */
export function subscribeOverSharedSocket<T>(
  query: string,
  variables: Record<string, unknown>,
  onEvent: (event: T) => void,
  dataKey: string,
): () => void {
  return hub.subscribe(query, variables, onEvent, dataKey);
}

/** Tests only: a fresh hub with no socket and no subscriptions. */
export function resetSubscriptionHubForTests(): SubscriptionHub {
  hub = new SubscriptionHub();
  return hub;
}
