import React, { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Bot, GitBranch, Shuffle } from "lucide-react";
import { type ActorActionLogEntry } from "@/lib/graphqlApi";
import { LocalEmptyState, relativeTime } from "./shared";

/** Extract partner actor name + ID from a handoff summary string. */
function parseHandoffPartner(summary: string): {
  name: string;
  id: string | null;
} {
  const uuidRe =
    /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
  const match = summary.match(uuidRe);
  const id = match ? match[1] : null;
  const name =
    summary
      .replace(/\s*\([0-9a-f-]{36}\)\s*$/i, "")
      .replace(
        /^(Handed off to|Received handoff from|Sent to|Received from)\s*/i,
        "",
      )
      .trim() || summary;
  return { name, id };
}

export function HandoffsPanel({ entries }: { entries: ActorActionLogEntry[] }) {
  const navigate = useNavigate();

  const handoffs = entries.filter((e) =>
    e.actionType.toLowerCase().includes("handoff"),
  );
  const outbound = handoffs.filter(
    (e) => !e.actionType.toLowerCase().includes("received"),
  );
  const inbound = handoffs.filter((e) =>
    e.actionType.toLowerCase().includes("received"),
  );

  const partnerFreq = useMemo(() => {
    const freq = new Map<
      string,
      { name: string; id: string | null; outCount: number; inCount: number }
    >();
    for (const e of outbound) {
      const { name, id } = parseHandoffPartner(e.summary);
      const key = id ?? name;
      const cur = freq.get(key) ?? { name, id, outCount: 0, inCount: 0 };
      cur.outCount++;
      freq.set(key, cur);
    }
    for (const e of inbound) {
      const { name, id } = parseHandoffPartner(e.summary);
      const key = id ?? name;
      const cur = freq.get(key) ?? { name, id, outCount: 0, inCount: 0 };
      cur.inCount++;
      freq.set(key, cur);
    }
    return [...freq.values()].sort(
      (a, b) => b.outCount + b.inCount - (a.outCount + a.inCount),
    );
  }, [outbound, inbound]);

  if (handoffs.length === 0) {
    return (
      <div className="space-y-4">
        <LocalEmptyState
          icon={<Shuffle size={40} />}
          message="No handoffs recorded yet"
        />
        <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-5 py-4">
          <p className="text-muted-foreground/40 text-xs leading-relaxed">
            Handoffs let this actor delegate work to another actor
            mid-execution. Use the{" "}
            <code className="text-violet-300 bg-violet-500/10 px-1 rounded font-mono text-[11px]">
              handoff_to_actor
            </code>{" "}
            MCP tool or call it from a workflow node to start building a handoff
            chain.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Partner frequency */}
      {partnerFreq.length > 0 && (
        <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
          <h2 className="text-white font-medium text-sm mb-4 flex items-center gap-2">
            <Bot className="w-4 h-4 text-violet-400" />
            Partner Actors
            <span className="text-[10px] bg-surface-4/60 text-muted-foreground px-1.5 py-0.5 rounded-full ml-1">
              {partnerFreq.length}
            </span>
          </h2>
          <div className="space-y-2">
            {partnerFreq.map((p) => (
              <div
                key={p.id ?? p.name}
                className="flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <div className="w-6 h-6 rounded-full bg-violet-500/20 flex items-center justify-center shrink-0">
                    <Bot className="w-3 h-3 text-violet-400" />
                  </div>
                  {p.id ? (
                    <button
                      onClick={() => navigate(`/actors/${p.id}`)}
                      className="text-sm text-violet-300 hover:text-violet-200 transition-premium truncate"
                    >
                      {p.name}
                    </button>
                  ) : (
                    <span className="text-sm text-muted-foreground truncate">
                      {p.name}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 shrink-0 text-[11px]">
                  {p.outCount > 0 && (
                    <span className="text-violet-400" title="Outbound handoffs">
                      → {p.outCount}
                    </span>
                  )}
                  {p.inCount > 0 && (
                    <span className="text-emerald-400" title="Inbound handoffs">
                      ← {p.inCount}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {outbound.length > 0 && (
        <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
          <h2 className="text-white font-medium text-sm mb-4 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-violet-400" />
            Outbound Handoffs
            <span className="text-[10px] bg-surface-4/60 text-muted-foreground px-1.5 py-0.5 rounded-full ml-1">
              {outbound.length}
            </span>
          </h2>
          <div className="space-y-3">
            {outbound.map((e) => {
              const { name, id } = parseHandoffPartner(e.summary);
              return (
                <div
                  key={e.id}
                  className="flex items-start justify-between gap-4"
                >
                  <p className="text-muted-foreground text-sm">
                    <span className="text-violet-400 font-mono mr-1">→</span>
                    {id ? (
                      <button
                        onClick={() => navigate(`/actors/${id}`)}
                        className="text-violet-300 hover:text-violet-200 transition-premium"
                      >
                        {name}
                      </button>
                    ) : (
                      name
                    )}
                  </p>
                  <time className="text-muted-foreground/40 text-[11px] shrink-0">
                    {relativeTime(e.timestamp)}
                  </time>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {inbound.length > 0 && (
        <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
          <h2 className="text-white font-medium text-sm mb-4 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-emerald-400" />
            Inbound Handoffs
            <span className="text-[10px] bg-surface-4/60 text-muted-foreground px-1.5 py-0.5 rounded-full ml-1">
              {inbound.length}
            </span>
          </h2>
          <div className="space-y-3">
            {inbound.map((e) => {
              const { name, id } = parseHandoffPartner(e.summary);
              return (
                <div
                  key={e.id}
                  className="flex items-start justify-between gap-4"
                >
                  <p className="text-muted-foreground text-sm">
                    <span className="text-emerald-400 font-mono mr-1">←</span>
                    {id ? (
                      <button
                        onClick={() => navigate(`/actors/${id}`)}
                        className="text-emerald-300 hover:text-emerald-200 transition-premium"
                      >
                        {name}
                      </button>
                    ) : (
                      name
                    )}
                  </p>
                  <time className="text-muted-foreground/40 text-[11px] shrink-0">
                    {relativeTime(e.timestamp)}
                  </time>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
