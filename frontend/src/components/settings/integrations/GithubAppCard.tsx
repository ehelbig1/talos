/**
 * GitHub App card (RFC 0008) — not a registry OAuth provider; bespoke card.
 * Initiates the App install flow; the result toast is handled by the
 * github_connected / github_error query-param effect in the data hook.
 *
 * Strictly presentational — installations + connect handler come in via
 * props.
 */

import React from "react";
import { Github, Plus } from "lucide-react";
import type { GithubInstallation } from "./types";

export function GithubAppCard({
  installations,
  onConnect,
}: {
  installations: GithubInstallation[];
  onConnect: () => void;
}) {
  return (
    <div className="bg-surface-3/30 border border-white/5 rounded-[2rem] p-6 transition-premium hover:border-white/10 hover:shadow-2xl hover:shadow-primary/5 group relative overflow-hidden flex flex-col h-full">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
      <div className="flex items-start justify-between mb-8 relative z-10">
        <div className="flex items-center gap-5">
          <div
            className="w-14 h-14 rounded-2xl flex items-center justify-center text-white shadow-2xl transition-premium group-hover:scale-110 group-hover:rotate-3"
            style={{
              background: "linear-gradient(135deg, #24292f, #24292fdd)",
              boxShadow: "0 10px 25px -5px #24292f44",
            }}
          >
            <Github size={28} />
          </div>
          <div>
            <h3 className="text-xl font-black text-white tracking-tight">
              GitHub App
            </h3>
            <p className="text-[10px] text-muted-foreground/60 font-black uppercase tracking-widest mt-0.5">
              Scoped, auto-rotating repo access
            </p>
          </div>
        </div>
        <button
          onClick={onConnect}
          className="p-2.5 bg-white/5 border border-white/5 hover:bg-primary/10 hover:border-primary/20 hover:text-primary transition-premium rounded-xl active:scale-90"
          title="Install GitHub App"
        >
          <Plus size={18} />
        </button>
      </div>
      <div className="space-y-3 mt-auto relative z-10">
        {installations.length > 0 ? (
          installations.map((inst) => (
            <div
              key={inst.installation_id}
              className="bg-black/20 border border-white/5 rounded-2xl px-5 py-4 flex items-center justify-between shadow-inner"
            >
              <div className="flex flex-col">
                <span className="text-[11px] font-black text-white/80 tracking-tight">
                  {inst.account_login}
                </span>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                  <span className="text-[8px] text-success font-black uppercase tracking-widest">
                    {inst.repository_selection === "all"
                      ? "All repositories"
                      : "Selected repositories"}
                  </span>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="h-[68px] border border-dashed border-white/5 rounded-[1.5rem] flex items-center justify-center bg-black/10 group-hover:bg-black/20 transition-premium px-4">
            <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.25em] text-center leading-relaxed">
              Install to grant short-lived, per-repo tokens
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
