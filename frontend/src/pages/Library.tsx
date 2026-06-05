import React, { Suspense, lazy, useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Box, BookOpen } from "lucide-react";

const Modules = lazy(() => import("./Modules"));
const Catalog = lazy(() => import("./Catalog"));

function TabLoading() {
  return (
    <div className="flex flex-col items-center justify-center py-40 space-y-8 animate-in fade-in duration-700">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-primary/10 rounded-full" />
        <div className="w-16 h-16 border-4 border-t-primary border-transparent rounded-full animate-spin absolute inset-0 shadow-[0_0_15px_hsla(var(--primary),0.3)]" />
      </div>
      <div className="flex flex-col items-center gap-2">
        <span className="text-xs font-black text-white/40 uppercase tracking-[0.4em] animate-pulse">
          Synchronizing Registry
        </span>
        <div className="flex gap-1">
          <div className="w-1 h-1 rounded-full bg-primary animate-bounce [animation-delay:-0.3s]" />
          <div className="w-1 h-1 rounded-full bg-primary animate-bounce [animation-delay:-0.15s]" />
          <div className="w-1 h-1 rounded-full bg-primary animate-bounce" />
        </div>
      </div>
    </div>
  );
}

export default function Library() {
  const [tab, setTab] = useState<"installed" | "templates">(() => {
    const hash = window.location.hash.slice(1);
    return hash === "templates" ? "templates" : "installed";
  });

  useEffect(() => {
    window.location.hash = tab;
  }, [tab]);

  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash.slice(1);
      if (hash === "templates" || hash === "installed") setTab(hash);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <div className="flex flex-col h-full overflow-hidden bg-background relative selection:bg-primary/30">
      {/* Dynamic Background Glows */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden select-none z-0">
        <div
          className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-primary/5 blur-[120px] rounded-full mix-blend-screen animate-pulse"
          style={{ animationDuration: "15s" }}
        />
        <div
          className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-surface-2/20 blur-[100px] rounded-full mix-blend-screen animate-pulse"
          style={{ animationDuration: "20s" }}
        />
      </div>

      {/* Header Area */}
      <div className="px-10 pt-16 pb-10 shrink-0 relative z-10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-10 mb-12">
          <div className="space-y-4">
            <div className="flex items-center gap-5">
              <div className="w-16 h-16 rounded-[2rem] bg-surface-3/40 border border-white/10 flex items-center justify-center shadow-2xl glass">
                <Box className="w-8 h-8 text-primary" />
              </div>
              <div>
                <h1 className="text-5xl font-black text-white tracking-tighter font-outfit uppercase leading-none">
                  Resource Library
                </h1>
                <div className="flex items-center gap-3 mt-3">
                  <span className="text-[10px] font-black text-primary/60 uppercase tracking-[0.3em]">
                    Operational Node Management
                  </span>
                  <div className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_hsla(var(--primary),0.5)] animate-pulse" />
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest max-w-xl leading-relaxed">
              Browse pre-configured protocols from the synchronized Registry or
              manage your provisioned WASM execution modules.
            </p>
          </div>

          {/* Tab bar */}
          <div className="flex items-center gap-3 p-2 bg-surface-3/40 backdrop-blur-3xl rounded-[2.5rem] border border-white/5 w-fit glass shadow-2xl gpu">
            <button
              onClick={() => setTab("installed")}
              className={cn(
                "flex items-center gap-4 px-10 py-4 text-[10px] font-black uppercase tracking-[0.2em] rounded-[1.5rem] transition-premium active:scale-95 relative group",
                tab === "installed"
                  ? "bg-primary text-white shadow-2xl shadow-primary/30 border border-white/20"
                  : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
              )}
            >
              <div
                className={cn(
                  "absolute inset-0 bg-white/10 opacity-0 group-hover:opacity-100 transition-premium rounded-[1.5rem]",
                  tab === "installed" && "hidden",
                )}
              />
              <Box
                className={cn(
                  "w-4 h-4 relative z-10 transition-transform group-hover:scale-110",
                  tab === "installed" ? "text-white" : "text-primary/40",
                )}
              />
              <span className="relative z-10">Active Modules</span>
            </button>
            <button
              onClick={() => setTab("templates")}
              className={cn(
                "flex items-center gap-4 px-10 py-4 text-[10px] font-black uppercase tracking-[0.2em] rounded-[1.5rem] transition-premium active:scale-95 relative group",
                tab === "templates"
                  ? "bg-primary text-white shadow-2xl shadow-primary/30 border border-white/20"
                  : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
              )}
            >
              <div
                className={cn(
                  "absolute inset-0 bg-white/10 opacity-0 group-hover:opacity-100 transition-premium rounded-[1.5rem]",
                  tab === "templates" && "hidden",
                )}
              />
              <BookOpen
                className={cn(
                  "w-4 h-4 relative z-10 transition-transform group-hover:scale-110",
                  tab === "templates" ? "text-white" : "text-primary/40",
                )}
              />
              <span className="relative z-10">Registry Catalog</span>
            </button>
          </div>
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden relative z-10">
        <Suspense fallback={<TabLoading />}>
          <div className="h-full overflow-auto custom-scrollbar gpu optimize-blur">
            <div className="max-w-[1600px] mx-auto pb-32">
              {tab === "installed" ? <Modules /> : <Catalog />}
            </div>
          </div>
        </Suspense>
      </div>
    </div>
  );
}
