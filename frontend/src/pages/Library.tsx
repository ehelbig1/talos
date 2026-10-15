import React, { Suspense, lazy, useState, useEffect } from "react";
import { Button, PageHeader } from "@/components/ui";

const Modules = lazy(() => import("./Modules"));
const Catalog = lazy(() => import("./Catalog"));

function TabLoading() {
  return (
    <div className="flex flex-col items-center justify-center py-40 space-y-8 animate-in fade-in duration-700">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-primary/10 rounded-full" />
        <div className="w-16 h-16 border-4 border-t-primary border-transparent rounded-full animate-spin absolute inset-0" />
      </div>
      <div className="flex flex-col items-center gap-2">
        <span className="text-xs font-semibold text-white/70 animate-pulse">
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
          className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-primary/5 blur-[120px] rounded-full mix-blend-screen"
          style={{ animationDuration: "15s" }}
        />
        <div
          className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-surface-2/20 blur-[100px] rounded-full mix-blend-screen"
          style={{ animationDuration: "20s" }}
        />
      </div>

      {/* Header Area */}
      <div className="w-full max-w-7xl mx-auto px-6 md:px-8 pt-8 md:pt-10 shrink-0 relative z-10">
        <PageHeader
          title="Library"
          description="Templates you can install, and the modules you have created."
          actions={
            <div
              role="tablist"
              aria-label="Library sections"
              className="flex items-center gap-1 p-1 bg-surface-3/40 border border-white/5 rounded-xl"
            >
              <Button
                role="tab"
                aria-selected={tab === "templates"}
                variant={tab === "templates" ? "premium" : "ghost"}
                size="sm"
                onClick={() => setTab("templates")}
              >
                Templates
              </Button>
              <Button
                role="tab"
                aria-selected={tab === "installed"}
                variant={tab === "installed" ? "premium" : "ghost"}
                size="sm"
                onClick={() => setTab("installed")}
              >
                Your modules
              </Button>
            </div>
          }
          className="mb-0"
        />
      </div>
      {/* Tab content */}
      <div className="flex-1 overflow-hidden relative z-10">
        <Suspense fallback={<TabLoading />}>
          <div className="h-full overflow-auto custom-scrollbar gpu optimize-blur">
            <div className="max-w-7xl mx-auto px-6 md:px-8 pb-24">
              {tab === "installed" ? <Modules /> : <Catalog />}
            </div>
          </div>
        </Suspense>
      </div>
    </div>
  );
}
