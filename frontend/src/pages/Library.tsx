import React, { Suspense, lazy, useState, useEffect } from "react";
import { Button, PageContainer, PageHeader } from "@/components/ui";

const Modules = lazy(() => import("./Modules"));
const Catalog = lazy(() => import("./Catalog"));

function TabLoading() {
  return (
    <div className="flex flex-col items-center justify-center py-40 space-y-8">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-primary/10 rounded-full" />
        <div className="w-16 h-16 border-4 border-t-primary border-transparent rounded-full animate-spin absolute inset-0" />
      </div>
      <div className="flex flex-col items-center gap-2">
        <span className="text-xs font-semibold text-white/70">Loading…</span>
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
    <div className="h-full overflow-auto bg-background custom-scrollbar">
      <PageContainer>
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
        />
        <Suspense fallback={<TabLoading />}>
          {tab === "installed" ? <Modules /> : <Catalog />}
        </Suspense>
      </PageContainer>
    </div>
  );
}
