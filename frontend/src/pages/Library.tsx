import React, { Suspense, lazy, useState, useEffect } from "react";
import { LoadingState } from "@/components/ui/spinner";
import { Button, PageContainer, PageHeader } from "@/components/ui";

const Modules = lazy(() => import("./Modules"));
const Catalog = lazy(() => import("./Catalog"));

function TabLoading() {
  return <LoadingState />;
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
                variant={tab === "templates" ? "default" : "ghost"}
                size="sm"
                onClick={() => setTab("templates")}
              >
                Templates
              </Button>
              <Button
                role="tab"
                aria-selected={tab === "installed"}
                variant={tab === "installed" ? "default" : "ghost"}
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
