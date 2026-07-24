import React from "react";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { cn } from "@/lib/utils";
import type { Org } from "./graphql";

/** Left column: the caller's organizations with the active selection. */
export function OrgListSidebar({
  organizations,
  isLoading,
  selectedOrgId,
  onSelect,
}: {
  organizations: Org[] | undefined;
  isLoading: boolean;
  selectedOrgId: string | null;
  onSelect: (orgId: string) => void;
}): React.ReactElement {
  return (
    <div className="md:col-span-1 space-y-4">
      <div className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 px-1 mb-2">
        Active_Protocols
      </div>
      {isLoading ? (
        <div className="py-12 flex justify-center bg-white/[0.02] border border-white/5 rounded-[2rem]">
          <LoadingSpinner />
        </div>
      ) : organizations?.length === 0 ? (
        <div className="p-10 border border-dashed border-white/5 rounded-[2rem] text-center bg-white/[0.01]">
          <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest">
            No active organizations
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {organizations?.map((org) => (
            <button
              type="button"
              key={org.id}
              onClick={() => onSelect(org.id)}
              className={cn(
                "w-full flex items-center gap-4 p-4 rounded-[1.5rem] border transition-premium text-left relative overflow-hidden group",
                selectedOrgId === org.id
                  ? "bg-primary/10 border-primary/40 shadow-[0_0_20px_hsla(var(--primary),0.1)]"
                  : "bg-white/[0.02] border-white/5 hover:bg-white/[0.04] hover:border-white/10",
              )}
            >
              <div
                className={cn(
                  "w-12 h-12 rounded-xl flex items-center justify-center text-xl font-black font-outfit shadow-2xl transition-premium group-hover:scale-110",
                  selectedOrgId === org.id
                    ? "bg-primary text-white"
                    : "bg-white/5 text-muted-foreground/60",
                )}
              >
                {org.name.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0 relative z-10">
                <div
                  className={cn(
                    "text-sm font-black tracking-tight uppercase font-outfit truncate transition-premium",
                    selectedOrgId === org.id
                      ? "text-white"
                      : "text-muted-foreground/60 group-hover:text-white",
                  )}
                >
                  {org.name}
                </div>
                <div className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest mt-1 truncate">
                  /{org.slug}
                </div>
              </div>
              {selectedOrgId === org.id && (
                <div className="absolute right-4 w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
