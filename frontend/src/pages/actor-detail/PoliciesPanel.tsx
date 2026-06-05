import React from "react";
import { Shield } from "lucide-react";
import { ManagedViaMcp } from "./shared";

export function PoliciesPanel() {
  return (
    <div className="space-y-6">
      <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
        <div className="flex items-start gap-3 mb-4">
          <Shield className="w-5 h-5 text-violet-400 shrink-0 mt-0.5" />
          <p className="text-muted-foreground text-sm leading-relaxed">
            Approval policies define when this Actor must pause and request
            human approval before proceeding.
          </p>
        </div>
        <ManagedViaMcp
          tools={[
            "list_actor_approval_policies",
            "create_actor_approval_policy",
            "delete_actor_approval_policy",
          ]}
        />
        <div className="flex flex-col items-center justify-center py-10 gap-3 mt-4">
          <Shield className="w-12 h-12 text-violet-500/20" />
          <p className="text-muted-foreground/40 text-sm">
            No approval policies configured.
          </p>
        </div>
      </div>
    </div>
  );
}
