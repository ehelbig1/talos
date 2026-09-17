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
            human approval before proceeding. Enforced triggers today are
            first_workflow_deploy and custom Rhai expressions, both evaluated
            when a workflow version is published.
          </p>
        </div>
        <ManagedViaMcp
          tools={[
            "list_actor_approval_policies",
            "add_actor_approval_policy",
            "remove_actor_approval_policy",
          ]}
        />
        <p className="text-muted-foreground/60 text-sm mt-4">
          This panel does not load policies; list them with
          list_actor_approval_policies.
        </p>
      </div>
    </div>
  );
}
