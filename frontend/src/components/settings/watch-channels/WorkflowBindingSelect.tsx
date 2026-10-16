/**
 * The workflow a push on one watch channel starts, as a picker.
 *
 * A channel's row carries `workflow_id`; this shows it by name and lets the
 * owner change or clear it. Two things it must not do:
 *
 *   - show a bound channel as bound to nothing. If the bound workflow is not
 *     in the list (the list has not loaded, or the workflow was deleted), the
 *     binding is shown as an id that is not found, never as "None".
 *   - change anything by itself. It reports the choice; the caller makes the
 *     request and, if the server refuses, the row's own value puts the picker
 *     back.
 */

import React from "react";
import { Select } from "@/components/ui/select";

export interface WorkflowOption {
  id: string;
  name: string;
}

const NONE = "";

export function WorkflowBindingSelect({
  channelLabel,
  value,
  workflows,
  disabled,
  onChange,
}: {
  /** What the channel watches, for the control's accessible name. */
  channelLabel: string;
  value: string | null | undefined;
  /** `undefined` while the list is loading. */
  workflows: WorkflowOption[] | undefined;
  disabled?: boolean;
  onChange: (workflowId: string | null) => void;
}): React.ReactElement {
  const bound = value ?? NONE;
  const known = (workflows ?? []).some((w) => w.id === bound);
  return (
    <Select
      aria-label={`Workflow started by ${channelLabel}`}
      value={bound}
      disabled={disabled || workflows === undefined}
      onChange={(e) => {
        const next = e.target.value;
        if (next !== bound) onChange(next === NONE ? null : next);
      }}
      className="max-w-[14rem] text-xs"
    >
      <option value={NONE}>None</option>
      {bound !== NONE && !known && (
        <option value={bound}>
          {workflows === undefined
            ? `${bound.slice(0, 8)}…`
            : `Not found (${bound.slice(0, 8)}…)`}
        </option>
      )}
      {(workflows ?? []).map((w) => (
        <option key={w.id} value={w.id}>
          {w.name}
        </option>
      ))}
    </Select>
  );
}
