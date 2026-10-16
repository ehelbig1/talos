/**
 * The control-flow (system) node kinds the editor can add, with the words a
 * person sees for each. The `kind` is the wire name (`system:<kind>`), never
 * shown on its own; the label is what the Control flow menu offers, what a
 * new node is called, and what the badge on the canvas says.
 */
export const SYSTEM_NODES = [
  {
    kind: "ForEach",
    label: "For each item",
    desc: "Run the next step once per item",
  },
  {
    kind: "FanIn",
    label: "Join branches",
    desc: "Wait for parallel branches, then continue",
  },
  {
    kind: "WhileLoop",
    label: "Repeat while",
    desc: "Repeat while a condition holds",
  },
  {
    kind: "RepeatLoop",
    label: "Repeat",
    desc: "Run a step a set number of times",
  },
  {
    kind: "SubWorkflow",
    label: "Run a workflow",
    desc: "Run another workflow as one step",
  },
  {
    kind: "ErrorHandler",
    label: "On error",
    desc: "Catch a failure and route it",
  },
  {
    kind: "Wait",
    label: "Wait for approval",
    desc: "Pause until a person decides",
  },
  {
    kind: "Collect",
    label: "Collect",
    desc: "Gather several inputs into one",
  },
  {
    kind: "DynamicDispatch",
    label: "Route by name",
    desc: "Pick the module to run from the input",
  },
  {
    kind: "CapabilityDispatch",
    label: "Route by capability",
    desc: "Pick the module to run by what it can do",
  },
] as const;

export type SystemNodeKind = (typeof SYSTEM_NODES)[number]["kind"];

const LABELS: Record<string, string> = Object.fromEntries(
  SYSTEM_NODES.map((n) => [n.kind, n.label]),
);

/** The words for a system node kind; a kind the editor cannot add (a loaded
 *  graph's legacy `Loop`, or something newer than this build) is shown as
 *  its wire name rather than hidden. */
export function systemNodeLabel(kind: string): string {
  return LABELS[kind] ?? kind;
}
