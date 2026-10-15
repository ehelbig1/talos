import { useNavigate } from "react-router";
import { Folder, BookOpen } from "lucide-react";
import { Button } from "@/components/ui";

/**
 * The three things a new user does, in order. Each step says where it
 * happens; the two buttons above start the first two.
 */
const STEPS = [
  {
    title: "Get a module",
    desc: "Install one from Templates, or create one in the editor. A module is one unit of work: a fetch, a transform, a send.",
  },
  {
    title: "Create a workflow",
    desc: "Add the module to a blank canvas, connect it to any others, and save.",
  },
  {
    title: "Run it",
    desc: "Run from the editor header. The console opens and shows each node's output.",
  },
];

/** The dashboard before the first workflow exists. */
export default function EmptyState({ onNew }: { onNew: () => void }) {
  const navigate = useNavigate();
  return (
    <div className="space-y-8 max-w-3xl mx-auto">
      <div className="text-center py-14 px-6 bg-surface-3/40 border border-white/10 border-dashed rounded-2xl">
        <div className="w-14 h-14 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-5 border border-primary/20">
          <Folder className="w-6 h-6 text-primary" />
        </div>

        <h2 className="text-xl font-semibold text-white font-outfit mb-2">
          No workflows yet
        </h2>
        <p className="text-sm text-muted-foreground mb-7 max-w-md mx-auto leading-relaxed">
          A workflow connects modules on a canvas and runs them on a schedule, a
          webhook, or by hand.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <Button onClick={onNew}>Create a workflow</Button>
          <Button
            variant="outline"
            onClick={() => navigate("/library#templates")}
          >
            <BookOpen className="w-4 h-4" />
            Browse templates
          </Button>
        </div>
      </div>

      <ol className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {STEPS.map((step, i) => (
          <li
            key={step.title}
            className="p-5 rounded-2xl bg-surface-3/60 border border-white/5"
          >
            <p className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
              Step {i + 1}
            </p>
            <p className="text-sm font-semibold text-white font-outfit mb-1">
              {step.title}
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {step.desc}
            </p>
          </li>
        ))}
      </ol>
    </div>
  );
}
