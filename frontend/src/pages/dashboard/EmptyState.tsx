import { useNavigate } from "react-router";
import { Zap, Folder, Calendar, Globe, BookOpen } from "lucide-react";
import { Button } from "@/components/ui";

const STARTERS = [
  {
    icon: Globe,
    title: "Call an API",
    desc: "Fetch from a service on a schedule or a webhook and act on the result.",
    color: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  },
  {
    icon: Calendar,
    title: "Run on a schedule",
    desc: "A recurring job on a cron schedule, with its results kept in memory.",
    color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  },
  {
    icon: Zap,
    title: "Process incoming data",
    desc: "Receive events from a webhook and route them through your modules.",
    color: "text-violet-400 bg-violet-500/10 border-violet-500/20",
  },
];

/** The dashboard before the first workflow exists. */
export default function EmptyState({ onNew }: { onNew: () => void }) {
  const navigate = useNavigate();
  return (
    <div className="space-y-10">
      <div className="text-center py-16 px-6 bg-surface-3/40 border border-white/10 border-dashed rounded-2xl">
        <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-primary/20">
          <Folder className="w-7 h-7 text-primary" />
        </div>

        <h3 className="text-2xl font-semibold text-white font-outfit mb-3">
          No workflows yet
        </h3>
        <p className="text-sm text-muted-foreground mb-8 max-w-md mx-auto leading-relaxed">
          A workflow connects modules on a canvas and runs them on a schedule, a
          webhook, or by hand. Start from a blank canvas or from a template.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <Button onClick={onNew}>Create a workflow</Button>
          <Button variant="outline" onClick={() => navigate("/catalog")}>
            <BookOpen className="w-4 h-4" />
            Browse templates
          </Button>
        </div>
      </div>

      <div>
        <p className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground mb-4 px-1">
          Common starting points
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {STARTERS.map((card) => (
            <button
              key={card.title}
              onClick={onNew}
              className="text-left p-5 rounded-2xl bg-surface-3/60 border border-white/5 hover:border-white/20 hover:bg-surface-3 transition-ui focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
            >
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center border mb-4 ${card.color}`}
              >
                <card.icon className="w-5 h-5" />
              </div>
              <p className="text-sm font-semibold text-white font-outfit mb-1">
                {card.title}
              </p>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {card.desc}
              </p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
