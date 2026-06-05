import { useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Zap, Folder, Calendar, Globe, BookOpen } from "lucide-react";

export default function EmptyState({ onNew }: { onNew: () => void }) {
  const navigate = useNavigate();
  return (
    <div className="space-y-12 animate-in fade-in slide-in-from-bottom-8 duration-1000">
      {/* Hero */}
      <div className="text-center py-24 bg-surface-3/40 border border-white/10 border-dashed rounded-[4rem] shadow-2xl backdrop-blur-3xl glass gpu relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent pointer-events-none" />

        <div className="w-24 h-24 bg-primary/10 rounded-[2.5rem] flex items-center justify-center mx-auto mb-10 border border-primary/20 shadow-[0_0_30px_hsla(var(--primary),0.1)] relative group">
          <div className="absolute inset-0 bg-primary/5 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-premium" />
          <Folder className="w-10 h-10 text-primary relative z-10 group-hover:scale-110 transition-premium" />
        </div>

        <h3 className="text-4xl font-black text-white tracking-tighter font-outfit uppercase mb-4 leading-tight">
          Initialize Workflow
        </h3>
        <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest mb-10 max-w-lg mx-auto leading-relaxed">
          Automate complex operations by orchestrating modules into
          high-fidelity visual pipelines. Start from a clean slate or utilize
          registered protocols.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-6 relative z-10">
          <button
            onClick={onNew}
            className="px-10 py-5 text-xs font-black bg-primary text-white rounded-2xl transition-premium shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] hover:shadow-[0_20px_40px_-5px_hsla(var(--primary),0.5)] hover:scale-105 active:scale-95 border border-white/20 uppercase tracking-[0.2em]"
          >
            Create New Sequence
          </button>
          <button
            onClick={() => navigate("/catalog")}
            className="px-8 py-5 text-xs font-black text-muted-foreground/60 border border-white/5 bg-white/5 hover:text-white hover:bg-white/10 hover:border-white/20 rounded-2xl transition-premium active:scale-95 flex items-center gap-4 uppercase tracking-[0.2em] shadow-xl glass-light"
          >
            <BookOpen className="w-5 h-5 opacity-40" />
            Registry Catalog
          </button>
        </div>
      </div>

      {/* Quick start cards */}
      <div className="animate-in fade-in slide-in-from-bottom-4 duration-1000 delay-300">
        <p className="text-[10px] text-muted-foreground/30 font-black uppercase tracking-[0.4em] mb-6 px-4">
          OPERATIONAL TEMPLATES
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-8">
          {[
            {
              icon: Globe,
              title: "HTTP Request",
              desc: "Egress orchestration and protocol transformation.",
              color: "text-blue-400 bg-blue-500/10 border-blue-500/20",
              accent: "group-hover:border-blue-400/30",
            },
            {
              icon: Calendar,
              title: "Scheduled Task",
              desc: "Recurring execution on synchronized cron schedules.",
              color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
              accent: "group-hover:border-emerald-400/30",
            },
            {
              icon: Zap,
              title: "Data Pipeline",
              desc: "Stream processing and reactive data routing.",
              color: "text-violet-400 bg-violet-500/10 border-violet-500/20",
              accent: "group-hover:border-violet-400/30",
            },
          ].map((card) => (
            <button
              key={card.title}
              onClick={onNew}
              className={cn(
                "text-left p-8 rounded-[2rem] bg-surface-3/40 border border-white/5 hover:bg-surface-3 transition-premium shadow-xl glass-light group relative overflow-hidden",
                card.accent,
              )}
            >
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
              <div
                className={cn(
                  "w-12 h-12 rounded-2xl flex items-center justify-center border mb-6 shadow-2xl transition-premium group-hover:scale-110",
                  card.color,
                )}
              >
                <card.icon className="w-5 h-5" />
              </div>
              <p className="text-lg font-black text-white font-outfit uppercase tracking-tight group-hover:text-primary transition-premium leading-none mb-2">
                {card.title}
              </p>
              <p className="text-[11px] text-muted-foreground/40 font-bold leading-relaxed uppercase tracking-widest">
                {card.desc}
              </p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
