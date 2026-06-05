import React, { useMemo, useState, useEffect, useRef } from "react";
import { useUIStore } from "@/store/uiStore";
import {
  useEphemeralExecutionStore,
  type TimedEvent,
  type NodeStatus,
} from "@/store/executionStore";
import { cn } from "@/lib/utils";
import {
  Terminal as TerminalIcon,
  Trash2,
  ChevronUp,
  ChevronDown,
  AlertCircle,
  CheckCircle2,
  Info,
  Maximize2,
  Minimize2,
  Search,
  Cpu,
  Copy,
} from "lucide-react";
import {
  Button,
  Badge,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui";

type LogLevel = "all" | "errors" | "warnings" | "info";

const Terminal = () => {
  const [filter, setFilter] = useState<LogLevel>("all");
  const [searchTerm, setSearchTerm] = useState("");

  const terminalState = useUIStore((state) => state.terminalState);
  const setTerminalState = useUIStore((state) => state.setTerminalState);

  const processedLogs = useEphemeralExecutionStore(
    (state) => state.processedLogs,
  );
  const clearEvents = useEphemeralExecutionStore((state) => state.clearEvents);

  const cycleTerminalState = () => {
    if (terminalState === "collapsed") setTerminalState("compact");
    else if (terminalState === "compact") setTerminalState("full");
    else setTerminalState("collapsed");
  };

  const filteredLogEntries = useMemo(() => {
    let filtered = processedLogs.filter((entry) => {
      const levelMatch =
        filter === "all" ||
        (filter === "errors" && entry.level === "[ERROR]") ||
        (filter === "warnings" && entry.level === "[WARN]") ||
        (filter === "info" && entry.level === "[INFO]");

      const searchMatch =
        !searchTerm ||
        entry.text.toLowerCase().includes(searchTerm.toLowerCase()) ||
        entry.nodeId?.toLowerCase().includes(searchTerm.toLowerCase());

      return levelMatch && searchMatch;
    });

    if (terminalState === "compact") return filtered.slice(-10);
    return filtered;
  }, [processedLogs, filter, terminalState, searchTerm]);

  const errorCount = useMemo(
    () => processedLogs.filter((e) => e.level === "[ERROR]").length,
    [processedLogs],
  );
  const warningCount = useMemo(
    () => processedLogs.filter((e) => e.level === "[WARN]").length,
    [processedLogs],
  );

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredLogEntries, terminalState]);

  if (terminalState === "collapsed") {
    return (
      <div
        className="h-full flex items-center justify-between px-6 cursor-pointer hover:bg-white/[0.04] transition-premium border-t border-white/5 bg-surface-2/60 backdrop-blur-3xl relative overflow-hidden"
        onClick={() => setTerminalState("compact")}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
        <div className="flex items-center gap-6 relative z-10">
          <div className="flex items-center gap-3 text-muted-foreground/40">
            <TerminalIcon className="h-4 w-4" />
            <span className="text-[10px] font-black uppercase tracking-[0.2em]">
              Console Uplink
            </span>
          </div>
          <div className="flex items-center gap-4">
            {errorCount > 0 && (
              <div className="flex items-center gap-2 px-2.5 py-0.5 bg-destructive/10 border border-destructive/20 rounded-full">
                <div className="w-1.5 h-1.5 rounded-full bg-destructive animate-pulse" />
                <span className="text-[9px] font-black text-destructive uppercase tracking-widest">
                  {errorCount} FAULTS
                </span>
              </div>
            )}
            {warningCount > 0 && (
              <div className="flex items-center gap-2 px-2.5 py-0.5 bg-warning/10 border border-warning/20 rounded-full">
                <div className="w-1.5 h-1.5 rounded-full bg-warning animate-pulse" />
                <span className="text-[9px] font-black text-warning uppercase tracking-widest">
                  {warningCount} ALERTS
                </span>
              </div>
            )}
            <span className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.1em]">
              {processedLogs.length} EVENTS RECORDED
            </span>
          </div>
        </div>
        <ChevronUp className="h-4 w-4 text-muted-foreground/20 relative z-10" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        "h-full flex flex-col bg-surface-1/80 backdrop-blur-3xl border-t border-white/5 shadow-[0_-20px_50px_rgba(0,0,0,0.5)] transition-premium relative overflow-hidden",
        terminalState === "full" ? "rounded-t-3xl" : "",
      )}
    >
      <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-white/5 bg-surface-2/40 relative z-10">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 shadow-[0_0_15px_hsla(var(--primary),0.1)]">
              <TerminalIcon className="h-4 w-4 text-primary" />
            </div>
            <span className="text-[11px] font-black uppercase tracking-[0.3em] text-white font-outfit">
              Command Console
            </span>
          </div>

          <div className="flex bg-surface-3/40 p-1 rounded-xl border border-white/5">
            {(["all", "info", "warnings", "errors"] as LogLevel[]).map(
              (level) => (
                <button
                  key={level}
                  onClick={() => setFilter(level)}
                  className={cn(
                    "text-[9px] px-4 py-1.5 rounded-lg transition-premium font-black uppercase tracking-widest",
                    filter === level
                      ? "bg-primary text-primary-foreground shadow-lg shadow-primary/20"
                      : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
                  )}
                >
                  {level}
                </button>
              ),
            )}
          </div>

          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/20 group-focus-within:text-primary transition-premium" />
            <input
              type="text"
              placeholder="SEARCH LOGS..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-surface-3/40 border border-white/5 rounded-xl pl-10 pr-4 py-1.5 text-[10px] font-bold uppercase tracking-widest w-40 focus:w-64 transition-premium outline-none text-white placeholder:text-muted-foreground/20 focus:border-primary/50"
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => clearEvents()}
                  aria-label="Clear all logs"
                  className="h-9 w-9 text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10 transition-premium rounded-xl"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest text-white shadow-2xl">
                PURGE LOG BUFFER
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <div className="w-px h-6 bg-white/5 mx-1" />

          <Button
            variant="ghost"
            size="icon"
            onClick={cycleTerminalState}
            aria-label={
              terminalState === "compact"
                ? "Maximize terminal"
                : "Minimize terminal"
            }
            className="h-9 w-9 text-muted-foreground/40 hover:text-white hover:bg-white/5 transition-premium rounded-xl active:scale-90"
          >
            {terminalState === "compact" ? (
              <Maximize2 className="h-4 w-4" />
            ) : (
              <Minimize2 className="h-4 w-4" />
            )}
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => setTerminalState("collapsed")}
            aria-label="Collapse terminal"
            className="h-9 w-9 text-muted-foreground/40 hover:text-white hover:bg-white/5 transition-premium rounded-xl active:scale-90"
          >
            <ChevronDown className="h-5 w-5" />
          </Button>
        </div>
      </div>

      {/* Log Feed */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto font-mono text-[11px] p-6 space-y-1 custom-scrollbar bg-surface-1/40 relative z-10"
      >
        <div className="absolute inset-0 pointer-events-none opacity-20">
          <div className="h-full w-full bg-[radial-gradient(hsla(var(--primary),0.05)_1px,transparent_1px)] bg-[size:20px_20px]" />
        </div>

        {filteredLogEntries.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center opacity-10 gap-6 grayscale">
            <div className="p-8 rounded-[3rem] bg-surface-3/40 border border-white/5 shadow-2xl">
              <TerminalIcon className="h-12 w-12 stroke-[1px]" />
            </div>
            <div className="text-center">
              <p className="text-[12px] uppercase tracking-[0.4em] font-black mb-2">
                SYSTEM STANDBY
              </p>
              <p className="text-[10px] font-bold uppercase tracking-widest">
                AWAITING UPLINK DATA STREAM
              </p>
            </div>
          </div>
        ) : (
          filteredLogEntries.map((entry, i) => {
            const isError = entry.level === "[ERROR]";
            const isWarn = entry.level === "[WARN]";

            return (
              <div
                key={`${i}-${entry.timestamp}`}
                className={cn(
                  "group flex gap-6 px-4 py-2 transition-premium rounded-xl border-l-4",
                  isError
                    ? "bg-destructive/5 border-destructive shadow-[0_0_20px_hsla(var(--destructive),0.1)] text-white"
                    : isWarn
                      ? "bg-warning/5 border-warning shadow-[0_0_20px_hsla(var(--warning),0.1)] text-white"
                      : "border-transparent hover:bg-white/[0.02] text-muted-foreground/80 hover:text-white",
                )}
              >
                <span className="text-[10px] font-black font-mono text-muted-foreground/30 group-hover:text-primary transition-premium shrink-0 select-none uppercase tracking-tighter w-12 text-right">
                  {entry.timestamp}
                </span>

                <div className="flex-1 min-w-0">
                  {entry.nodeId && (
                    <span className="text-primary font-black mr-3 text-[10px] tracking-[0.1em] font-outfit uppercase">
                      [{entry.nodeId.slice(0, 8)}]
                    </span>
                  )}

                  {entry.structured ? (
                    <div className="inline-block align-top w-full">
                      {entry.structured.type === "llm_stream" && (
                        <div className="flex gap-4 items-start bg-primary/5 p-4 rounded-2xl border border-primary/10 shadow-2xl glass-dark optimize-blur">
                          <div className="flex flex-col items-center gap-1 shrink-0 mt-1">
                            <Badge
                              variant="outline"
                              className="bg-primary/20 text-primary border-primary/30 text-[9px] h-4 px-2 font-black shadow-[0_0_15px_hsla(var(--primary),0.2)] rounded-full uppercase tracking-widest"
                            >
                              LLM
                            </Badge>
                          </div>
                          <span className="text-white/90 leading-relaxed italic font-medium selection:bg-primary/30">
                            {entry.structured.content}
                          </span>
                        </div>
                      )}
                      {entry.structured.type === "tool_call" && (
                        <div className="flex flex-col gap-3 bg-warning/5 p-4 rounded-2xl border border-warning/10 shadow-2xl glass-dark optimize-blur">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <Badge
                                variant="outline"
                                className="bg-warning/20 text-warning border-warning/30 text-[9px] h-4 px-2 font-black shadow-[0_0_15px_hsla(var(--warning),0.2)] rounded-full uppercase tracking-widest"
                              >
                                TOOL
                              </Badge>
                              <span className="text-white font-black uppercase tracking-widest font-outfit text-xs">
                                {entry.structured.toolName}
                              </span>
                            </div>
                            <div className="w-2 h-2 rounded-full bg-warning animate-status-pulse" />
                          </div>
                          <div className="relative">
                            <div className="absolute top-0 right-0 p-2">
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 text-muted-foreground/30 hover:text-warning"
                                onClick={() =>
                                  entry.structured?.arguments &&
                                  navigator.clipboard.writeText(
                                    entry.structured.arguments,
                                  )
                                }
                              >
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                            <pre className="text-warning/70 p-4 bg-black/40 rounded-xl border border-white/5 overflow-x-auto selection:bg-warning/30 font-mono text-[10px] leading-relaxed custom-scrollbar">
                              {entry.structured.arguments}
                            </pre>
                          </div>
                        </div>
                      )}
                      {entry.structured.type === "token_usage" && (
                        <div className="flex items-center gap-4 bg-success/5 px-4 py-2 rounded-full border border-success/10 shadow-lg w-fit mt-1">
                          <Cpu className="h-3.5 w-3.5 text-success shadow-[0_0_10px_hsla(var(--success),0.5)]" />
                          <div className="flex items-center gap-3">
                            <span className="text-success/80 font-black text-[10px] uppercase tracking-[0.2em]">
                              UPLINK: {entry.structured.inputTokens ?? 0}
                            </span>
                            <div className="w-1 h-1 rounded-full bg-success/30" />
                            <span className="text-success/80 font-black text-[10px] uppercase tracking-[0.2em]">
                              DOWNLINK: {entry.structured.outputTokens ?? 0}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <span
                      className={cn(
                        "break-words selection:bg-primary/30 leading-relaxed font-medium",
                        isError
                          ? "text-white font-black"
                          : isWarn
                            ? "text-white"
                            : "text-muted-foreground group-hover:text-white transition-premium",
                      )}
                    >
                      {entry.text.toUpperCase()}
                    </span>
                  )}
                </div>

                <div className="w-12 flex justify-end shrink-0 opacity-0 group-hover:opacity-100 transition-premium">
                  {isError ? (
                    <AlertCircle className="h-4 w-4 text-destructive shadow-[0_0_10px_hsla(var(--destructive),0.5)]" />
                  ) : isWarn ? (
                    <Info className="h-4 w-4 text-warning shadow-[0_0_10px_hsla(var(--warning),0.5)]" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 text-success/40" />
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default React.memo(Terminal);
