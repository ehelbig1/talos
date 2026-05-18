import * as React from "react";
import { Button, Textarea, Dialog } from "@/components/ui";
import { Loader2, XCircle, CheckCircle2, Terminal, Code2, Play } from "lucide-react";
import { testRhaiExpression } from "@/lib/graphqlClient";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { LoadingSpinner } from "@/components/LoadingSpinner";

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "10px",
  fontWeight: "900",
  textTransform: "uppercase",
  letterSpacing: "0.2em",
  color: "hsla(var(--white), 0.3)",
  marginBottom: "12px",
  fontFamily: "var(--font-outfit)",
};

interface TestRhaiModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  script: string;
  initialMockContext?: string;
}

export const TestRhaiModal: React.FC<TestRhaiModalProps> = ({
  open,
  onOpenChange,
  script,
  initialMockContext = '{\n  "items": [1, 2, 3]\n}',
}) => {
  const [mockContext, setMockContext] = React.useState(initialMockContext);
  const [result, setResult] = React.useState<{
    success: boolean;
    output?: string;
    error?: string;
  } | null>(null);
  const [loading, setLoading] = React.useState(false);

  const handleTest = async () => {
    setLoading(true);
    setResult(null);
    try {
      const resp = await testRhaiExpression({
        script,
        mockContext,
      });
      setResult(resp);
    } catch (e: unknown) {
      setResult({
        success: false,
        error:
          e instanceof Error
            ? e.message
            : "An unknown error occurred during testing",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => onOpenChange(false);

  return (
    <Dialog 
      open={open} 
      onClose={handleClose} 
      title="Protocol Evaluation"
      className="max-w-2xl"
    >
      <div className="space-y-8 relative z-10 p-2 -mt-4">
        <div className="flex items-center justify-between mb-2">
            <p className="text-[11px] text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed">
                Validate Rhai logic against synthetic telemetry context
            </p>
            <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-primary/40 shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
                <span className="text-[9px] font-black text-primary/40 uppercase tracking-[0.2em]">Rhai Runtime v1.0</span>
            </div>
        </div>

        <div className="space-y-10 flex-1 overflow-auto custom-scrollbar pr-1 min-h-0">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
                <Code2 className="w-4 h-4 text-primary" />
                <label style={labelStyle} className="mb-0">Operational Expression</label>
            </div>
            <div className="bg-surface-4/60 p-6 rounded-[2rem] border border-white/5 font-mono text-[11px] text-primary/80 break-all leading-relaxed shadow-inner glass-light relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />
              <div className="relative z-10">
                {script || (
                    <span className="text-muted-foreground/20 italic font-black uppercase tracking-widest">
                    Awaiting Instruction...
                    </span>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                  <Terminal className="w-4 h-4 text-primary" />
                  <label style={labelStyle} className="mb-0">Synthetic Telemetry Context (JSON)</label>
              </div>
              <div className="relative group">
                <div className="absolute -inset-0.5 bg-primary/20 rounded-[2rem] blur opacity-0 group-focus-within:opacity-100 transition-premium" />
                <Textarea
                    value={mockContext}
                    onChange={(e) => setMockContext(e.target.value)}
                    rows={6}
                    className="font-mono text-[11px] bg-surface-4/60 border-white/5 focus:ring-primary/20 focus:border-primary/40 rounded-[2rem] p-6 text-white shadow-inner resize-none uppercase tracking-widest relative z-10"
                    placeholder='{ "items": [1, 2, 3] }'
                />
              </div>
            </div>

            <Button
              onClick={handleTest}
              disabled={loading || !script}
              variant="premium"
              className="w-full h-16 rounded-2xl shadow-2xl shadow-primary/20"
            >
              {loading ? (
                <div className="flex items-center gap-4">
                  <LoadingSpinner className="w-5 h-5" />
                  <span className="font-black uppercase tracking-[0.2em] text-xs">ORCHESTRATING EVALUATION...</span>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                    <Play className="w-4 h-4 fill-current" />
                    <span className="font-black uppercase tracking-[0.2em] text-xs">INITIATE LOGIC TEST</span>
                </div>
              )}
            </Button>
          </div>

          {result && (
            <div
              className={cn(
                "p-8 rounded-[2.5rem] border text-[11px] font-mono overflow-hidden animate-in slide-in-from-top-4 duration-500 shadow-2xl relative glass",
                result.success
                  ? "bg-success/5 border-success/20 text-success"
                  : "bg-destructive/5 border-destructive/20 text-destructive",
              )}
            >
              <div className={cn(
                "absolute inset-0 bg-gradient-to-br opacity-10",
                result.success ? "from-success via-transparent" : "from-destructive via-transparent"
              )} />
              {result.success ? (
                <div className="relative z-10">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-8 h-8 rounded-xl bg-success/10 flex items-center justify-center border border-success/20">
                        <CheckCircle2 size={16} className="text-success" />
                    </div>
                    <div className="text-[10px] font-black uppercase tracking-[0.3em] text-success/60">
                      Execution Successful
                    </div>
                  </div>
                  <pre className="whitespace-pre-wrap leading-relaxed font-bold bg-black/20 p-6 rounded-2xl shadow-inner border border-white/5">
                    {result.output}
                  </pre>
                </div>
              ) : (
                <div className="relative z-10">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-8 h-8 rounded-xl bg-destructive/10 flex items-center justify-center border border-destructive/20">
                        <XCircle size={16} className="text-destructive" />
                    </div>
                    <div className="text-[10px] font-black uppercase tracking-[0.3em] text-destructive/60">
                      Critical Evaluation Failure
                    </div>
                  </div>
                  <div className="whitespace-pre-wrap leading-relaxed font-bold bg-black/20 p-6 rounded-2xl shadow-inner border border-white/5">
                    {sanitizeErrorMessage(result.error ?? "")}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="pt-10 border-t border-white/5 flex justify-end">
          <Button
            variant="ghost"
            onClick={handleClose}
            className="h-14 px-12 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95 shadow-xl"
          >
            Close Diagnostics
          </Button>
        </div>
      </div>
    </Dialog>
  );
};

