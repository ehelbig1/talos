import React from "react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  Shield,
  Clock,
  User,
  Box,
  Settings,
  AlertCircle,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { gql } from "@/lib/graphqlClient";
import type { Secret, SecretAuditLog } from "@/generated/graphql";
import { useGetSecretAuditLogQuery } from "@/generated/graphql";

const GET_SECRET_AUDIT_LOG = gql`
  query GetSecretAuditLog($secretId: UUID!, $limit: Int) {
    secretAuditLog(secretId: $secretId, pagination: { limit: $limit }) {
      id
      action
      actorType
      success
      timestamp
      errorMessage
    }
  }
`;

interface AuditLogViewerProps {
  open: boolean;
  secret: Pick<Secret, "id" | "name" | "keyPath">;
  onClose: () => void;
}

export function AuditLogViewer({ open, secret, onClose }: AuditLogViewerProps) {
  const { data, isLoading, error } = useGetSecretAuditLogQuery(
    { secretId: secret.id, limit: 100 },
    { enabled: open },
  );

  const logs = data?.secretAuditLog as SecretAuditLog[] | undefined;

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return new Intl.DateTimeFormat("en-US", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(date);
  };

  const getActorIcon = (actorType: string) => {
    switch (actorType.toLowerCase()) {
      case "user":
        return <User className="w-3.5 h-3.5" />;
      case "module":
        return <Box className="w-3.5 h-3.5" />;
      case "system":
        return <Settings className="w-3.5 h-3.5" />;
      default:
        return <Shield className="w-3.5 h-3.5" />;
    }
  };

  if (!open) return null;

  return (
    <Dialog open={open} onClose={onClose} title="Security Audit Log">
      <div className="space-y-6">
        <div className="flex items-center gap-5 p-5 bg-card/60 backdrop-blur-xl rounded-2xl border border-border/80 shadow-inner relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 blur-3xl -mr-16 -mt-16 pointer-events-none group-hover:bg-primary/10 transition-premium" />
          <div className="w-12 h-12 bg-primary/10 border border-primary/20 rounded-xl flex items-center justify-center shadow-inner group-hover:scale-110 transition-transform relative z-10">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div className="relative z-10">
            <h3 className="text-base font-black text-foreground tracking-tight uppercase">
              {secret.name}
            </h3>
            <div className="flex items-center gap-2 mt-1">
              <code className="text-[10px] text-primary/80 font-mono font-bold tracking-tight bg-primary/5 border border-primary/10 px-2 py-0.5 rounded-md">
                {secret.keyPath}
              </code>
              <Badge
                variant="outline"
                className="text-[9px] uppercase font-black tracking-widest bg-success/10 text-success border-success/20 px-2 h-5 rounded-md"
              >
                Active Audit
              </Badge>
            </div>
          </div>
        </div>

        <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-2 custom-scrollbar">
          {isLoading ? (
            <div className="py-20 flex flex-col items-center justify-center text-muted-foreground">
              <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mb-4" />
              <p className="text-sm font-medium">Fetching audit trail...</p>
            </div>
          ) : error ? (
            <div className="py-12 px-6 text-center text-destructive bg-destructive/5 rounded-2xl border border-destructive/10">
              <AlertCircle className="w-10 h-10 mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">Failed to load audit logs</p>
              <p className="text-xs opacity-70 mt-1">
                {sanitizeErrorMessage((error as Error).message)}
              </p>
            </div>
          ) : logs?.length === 0 ? (
            <div className="py-20 text-center text-muted-foreground bg-muted/40 rounded-2xl border border-dashed border-border">
              <Clock className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-medium">No activity recorded yet</p>
              <p className="text-xs opacity-60">
                Operations on this secret will appear here.
              </p>
            </div>
          ) : (
            logs?.map((entry) => (
              <div
                key={entry.id}
                className={cn(
                  "p-4 rounded-xl border transition-premium duration-200",
                  entry.success
                    ? "bg-card/40 border-border/80 hover:border-border hover:bg-muted/60"
                    : "bg-destructive/5 border-destructive/10 hover:border-destructive/20",
                )}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-2.5 flex-1">
                    <div className="flex items-center gap-2">
                      <Badge
                        variant="outline"
                        className={cn(
                          "px-2 py-0 text-[10px] uppercase font-bold tracking-wider rounded-md",
                          entry.action === "create" &&
                            "bg-success/10 text-success border-success/20",
                          entry.action === "read" &&
                            "bg-primary/10 text-primary border-primary/20",
                          entry.action === "rotate" &&
                            "bg-warning/10 text-warning border-warning/20",
                          entry.action === "delete" &&
                            "bg-destructive/10 text-destructive border-destructive/20",
                        )}
                      >
                        {entry.action}
                      </Badge>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground px-2 py-0.5 bg-muted/60 rounded-full border border-border/50">
                        {getActorIcon(entry.actorType)}
                        <span>{entry.actorType}</span>
                      </div>
                    </div>

                    {!entry.success && (
                      <div className="flex items-start gap-2 p-2 bg-destructive/5 rounded-lg border border-destructive/10">
                        <XCircle className="w-3.5 h-3.5 text-destructive mt-0.5 shrink-0" />
                        <p className="text-xs text-destructive/80 leading-relaxed font-medium">
                          {sanitizeErrorMessage(
                            entry.errorMessage ||
                              "Operation failed due to an internal security error.",
                          )}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="text-right shrink-0">
                    <div className="flex items-center justify-end gap-1.5 mb-1.5">
                      {entry.success ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-destructive" />
                      )}
                      <span
                        className={cn(
                          "text-[10px] font-bold uppercase tracking-tight",
                          entry.success ? "text-success" : "text-destructive",
                        )}
                      >
                        {entry.success ? "Success" : "Denied"}
                      </span>
                    </div>
                    <p className="text-[10px] text-muted-foreground font-medium tabular-nums">
                      {formatTimestamp(entry.timestamp)}
                    </p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="pt-6 border-t border-border/50 flex justify-end bg-muted/5 -mx-1 px-1 -mb-1 pb-1">
          <Button
            onClick={onClose}
            className="bg-accent hover:bg-black/20 text-foreground font-black uppercase tracking-widest text-[10px] h-11 px-8 rounded-xl transition-premium border border-border/60 shadow-sm"
          >
            Close Audit Trail
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
