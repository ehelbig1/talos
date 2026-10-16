/**
 * API-keys table for ApiKeysManager: loading state, populated rows with
 * per-row Rotate / Revoke / Delete actions, and the empty-state row.
 *
 * Strictly presentational — data + action callbacks come in via props;
 * the parent owns all state and mutations.
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Calendar,
  Shield,
  Trash2,
  Key,
  Terminal,
  Clock,
  RefreshCw,
} from "lucide-react";
import { formatDate } from "@/lib/format";
import type { ApiKeyInfo } from "@/generated/graphql";

export function KeysTable({
  keys,
  isLoading,
  onRotate,
  onRevoke,
  onDelete,
}: {
  keys: ApiKeyInfo[] | undefined;
  isLoading: boolean;
  onRotate: (id: string) => void;
  onRevoke: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="relative">
      <Card className="relative bg-surface-3/80 border-white/10 overflow-hidden rounded-[20px] border">
        {isLoading ? (
          <div className="p-10 flex flex-col items-center justify-center gap-4">
            <Spinner className="w-8 h-8 text-primary" />
            <p className="text-xs text-muted-foreground font-medium">
              Loading Keys...
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-white/[0.02] border-b border-white/5">
                  <th className="px-8 py-5 text-sm font-bold text-muted-foreground">
                    Key Name
                  </th>
                  <th className="px-8 py-5 text-sm font-bold text-muted-foreground">
                    Permissions
                  </th>
                  <th className="px-8 py-5 text-sm font-bold text-muted-foreground">
                    Created
                  </th>
                  <th className="px-8 py-5 text-sm font-bold text-muted-foreground">
                    Status
                  </th>
                  <th className="px-8 py-5 text-right text-sm font-bold text-muted-foreground">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {keys && keys.length > 0 ? (
                  keys.map((k: ApiKeyInfo) => {
                    const isExpired =
                      k.expiresAt && new Date(k.expiresAt) < new Date();
                    return (
                      <tr
                        key={k.id}
                        className="group hover:bg-primary/[0.02] transition-ui"
                      >
                        <td className="px-8 py-5">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                              <Key className="w-4 h-4" />
                            </div>
                            <div className="text-sm font-bold text-foreground leading-tight">
                              {k.name}
                            </div>
                          </div>
                        </td>
                        <td className="px-8 py-5">
                          <div className="flex flex-wrap gap-1.5 min-w-[200px]">
                            {k.scopes.map((s) => (
                              <span
                                key={s}
                                className="px-2 py-0.5 bg-surface-4/60 border border-white/10 rounded text-2xs text-primary font-bold"
                              >
                                {s.split(":").pop()}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-8 py-5">
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium tracking-tight whitespace-nowrap">
                            <Calendar className="w-3.5 h-3.5 text-muted-foreground/50" />
                            {formatDate(k.createdAt)}
                          </div>
                        </td>
                        <td className="px-8 py-5">
                          {isExpired ? (
                            <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-destructive/10 border border-destructive/20 text-xs font-bold text-destructive rounded-md">
                              <Clock className="w-3 h-3" />
                              Expired
                            </span>
                          ) : k.expiresAt ? (
                            <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-warning/10 border border-warning/20 text-xs font-bold text-warning rounded-md">
                              <Calendar className="w-3.5 h-3.5" />
                              {formatDate(k.expiresAt)}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-primary/10 border border-primary/20 text-xs font-bold text-primary rounded-md">
                              <Shield className="w-3 h-3" />
                              Permanent
                            </span>
                          )}
                        </td>
                        <td className="px-8 py-5 text-right">
                          <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-ui">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => onRotate(k.id)}
                              className="text-muted-foreground hover:text-primary hover:bg-primary/10 h-9 px-3 font-bold transition-ui text-xs gap-1.5"
                            >
                              <RefreshCw className="w-4 h-4" />
                              Rotate
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => onRevoke(k.id)}
                              className="text-muted-foreground hover:text-warning hover:bg-warning/10 h-9 px-3 font-bold transition-ui text-xs gap-1.5"
                            >
                              <Shield className="w-4 h-4" />
                              Revoke
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => onDelete(k.id)}
                              className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-9 px-3 font-bold transition-ui text-xs gap-1.5"
                            >
                              <Trash2 className="w-4 h-4" />
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="px-8 py-12 text-center">
                      <div className="flex flex-col items-center gap-4">
                        <div className="w-14 h-14 rounded-full bg-surface-3/60 border border-white/5 flex items-center justify-center text-muted-foreground/70">
                          <Terminal size={28} />
                        </div>
                        <div className="max-w-xs mx-auto">
                          <p className="text-sm font-medium text-muted-foreground mb-1">
                            No API keys found
                          </p>
                          <p className="text-xs text-muted-foreground max-w-[240px] leading-relaxed">
                            Create your first key to start using the Talos CLI
                            or automated integrations.
                          </p>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
