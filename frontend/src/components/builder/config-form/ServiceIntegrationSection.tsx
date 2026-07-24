/**
 * "Configure Unified Integration" collapsible for the node ConfigForm —
 * template-aware Slack / Google Calendar / Gmail integration pickers.
 *
 * Strictly presentational — config value + onChange come in via props.
 */

import React from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { Link, ChevronDown, Mail } from "lucide-react";
import { SlackAppSelector } from "../SlackAppSelector";
import { GoogleCalendarSelector } from "../GoogleCalendarSelector";

export function ServiceIntegrationSection({
  templateName,
  value,
  onChange,
}: {
  templateName?: string;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
}) {
  return (
    <Collapsible
      defaultOpen={!value || Object.keys(value).length === 0}
      className="group/collapsible"
    >
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="w-full p-4 bg-surface-3 hover:bg-surface-4 border border-white/5 rounded-2xl cursor-pointer text-[10px] font-black text-white uppercase tracking-widest flex items-center justify-between transition-premium shadow-xl group-hover/collapsible:border-primary/20"
        >
          <div className="flex items-center gap-3">
            <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
              <Link className="h-4 w-4" />
            </div>
            <span>Configure Unified Integration</span>
          </div>
          <ChevronDown className="h-4 w-4 text-muted-foreground/40 group-data-[state=open]/collapsible:rotate-180 transition-transform duration-500" />
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="mt-4 space-y-4 animate-in fade-in slide-in-from-top-2 duration-500">
        {templateName && templateName.toLowerCase().includes("slack") && (
          <SlackAppSelector
            onSelect={(slackConfig) => onChange({ ...value, ...slackConfig })}
            currentConfig={value}
          />
        )}

        {templateName &&
          templateName.toLowerCase().includes("google") &&
          templateName.toLowerCase().includes("calendar") && (
            <GoogleCalendarSelector
              onSelect={(calendarConfig) =>
                onChange({ ...value, ...calendarConfig })
              }
              currentConfig={value}
            />
          )}

        {templateName &&
          (templateName.toLowerCase().includes("gmail") ||
            templateName.toLowerCase().includes("google-mail")) && (
            <div className="p-6 bg-surface-2/60 border border-white/5 rounded-2xl">
              <div className="text-[10px] font-black text-primary uppercase tracking-[0.2em] mb-3 flex items-center gap-3">
                <Mail className="h-4 w-4" /> Gmail Integration Vector
              </div>
              <p className="m-0 text-[11px] font-bold text-muted-foreground/40 leading-relaxed uppercase tracking-widest">
                Direct Gmail binding coming soon. Manually configure labels in
                primary settings.
              </p>
            </div>
          )}
      </CollapsibleContent>
    </Collapsible>
  );
}
