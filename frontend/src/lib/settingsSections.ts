import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  BarChart,
  BrainCircuit,
  Building,
  Calendar,
  CheckSquare,
  FileSearch,
  Inbox,
  Key,
  Layers,
  Lock as LockIcon,
  Plug,
  Server,
  Shield,
  User as UserIcon,
  Webhook,
} from "lucide-react";

export interface SettingsSection {
  value: string;
  label: string;
  icon: LucideIcon;
  /** A page of its own, listed here so it has a home; it is not a section. */
  to?: string;
}

export interface SettingsGroup {
  label: string;
  items: SettingsSection[];
}

/* Six groups, one line each where one will do. Account is ONE section: the
   profile, password, two-factor and connected sign-ins stack on one page (the
   old #password, #two-factor and #oauth hashes still land on their card).
   The Settings sidebar and the command palette both read this list. */
export const SETTINGS_GROUPS: SettingsGroup[] = [
  {
    label: "Account",
    items: [{ value: "account", label: "Account and sign-in", icon: UserIcon }],
  },
  {
    label: "Workflows",
    items: [
      { value: "schedules", label: "Schedules", icon: Calendar },
      { value: "webhooks", label: "Webhooks", icon: Webhook },
      { value: "approvals", label: "Approvals", icon: CheckSquare },
    ],
  },
  {
    label: "Connections",
    items: [
      { value: "integrations", label: "Integrations", icon: Plug },
      { value: "mcp-server", label: "MCP server", icon: Server },
    ],
  },
  {
    label: "Security",
    items: [
      { value: "secrets", label: "Secrets", icon: LockIcon },
      { value: "api-keys", label: "API keys", icon: Key },
      { value: "capability-ceiling", label: "Capabilities", icon: Layers },
      { value: "security", label: "Access and encryption", icon: Shield },
    ],
  },
  {
    label: "Organization",
    items: [
      { value: "organizations", label: "Organizations", icon: Building },
      { value: "quotas", label: "Quotas", icon: BarChart },
      { value: "audit", label: "Audit log and tracing", icon: FileSearch },
      { value: "dlq", label: "Failed deliveries", icon: Inbox },
    ],
  },
  {
    label: "Operations",
    items: [
      {
        value: "system-health",
        label: "System health",
        icon: Activity,
        to: "/system-health",
      },
      { value: "alerts", label: "Alerts", icon: AlertTriangle, to: "/alerts" },
      {
        value: "models",
        label: "Model review",
        icon: BrainCircuit,
        to: "/models",
      },
    ],
  },
];

/** Where a section lives: its own page, or a hash on /settings. */
export function settingsSectionPath(item: SettingsSection): string {
  return item.to ?? `/settings#${item.value}`;
}
