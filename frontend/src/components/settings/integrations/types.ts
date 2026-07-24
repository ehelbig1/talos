/**
 * Shared types + icon mapping for the IntegrationsManager panel.
 */

import { Calendar, LayoutGrid, Mail, MessageSquare, Plug } from "lucide-react";
import type { LucideIcon } from "lucide-react";

/** Shape returned by GET /api/integrations/providers */
export interface ProviderInfo {
  id: string;
  display_name: string;
  description: string;
  icon: string;
  color: string;
  graphql_enum: string;
  oauth_hosts: string[];
  configured: boolean;
  connect_url: string;
}

/** Shape returned by GET /api/github/installations (RFC 0008). */
export interface GithubInstallation {
  installation_id: number;
  account_login: string;
  account_type?: string | null;
  repository_selection?: string | null;
}

/** Maps an icon name string from the API to the corresponding Lucide component. */
const ICON_MAP: Record<string, LucideIcon> = {
  Calendar,
  Mail,
  MessageSquare,
  LayoutGrid,
};

export function getIcon(iconName: string): LucideIcon {
  return ICON_MAP[iconName] ?? Plug;
}
