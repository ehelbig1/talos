import React, { Suspense, lazy, useCallback, useState, useEffect } from "react";
import ErrorBoundary from "@/components/ErrorBoundary";
import { SectionHeader } from "@/components/ui";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import {
  Lock as LockIcon,
  User as UserIcon,
  Plug,
  Server,
  Webhook,
  Key,
  Shield,
  Building,
  CheckSquare,
  Calendar,
  Layout,
  FileSearch,
  Inbox,
  BarChart,
  Fingerprint,
  Globe,
  Search,
  Layers,
  type LucideIcon,
} from "lucide-react";

// Lazy-loaded panel chunks with module references for prefetching.
const integrationsImport = () =>
  import("@/components/settings/IntegrationsManager");
const secretsImport = () => import("@/components/secrets/SecretsManager");
const apiKeysImport = () => import("@/components/settings/ApiKeysManager");
const mcpImport = () => import("@/components/settings/McpServerSettings");
const auditImport = () => import("@/components/settings/AuditSettings");
const approvalsImport = () => import("@/components/settings/ApprovalQueue");
const dlqImport = () => import("@/components/settings/DLQViewer");
const quotasImport = () => import("@/components/settings/ResourceQuotas");
const organizationsImport = () =>
  import("@/components/settings/OrganizationsManager");
const twoFactorImport = () => import("@/components/settings/TwoFactorSettings");
const oauthImport = () => import("@/components/settings/OAuthManager");
const schedulesImport = () => import("@/components/settings/SchedulesManager");
const securityImport = () => import("@/components/settings/SecurityManager");
const webhooksImport = () => import("@/components/settings/WebhookManager");
const templatesImport = () =>
  import("@/components/settings/ModuleTemplatesBrowser");
const capabilityCeilingImport = () =>
  import("@/components/settings/CapabilityCeilingManager");

const IntegrationsManager = lazy(() =>
  integrationsImport().then((m) => ({ default: m.IntegrationsManager })),
);
const SecretsManager = lazy(() => secretsImport());
const ApiKeysManager = lazy(() =>
  apiKeysImport().then((m) => ({ default: m.default })),
);
const McpServerSettings = lazy(() =>
  mcpImport().then((m) => ({ default: m.default })),
);
const AuditSettings = lazy(() =>
  auditImport().then((m) => ({ default: m.default })),
);
const ApprovalQueue = lazy(() =>
  approvalsImport().then((m) => ({ default: m.ApprovalQueue })),
);
const DLQViewer = lazy(() =>
  dlqImport().then((m) => ({ default: m.DLQViewer })),
);
const ResourceQuotas = lazy(() =>
  quotasImport().then((m) => ({ default: m.ResourceQuotas })),
);
const OrganizationsManager = lazy(() => organizationsImport());
const TwoFactorSettings = lazy(() => twoFactorImport());
const OAuthManager = lazy(() => oauthImport());
const SchedulesManager = lazy(() =>
  schedulesImport().then((m) => ({ default: m.default })),
);
const SecurityManager = lazy(() =>
  securityImport().then((m) => ({ default: m.default })),
);
const WebhookManager = lazy(() =>
  webhooksImport().then((m) => ({ default: m.default })),
);
const ModuleTemplatesBrowser = lazy(() =>
  templatesImport().then((m) => ({ default: m.default })),
);
const CapabilityCeilingManager = lazy(() =>
  capabilityCeilingImport().then((m) => ({ default: m.default })),
);

// Prefetch map: value → chunk loader.
const prefetchMap: Record<string, () => Promise<unknown>> = {
  integrations: integrationsImport,
  "api-keys": apiKeysImport,
  secrets: secretsImport,
  "mcp-server": mcpImport,
  audit: auditImport,
  approvals: approvalsImport,
  dlq: dlqImport,
  quotas: quotasImport,
  organizations: organizationsImport,
  "two-factor": twoFactorImport,
  oauth: oauthImport,
  schedules: schedulesImport,
  security: securityImport,
  webhooks: webhooksImport,
  templates: templatesImport,
  "capability-ceiling": capabilityCeilingImport,
};

// ─── Sidebar data ─────────────────────────────────────────────────────────────

interface SidebarItem {
  value: string;
  label: string;
  icon: LucideIcon;
}

interface SidebarCategory {
  label: string;
  items: SidebarItem[];
}

const SIDEBAR_CATEGORIES: SidebarCategory[] = [
  {
    label: "Account",
    items: [
      { value: "account", label: "Profile", icon: UserIcon },
      { value: "two-factor", label: "Two-Factor Auth", icon: Fingerprint },
      { value: "oauth", label: "OAuth Apps", icon: Globe },
    ],
  },
  {
    label: "Workflow",
    items: [
      { value: "schedules", label: "Schedules", icon: Calendar },
      { value: "templates", label: "Templates", icon: Layout },
    ],
  },
  {
    label: "Integrations",
    items: [
      { value: "integrations", label: "Integrations", icon: Plug },
      { value: "webhooks", label: "Webhooks", icon: Webhook },
      { value: "mcp-server", label: "MCP Server", icon: Server },
    ],
  },
  {
    label: "Security",
    items: [
      { value: "secrets", label: "Secrets", icon: LockIcon },
      { value: "api-keys", label: "API Keys", icon: Key },
      { value: "capability-ceiling", label: "Capabilities", icon: Layers },
      { value: "security", label: "Firewall & Access", icon: Shield },
    ],
  },
  {
    label: "Admin",
    items: [
      { value: "organizations", label: "Organizations", icon: Building },
      { value: "approvals", label: "Approvals", icon: CheckSquare },
      { value: "audit", label: "Audit & OTLP", icon: FileSearch },
      { value: "dlq", label: "Dead Letter Queue", icon: Inbox },
      { value: "quotas", label: "Resource Quotas", icon: BarChart },
    ],
  },
];

const ALL_ITEMS: SidebarItem[] = SIDEBAR_CATEGORIES.flatMap((c) => c.items);

// ─── Sidebar component ────────────────────────────────────────────────────────

interface SettingsSidebarProps {
  active: string;
  onSelect: (value: string) => void;
  onPrefetch: (value: string) => void;
}

function SettingsSidebar({ active, onSelect, onPrefetch }: SettingsSidebarProps) {
  const [search, setSearch] = useState("");

  const filteredCategories = search.trim()
    ? [
        {
          label: "Results",
          items: ALL_ITEMS.filter((item) =>
            item.label.toLowerCase().includes(search.toLowerCase()),
          ),
        },
      ]
    : SIDEBAR_CATEGORIES;

  return (
    <aside className="hidden sm:flex w-64 shrink-0 flex-col border-r border-white/5 bg-surface-2/40 backdrop-blur-xl overflow-y-auto custom-scrollbar">
      {/* Search */}
      <div className="p-4 sticky top-0 bg-surface-2/80 backdrop-blur-xl z-10">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/30 group-focus-within:text-primary transition-premium" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Find a setting…"
            className="w-full bg-surface-4/60 border border-white/10 rounded-2xl pl-10 pr-4 py-2.5 text-xs text-foreground placeholder-muted-foreground/20 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-premium"
          />
        </div>
      </div>

      {/* Category groups */}
      <nav className="flex-1 py-4 px-3 space-y-6">
        {filteredCategories.map((category) => (
          <div key={category.label}>
            <p className="px-3 mb-2 text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/30">
              {category.label}
            </p>
            <ul className="space-y-1">
              {category.items.map((item) => {
                const Icon = item.icon;
                const isActive = active === item.value;
                return (
                  <li key={item.value}>
                    <button
                      onClick={() => onSelect(item.value)}
                      onMouseEnter={() => onPrefetch(item.value)}
                      onFocus={() => onPrefetch(item.value)}
                      className={cn(
                        "w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-premium active:scale-95",
                        isActive
                          ? "bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_hsla(var(--primary),0.1)]"
                          : "text-muted-foreground/60 hover:text-foreground hover:bg-white/5 border border-transparent",
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-4 w-4 shrink-0 transition-transform",
                          isActive ? "text-primary scale-110" : "text-muted-foreground/30",
                        )}
                      />
                      {item.label}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}

        {filteredCategories[0]?.items.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
            <Search className="w-8 h-8 text-muted-foreground/10 mb-3" />
            <p className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-widest">
              No results for "{search}"
            </p>
          </div>
        )}
      </nav>
    </aside>
  );
}

// ─── Panel loading fallback ───────────────────────────────────────────────────

function PanelLoading() {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-4">
      <div className="w-12 h-12 rounded-2xl bg-surface-4/60 border border-white/5 flex items-center justify-center relative overflow-hidden">
        <div className="absolute inset-0 bg-primary/10 animate-pulse" />
        <div className="w-6 h-6 border-2 border-primary/20 border-t-primary rounded-full animate-spin relative z-10" />
      </div>
      <span className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-widest animate-status-pulse">Syncing Protocol...</span>
    </div>
  );
}

// ─── Main Settings page ───────────────────────────────────────────────────────

export default function Settings() {
  const { user, logout } = useAuth();

  // Initialize from URL hash, fall back to "integrations".
  const [active, setActive] = useState<string>(() => {
    const hash = window.location.hash.slice(1);
    return ALL_ITEMS.some((i) => i.value === hash) ? hash : "integrations";
  });

  // Keep URL hash in sync when active section changes.
  useEffect(() => {
    window.location.hash = active;
  }, [active]);

  // Handle browser back/forward navigation.
  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash.slice(1);
      if (ALL_ITEMS.some((i) => i.value === hash)) setActive(hash);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const handlePrefetch = useCallback((tab: string) => {
    prefetchMap[tab]?.();
  }, []);

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background relative">
      {/* Dynamic Background Glow */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-primary/5 via-background to-background opacity-50" />

      {/* Page header */}
      <header className="shrink-0 px-8 py-8 border-b border-white/5 bg-surface-1/60 backdrop-blur-xl relative z-20">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-surface-4/60 border border-white/5 flex items-center justify-center shadow-lg">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h1 className="text-3xl md:text-4xl font-black text-white tracking-tighter">Configuration</h1>
            <p className="text-[11px] font-black text-muted-foreground/40 uppercase tracking-widest mt-1.5 flex items-center gap-2">
              System Parameters &bull; Access Control &bull; Core Protocols
            </p>
          </div>
        </div>
      </header>

      {/* Mobile nav — horizontal scrollable pills, shown only below sm breakpoint */}
      <div className="sm:hidden relative shrink-0 z-20">
        <div className="absolute left-0 inset-y-0 w-8 bg-gradient-to-r from-background to-transparent z-10 pointer-events-none" />
        <div className="absolute right-0 inset-y-0 w-8 bg-gradient-to-l from-background to-transparent z-10 pointer-events-none" />
        <div className="flex gap-2 overflow-x-auto px-8 py-4 border-b border-white/5 bg-surface-2/40 backdrop-blur-xl custom-scrollbar">
        {ALL_ITEMS.map((item) => {
          const isActive = active === item.value;
          return (
            <button
              key={item.value}
              onClick={() => setActive(item.value)}
              className={cn(
                "whitespace-nowrap text-[10px] font-black uppercase tracking-widest px-4 py-2.5 rounded-full border transition-premium shrink-0",
                isActive
                  ? "bg-primary/10 text-primary border-primary/20 shadow-lg shadow-primary/5"
                  : "bg-surface-4/60 text-muted-foreground border-white/5 hover:text-foreground",
              )}
            >
              {item.label}
            </button>
          );
        })}
        </div>
      </div>

      {/* Two-column layout */}
      <div className="flex flex-1 overflow-hidden relative z-10">
        <SettingsSidebar
          active={active}
          onSelect={setActive}
          onPrefetch={handlePrefetch}
        />

        {/* Content area */}
        <main className="flex-1 overflow-y-auto custom-scrollbar">
          <div className="max-w-6xl mx-auto px-8 py-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {active === "integrations" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <IntegrationsManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "api-keys" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <ApiKeysManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "secrets" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <SecretsManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "mcp-server" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <McpServerSettings />
              </Suspense></ErrorBoundary>
            )}
            {active === "audit" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <AuditSettings />
              </Suspense></ErrorBoundary>
            )}
            {active === "approvals" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <ApprovalQueue />
              </Suspense></ErrorBoundary>
            )}
            {active === "dlq" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <DLQViewer />
              </Suspense></ErrorBoundary>
            )}
            {active === "quotas" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <ResourceQuotas />
              </Suspense></ErrorBoundary>
            )}
            {active === "organizations" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <OrganizationsManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "schedules" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <SchedulesManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "webhooks" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <WebhookManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "templates" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <ModuleTemplatesBrowser />
              </Suspense></ErrorBoundary>
            )}
            {active === "capability-ceiling" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <CapabilityCeilingManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "security" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <SecurityManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "two-factor" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <TwoFactorSettings enabled={user?.twoFactorEnabled || false} />
              </Suspense></ErrorBoundary>
            )}
            {active === "oauth" && (
              <ErrorBoundary><Suspense fallback={<PanelLoading />}>
                <OAuthManager />
              </Suspense></ErrorBoundary>
            )}
            {active === "account" && (
              <div className="bg-surface-3/40 border border-white/5 rounded-[3rem] p-10 glass relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />
                
                <div className="relative z-10 space-y-10">
                  <div className="flex items-center gap-6">
                    <div className="w-20 h-20 bg-surface-4/60 border border-white/10 rounded-[2rem] flex items-center justify-center shadow-2xl relative group/avatar">
                      <div className="absolute inset-0 bg-primary/10 rounded-[2rem] scale-0 group-hover/avatar:scale-100 transition-transform duration-500" />
                      <UserIcon className="w-10 h-10 text-primary relative z-10" />
                    </div>
                    <div>
                      <h2 className="text-4xl font-black text-white tracking-tighter">Identity Profile</h2>
                      <p className="text-[10px] font-black text-primary uppercase tracking-[0.2em] mt-1.5">
                        Operational Access & Security
                      </p>
                    </div>
                  </div>

                  <div className="grid gap-6">
                    <div className="bg-surface-4/40 border border-white/5 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 group/field hover:bg-surface-4/60 transition-premium">
                      <div className="min-w-0">
                        <span className="text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 mb-1.5 block">
                          Authenticated Entity
                        </span>
                        <p className="text-lg md:text-xl font-black text-white tracking-tight truncate">
                          {user?.email || user?.name}
                        </p>
                      </div>
                      <div className="shrink-0 px-4 py-2 bg-success/10 border border-success/20 rounded-full shadow-[0_0_15px_hsla(var(--success),0.1)] w-fit">
                        <span className="text-[10px] font-black text-success uppercase tracking-widest">
                          Primary Identity
                        </span>
                      </div>
                    </div>

                    <div className="bg-warning/5 border border-warning/10 rounded-[2rem] p-8 flex items-start gap-6 relative overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-warning/10 to-transparent opacity-50" />
                      <div className="p-4 bg-warning/10 rounded-2xl text-warning relative z-10 border border-warning/20">
                        <LockIcon className="w-6 h-6" />
                      </div>
                      <div className="relative z-10 flex-1">
                        <h4 className="text-lg font-black text-warning tracking-tight">Security Integrity Protocol</h4>
                        <p className="text-xs text-warning/60 leading-relaxed mt-2 font-medium">
                          You are currently using session-based authentication. Advanced 
                          multi-factor parameters and biometric keys are managed through 
                          the primary core identity provider.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="pt-8 border-t border-white/5 flex justify-end">
                    <button
                      onClick={logout}
                      className="px-10 py-4 text-[10px] font-black uppercase tracking-widest border border-destructive/20 text-destructive hover:text-white hover:bg-destructive transition-premium active:scale-95 rounded-2xl shadow-lg shadow-destructive/5"
                    >
                      De-authenticate Session
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
