import React, { Suspense, lazy, useCallback, useState, useEffect } from "react";
import ErrorBoundary from "@/components/ErrorBoundary";
import { useAuth } from "@/contexts/AuthContext";
import { Link } from "react-router";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui";
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
  KeyRound,
  Globe,
  Search,
  Layers,
  type LucideIcon,
  Activity,
  AlertTriangle,
  BrainCircuit,
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
const passwordImport = () => import("@/components/settings/PasswordSettings");
const oauthImport = () => import("@/components/settings/OAuthManager");
const schedulesImport = () => import("@/components/settings/SchedulesManager");
const securityImport = () => import("@/components/settings/SecurityManager");
const webhooksImport = () => import("@/components/settings/WebhookManager");
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
const PasswordSettings = lazy(() => passwordImport());
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
  password: passwordImport,
  oauth: oauthImport,
  schedules: schedulesImport,
  security: securityImport,
  webhooks: webhooksImport,
  "capability-ceiling": capabilityCeilingImport,
};

// ─── Sidebar data ─────────────────────────────────────────────────────────────

interface SidebarItem {
  value: string;
  label: string;
  icon: LucideIcon;
  /** A page of its own, listed here so it has a home; it is not a section. */
  to?: string;
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
      { value: "password", label: "Password", icon: KeyRound },
      { value: "two-factor", label: "Two-factor auth", icon: Fingerprint },
      { value: "oauth", label: "Connected sign-ins", icon: Globe },
    ],
  },
  {
    label: "Workflow",
    items: [
      { value: "schedules", label: "Schedules", icon: Calendar },
      {
        value: "templates",
        label: "Templates",
        icon: Layout,
        to: "/library#templates",
      },
    ],
  },
  {
    label: "Integrations",
    items: [
      { value: "integrations", label: "Integrations", icon: Plug },
      { value: "webhooks", label: "Webhooks", icon: Webhook },
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
  {
    label: "Admin",
    items: [
      { value: "organizations", label: "Organizations", icon: Building },
      { value: "approvals", label: "Approvals", icon: CheckSquare },
      { value: "audit", label: "Audit log and tracing", icon: FileSearch },
      { value: "dlq", label: "Failed deliveries", icon: Inbox },
      { value: "quotas", label: "Quotas", icon: BarChart },
    ],
  },
];

const ALL_ITEMS: SidebarItem[] = SIDEBAR_CATEGORIES.flatMap((c) => c.items);
/** The sections this page renders itself (a hash may name one of these). */
const SECTION_ITEMS: SidebarItem[] = ALL_ITEMS.filter((i) => !i.to);

const sidebarItemClass = (isActive: boolean) =>
  cn(
    "w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-premium",
    isActive
      ? "bg-primary/10 text-primary"
      : "text-muted-foreground hover:text-foreground hover:bg-white/5",
  );

// ─── Sidebar component ────────────────────────────────────────────────────────

interface SettingsSidebarProps {
  active: string;
  onSelect: (value: string) => void;
  onPrefetch: (value: string) => void;
}

function SettingsSidebar({
  active,
  onSelect,
  onPrefetch,
}: SettingsSidebarProps) {
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
    <aside className="hidden sm:flex w-64 shrink-0 flex-col border-r border-white/5 bg-surface-2/40 overflow-y-auto custom-scrollbar">
      {/* Search */}
      <div className="p-4 sticky top-0 bg-surface-2/80 z-10">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60 group-focus-within:text-primary transition-premium" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Find a setting…"
            className="w-full bg-surface-4/60 border border-white/10 rounded-xl pl-10 pr-4 py-2 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-premium"
          />
        </div>
      </div>

      {/* Category groups */}
      <nav className="flex-1 py-4 px-3 space-y-6">
        {filteredCategories.map((category) => (
          <div key={category.label}>
            <p className="px-3 mb-2 text-2xs font-semibold uppercase tracking-wider text-muted-foreground">
              {category.label}
            </p>
            <ul className="space-y-1">
              {category.items.map((item) => {
                const Icon = item.icon;
                const isActive = active === item.value;
                const content = (
                  <>
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        isActive ? "text-primary" : "text-muted-foreground/70",
                      )}
                    />
                    {item.label}
                  </>
                );
                return (
                  <li key={item.value}>
                    {item.to ? (
                      <Link to={item.to} className={sidebarItemClass(false)}>
                        {content}
                      </Link>
                    ) : (
                      <button
                        onClick={() => onSelect(item.value)}
                        onMouseEnter={() => onPrefetch(item.value)}
                        onFocus={() => onPrefetch(item.value)}
                        className={sidebarItemClass(isActive)}
                      >
                        {content}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        ))}

        {filteredCategories[0]?.items.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
            <Search className="w-8 h-8 text-muted-foreground/30 mb-3" />
            <p className="text-sm text-muted-foreground">
              No settings match “{search}”
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
      <span className="text-sm text-muted-foreground">Loading…</span>
    </div>
  );
}

// ─── Main Settings page ───────────────────────────────────────────────────────

export default function Settings() {
  const { user, logout } = useAuth();

  // Initialize from URL hash, fall back to "integrations".
  const [active, setActive] = useState<string>(() => {
    const hash = window.location.hash.slice(1);
    return SECTION_ITEMS.some((i) => i.value === hash) ? hash : "integrations";
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
      <header className="shrink-0 px-8 py-6 border-b border-white/5 bg-surface-1/60 relative z-20">
        <PageHeader
          title="Settings"
          description="Your account, integrations and security."
          className="mb-0"
        />
      </header>

      {/* Mobile nav — horizontal scrollable pills, shown only below sm breakpoint */}
      <div className="sm:hidden relative shrink-0 z-20">
        <div className="flex gap-2 overflow-x-auto px-8 py-4 border-b border-white/5 bg-surface-2/40 custom-scrollbar">
          {ALL_ITEMS.map((item) => {
            const isActive = !item.to && active === item.value;
            const pill = cn(
              "whitespace-nowrap text-xs font-medium px-3 py-2 rounded-full border transition-premium shrink-0",
              isActive
                ? "bg-primary/10 text-primary border-primary/20"
                : "bg-surface-4/60 text-muted-foreground border-white/5 hover:text-foreground",
            );
            return item.to ? (
              <Link key={item.value} to={item.to} className={pill}>
                {item.label}
              </Link>
            ) : (
              <button
                key={item.value}
                onClick={() => setActive(item.value)}
                className={pill}
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
          <div className="max-w-6xl mx-auto px-8 py-10 animate-in fade-in duration-300">
            {active === "integrations" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <IntegrationsManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "api-keys" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <ApiKeysManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "secrets" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <SecretsManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "mcp-server" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <McpServerSettings />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "audit" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <AuditSettings />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "approvals" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <ApprovalQueue />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "dlq" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <DLQViewer />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "quotas" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <ResourceQuotas />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "organizations" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <OrganizationsManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "schedules" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <SchedulesManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "webhooks" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <WebhookManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "capability-ceiling" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <CapabilityCeilingManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "security" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <SecurityManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "password" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <PasswordSettings />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "two-factor" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <TwoFactorSettings
                    enabled={user?.twoFactorEnabled || false}
                  />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "oauth" && (
              <ErrorBoundary>
                <Suspense fallback={<PanelLoading />}>
                  <OAuthManager />
                </Suspense>
              </ErrorBoundary>
            )}
            {active === "account" && (
              <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden group">
                <div className="relative z-10 space-y-10">
                  <div className="flex items-center gap-6">
                    <div className="w-20 h-20 bg-surface-4/60 border border-white/10 rounded-2xl flex items-center justify-center relative group/avatar">
                      <div className="absolute inset-0 bg-primary/10 rounded-2xl scale-0 transition-transform duration-500" />
                      <UserIcon className="w-10 h-10 text-primary relative z-10" />
                    </div>
                    <div>
                      <h2 className="text-2xl font-semibold text-white tracking-tight">
                        Profile
                      </h2>
                      <p className="text-sm text-muted-foreground mt-1">
                        The account you are signed in with.
                      </p>
                    </div>
                  </div>

                  <div className="grid gap-6">
                    <div className="bg-surface-4/40 border border-white/5 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 group/field hover:bg-surface-4/60 transition-premium">
                      <div className="min-w-0">
                        <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5 block">
                          Signed in as
                        </span>
                        <p className="text-lg md:text-xl font-semibold text-white tracking-tight truncate">
                          {user?.email || user?.name}
                        </p>
                      </div>
                      <div className="shrink-0 px-4 py-2 bg-success/10 border border-success/20 rounded-full w-fit">
                        <span className="text-xs font-medium text-success">
                          Active session
                        </span>
                      </div>
                    </div>

                    <div className="bg-warning/5 border border-warning/10 rounded-2xl p-8 flex items-start gap-6 relative overflow-hidden">
                      <div className="p-4 bg-warning/10 rounded-2xl text-warning relative z-10 border border-warning/20">
                        <LockIcon className="w-6 h-6" />
                      </div>
                      <div className="relative z-10 flex-1">
                        <h4 className="text-base font-semibold text-warning tracking-tight">
                          Password and two-factor sign-in
                        </h4>
                        <p className="text-sm text-warning/70 leading-relaxed mt-1.5">
                          Change your password under Password, and turn on an
                          authenticator app under Two-factor auth. Accounts that
                          sign in with Google or Okta manage both with that
                          provider.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="pt-8 border-t border-white/5 flex justify-end">
                    <button
                      onClick={logout}
                      className="px-4 h-10 text-sm font-medium border border-destructive/20 text-destructive hover:text-white hover:bg-destructive transition-premium rounded-xl"
                    >
                      Sign out
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
