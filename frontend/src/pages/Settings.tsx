import React, { Suspense, lazy, useCallback, useState, useEffect } from "react";
import { LoadingState } from "@/components/ui/spinner";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import ErrorBoundary from "@/components/ErrorBoundary";
import { useAuth } from "@/contexts/AuthContext";
import { Link, useNavigate } from "react-router";
import { cn } from "@/lib/utils";
import { PageContainer, PageHeader } from "@/components/ui";
import { SETTINGS_GROUPS, type SettingsSection } from "@/lib/settingsSections";
import { User as UserIcon } from "lucide-react";

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
  account: () =>
    Promise.all([passwordImport(), twoFactorImport(), oauthImport()]),
  schedules: schedulesImport,
  security: securityImport,
  webhooks: webhooksImport,
  "capability-ceiling": capabilityCeilingImport,
};

// ─── Sidebar data ─────────────────────────────────────────────────────────────

/** Hashes that used to name a section of their own; each is a card on Account. */
const SECTION_ALIASES: Record<string, string> = {
  password: "account",
  "two-factor": "account",
  oauth: "account",
};

/** Which section a hash opens, and which card on it to scroll to. */
function resolveHash(
  hash: string,
): { section: string; anchor?: string } | null {
  if (SECTION_ALIASES[hash])
    return { section: SECTION_ALIASES[hash], anchor: hash };
  if (SECTION_ITEMS.some((i) => i.value === hash)) return { section: hash };
  return null;
}

const ALL_ITEMS: SettingsSection[] = SETTINGS_GROUPS.flatMap((c) => c.items);
/** The sections this page renders itself (a hash may name one of these). */
const SECTION_ITEMS: SettingsSection[] = ALL_ITEMS.filter((i) => !i.to);

const sidebarItemClass = (isActive: boolean) =>
  cn(
    "w-full flex items-center gap-3 px-3 py-1 rounded-lg text-sm font-medium transition-ui",
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
  return (
    <aside className="hidden sm:flex w-60 shrink-0 flex-col border-r border-white/5 bg-surface-2/40 overflow-y-auto custom-scrollbar">
      <nav className="flex-1 py-3 px-3 space-y-3" aria-label="Settings">
        {SETTINGS_GROUPS.map((category) => (
          <div key={category.label}>
            <p className="px-3 mb-0.5 text-2xs font-semibold uppercase tracking-wider text-muted-foreground">
              {category.label}
            </p>
            <ul className="space-y-0.5">
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
                        aria-current={isActive ? "page" : undefined}
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
      </nav>
    </aside>
  );
}

// ─── Panel loading fallback ───────────────────────────────────────────────────

function PanelLoading() {
  return <LoadingState data-panel-loading />;
}

// ─── Main Settings page ───────────────────────────────────────────────────────

export default function Settings() {
  const { user, logout } = useAuth();

  // Initialize from URL hash, fall back to "integrations".
  const navigate = useNavigate();
  const [active, setActive] = useState<string>(
    () => resolveHash(window.location.hash.slice(1))?.section ?? "integrations",
  );
  // A card on the Account page the hash asked for (#password, #two-factor, #oauth).
  const [anchor, setAnchor] = useState<string | null>(
    () => resolveHash(window.location.hash.slice(1))?.anchor ?? null,
  );

  // Keep URL hash in sync when active section changes.
  useEffect(() => {
    window.location.hash = active;
  }, [active]);

  // Handle browser back/forward navigation.
  useEffect(() => {
    const onHashChange = () => {
      const target = resolveHash(window.location.hash.slice(1));
      if (!target) return;
      setActive(target.section);
      if (target.anchor) setAnchor(target.anchor);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // Scroll to the requested card once every lazy card above it has rendered
  // (the section wrappers exist at once; their content arrives in chunks, and
  // a scroll taken before the cards above have their height lands short).
  useEffect(() => {
    if (!anchor) return;
    let tries = 0;
    const timer = window.setInterval(() => {
      const el = document.getElementById(anchor);
      const settled = el && !document.querySelector("[data-panel-loading]");
      if (settled || ++tries > 40) {
        el?.scrollIntoView({ block: "start" });
        window.clearInterval(timer);
        setAnchor(null);
      }
    }, 100);
    return () => window.clearInterval(timer);
  }, [anchor]);

  const handlePrefetch = useCallback((tab: string) => {
    prefetchMap[tab]?.();
  }, []);

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background">
      {/* Page header */}
      <header className="shrink-0 px-6 md:px-8 py-6 border-b border-white/5 bg-surface-1/60">
        <PageHeader
          title="Settings"
          description="Your account, integrations and security."
          className="mb-0"
        />
      </header>

      {/* Below sm the sidebar is a select: every section, grouped, on one tap. */}
      <div className="sm:hidden shrink-0 px-6 py-3 border-b border-white/5 bg-surface-2/40">
        <label htmlFor="settings-section" className="sr-only">
          Settings section
        </label>
        <Select
          id="settings-section"
          value={active}
          onChange={(e) => {
            const item = ALL_ITEMS.find((i) => i.value === e.target.value);
            if (item?.to) navigate(item.to);
            else setActive(e.target.value);
          }}
        >
          {SETTINGS_GROUPS.map((category) => (
            <optgroup key={category.label} label={category.label}>
              {category.items.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </optgroup>
          ))}
        </Select>
      </div>

      {/* Two-column layout */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        <SettingsSidebar
          active={active}
          onSelect={setActive}
          onPrefetch={handlePrefetch}
        />

        {/* Content area */}
        <main className="flex-1 overflow-y-auto custom-scrollbar">
          <PageContainer>
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
            {active === "account" && (
              <div className="space-y-8">
                <section
                  id="profile"
                  className="bg-surface-3/40 border border-white/5 rounded-2xl p-10"
                >
                  <div className="flex items-center gap-6">
                    <div className="w-14 h-14 bg-surface-4/60 border border-white/10 rounded-2xl flex items-center justify-center shrink-0">
                      <UserIcon className="w-7 h-7 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5 block">
                        Signed in as
                      </span>
                      <p className="text-lg md:text-xl font-semibold text-white tracking-tight truncate">
                        {user?.email || user?.name}
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      className="ml-auto shrink-0 text-destructive border-destructive/20 hover:bg-destructive/10 hover:text-destructive"
                      onClick={logout}
                    >
                      Sign out
                    </Button>
                  </div>
                </section>
                <section id="password" className="scroll-mt-6">
                  <ErrorBoundary>
                    <Suspense fallback={<PanelLoading />}>
                      <PasswordSettings />
                    </Suspense>
                  </ErrorBoundary>
                </section>
                <section id="two-factor" className="scroll-mt-6">
                  <ErrorBoundary>
                    <Suspense fallback={<PanelLoading />}>
                      <TwoFactorSettings
                        enabled={user?.twoFactorEnabled || false}
                      />
                    </Suspense>
                  </ErrorBoundary>
                </section>
                <section id="oauth" className="scroll-mt-6">
                  <ErrorBoundary>
                    <Suspense fallback={<PanelLoading />}>
                      <OAuthManager />
                    </Suspense>
                  </ErrorBoundary>
                </section>
              </div>
            )}
          </PageContainer>
        </main>
      </div>
    </div>
  );
}
