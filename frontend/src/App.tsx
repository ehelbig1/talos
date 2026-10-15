import React, { Suspense, lazy } from "react";
import {
  createBrowserRouter,
  Routes,
  Route,
  NavLink,
  Navigate,
  useLocation,
} from "react-router";
import { RouterProvider } from "react-router/dom";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { AuthForm } from "@/components/auth/AuthForm";
import { OAuthCallback } from "@/components/auth/OAuthCallback";
import { useTokenRefresh } from "@/hooks/useTokenRefresh";
import { useGetApprovalsQuery } from "@/generated/graphql";
import {
  Zap,
  Loader2,
  Workflow,
  Newspaper,
  Bot,
  BookOpen,
  Settings as SettingsIcon,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import ErrorBoundary from "@/components/ErrorBoundary";
import { CompilationStatus } from "@/components/CompilationStatus";

const Dashboard = lazy(() => import("@/pages/dashboard"));
const Briefings = lazy(() => import("@/pages/Briefings"));
const EditorPage = lazy(() => import("@/pages/EditorPage"));
const Settings = lazy(() => import("@/pages/Settings"));
const Actors = lazy(() => import("@/pages/Actors"));
const ActorDetail = lazy(() => import("@/pages/ActorDetail"));
const ActorCompare = lazy(() => import("@/pages/ActorCompare"));
const Health = lazy(() => import("@/pages/Health"));
const Library = lazy(() => import("@/pages/Library"));
const ModelReview = lazy(() => import("@/pages/ModelReview"));
const AlertTriage = lazy(() => import("@/pages/AlertTriage"));

/** The primary navigation, in the order a new user meets the product. */
const NAV_ITEMS: {
  to: string;
  label: string;
  /** Shown in place of the label below the md breakpoint. */
  icon: LucideIcon;
  end?: boolean;
  /** Other paths this entry is the home of (the editor belongs to Workflows). */
  alsoActiveOn?: string[];
}[] = [
  {
    to: "/",
    label: "Workflows",
    icon: Workflow,
    end: true,
    alsoActiveOn: ["/editor"],
  },
  { to: "/briefings", label: "Briefings", icon: Newspaper },
  { to: "/actors", label: "Actors", icon: Bot },
  { to: "/library", label: "Library", icon: BookOpen },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

function isHomeOf(item: (typeof NAV_ITEMS)[number], pathname: string): boolean {
  return (item.alsoActiveOn ?? []).some(
    (p) => pathname === p || pathname.startsWith(p + "/"),
  );
}

function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-5">
        <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
          <Zap size={28} className="text-primary" fill="currentColor" />
        </div>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading…
        </div>
      </div>
    </div>
  );
}

function AuthenticatedApp() {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  useTokenRefresh();

  const { data: approvalsData } = useGetApprovalsQuery(
    {},
    { refetchInterval: 60_000, refetchOnWindowFocus: true },
  );
  const pendingCount =
    approvalsData?.pendingApprovals?.filter((a) => a.status === "pending")
      .length ?? 0;

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "relative px-3 py-1.5 text-sm font-medium rounded-lg transition-ui",
      isActive
        ? "text-white bg-white/5"
        : "text-muted-foreground hover:text-white hover:bg-white/5",
    );

  return (
    <TooltipProvider>
      <div className="flex flex-col h-screen bg-background font-inter">
        {/* Real-time Compilation Feedback */}
        <CompilationStatus />

        {/* Skip to content — keyboard accessibility */}
        <a href="#main-content" className="skip-to-content">
          Skip to main content
        </a>
        {/* Navigation */}
        <nav
          role="navigation"
          aria-label="Main navigation"
          className="h-14 flex items-center px-4 md:px-6 gap-4 md:gap-8 shrink-0 z-50 border-b border-white/5 bg-surface-1/60 backdrop-blur-xl"
        >
          <NavLink to="/" className="flex items-center gap-3">
            <div className="p-1.5 bg-primary/10 rounded-lg border border-primary/20">
              <Zap className="w-4 h-4 text-primary" fill="currentColor" />
            </div>
            <span className="hidden md:inline text-sm font-semibold text-white tracking-tight font-outfit">
              Talos
            </span>
          </NavLink>

          <div className="flex items-center gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                aria-label={item.label}
                title={item.label}
                className={({ isActive }) =>
                  navLinkClass({
                    isActive: isActive || isHomeOf(item, pathname),
                  })
                }
              >
                {({ isActive: routeActive }) => (
                  <>
                    <span className="flex items-center gap-2">
                      <item.icon className="w-4 h-4 md:hidden" aria-hidden />
                      <span className="hidden md:inline">{item.label}</span>
                      {item.to === "/settings" && pendingCount > 0 && (
                        <span
                          className="inline-flex items-center justify-center min-w-4 h-4 px-1 text-2xs font-semibold bg-warning text-warning-foreground rounded-full"
                          title={`${pendingCount} pending approval${pendingCount === 1 ? "" : "s"}`}
                        >
                          {pendingCount > 9 ? "9+" : pendingCount}
                        </span>
                      )}
                    </span>
                    {(routeActive || isHomeOf(item, pathname)) && (
                      <span className="absolute -bottom-[13px] left-3 right-3 h-0.5 bg-primary rounded-full" />
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </div>

          <div className="ml-auto flex items-center gap-4">
            <div className="hidden lg:block h-6 w-px bg-white/10" />

            <div
              className="hidden lg:flex flex-col items-end leading-tight max-w-[220px]"
              title={user?.email}
            >
              <span className="text-sm font-medium text-white truncate max-w-full">
                {user?.name || "User"}
              </span>
              <span className="text-xs text-muted-foreground truncate max-w-full">
                {user?.email}
              </span>
            </div>

            <button
              onClick={logout}
              className="px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-white hover:bg-white/5 rounded-lg transition-ui"
            >
              Sign out
            </button>
          </div>
        </nav>

        {/* Page content */}
        <main
          id="main-content"
          role="main"
          className="flex-1 overflow-hidden bg-background"
        >
          <ErrorBoundary>
            <Suspense fallback={<LoadingScreen />}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/briefings" element={<Briefings />} />
                <Route path="/editor/:id?" element={<EditorPage />} />
                <Route path="/actors" element={<Actors />} />
                <Route path="/actors/compare" element={<ActorCompare />} />
                <Route path="/actors/:id" element={<ActorDetail />} />
                <Route path="/models" element={<ModelReview />} />
                <Route path="/alerts" element={<AlertTriage />} />
                <Route path="/library" element={<Library />} />
                <Route
                  path="/catalog"
                  element={<Navigate to="/library#templates" replace />}
                />
                <Route
                  path="/modules"
                  element={<Navigate to="/library#installed" replace />}
                />
                <Route path="/system-health" element={<Health />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </TooltipProvider>
  );
}

function AppContent() {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <LoadingScreen />;
  }

  // OAuth callback must be accessible before authentication
  if (location.pathname.startsWith("/auth/callback")) {
    return <OAuthCallback />;
  }

  if (!isAuthenticated) {
    return <AuthForm />;
  }

  return <AuthenticatedApp />;
}

// A data router (one splat route; the app's own <Routes> stay descendant
// routes) so pages can use `useBlocker` — the editor's unsaved-changes guard.
function createAppRouter() {
  return createBrowserRouter([
    {
      path: "*",
      element: (
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      ),
    },
  ]);
}

export default function App() {
  const [router] = React.useState(createAppRouter);
  return <RouterProvider router={router} />;
}
