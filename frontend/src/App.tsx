import React, { Suspense, lazy } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  Navigate,
  useLocation,
} from "react-router-dom";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { AuthForm } from "@/components/auth/AuthForm";
import { OAuthCallback } from "@/components/auth/OAuthCallback";
import { useTokenRefresh } from "@/hooks/useTokenRefresh";
import { useGetApprovalsQuery } from "@/generated/graphql";
import { Zap, Activity } from "lucide-react";
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

function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-50" />
      <div className="absolute top-[-20%] right-[-10%] w-[60%] h-[60%] bg-primary/5 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] bg-violet-500/5 rounded-full blur-[100px] animate-pulse delay-700" />

      <div className="relative z-10 text-center space-y-8 animate-in fade-in zoom-in-95 duration-1000">
        <div className="relative inline-block group">
          <div className="absolute -inset-4 bg-primary/20 rounded-[2.5rem] blur-2xl group-hover:bg-primary/30 transition-premium opacity-50" />
          <div className="relative w-24 h-24 rounded-3xl bg-surface-1/60 border border-white/10 flex items-center justify-center shadow-2xl glass-dark optimize-blur">
            <Zap
              size={48}
              className="text-primary animate-status-pulse"
              fill="currentColor"
            />
          </div>
        </div>

        <div className="space-y-3">
          <h2 className="text-sm font-black text-white tracking-[0.4em] uppercase font-outfit">
            Initializing Talos
          </h2>
          <div className="w-48 h-1 bg-white/5 rounded-full mx-auto overflow-hidden relative">
            <div className="absolute inset-y-0 left-0 bg-primary w-1/2 rounded-full animate-progress-shimmer shadow-[0_0_15px_hsla(var(--primary),0.5)]" />
          </div>
          <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.2em] animate-pulse">
            Establishing Secure Link...
          </p>
        </div>
      </div>
    </div>
  );
}

function AuthenticatedApp() {
  const { user, logout } = useAuth();
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
      "relative px-4 py-2 text-xs font-black uppercase tracking-widest transition-premium rounded-xl group",
      isActive
        ? "text-primary bg-primary/5"
        : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
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
          className="h-16 flex items-center px-8 gap-10 shrink-0 z-50 border-b border-white/5 bg-surface-1/40 backdrop-blur-3xl relative"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

          <div className="flex items-center gap-4 group cursor-pointer relative z-10">
            <div className="p-2 bg-primary/10 rounded-2xl border border-primary/20 group-hover:bg-primary/20 group-hover:shadow-[0_0_20px_hsla(var(--primary),0.2)] transition-premium">
              <Zap className="w-5 h-5 text-primary" fill="currentColor" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-black text-white tracking-tight leading-none font-outfit">
                TALOS
              </span>
              <span className="text-[9px] text-primary/40 font-black tracking-[0.3em] mt-1 uppercase">
                Studio
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 relative z-10">
            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/" end className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Workflows
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                View and manage saved workflows
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/briefings" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Briefings
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Latest results from your workflows
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/editor" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Editor
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Build workflows on the visual canvas
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/actors" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Actors
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Manage AI execution identities
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/models" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Models
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Review model disagreements
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/library" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      Library
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Browse templates and installed modules
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink to="/settings" className={navLinkClass}>
                  {({ isActive }) => (
                    <>
                      <span className="flex items-center gap-2">
                        Settings
                        {pendingCount > 0 && (
                          <span className="inline-flex items-center justify-center w-4 h-4 text-[9px] font-black bg-warning text-warning-foreground rounded-full shadow-[0_0_10px_hsla(var(--warning),0.3)]">
                            {pendingCount > 9 ? "9+" : pendingCount}
                          </span>
                        )}
                      </span>
                      {isActive && (
                        <span className="absolute -bottom-1.5 left-4 right-4 h-0.5 bg-primary rounded-full shadow-[0_0_10px_hsla(var(--primary),0.5)] animate-in fade-in zoom-in-50 duration-500" />
                      )}
                    </>
                  )}
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                Integrations, security, and account
              </TooltipContent>
            </Tooltip>
          </div>

          <div className="ml-auto flex items-center gap-6 relative z-10">
            <Tooltip>
              <TooltipTrigger asChild>
                <NavLink
                  to="/health"
                  className={({ isActive }) =>
                    cn(
                      "p-2.5 rounded-2xl transition-premium border relative group",
                      isActive
                        ? "text-primary bg-primary/5 border-primary/20 shadow-[0_0_15px_hsla(var(--primary),0.1)]"
                        : "text-muted-foreground/40 hover:text-white hover:bg-white/5 border-transparent",
                    )
                  }
                >
                  <Activity className="w-4 h-4" />
                  <div className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-success animate-status-pulse group-hover:shadow-[0_0_8px_hsla(var(--success),0.5)]" />
                </NavLink>
              </TooltipTrigger>
              <TooltipContent
                side="bottom"
                className="bg-surface-4 border-white/5 text-[10px] font-black uppercase tracking-widest shadow-2xl"
              >
                System health
              </TooltipContent>
            </Tooltip>

            <div className="h-6 w-px bg-white/5 mx-1" />

            <div className="flex flex-col items-end">
              <span className="font-black text-white text-xs tracking-tight font-outfit leading-none">
                {user?.name || "User"}
              </span>
              <span className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-tight mt-1">
                {user?.email}
              </span>
            </div>

            <button
              onClick={logout}
              className="px-4 py-2 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-destructive hover:bg-destructive/5 border border-transparent hover:border-destructive/20 rounded-xl transition-premium active:scale-95"
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
                <Route path="/library" element={<Library />} />
                <Route
                  path="/catalog"
                  element={<Navigate to="/library#templates" replace />}
                />
                <Route
                  path="/modules"
                  element={<Navigate to="/library#installed" replace />}
                />
                <Route path="/health" element={<Health />} />
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

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </BrowserRouter>
  );
}
