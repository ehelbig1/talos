import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useNavigate } from "react-router";
import {
  BookOpen,
  Bot,
  CornerDownLeft,
  GitCompare,
  Newspaper,
  Plus,
  Search,
  Settings as SettingsIcon,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useListActorsQuery, useWorkflowsQuery } from "@/generated/graphql";
import { SETTINGS_GROUPS, settingsSectionPath } from "@/lib/settingsSections";
import { cn } from "@/lib/utils";

/** Fired on `window` to open the palette from anywhere (the nav button). */
export const OPEN_COMMAND_PALETTE_EVENT = "talos:open-command-palette";

export function openCommandPalette(): void {
  window.dispatchEvent(new Event(OPEN_COMMAND_PALETTE_EVENT));
}

interface PaletteItem {
  id: string;
  label: string;
  /** Shown after the label, in muted type. */
  hint?: string;
  group: "Pages" | "Actions" | "Settings" | "Workflows" | "Actors";
  icon: LucideIcon;
  to: string;
}

/** `g` then one of these goes to the page, outside a text field. */
export const GO_SHORTCUTS: Record<string, { label: string; to: string }> = {
  w: { label: "Workflows", to: "/" },
  b: { label: "Briefings", to: "/briefings" },
  a: { label: "Actors", to: "/actors" },
  l: { label: "Library", to: "/library" },
  s: { label: "Settings", to: "/settings" },
  h: { label: "System health", to: "/system-health" },
};

const SEQUENCE_WINDOW_MS = 800;
const MAX_PER_GROUP = 8;

const STATIC_ITEMS: PaletteItem[] = [
  { id: "page:/", label: "Workflows", group: "Pages", icon: Workflow, to: "/" },
  {
    id: "page:/briefings",
    label: "Briefings",
    group: "Pages",
    icon: Newspaper,
    to: "/briefings",
  },
  {
    id: "page:/actors",
    label: "Actors",
    group: "Pages",
    icon: Bot,
    to: "/actors",
  },
  {
    id: "page:/library",
    label: "Library",
    group: "Pages",
    icon: BookOpen,
    to: "/library",
  },
  {
    id: "page:/settings",
    label: "Settings",
    group: "Pages",
    icon: SettingsIcon,
    to: "/settings",
  },
  {
    id: "action:new-workflow",
    label: "New workflow",
    group: "Actions",
    icon: Plus,
    to: "/editor",
  },
  {
    id: "action:compare-actors",
    label: "Compare actors",
    group: "Actions",
    icon: GitCompare,
    to: "/actors/compare",
  },
  ...SETTINGS_GROUPS.flatMap((group) =>
    group.items.map((item): PaletteItem => ({
      id: `settings:${item.value}`,
      label: item.label,
      hint: group.label,
      group: "Settings",
      icon: item.icon,
      to: settingsSectionPath(item),
    })),
  ),
];

/** True when the key press belongs to a text field, where shortcuts must not fire. */
function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    el.isContentEditable
  );
}

/**
 * How well `label` matches `query`: 3 for a prefix, 2 for a word start,
 * 1 for a substring, 0 for no match. Case-insensitive.
 */
export function matchScore(label: string, query: string): number {
  const l = label.toLowerCase();
  const q = query.toLowerCase().trim();
  if (!q) return 1;
  if (l.startsWith(q)) return 3;
  if (l.split(/[\s/-]+/).some((w) => w.startsWith(q))) return 2;
  return l.includes(q) ? 1 : 0;
}

const GROUP_ORDER: PaletteItem["group"][] = [
  "Pages",
  "Actions",
  "Workflows",
  "Actors",
  "Settings",
];

/**
 * ⌘K / Ctrl+K: jump to a page, a settings section, a workflow or an actor.
 * Workflows and actors are fetched only while the palette is open.
 */
export function CommandPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const pendingGo = useRef<number | null>(null);
  const listId = "command-palette-list";

  const close = useCallback(() => {
    setOpen(false);
    setQuery("");
    setActive(0);
  }, []);

  const go = useCallback(
    (to: string) => {
      close();
      navigate(to);
    },
    [close, navigate],
  );

  // ⌘K toggles; `g` then a letter goes to a page; both stay out of text fields.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        (e.metaKey || e.ctrlKey) &&
        !e.altKey &&
        e.key.toLowerCase() === "k"
      ) {
        e.preventDefault();
        setOpen((v) => !v);
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target))
        return;
      if (document.querySelector("[role=dialog]")) return;
      const now = Date.now();
      if (
        pendingGo.current !== null &&
        now - pendingGo.current < SEQUENCE_WINDOW_MS
      ) {
        pendingGo.current = null;
        const target = GO_SHORTCUTS[e.key.toLowerCase()];
        if (target) {
          e.preventDefault();
          navigate(target.to);
        }
        return;
      }
      pendingGo.current = e.key === "g" ? now : null;
    };
    const onOpen = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener(OPEN_COMMAND_PALETTE_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(OPEN_COMMAND_PALETTE_EVENT, onOpen);
    };
  }, [navigate]);

  const workflows = useWorkflowsQuery(undefined, {
    enabled: open,
    staleTime: 60_000,
    select: (d) => d.workflows.map((w) => ({ id: w.id, name: w.name })),
  });
  const actors = useListActorsQuery(undefined, {
    enabled: open,
    staleTime: 60_000,
    select: (d) => d.actors.map((a) => ({ id: a.id, name: a.name })),
  });

  const items = useMemo(() => {
    const dynamic: PaletteItem[] = [
      ...(workflows.data ?? []).map((w): PaletteItem => ({
        id: `workflow:${w.id}`,
        label: w.name,
        group: "Workflows",
        icon: Workflow,
        to: `/editor/${encodeURIComponent(w.id)}`,
      })),
      ...(actors.data ?? []).map((a): PaletteItem => ({
        id: `actor:${a.id}`,
        label: a.name,
        group: "Actors",
        icon: Bot,
        to: `/actors/${encodeURIComponent(a.id)}`,
      })),
    ];
    const scored = [...STATIC_ITEMS, ...dynamic]
      .map((item) => ({ item, score: matchScore(item.label, query) }))
      .filter((x) => x.score > 0);
    const out: PaletteItem[] = [];
    for (const group of GROUP_ORDER) {
      out.push(
        ...scored
          .filter((x) => x.item.group === group)
          .sort(
            (a, b) =>
              b.score - a.score || a.item.label.localeCompare(b.item.label),
          )
          .slice(
            0,
            query ? MAX_PER_GROUP : group === "Settings" ? 0 : MAX_PER_GROUP,
          )
          .map((x) => x.item),
      );
    }
    return out;
  }, [workflows.data, actors.data, query]);

  const onInputKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && items[active]) {
      e.preventDefault();
      go(items[active].to);
    }
  };

  const loading = open && (workflows.isLoading || actors.isLoading);
  const activeId = items[active] ? `${listId}-${items[active].id}` : undefined;

  return (
    <Dialog open={open} onClose={close} title="Jump to" className="max-w-lg">
      <div className="relative">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none"
          aria-hidden
        />
        <Input
          autoFocus
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={activeId}
          aria-autocomplete="list"
          placeholder="Pages, settings, workflows, actors…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={onInputKey}
          className="pl-9 pr-9"
        />
        {loading && (
          <Spinner className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
        )}
      </div>
      <ul
        id={listId}
        role="listbox"
        aria-label="Destinations"
        className="mt-3 max-h-[50vh] overflow-y-auto custom-scrollbar -mx-2"
      >
        {items.length === 0 && (
          <li className="px-3 py-6 text-sm text-muted-foreground text-center">
            Nothing matches “{query}”.
          </li>
        )}
        {items.map((item, i) => {
          const first = i === 0 || items[i - 1].group !== item.group;
          return (
            <React.Fragment key={item.id}>
              {first && (
                <li
                  role="presentation"
                  className="px-3 pt-3 pb-1 text-2xs font-semibold uppercase tracking-wider text-muted-foreground/60"
                >
                  {item.group}
                </li>
              )}
              <li
                id={`${listId}-${item.id}`}
                role="option"
                aria-selected={i === active}
                onMouseEnter={() => setActive(i)}
                onClick={() => go(item.to)}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-lg text-sm cursor-pointer",
                  i === active ? "bg-white/5 text-white" : "text-foreground/90",
                )}
              >
                <item.icon
                  className="w-4 h-4 shrink-0 text-muted-foreground"
                  aria-hidden
                />
                <span className="truncate">{item.label}</span>
                {item.hint && (
                  <span className="ml-auto text-xs text-muted-foreground/70 truncate">
                    {item.hint}
                  </span>
                )}
                {i === active && (
                  <CornerDownLeft
                    className="w-3.5 h-3.5 shrink-0 text-muted-foreground/60"
                    aria-hidden
                  />
                )}
              </li>
            </React.Fragment>
          );
        })}
      </ul>
      <p className="mt-3 pt-3 border-t border-white/5 text-xs text-muted-foreground">
        <kbd className="px-1.5 py-0.5 font-mono text-2xs bg-white/5 border border-white/10 rounded">
          ↑↓
        </kbd>{" "}
        to move,{" "}
        <kbd className="px-1.5 py-0.5 font-mono text-2xs bg-white/5 border border-white/10 rounded">
          ↵
        </kbd>{" "}
        to open. Outside a text field,{" "}
        <kbd className="px-1.5 py-0.5 font-mono text-2xs bg-white/5 border border-white/10 rounded">
          g
        </kbd>{" "}
        then{" "}
        {Object.entries(GO_SHORTCUTS)
          .map(([k, v]) => `${k} (${v.label})`)
          .join(", ")}
        .
      </p>
    </Dialog>
  );
}
