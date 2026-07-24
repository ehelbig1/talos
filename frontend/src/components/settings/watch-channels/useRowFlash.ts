import { useEffect, useRef, useState } from "react";

/**
 * Per-row "flash" highlight after a successful row action.
 *
 * MCP-893 (2026-05-14): track flash timers in a ref so unmount can
 * cancel them. Pre-fix `window.setTimeout(...)` was orphaned — if
 * the user navigated away within the 1.6s flash window, the
 * setState fired on an unmounted component, producing React
 * strict-mode warnings and (in dev) leaked closure references.
 */
export function useRowFlash(): {
  flashedAt: Record<string, number>;
  triggerFlash: (rowKey: string) => void;
} {
  const [flashedAt, setFlashedAt] = useState<Record<string, number>>({});
  const flashTimersRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    const timers = flashTimersRef.current;
    return () => {
      timers.forEach(clearTimeout);
      timers.clear();
    };
  }, []);

  const triggerFlash = (rowKey: string) => {
    const now = Date.now();
    setFlashedAt((prev) => ({ ...prev, [rowKey]: now }));
    const timer = window.setTimeout(() => {
      flashTimersRef.current.delete(timer);
      setFlashedAt((prev) => {
        if (prev[rowKey] !== now) return prev;
        const next = { ...prev };
        delete next[rowKey];
        return next;
      });
    }, 1600);
    flashTimersRef.current.add(timer);
  };

  return { flashedAt, triggerFlash };
}
