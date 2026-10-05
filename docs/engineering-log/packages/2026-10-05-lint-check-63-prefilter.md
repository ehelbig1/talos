# Lint check 63 looks only at files that can match (2026-10-05)

Part B of structural check 63 (no `rhai::Engine::default()` outside the
sandbox builder) ran `sed`, `grep` and `grep` on every `.rs` file in the
workspace: 14.4 seconds of the lint, timed 2026-10-05.

Now one `grep -lF 'Engine::default'` over the same file list picks the
candidates, and the per-file pipeline runs only on those. This cannot change
a verdict: the pattern contains the literal `Engine::default`, and the only
transformation before it — removing `//` comments — deletes text, so a file
without the literal has no line that can match. The file count behind the
"scanned fewer than 100 files" guard is still taken from the full list.

Measured: check 63 takes 4.3 seconds. With a planted `rhai::Engine::default()`
in a new file the check still names it; on the real tree it still passes.
