#!/usr/bin/env bash
# Generate CHANGELOG [Unreleased] entries from merged PR titles.
#
# The CHANGELOG rots between manual passes (it sat 2+ weeks stale before
# the 2026-07 review). Every merge already carries a well-formed title
# ending in (#NNN), so the entries are scriptable. This emits markdown
# bullet lines for every PR merged to main AFTER the newest PR number
# already mentioned in CHANGELOG.md — review, trim, and paste (or use
# --write to insert them under the [Unreleased] heading automatically;
# still review the diff before committing).
#
# Usage:
#   bash scripts/changelog-update.sh            # print missing entries
#   bash scripts/changelog-update.sh --write    # insert under [Unreleased]
#
# Requires: gh (authenticated), jq.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v gh >/dev/null || { echo "✗ gh CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "✗ jq required" >&2; exit 1; }

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

# Newest PR number already present anywhere in the CHANGELOG. PR refs
# appear as (#NNN) or #NNN; take the max.
LAST_LOGGED="$(grep -oE '#[0-9]{2,}' CHANGELOG.md | tr -d '#' | sort -n | tail -1)"
LAST_LOGGED="${LAST_LOGGED:-0}"

# Merged PRs to main, newest first, filtered to those newer than LAST_LOGGED.
ENTRIES="$(gh pr list --base main --state merged --limit 200 \
    --json number,title,mergedAt \
    | jq -r --argjson last "$LAST_LOGGED" '
        [ .[] | select(.number > $last) ]
        | sort_by(.number)
        | .[]
        | "* **#\(.number)** (\(.mergedAt[:10])) — \(.title | sub(" \\(#[0-9]+\\)$"; ""))"
    ')"

if [ -z "$ENTRIES" ]; then
    echo "✓ CHANGELOG is current — no merged PR newer than #$LAST_LOGGED"
    exit 0
fi

echo "── Missing CHANGELOG entries (newer than #$LAST_LOGGED) ──"
echo "$ENTRIES"
echo

if [ "$WRITE" -eq 1 ]; then
    # Insert directly under the [Unreleased] heading block (after the
    # heading line and any immediately-following blockquote/blank lines).
    python3 - "$ENTRIES" <<'PYEOF'
import re, sys
entries = sys.argv[1]
path = "CHANGELOG.md"
s = open(path).read()
m = re.search(r"^## \[Unreleased\][^\n]*\n", s, re.M)
if not m:
    sys.exit("✗ no [Unreleased] heading found in CHANGELOG.md")
insert_at = m.end()
# Skip the note-blockquote paragraph directly under the heading, if present.
rest = s[insert_at:]
block = re.match(r"(\n?(>[^\n]*\n)+\n?)", rest)
if block:
    insert_at += block.end()
section = f"\n### Auto-generated from merged PRs (review before release)\n\n{entries}\n"
open(path, "w").write(s[:insert_at] + section + s[insert_at:])
print("✓ inserted under [Unreleased] — review `git diff CHANGELOG.md` before committing")
PYEOF
fi
