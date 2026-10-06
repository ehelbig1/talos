#!/usr/bin/env bash
# The integration suite's shards: the dealing rule (scripts/ci_shard.py) and
# the property CI rests on — whatever the shard count, the shards of the REAL
# work list partition it: every item on exactly one shard. No Docker, no build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

python3 scripts/ci_shard.py --self-test

whole="$(TALOS_IT_LIST_ONLY=1 bash scripts/test-integration.sh | sort)"
total="$(printf '%s\n' "$whole" | grep -c .)"
[ "$total" -gt 0 ] || { echo "✗ the work list is empty" >&2; exit 1; }
[ "$(printf '%s\n' "$whole" | uniq -d | grep -c . || true)" -eq 0 ] \
    || { echo "✗ the work list names an item twice" >&2; exit 1; }

for n in 2 3 4 5 7; do
    parts=""
    for i in $(seq 1 "$n"); do
        part="$(TALOS_IT_LIST_ONLY=1 TALOS_IT_SHARD="$i/$n" bash scripts/test-integration.sh)"
        [ -n "$part" ] || { echo "✗ shard $i/$n was dealt nothing" >&2; exit 1; }
        parts="${parts}${part}"$'\n'
    done
    if [ "$(printf '%s' "$parts" | sort)" != "$whole" ]; then
        echo "✗ the $n shards do not partition the work list ($total items)" >&2
        exit 1
    fi
    echo "  ok   $n shards partition all $total items"
done

# A table that cannot be read stops the run instead of running nothing.
bad="$(mktemp)"
trap 'rm -f "$bad"' EXIT
printf 'not-a-number\tcontroller|x\n' > "$bad"
if printf 'ctrl|controller|x|\n' | python3 scripts/ci_shard.py select 1 2 --weights "$bad" >/dev/null 2>&1; then
    echo "✗ a malformed weights table was accepted" >&2
    exit 1
fi
echo "  ok   a malformed weights table is refused"
if python3 scripts/ci_shard.py select 1 2 </dev/null >/dev/null 2>&1; then
    echo "✗ an empty work list was accepted" >&2
    exit 1
fi
echo "  ok   an empty work list is refused"
echo "✓ ci-shard: all checks passed"
