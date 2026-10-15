#!/usr/bin/env bash
# Tests for deploy/k3s/lib/template-signing.sh — the installer's refusal to
# run registry templates unsigned (security review 2026-10-14, H-1) — and for
# install.sh calling it before it changes anything, and for NOTES.txt naming
# both Sigstore switches. Pure bash; runs on a laptop and in CI
# (`make test-scripts`).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=../lib/template-signing.sh
source "$HERE/../lib/template-signing.sh"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
verdict() { # verdict <registry> <sigstore> <allow> → refused|admitted
    if ts_template_signing_refusal "$1" "$2" "$3" >/dev/null; then echo admitted; else echo refused; fi
}

REG=https://registry.example.test

echo "▶ policy spellings (talos_sigstore_policy::from_env_str)"
check "required"            required "$(ts_sigstore_mode required)"
check "TRUE"                required "$(ts_sigstore_mode TRUE)"
check "1"                   required "$(ts_sigstore_mode 1)"
check "audit"               audit    "$(ts_sigstore_mode audit)"
check "warn"                audit    "$(ts_sigstore_mode warn)"
check "disabled"            disabled "$(ts_sigstore_mode disabled)"
check "' No '"              disabled "$(ts_sigstore_mode ' No ')"
check "empty is disabled"   disabled "$(ts_sigstore_mode '')"
if ts_sigstore_mode requried >/dev/null; then check "a typo is not a policy" refused accepted; else check "a typo is not a policy" refused refused; fi
if ts_sigstore_mode yes >/dev/null; then check "yes is not a policy" refused accepted; else check "yes is not a policy" refused refused; fi

echo "▶ the refusal"
check "registry + unset → refused"              refused  "$(verdict "$REG" ''         no)"
check "registry + disabled → refused"           refused  "$(verdict "$REG" disabled   no)"
check "registry + off → refused"                refused  "$(verdict "$REG" off        no)"
check "registry + disabled + allow=yes"         admitted "$(verdict "$REG" disabled   yes)"
check "allow must be the word yes"              refused  "$(verdict "$REG" disabled   true)"
check "registry + required"                     admitted "$(verdict "$REG" required   no)"
check "registry + audit"                        admitted "$(verdict "$REG" audit      no)"
check "no registry + disabled (disk seeding)"   admitted "$(verdict ''     disabled   no)"
check "a typo is refused without a registry"    refused  "$(verdict ''     requried   yes)"
check "a typo is refused with allow=yes"        refused  "$(verdict "$REG" requried   yes)"
msg="$(ts_template_signing_refusal "$REG" disabled no || true)"
case "$msg" in *TALOS_ALLOW_UNSIGNED_TEMPLATES=yes*) check "the refusal names the opt-out" yes yes ;; *) check "the refusal names the opt-out" yes "$msg" ;; esac

echo "▶ install.sh refuses before it changes anything"
INSTALL="$REPO/deploy/k3s/install.sh"
call_line="$(grep -n 'ts_template_signing_refusal "\${TALOS_REGISTRY_URL:-}"' "$INSTALL" | head -1 | cut -d: -f1)"
root_line="$(grep -n '^\[\[ \$EUID -eq 0 \]\]' "$INSTALL" | head -1 | cut -d: -f1)"
check "install.sh calls the rule" yes "$([ -n "$call_line" ] && echo yes || echo no)"
check "the call precedes the root check (and every install step)" yes \
    "$([ -n "$call_line" ] && [ -n "$root_line" ] && [ "$call_line" -lt "$root_line" ] && echo yes || echo no)"
check "install.sh dies on the refusal" 'die "$ts_refusal"' \
    "$(sed -n "$((call_line + 1))p" "$INSTALL" | sed 's/^ *//')"

echo "▶ NOTES.txt names both switches"
NOTES="$REPO/deploy/helm/talos/templates/NOTES.txt"
check "image admission is named"        1 "$(grep -c 'Image admission (security.sigstore.enabled)' "$NOTES")"
check "template verification is named" 1 "$(grep -c 'Template verification' "$NOTES")"
check "template mode is read from worker.sigstore.required" yes \
    "$(grep -q 'worker.sigstore.required' "$NOTES" && echo yes || echo no)"

if [ "$fails" -gt 0 ]; then
    echo "✗ $fails template-signing check(s) failed" >&2
    exit 1
fi
echo "✓ template-signing checks passed"
