#!/usr/bin/env bash
# Tests for deploy/k3s/lib/worker-trust.sh — the installer's RFC 0010 phase
# state machine, its env rendering, and the OpenSSL Ed25519 derivation.
# Pure bash; runs on a laptop and in CI (quality.yml `audit` job). The key
# derivation part needs an OpenSSL with Ed25519 (3.x, or 1.1.1+); on a host
# without one (macOS LibreSSL) it SKIPS LOUDLY and the rest still runs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/worker-trust.sh
source "$HERE/../lib/worker-trust.sh"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}

echo "▶ phase state machine"
check "fresh install jumps to D"            D   "$(wt_next_phase ''  yes auto)"
check "fresh install ignores marker"        D   "$(wt_next_phase 'B' yes auto)"
check "no marker → A"                       A   "$(wt_next_phase ''  no  auto)"
check "off marker → A"                      A   "$(wt_next_phase off no  auto)"
check "A → B"                               B   "$(wt_next_phase A   no  auto)"
check "B → C"                               C   "$(wt_next_phase B   no  auto)"
check "C → D"                               D   "$(wt_next_phase C   no  auto)"
check "D stays D"                           D   "$(wt_next_phase D   no  auto)"
check "hold keeps last"                     B   "$(wt_next_phase B   no  hold)"
check "hold with no marker is off"          off "$(wt_next_phase ''  no  hold)"
check "explicit off"                        off "$(wt_next_phase D   no  off)"
check "explicit letter pins (rollback C→A)" A   "$(wt_next_phase C   no  A)"
check "explicit letter pins on fresh too"   B   "$(wt_next_phase ''  yes B)"
if wt_next_phase A no bogus >/dev/null 2>&1; then check "unknown override refused" refused accepted; else check "unknown override refused" refused refused; fi

echo "▶ env rendering — each phase adds exactly its keys"
W=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
C=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
keys() { sed -nE 's/^ *([A-Z_0-9]+):.*/\1/p' | tr '\n' ' ' | sed 's/ $//'; }
check "off renders nothing (controller)"   ""  "$(wt_render_controller_env off "$W" | keys)"
check "off renders nothing (worker)"       ""  "$(wt_render_worker_env off "$C" | keys)"
check "A controller"  "TALOS_WORKER_PUBLIC_KEYS" "$(wt_render_controller_env A "$W" | keys)"
check "A worker: nothing yet"              ""  "$(wt_render_worker_env A "$C" | keys)"
check "B controller unchanged from A"      "TALOS_WORKER_PUBLIC_KEYS" "$(wt_render_controller_env B "$W" | keys)"
check "B worker"      "TALOS_WORKER_ID TALOS_CONTROLLER_PUBLIC_KEY" "$(wt_render_worker_env B "$C" | keys)"
check "C controller"  "TALOS_WORKER_PUBLIC_KEYS TALOS_DISPATCH_SCHEME TALOS_ENVELOPE_SEALING" "$(wt_render_controller_env C "$W" | keys)"
check "C worker unchanged from B"          "TALOS_WORKER_ID TALOS_CONTROLLER_PUBLIC_KEY" "$(wt_render_worker_env C "$C" | keys)"
check "D controller"  "TALOS_WORKER_PUBLIC_KEYS TALOS_DISPATCH_SCHEME TALOS_ENVELOPE_SEALING TALOS_RESULT_REQUIRE_ED25519" "$(wt_render_controller_env D "$W" | keys)"
check "D worker"      "TALOS_WORKER_ID TALOS_CONTROLLER_PUBLIC_KEY TALOS_ENVELOPE_SEALING TALOS_DISPATCH_REQUIRE_ED25519" "$(wt_render_worker_env D "$C" | keys)"
check "fleet id binds the worker pub"      "    TALOS_WORKER_PUBLIC_KEYS: \"fleet=$W\"" "$(wt_render_controller_env A "$W")"
check "worker id matches the fleet id"     "fleet" "$(wt_render_worker_env B "$C" | sed -nE 's/^ *TALOS_WORKER_ID: "([a-z]+)"/\1/p')"
check "worker key live from B"             "no yes yes yes" "$( { wt_worker_key_live A && echo yes || echo no; wt_worker_key_live B && echo yes || echo no; wt_worker_key_live C && echo yes || echo no; wt_worker_key_live D && echo yes || echo no; } | tr '\n' ' ' | sed 's/ $//')"
check "rendered YAML is 4-space indented"  "" "$(wt_render_controller_env D "$W" | grep -vE '^    [A-Z]' || true)"

echo "▶ Ed25519 derivation (OpenSSL)"
if wt_openssl_supports_ed25519; then
    # RFC 8032 §7.1 test vector 1 — a PUBLIC test vector, not a credential.
    RFC_SEED=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    RFC_PUB=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    check "RFC 8032 vector 1 public key" "$RFC_PUB" "$(wt_ed25519_pub_hex_from_seed "$RFC_SEED")"
    seed=$(wt_ed25519_seed_hex); pub=$(wt_ed25519_pub_hex_from_seed "$seed")
    check "fresh seed is 64 hex" yes "$(wt_is_hex64 "$seed" && echo yes || echo no)"
    check "derived pub is 64 hex" yes "$(wt_is_hex64 "$pub" && echo yes || echo no)"
    check "derivation is deterministic" "$pub" "$(wt_ed25519_pub_hex_from_seed "$seed")"
    check "two seeds differ" no "$( [ "$seed" = "$(wt_ed25519_seed_hex)" ] && echo yes || echo no)"
    if wt_ed25519_pub_hex_from_seed "not-hex" >/dev/null 2>&1; then check "bad seed refused" refused accepted; else check "bad seed refused" refused refused; fi
else
    echo "  ⊘ SKIPPED — this openssl ($(openssl version 2>/dev/null | head -c 40)) has no Ed25519; CI (ubuntu, OpenSSL 3) runs this part"
fi

echo
if [ "$fails" -eq 0 ]; then echo "✓ worker-trust: all checks passed"; else echo "✗ worker-trust: $fails check(s) failed"; exit 1; fi
