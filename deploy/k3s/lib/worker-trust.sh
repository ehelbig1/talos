#!/usr/bin/env bash
# RFC 0010 worker trust (P1 Ed25519 dispatch signing, P2 per-worker result
# signing, P3 per-execution envelope sealing) — the installer's state machine.
#
# Sourced by deploy/k3s/install.sh; exercised by deploy/k3s/tests/worker-trust-test.sh.
# Every function here is PURE (no kubectl, no helm): install.sh feeds it the
# marker value and the Secret contents and renders what it returns. That is
# what makes the phase logic testable on a laptop with no cluster.
#
# ── Why four phases, and why the ORDER is load-bearing ─────────────────────
#
# Until 2026-09-11 the chart shipped Ed25519 dispatch and envelope sealing as
# a commented-out runbook, so every installer-built cluster ran the legacy
# posture the whole-codebase review flagged: one fleet-shared HMAC key signs
# every job and seals every secret envelope, so one compromised worker can
# forge dispatches to its peers and decrypt every job's secrets fleet-wide.
# The dev compose stack has run the full posture since 2026-07-06; the
# installer did not, because turning it on in ONE upgrade loses jobs:
#
#   * A worker signs its RESULTS with Ed25519 the moment it holds a signing
#     key (worker::worker_result_signing_key), and a controller can verify
#     those only once it holds that worker's PUBLIC key — so the controller
#     must learn the worker key BEFORE any worker starts signing with it.
#   * A worker can verify an Ed25519 DISPATCH only once it holds the
#     controller's public key — so workers must learn it BEFORE the
#     controller starts signing with it.
#   * A worker under TALOS_ENVELOPE_SEALING=required REFUSES a sealing=0
#     dispatch that carries secrets — so workers may require sealing only
#     AFTER every controller seals.
#
# Helm rolls the controller and worker Deployments concurrently, so each of
# those "before"s needs its own `helm upgrade`. Each install.sh run applies the
# NEXT phase and records it in the marker file; a fresh install has no old
# pods to disagree with and jumps straight to D.
#
#   off  legacy: nothing rendered (an operator's explicit choice).
#   A    controller learns the fleet worker public key
#        (controller.env TALOS_WORKER_PUBLIC_KEYS=fleet=<hex>). Workers
#        unchanged. Both keypairs are minted into the bootstrap Secret; the
#        worker SEED is stored STAGED (a key the chart does not mount) so no
#        worker starts signing yet.
#   B    workers get their identity: TALOS_WORKER_SIGNING_KEY (promoted from
#        the staged key), TALOS_WORKER_ID=fleet, TALOS_CONTROLLER_PUBLIC_KEY.
#        Results now sign Ed25519 — verifiable, because A ran first. Dispatch
#        still HMAC; workers accept both.
#   C    controller signs dispatches Ed25519 and seals secret envelopes
#        (TALOS_DISPATCH_SCHEME=ed25519, TALOS_ENVELOPE_SEALING=required).
#        Workers verify the signature (B gave them the key) and claim the
#        envelope (a claim is driven by the dispatch's sealing flag plus the
#        worker's signing key — the worker's own mode is not consulted).
#   D    both sides REQUIRE the new posture: worker TALOS_ENVELOPE_SEALING=
#        required + TALOS_DISPATCH_REQUIRE_ED25519=1, controller
#        TALOS_RESULT_REQUIRE_ED25519=1. A downgrade in either direction is
#        now refused, loudly.
#
# Rollback at any phase: set TALOS_WORKER_TRUST to an EARLIER phase letter (or
# `off`) in install.env and re-run — the same ordering argument holds in
# reverse one step at a time (never jump from D to off in one upgrade).

# ── Phase order ──────────────────────────────────────────────────────────────

# wt_phase_index <phase> → 0 for off, 1..4 for A..D, 99 for garbage.
wt_phase_index() {
    case "$1" in
        off|"") echo 0 ;;
        A) echo 1 ;; B) echo 2 ;; C) echo 3 ;; D) echo 4 ;;
        *) echo 99 ;;
    esac
}

# wt_phase_at_least <phase> <threshold> → exit 0 when phase ≥ threshold.
wt_phase_at_least() {
    [ "$(wt_phase_index "$1")" -ge "$(wt_phase_index "$2")" ]
}

# wt_succ <phase> → the next phase in order (D stays D; off/"" → A).
wt_succ() {
    case "$1" in
        off|"") echo A ;;
        A) echo B ;; B) echo C ;; C|D) echo D ;;
        *) return 1 ;;
    esac
}

# wt_next_phase <last_applied> <fresh yes|no> <override>
#   last_applied : contents of the marker file ("" when absent)
#   fresh        : "yes" when no bootstrap Secret existed before this run
#   override     : TALOS_WORKER_TRUST — auto (default) | off | hold | A | B | C | D
# Prints the phase to APPLY this run. Exits 1 on an unknown override.
wt_next_phase() {
    local last="${1:-}" fresh="${2:-no}" override="${3:-auto}"
    case "$override" in
        auto|"")
            if [ "$fresh" = "yes" ]; then echo D; return 0; fi
            wt_succ "$last"
            ;;
        hold)
            if [ -z "$last" ]; then echo off; else echo "$last"; fi
            ;;
        off|A|B|C|D)
            echo "$override"
            ;;
        *)
            echo "TALOS_WORKER_TRUST must be auto|hold|off|A|B|C|D, got '$override'" >&2
            return 1
            ;;
    esac
}

# wt_describe <phase> → one operator-facing sentence.
wt_describe() {
    case "$1" in
        off) echo "worker trust OFF — legacy fleet-shared HMAC dispatch + inline secret envelopes (operator choice)" ;;
        A)   echo "worker trust phase A of D — controller learns the fleet worker public key; workers unchanged" ;;
        B)   echo "worker trust phase B of D — workers hold their Ed25519 identity and the controller public key; results now Ed25519-signed" ;;
        C)   echo "worker trust phase C of D — controller signs dispatches Ed25519 and seals secret envelopes per execution" ;;
        D)   echo "worker trust phase D of D — both sides REQUIRE Ed25519 + sealing; HMAC dispatch and inline envelopes are refused" ;;
        *)   echo "worker trust phase '$1' (unknown)"; return 1 ;;
    esac
}

# ── Rendering: controller.env / worker.env YAML lines for the overlay ────────
# Indented for a `  env:` map nested under `controller:` / `worker:`. Prints
# nothing for a side that gains no keys at this phase, so the caller can omit
# the `env:` map entirely (Helm deep-merges these maps with values.yaml).

# wt_render_controller_env <phase> <worker_pub_hex>
wt_render_controller_env() {
    local phase="$1" wpub="$2"
    wt_phase_at_least "$phase" A || return 0
    printf '    TALOS_WORKER_PUBLIC_KEYS: "fleet=%s"\n' "$wpub"
    if wt_phase_at_least "$phase" C; then
        printf '    TALOS_DISPATCH_SCHEME: "ed25519"\n'
        printf '    TALOS_ENVELOPE_SEALING: "required"\n'
    fi
    if wt_phase_at_least "$phase" D; then
        printf '    TALOS_RESULT_REQUIRE_ED25519: "1"\n'
    fi
}

# wt_render_worker_env <phase> <controller_pub_hex>
wt_render_worker_env() {
    local phase="$1" cpub="$2"
    wt_phase_at_least "$phase" B || return 0
    printf '    TALOS_WORKER_ID: "fleet"\n'
    printf '    TALOS_CONTROLLER_PUBLIC_KEY: "%s"\n' "$cpub"
    if wt_phase_at_least "$phase" D; then
        printf '    TALOS_ENVELOPE_SEALING: "required"\n'
        printf '    TALOS_DISPATCH_REQUIRE_ED25519: "1"\n'
    fi
}

# wt_worker_key_live <phase> → exit 0 when the worker SEED must be present under
# the chart-mounted Secret key TALOS_WORKER_SIGNING_KEY (phase ≥ B).
wt_worker_key_live() { wt_phase_at_least "$1" B; }

# ── Ed25519 keys via OpenSSL (same encoding the controller keygen prints) ────
# `controller generate-worker-trust-keypair` prints the 32-byte SEED and the
# 32-byte PUBLIC key as 64 lowercase hex chars each. OpenSSL's PKCS#8 DER for an
# Ed25519 private key is a fixed 16-byte prefix followed by the seed; its SPKI
# DER for the public key is a fixed 12-byte prefix followed by the key. Both
# derivations below were checked against the real keygen (2026-09-11, on
# OpenSSL 3.3): identical public key for the same seed.

WT_PKCS8_ED25519_PREFIX_HEX="302e020100300506032b657004220420"

wt_openssl_supports_ed25519() {
    openssl genpkey -algorithm ed25519 -outform DER >/dev/null 2>&1
}

wt_is_hex64() {
    [ "${#1}" -eq 64 ] && [ -z "${1//[0-9a-f]/}" ]
}

# wt_ed25519_seed_hex → a fresh 64-hex seed on stdout.
wt_ed25519_seed_hex() {
    local seed
    seed=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | od -An -v -tx1 | tr -d ' \n')
    wt_is_hex64 "$seed" || { echo "ed25519 seed generation failed (openssl too old?)" >&2; return 1; }
    printf '%s' "$seed"
}

# wt_ed25519_pub_hex_from_seed <seed_hex> → 64-hex public key on stdout.
wt_ed25519_pub_hex_from_seed() {
    local seed="$1" pub
    wt_is_hex64 "$seed" || { echo "seed is not 64 hex chars" >&2; return 1; }
    pub=$(printf '%s%s' "$WT_PKCS8_ED25519_PREFIX_HEX" "$seed" \
        | wt_hex_to_bin \
        | openssl pkey -inform DER -pubout -outform DER 2>/dev/null \
        | tail -c 32 | od -An -v -tx1 | tr -d ' \n')
    wt_is_hex64 "$pub" || { echo "ed25519 public-key derivation failed" >&2; return 1; }
    printf '%s' "$pub"
}

# wt_hex_to_bin — stdin hex → stdout bytes, without depending on xxd (absent
# from minimal images) — `printf '\x..'` per byte.
wt_hex_to_bin() {
    local hex
    hex=$(tr -d ' \n')
    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        # shellcheck disable=SC2059  # the format IS the escape we want
        printf "\\x${hex:$i:2}"
    done
}
