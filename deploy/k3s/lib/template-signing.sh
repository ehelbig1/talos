#!/usr/bin/env bash
# OCI TEMPLATE signature verification — the installer's rule (security review
# 2026-10-14, H-1).
#
# Sourced by deploy/k3s/install.sh; exercised by
# deploy/k3s/tests/template-signing-test.sh. Every function here is PURE (no
# kubectl, no helm, no environment read): install.sh passes the values in.
#
# Two switches guard two different things, and only one of them was on:
#
#   * security.sigstore.enabled (TALOS_DISABLE_SIGSTORE) — the policy-controller
#     ClusterImagePolicy: admission of the three SERVICE images. On by default.
#   * worker.sigstore.required (TALOS_SIGSTORE_REQUIRED) — `cosign verify` of
#     the WASM module TEMPLATES the worker pulls from TALOS_REGISTRY_URL and
#     executes, and of the catalog index the controller syncs. Rendered as the
#     explicit `disabled` when unset.
#
# NOTES.txt said "sigstore enforcement is ON" on the strength of the first,
# so an operator who then set TALOS_REGISTRY_URL ran unsigned registry
# artefacts with nothing saying so. The digest check binds bytes to a
# manifest; only the signature binds the manifest to the publisher.
#
# The rule: with a registry configured, `disabled` is refused unless the
# operator also sets TALOS_ALLOW_UNSIGNED_TEMPLATES=yes. A value that is not a
# policy is refused always — the worker refuses to boot on one (E-7).

# ts_sigstore_mode <raw> — print `required`, `audit` or `disabled` for a
# TALOS_SIGSTORE_REQUIRED value, with the spellings and trimming of
# talos_sigstore_policy::SigstorePolicy::from_env_str (empty → disabled).
# Returns 1 for anything else.
ts_sigstore_mode() {
    local v="${1:-}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"
    case "$v" in
        required | true | 1) echo required ;;
        audit | warn) echo audit ;;
        disabled | off | 0 | false | no | "") echo disabled ;;
        *) return 1 ;;
    esac
}

# ts_template_signing_refusal <registry_url> <sigstore_raw> <allow_unsigned>
# Prints why the install must stop and returns 1, or returns 0 silently.
ts_template_signing_refusal() {
    local registry_url="${1:-}" raw="${2:-}" allow="${3:-}" mode
    if ! mode="$(ts_sigstore_mode "$raw")"; then
        printf 'TALOS_SIGSTORE_REQUIRED=%q is not a Sigstore policy: set required, audit or disabled (the worker refuses to boot on any other value).\n' "$raw"
        return 1
    fi
    if [[ -n "$registry_url" && "$mode" == disabled && "$allow" != yes ]]; then
        printf '%s\n' "TALOS_REGISTRY_URL is set but TALOS_SIGSTORE_REQUIRED resolves to disabled: the worker would execute module templates from the registry with no signature check (image admission does not cover them). Set TALOS_SIGSTORE_REQUIRED=required (or audit during a migration), or set TALOS_ALLOW_UNSIGNED_TEMPLATES=yes to accept unsigned templates explicitly."
        return 1
    fi
    return 0
}
