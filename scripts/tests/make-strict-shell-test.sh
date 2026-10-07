#!/usr/bin/env bash
# The root Makefile's recipes run under `bash -eu -o pipefail` on EVERY make,
# including the GNU Make 3.81 that macOS ships as /usr/bin/make.
#
# Until 2026-10-07 the flags were set through `.SHELLFLAGS`, which make 3.81
# does not know and silently ignores: on a Mac no recipe had -e, -u or
# pipefail. `make clippy` exited 0 when clippy failed to compile a crate (the
# pipeline's status was `tee`'s), and `make up` answered a failed image build
# with "NOTHING REBUILT" and started the old images. CI runs make 4.x and
# never saw either.
#
#     make-strict-shell-test.sh [MAKEFILE]
#
# Runs against every distinct make it finds: the one on PATH, /usr/bin/make and
# gmake. A Mac covers 3.81 and CI covers 4.x. Nothing real is run: probe
# recipes are added to the Makefile through `include`, and the recipes taken
# from the Makefile itself (clippy, test-clean, ps, observability-reload,
# sqlx-check, sqlx-prepare, up) see only stub `cargo` / `docker` / `curl` /
# `sqlx` / `sleep` programs from a temp folder; `up` runs in a temp folder of
# its own, on a copy of the Makefile.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MAKEFILE="${1:-$ROOT/Makefile}"
case "$MAKEFILE" in /*) ;; *) MAKEFILE="$PWD/$MAKEFILE" ;; esac

fails=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fails=$((fails+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

T="$(cd "$(mktemp -d)" && pwd -P)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ make-strict-shell test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

# ── the makes to test ────────────────────────────────────────────────────
makes=()
for cand in "$(command -v make || true)" /usr/bin/make "$(command -v gmake || true)"; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    dup=""
    for m in ${makes[@]+"${makes[@]}"}; do [[ "$cand" -ef "$m" ]] && dup=1; done
    [[ -z "$dup" ]] || continue
    makes+=("$cand")
done
if [[ "${#makes[@]}" -eq 0 ]]; then
    echo "✗ no make found — this test cannot say anything" >&2
    exit 1
fi

# ── probe recipes, run under the Makefile's own SHELL settings ───────────
# `$$-` is the running shell's option letters; `reached` is printed only if
# the command before it did not stop the recipe.
cat > "$T/probe.mk" <<EOF
include $MAKEFILE
_probe-opts:
	@echo "opts=\$\$- pipefail=\$\$(set -o | awk '\$\$1 == "pipefail" {print \$\$2}')"
_probe-pipeline:
	@false | cat; echo reached
_probe-errexit:
	@false; echo reached
_probe-nounset:
	@echo "\$\$TALOS_PROBE_NEVER_SET"; echo reached
_probe-healthy:
	@true | cat; echo reached
_probe-shell-fn:
	@echo "fn=\$(shell false | cat; echo reached)"
_probe-submake:
	@\$(MAKE) -f $T/probe.mk _probe-pipeline
EOF

# ── stubs for the recipes taken from the Makefile itself ─────────────────
mkdir -p "$T/bin" "$T/tmp" "$T/home"
cat > "$T/bin/cargo" <<'EOF'
#!/bin/bash
# What `make clippy` runs, word for word; anything else is not this test's.
[[ "$*" == "clippy --workspace --all-targets --no-deps -- -D warnings" ]] || { echo "stub cargo: unexpected: $*" >&2; exit 97; }
case "${STUB_CARGO:-}" in
    fail)       echo "error: could not compile \`some-crate\` (lib) due to 1 previous error" >&2; exit 101 ;;
    unresolved) echo "warning: \`a::b\` does not refer to a reachable function"; exit 0 ;;
    *)          echo "    Finished dev profile"; exit 0 ;;
esac
EOF
cat > "$T/bin/docker" <<'EOF'
#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
case "${STUB_DOCKER:-}:$1:${2:-}" in
    down:*)                echo "Cannot connect to the Docker daemon" >&2; exit 1 ;;
    leaked*:ps:*)          printf 'aaa111\nbbb222\n' ;;
    leaked-stuck:rm:*)     echo "Error response from daemon: removal in progress" >&2; exit 1 ;;
    db-down:compose:exec)  echo "service postgres is not running" >&2; exit 1 ;;
    db-up:compose:exec)    echo "workflows|7" ;;
    build-fails:compose:build) echo "failed to solve: process did not complete successfully" >&2; exit 17 ;;
    *:image:inspect)       echo "sha256:0001" ;;
    *:compose:ps)          echo "NAME STATUS" ;;
esac
exit 0
EOF
cat > "$T/bin/curl" <<'EOF'
#!/bin/bash
case "$*" in
    *localhost:8000/health*) exit 0 ;;          # the controller answers
    *) printf '000'; exit 7 ;;                  # nothing else is listening: what
esac                                            # `-w '%{http_code}'` prints, and curl's status
EOF
printf '#!/bin/bash\nexit 0\n' > "$T/bin/sqlx"
printf '#!/bin/bash\nexit 0\n' > "$T/bin/sleep"
chmod +x "$T/bin/"*

# `make up` reads ./.env and two scripts by relative path, and calls $(MAKE):
# it gets a folder of its own, outside any git checkout, with the Makefile
# under test copied in.
mkdir -p "$T/up/scripts"
cp "$MAKEFILE" "$T/up/Makefile"
printf 'exit 0\n' > "$T/up/scripts/preflight-disk.sh"
printf 'exit 0\n' > "$T/up/scripts/verify-observability.sh"

for MAKE_BIN in "${makes[@]}"; do
    version="$("$MAKE_BIN" --version | head -1)"
    echo "── $MAKE_BIN ($version)"

    # run <target> [VAR=value …] — in $CWD, with -f $FILE when set. Never the
    # caller's cargo, docker or curl, never the caller's MAKEFLAGS (this test
    # is itself run from a recipe), never the caller's home or checkout.
    run() {
        local target="$1"; shift
        ( cd "$CWD" && env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS -u DATABASE_URL -u GITHUB_ACTIONS \
            -u TALOS_TEXTFILE_DIR PATH="$T/bin:/usr/bin:/bin" HOME="$T/home" GIT_CEILING_DIRECTORIES="$T" \
            TMPDIR="$T/tmp" RUNNER_TEMP="$T/tmp" STUB_LOG="$T/stub.log" "$@" \
            "$MAKE_BIN" ${FILE:+-f "$FILE"} "$target" 2>&1 )
    }
    # status <target> [VAR=value …] — sets OUT and RC; $T/stub.log holds what
    # this one run asked docker to do.
    status() { : > "$T/stub.log"; RC=0; OUT="$(run "$@")" || RC=$?; }

    echo "every recipe runs under bash -eu -o pipefail"
    CWD="$ROOT" FILE="$T/probe.mk"
    status _probe-opts
    check "the options are on (got: $OUT)" '[[ "$RC" == 0 && "$OUT" == opts=*e* && "$OUT" == opts=*u* && "$OUT" == *"pipefail=on" ]]'
    status _probe-pipeline
    check "a failing pipeline fails the target" '[[ "$RC" != 0 ]] && ! grep -q reached <<< "$OUT"'
    status _probe-errexit
    check "a failing command stops the recipe"  '[[ "$RC" != 0 ]] && ! grep -q reached <<< "$OUT"'
    status _probe-nounset
    check "an unset variable stops the recipe"  '[[ "$RC" != 0 ]] && ! grep -q reached <<< "$OUT"'
    status _probe-submake
    check "and through \$(MAKE)"                '[[ "$RC" != 0 ]] && ! grep -q reached <<< "$OUT"'
    status _probe-shell-fn
    check "\$(shell …) runs under the same options" '[[ "$OUT" == "fn=" ]]'
    status _probe-healthy
    check "a healthy pipeline still passes"     '[[ "$RC" == 0 ]] && grep -q reached <<< "$OUT"'

    FILE="$MAKEFILE"
    echo "make clippy"
    status clippy STUB_CARGO=fail
    check "fails when clippy fails"             '[[ "$RC" != 0 ]] && grep -q "could not compile" <<< "$OUT"'
    status clippy STUB_CARGO=unresolved
    check "fails on an unresolved clippy.toml path" '[[ "$RC" != 0 ]] && grep -q "that rule is off" <<< "$OUT"'
    status clippy
    check "passes when clippy passes"           '[[ "$RC" == 0 ]] && grep -q Finished <<< "$OUT"'

    echo "make test-clean"
    status test-clean STUB_DOCKER=down
    check "a docker that cannot list is not 'no leaked containers'" '[[ "$RC" != 0 ]] && ! grep -q "no leaked" <<< "$OUT"'
    status test-clean STUB_DOCKER=leaked-stuck
    check "a removal that fails is not 'removed'" '[[ "$RC" != 0 ]] && ! grep -q "removed" <<< "$OUT"'
    status test-clean STUB_DOCKER=leaked
    check "removes what it lists"               '[[ "$RC" == 0 ]] && grep -q "removed 2 leaked" <<< "$OUT" && grep -qx "docker rm -f aaa111 bbb222" "$T/stub.log"'
    status test-clean
    check "nothing leaked is a pass"            '[[ "$RC" == 0 ]] && grep -q "no leaked" <<< "$OUT"'

    echo "make ps"
    status ps STUB_DOCKER=db-down
    check "says so when the database is unreachable" '[[ "$RC" == 0 ]] && grep -q "database unreachable" <<< "$OUT"'
    status ps STUB_DOCKER=db-up
    check "prints the counts when it is reachable" '[[ "$RC" == 0 ]] && grep -q "workflows  *7" <<< "$OUT" && ! grep -q unreachable <<< "$OUT"'

    echo "make up"
    CWD="$T/up" FILE=""
    printf 'NATS_WORKER_USER=talos-worker\n' > "$T/up/.env"
    status up STUB_DOCKER=build-fails
    check "a failed image build fails it"       '[[ "$RC" != 0 ]] && ! grep -q "NOTHING REBUILT" <<< "$OUT"'
    check "and the old images are not started"  '! grep -q "^docker compose up" "$T/stub.log"'
    status up
    check "a build that works starts the stack, outside a git checkout too" '[[ "$RC" == 0 ]] && grep -q "stack healthy" <<< "$OUT" && grep -qx "docker compose up -d --scale worker=1" "$T/stub.log"'
    printf 'NGROK_AUTHTOKEN=not-a-token\n' >> "$T/up/.env"
    status up
    check "a tunnel that is not up yet is a notice, not a failure" '[[ "$RC" == 0 ]] && grep -q "tunnel starting" <<< "$OUT"'
    CWD="$ROOT" FILE="$MAKEFILE"

    echo "a failure the recipe goes on to handle does not stop it first"
    status observability-reload
    check "observability-reload says Prometheus did not answer" '[[ "$RC" != 0 ]] && grep -q "no response from http://127.0.0.1:9090" <<< "$OUT"'

    echo "a recipe's own message survives -u"
    status sqlx-check
    check "sqlx-check names DATABASE_URL itself" '[[ "$RC" != 0 ]] && grep -q "DATABASE_URL unset" <<< "$OUT" && ! grep -q "unbound variable" <<< "$OUT"'
    status sqlx-prepare
    check "sqlx-prepare names DATABASE_URL itself" '[[ "$RC" != 0 ]] && grep -q "DATABASE_URL unset" <<< "$OUT" && ! grep -q "unbound variable" <<< "$OUT"'
done

completed=1
if [[ "$fails" -gt 0 ]]; then
    echo "✗ $fails check(s) failed" >&2
    exit 1
fi
echo "✓ recipes are strict under: ${makes[*]}"
