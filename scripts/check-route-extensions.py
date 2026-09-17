#!/usr/bin/env python3
"""Crawl a running controller for routes that extract an axum Extension their
router does not provide.

Package BZ (2026-09-16). `GET /metrics` and `GET /graphql/schema` asked for
`Extension<TalosSchema>`, which only the `/graphql` + `/ws` sub-router carries,
so axum rejected every request to them with a 500 before the handler ran — from
the day each was mounted. Nothing at compile time can see this: `Extension<T>`
is looked up in the request at runtime. Both routes were deleted; this script
is the deploy-time half of the guard. The runtime half is
`talos_http_utils::missing_extension`, which logs the route, counts
`talos_http_missing_extension_total` and replaces the rejection body.

What it does:
  1. derives every (method, path) the workspace mounts, from source: each
     `.route("<path>", <method router>)` outside test code, with the prefix of
     any `.nest("<prefix>", ..)` whose router is built by the function that
     holds the route (directly, or through a `let` binding in the same file);
  2. reads `talos_http_missing_extension_total` from `/metrics/prometheus`;
  3. sends each (method, path) once, UNAUTHENTICATED (`{}` body on non-GET),
     path parameters filled with a nil UUID or `x`;
  4. reads the counter again. Any increase is a finding; the 500 responses are
     then re-sent one at a time to name the route. A response body that still
     carries axum's rejection text (a build older than the runtime layer) is a
     finding too.

Verdict: exit 0 clean, 1 finding, 2 could not verify (no routes parsed, the
controller did not answer, or the counter could not be read — pass
`--text-only` to accept the body-text check alone).

Stated limits:
  * the crawl is unauthenticated, so a route behind an auth middleware is
    refused before extraction and is not verified by it (reported as a count);
    the runtime layer covers those routes on real traffic;
  * route discovery is textual: a path built at runtime, or a router built in a
    function whose name the nest argument does not show, is not crawled;
  * sending a request moves that route's own counters (e.g. a push endpoint's
    refusal count) — it writes nothing a refused request would not write.

Usage:
  check-route-extensions.py --controller-url http://localhost:8000 [--delay S]
  check-route-extensions.py --list          # print the derived routes
  check-route-extensions.py --self-test     # parser fixtures, no network
Env: PROMETHEUS_SCRAPE_TOKEN (bearer for /metrics/prometheus; never printed).
"""

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

REJECTION_PREFIX = "Missing request extension"
COUNTER = "talos_http_missing_extension_total"
METHODS = ("get", "post", "put", "delete", "patch")
NIL_UUID = "00000000-0000-0000-0000-000000000000"
EXCLUDED_PATH_PARTS = ("/tests/", "/benches/", "/examples/", "/src/bin/")


# ── source parsing ──────────────────────────────────────────────────────────

def strip_test_modules(src):
    """Drop column-0 `#[cfg(test)]` items up to the first column-0 `}`."""
    out, skipping = [], False
    for line in src.splitlines(keepends=True):
        if not skipping and line.startswith("#[cfg(test)]"):
            skipping = True
            continue
        if skipping:
            if line.startswith("}"):
                skipping = False
            continue
        out.append(line)
    return "".join(out)


def blank_comments(src):
    """Replace `//` comments (outside string literals) with spaces."""
    out, i, n = [], 0, len(src)
    in_str = False
    while i < n:
        c = src[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def balanced_args(src, open_idx):
    """Given the index of `(`, return (args_text, index_after_close)."""
    depth, i, n, in_str = 0, open_idx, len(src), False
    while i < n:
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return src[open_idx + 1:i], i + 1
        i += 1
    return src[open_idx + 1:], n


def enclosing_fn(src, idx):
    names = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", src[:idx])]
    return names[-1][1] if names else None


def parse_sources(sources):
    """sources: {path: text}. Returns sorted list of (method, path)."""
    routes = []   # (fn, path, [methods], file)
    nests = []    # (prefix, [candidate fn names], file)
    for f, raw in sources.items():
        src = blank_comments(strip_test_modules(raw))
        for m in re.finditer(r"\.(route|nest)\s*\(", src):
            args, _ = balanced_args(src, m.end() - 1)
            lit = re.match(r'\s*"([^"]*)"\s*,(.*)\Z', args, re.S)
            if not lit:
                continue
            path, rest = lit.group(1), lit.group(2)
            if m.group(1) == "route":
                meths = [x for x in re.findall(r"\b(get|post|put|delete|patch|any)(?:_service)?\s*\(", rest)]
                if "any" in meths or not meths:
                    meths = ["get"] if not meths else list(METHODS)
                routes.append((enclosing_fn(src, m.start()), path, list(dict.fromkeys(meths)), f))
            else:
                calls = re.findall(r"(\w+)\s*\(", rest)
                ident = re.match(r"\s*(\w+)\s*\Z", rest)
                if ident:
                    b = re.search(r"\blet\s+(?:mut\s+)?" + re.escape(ident.group(1)) + r"\s*=\s*([\w:]+)\s*\(", src)
                    calls = [b.group(1).split("::")[-1]] if b else []
                cands = [c for c in calls if c not in ("with_state", "clone", "layer", "Router", "new")]
                nests.append((path, cands, f))

    nested_fns = {}
    for prefix, cands, _ in nests:
        for c in cands:
            nested_fns.setdefault(c, []).append(prefix)

    out = set()
    for fn, path, meths, _ in routes:
        prefixes = nested_fns.get(fn, [""])
        for p in prefixes:
            full = (p.rstrip("/") + path) if p else path
            if p and path == "/":
                full = p
            for meth in meths:
                out.add((meth.upper(), full))
    return sorted(out, key=lambda r: (r[1], r[0]))


def fill_params(path):
    def sub(m):
        name = m.group(1).lstrip("*")
        return NIL_UUID if name == "id" or name.endswith("_id") or name.endswith("uuid") else "x"
    return re.sub(r"\{([^}]+)\}", sub, path)


def workspace_sources():
    files = subprocess.run(["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True).stdout.split()
    out = {}
    for f in files:
        if any(p in "/" + f for p in EXCLUDED_PATH_PARTS) or f.endswith("_tests.rs") or f.endswith("/tests.rs"):
            continue
        if not os.path.exists(f):
            continue
        with open(f, encoding="utf-8", errors="replace") as h:
            text = h.read()
        if ".route(" in text or ".nest(" in text:
            out[f] = text
    return out


# ── crawl ───────────────────────────────────────────────────────────────────

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def send(base, method, path, timeout=10.0, headers=None):
    body = None if method == "GET" else b"{}"
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    if body is not None:
        req.add_header("content-type", "application/json")
    try:
        with OPENER.open(req, timeout=timeout) as r:
            try:
                return r.status, r.read(8192).decode("utf-8", "replace")
            except TimeoutError:
                # A streaming response (SSE) sends its status and never ends;
                # the rejection is a short complete body, so this is not one.
                return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.read(8192).decode("utf-8", "replace")


def read_counter(base):
    headers = {}
    token = os.environ.get("PROMETHEUS_SCRAPE_TOKEN", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    status, text = send(base, "GET", "/metrics/prometheus", headers=headers)
    if status != 200:
        return None, f"/metrics/prometheus answered {status}"
    for line in text.splitlines():
        if line.startswith(COUNTER + " "):
            return float(line.split()[1]), None
    # read(8192) may have cut the exposition; fetch in full.
    req = urllib.request.Request(base + "/metrics/prometheus", headers=headers)
    with OPENER.open(req, timeout=10.0) as r:
        full = r.read().decode("utf-8", "replace")
    for line in full.splitlines():
        if line.startswith(COUNTER + " "):
            return float(line.split()[1]), None
    return None, f"{COUNTER} is not exported (a build older than package BZ?)"


def crawl(args, routes=None):
    if routes is None:
        try:
            routes = parse_sources(workspace_sources())
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"✗ cannot list the workspace sources (run from a git checkout): {e}", file=sys.stderr)
            return 2
    if not routes:
        print("✗ no routes derived from source — the parser matched nothing", file=sys.stderr)
        return 2
    base = args.controller_url.rstrip("/")
    before, why = read_counter(base) if not args.text_only else (None, "text-only")
    if before is None and not args.text_only:
        print(f"✗ cannot read the counter: {why}. Set PROMETHEUS_SCRAPE_TOKEN, or pass --text-only.", file=sys.stderr)
        return 2

    statuses, text_hits, fives, unreachable = {}, [], [], 0
    for method, path in routes:
        url_path = fill_params(path)
        try:
            status, body = send(base, method, url_path)
        except (urllib.error.URLError, OSError) as e:
            unreachable += 1
            print(f"  ⚠ {method} {path}: no response ({type(e).__name__})")
            continue
        statuses[status] = statuses.get(status, 0) + 1
        if REJECTION_PREFIX in body:
            text_hits.append((method, path, status))
        if status == 500:
            fives.append((method, path))
        if args.delay:
            time.sleep(args.delay)
    if unreachable == len(routes):
        print(f"✗ the controller at {base} answered none of {len(routes)} requests", file=sys.stderr)
        return 2

    findings = list(text_hits)
    if before is not None:
        after, why = read_counter(base)
        if after is None:
            print(f"✗ counter unreadable after the crawl: {why}", file=sys.stderr)
            return 2
        if after > before:
            for method, path in fives:
                c0, _ = read_counter(base)
                send(base, method, fill_params(path))
                c1, _ = read_counter(base)
                if c0 is not None and c1 is not None and c1 > c0:
                    findings.append((method, path, 500))
            if not findings:
                findings.append(("?", f"counter rose by {after - before:g} but no 500 route re-offended", 500))

    blocked = sum(v for k, v in statuses.items() if k in (401, 403, 429))
    summary = ", ".join(f"{k}×{v}" for k, v in sorted(statuses.items()))
    print(f"  {len(routes)} route/method pair(s) derived; responses: {summary}; unreachable: {unreachable}")
    print(f"  {blocked} refused with 401/403/429 — extraction not proven for those (the runtime layer covers them)")
    if findings:
        for method, path, status in sorted(set(findings)):
            print(f"✗ {method} {path} extracts an Extension its router does not provide ({status})")
        return 1
    print("✓ no route answered a missing-extension rejection")
    return 0


# ── self-test ───────────────────────────────────────────────────────────────

def self_test():
    fixtures = {
        "controller/src/bootstrap/router.rs": '''
pub fn build_router() {
    let mcp_routes = mcp::create_router(a, b);
    let app = Router::new()
        .route("/metrics/prometheus", get(prometheus)) // no-nginx-route: ".route(\\"/fake\\", get(x))"
        .route(
            "/approval-actions/{token}/{action}",
            get(approval_action_get).post(approval_action_post),
        )
        .route("/graphql", graphql_router)
        .route("/any", any(h))
        .nest("/mcp", mcp_routes)
        .nest(
            "/api/registry",
            registry::api::registry_router().with_state(registry.clone()),
        );
    // .route("/commented-out", get(h))
}

#[cfg(test)]
mod tests {
    fn t() { Router::new().route("/only-in-tests", get(h)); }
}
''',
        "talos-mcp-handlers/src/lib.rs": '''
pub fn create_router() -> Router {
    Router::new().route("/sse", get(sse)).route("/", get(root).post(root))
}
''',
        "talos-registry/src/api.rs": '''
pub fn registry_router() -> Router { Router::new().route("/publish", post(publish)) }
''',
    }
    got = parse_sources(fixtures)
    want = sorted({
        ("GET", "/metrics/prometheus"),
        ("GET", "/approval-actions/{token}/{action}"),
        ("POST", "/approval-actions/{token}/{action}"),
        ("GET", "/graphql"),
        ("GET", "/any"), ("POST", "/any"), ("PUT", "/any"), ("DELETE", "/any"), ("PATCH", "/any"),
        ("GET", "/mcp/sse"), ("GET", "/mcp"), ("POST", "/mcp"),
        ("POST", "/api/registry/publish"),
    }, key=lambda r: (r[1], r[0]))
    ok = True
    if got != want:
        ok = False
        print("✗ parse_sources mismatch")
        print("  missing:", sorted(set(want) - set(got)))
        print("  extra:  ", sorted(set(got) - set(want)))
    for path, expect in [
        ("/webhooks/{id}", f"/webhooks/{NIL_UUID}"),
        ("/api/gmail/watch-channels/{channel_uuid}/test", f"/api/gmail/watch-channels/{NIL_UUID}/test"),
        ("/auth/oauth/{provider}/login", "/auth/oauth/x/login"),
        ("/api/callbacks/{correlation_id}", f"/api/callbacks/{NIL_UUID}"),
    ]:
        if fill_params(path) != expect:
            ok = False
            print(f"✗ fill_params({path}) = {fill_params(path)}, want {expect}")
    ok = crawl_self_test() and ok
    print("✓ self-test passed" if ok else "✗ self-test failed")
    return 0 if ok else 1


def crawl_self_test():
    """Drive `crawl` against an in-process fake controller: the counter moves
    only on the scrubbed route, a plain 500 must not be blamed, and a legacy
    body-text rejection is a finding without the counter."""
    import http.server
    import threading
    from types import SimpleNamespace

    state = {"count": 0, "scrape_status": 200}

    class Fake(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, status, body):
            data = body.encode()
            self.send_response(status)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/metrics/prometheus":
                if state["scrape_status"] != 200:
                    return self.reply(state["scrape_status"], "no")
                return self.reply(200, f"# HELP x\n{COUNTER} {state['count']}\n")
            if self.path == "/scrubbed":
                state["count"] += 1
                return self.reply(500, "Internal Server Error")
            if self.path == "/db-down":
                return self.reply(500, "Internal Server Error")
            if self.path == "/legacy":
                return self.reply(500, REJECTION_PREFIX + ": Extension of type `X` was not found")
            if self.path == "/private":
                return self.reply(401, "unauthorized")
            return self.reply(200, "ok")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    args = SimpleNamespace(controller_url=base, delay=0.0, text_only=False)
    ok = True

    import contextlib
    import io

    last_out = {"text": ""}

    def quiet(a, r):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = crawl(a, r)
        last_out["text"] = buf.getvalue()
        return rc

    def expect(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"✗ crawl self-test: {name}: exit {got}, want {want}")

    try:
        expect("clean", quiet(args, [("GET", "/fine"), ("GET", "/db-down"), ("GET", "/private")]), 0)
        expect("counter moves on the scrubbed route", quiet(args, [("GET", "/fine"), ("GET", "/db-down"), ("GET", "/scrubbed")]), 1)
        if "GET /scrubbed extracts" not in last_out["text"] or "/db-down" in last_out["text"].split("responses:")[-1].split("\n", 1)[-1]:
            ok = False
            print("✗ crawl self-test: the finding must name /scrubbed and never the plain 500 /db-down")
        expect("legacy body text", quiet(args, [("GET", "/legacy")]), 1)
        expect("no routes", quiet(args, [("GET", "/fine")][:0]), 2)
        state["scrape_status"] = 403
        expect("counter unreadable", quiet(args, [("GET", "/fine")]), 2)
        args.text_only = True
        expect("text-only still sees legacy text", quiet(args, [("GET", "/legacy")]), 1)
        expect("text-only cannot see a scrubbed rejection", quiet(args, [("GET", "/scrubbed")]), 0)
        args.text_only = False
        state["scrape_status"] = 200
        dead = SimpleNamespace(controller_url="http://127.0.0.1:9", delay=0.0, text_only=True)
        expect("unreachable controller", quiet(dead, [("GET", "/fine")]), 2)
    finally:
        srv.shutdown()
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--controller-url", default=os.environ.get("CONTROLLER_URL", ""))
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    ap.add_argument("--text-only", action="store_true", help="skip the counter; body text only")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.list:
        for method, path in parse_sources(workspace_sources()):
            print(f"{method}\t{path}")
        return 0
    if not args.controller_url:
        print("✗ --controller-url (or CONTROLLER_URL) is required", file=sys.stderr)
        return 2
    return crawl(args)


if __name__ == "__main__":
    sys.exit(main())
