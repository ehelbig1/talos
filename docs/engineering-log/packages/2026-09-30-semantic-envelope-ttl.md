# 2026-09-30: a `semantic` memory written through `__memory_write__` expired in a week

**Found live** while giving the weekly essay pipeline a covered-titles list.
The list was written as `semantic` through the envelope, and the stored row
had `expires_at` seven days out.

**Cause.** `talos_engine::node_hook` defaulted a missing `ttl_hours` to 168 for
every memory type. `talos_memory::default_expires_at` honours any explicit
TTL, so the 168 reached the store for `semantic` too. CLAUDE.md documented
the envelope as "semantic memories ignore TTL". The two other routes to a
semantic memory were right: `actor_remember` and reflection pass no TTL for
semantic.

**Population, measured.**
- Every installed module that emits the envelope sends `ttl_hours` itself (6
  modules, including LLM Inference, whose own default is 168).
- The catalog's Actor Memory Writer template defaults to `semantic` and sends
  none. Every write it makes has been expiring after a week, which defeats
  the template's purpose. No live workflow uses it.
- Of 9 live `semantic` rows, 1 carried an expiry: the essay list that exposed
  this.
- So the change is **latent** here.

**Decided.**
- One rule, the pure `envelope_ttl_hours`:
  - an explicit `ttl_hours` always wins;
  - omitted, `semantic` gets no expiry;
  - every other type keeps the envelope's documented 168 h.
- **Deliberately NOT** switching `working` / `scratchpad` to the store's type
  defaults (1 h / 24 h). The envelope has documented 168 for them, and
  shortening a live memory is a behaviour change with its own blast radius.
- **Deliberately NOT** ignoring an explicit TTL on `semantic`. `actor_remember`
  and the MCP-437 clamp test both treat an explicit TTL as authoritative.
- The CLAUDE.md sentence is rewritten to say this.

**Proof.**
- Three unit tests on the rule.
- `controller/tests/memory_write_envelope_ttl_tests` (controller DB harness)
  drives the real engine and the real `ControllerNodeHook` against Postgres,
  and asserts on `actor_memory.expires_at`:
  - semantic without a TTL has none;
  - episodic and working without one get ~168 h;
  - an explicit 2 h on semantic is honoured.
- It **fails on the pre-fix hook** at the first phase.
- Check 88 PREPAREs all 1 247 statements.

**Stated limit.** Rows already written keep their expiry until rewritten. The
one affected live row was rewritten with an explicit 10-year TTL before this
change.
