const RULES: Array<{ pattern: RegExp; text: string }> = [
  { pattern: /404/, text: "Endpoint not found — check the URL path" },
  {
    pattern: /401|403|unauthorized|forbidden/i,
    text: "Auth failed — verify your API key in Secrets",
  },
  {
    pattern: /timeout|timed out/i,
    text: "Timed out — the server may be slow or down",
  },
  {
    pattern: /connection refused|ECONNREFUSED/i,
    text: "Connection refused — check host and port",
  },
  {
    pattern: /invalid json|unexpected token/i,
    text: "Invalid JSON — check the response format",
  },
  {
    pattern: /rate limit|429/i,
    text: "Rate limited — add a delay between requests",
  },
  {
    pattern: /ENOTFOUND|dns/i,
    text: "Domain not found — check for typos in the URL",
  },
  {
    pattern: /ssl|certificate/i,
    text: "TLS error — the server certificate may be invalid",
  },
  {
    pattern: /PANIC:/i,
    text: "Module panicked — check for unwrap() on None/Err in your Rust code",
  },
  {
    pattern: /fuel exhaustion|out of fuel/i,
    text: "Execution ran too long — increase timeout_secs or optimize the module",
  },
  {
    pattern: /memory allocation|out of memory|OOM/i,
    text: "Memory limit hit — reduce data size or split into smaller steps",
  },
  {
    pattern: /no route found|no actor matches/i,
    text: "Capability dispatch found no match — check actor capability world",
  },
  {
    pattern: /vault:\/\/|secret not found|vault_path/i,
    text: "Secret not found — check the vault:// path in node config matches a stored secret",
  },
  {
    pattern: /compilation failed|cargo build/i,
    text: "Module failed to compile — check for syntax errors in the Rust source",
  },
];

export function getFixSuggestion(error: string): string | undefined {
  return RULES.find((r) => r.pattern.test(error))?.text;
}
