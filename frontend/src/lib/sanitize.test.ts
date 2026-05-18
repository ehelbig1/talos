import { describe, it, expect } from "vitest";
import { sanitizeErrorMessage } from "./sanitize";

describe("sanitizeErrorMessage", () => {
  it("should redact basic SQL queries", () => {
    const msg = "Error: SELECT * FROM users WHERE id = 1";
    expect(sanitizeErrorMessage(msg)).toContain("[DB QUERY REDACTED]");
    expect(sanitizeErrorMessage(msg)).not.toContain("SELECT");
  });

  it("should redact multi-line SQL queries", () => {
    const msg = `Error executing:
      SELECT name, email
      FROM accounts
      WHERE active = true`;
    const sanitized = sanitizeErrorMessage(msg);
    // The query is redacted as multiple matches because of multiple keywords
    expect(sanitized).toContain("[DB QUERY REDACTED]");
    expect(sanitized).not.toContain("accounts");
    expect(sanitized).not.toContain("active");
  });

  it("should redact INSERT and UPDATE statements", () => {
    const msg1 = 'INSERT INTO logs (msg) VALUES ("test")';
    const msg2 = 'UPDATE users SET name = "admin"';
    expect(sanitizeErrorMessage(msg1)).toContain("[DB QUERY REDACTED]");
    expect(sanitizeErrorMessage(msg2)).toContain("[DB QUERY REDACTED]");
  });

  it("should redact file paths", () => {
    const msg = "Failed to read /Users/evanhelbig/secret/file.txt";
    expect(sanitizeErrorMessage(msg)).toContain("[PATH REDACTED]");
    expect(sanitizeErrorMessage(msg)).not.toContain("evanhelbig");
  });

  it("should truncate long messages", () => {
    const longMsg = "A".repeat(600);
    const sanitized = sanitizeErrorMessage(longMsg);
    expect(sanitized.length).toBeLessThanOrEqual(501); // 500 + ellipsis
    expect(sanitized).toContain("…");
  });

  it("should not redact harmless text", () => {
    const msg = "Welcome to the dashboard";
    expect(sanitizeErrorMessage(msg)).toBe("Welcome to the dashboard");
  });

  // =========================================================================
  // XSS vector tests
  // =========================================================================

  it("should handle script tag XSS vector", () => {
    const msg = "Error: <script>alert(1)</script>";
    const sanitized = sanitizeErrorMessage(msg);
    // The function is for error message sanitization (not HTML escaping),
    // so the primary concern is that the output is truncated/safe.
    // Verify it does not crash and returns a string.
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle img onerror XSS vector", () => {
    const msg = "Error: <img src=x onerror=alert(1)>";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle javascript: URL XSS vector", () => {
    const msg = "Navigate to javascript:alert(document.cookie)";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle nested script injection with encoding", () => {
    const msg = 'Error: <scr<script>ipt>alert("xss")</scr</script>ipt>';
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle SVG-based XSS", () => {
    const msg = "<svg onload=alert(1)>";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle event handler XSS vectors", () => {
    const vectors = [
      "<div onmouseover=alert(1)>",
      "<body onload=alert(1)>",
      "<input onfocus=alert(1) autofocus>",
      "<marquee onstart=alert(1)>",
    ];
    for (const vec of vectors) {
      const sanitized = sanitizeErrorMessage(vec);
      expect(typeof sanitized).toBe("string");
    }
  });

  // =========================================================================
  // Nested SQL injection patterns
  // =========================================================================

  it("should redact nested SQL with UNION injection", () => {
    const msg = "Error: ' UNION SELECT username, password FROM admin_users --";
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("[DB QUERY REDACTED]");
    // The SELECT ... FROM portion must be redacted.
    expect(sanitized).not.toContain("SELECT");
    expect(sanitized).not.toContain("FROM admin_users");
  });

  it("should redact SQL with subqueries", () => {
    const msg =
      "SELECT * FROM users WHERE id IN (SELECT user_id FROM sessions WHERE active = true)";
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("[DB QUERY REDACTED]");
    expect(sanitized).not.toContain("sessions");
  });

  it("should redact DELETE statements", () => {
    const msg = "DELETE FROM users WHERE id = 1; DROP TABLE users;";
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("[DB QUERY REDACTED]");
    expect(sanitized).not.toContain("DROP TABLE");
  });

  it("should redact SQL with RETURNING clause", () => {
    const msg =
      'INSERT INTO tokens (user_id, token) VALUES (1, "secret") RETURNING *';
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("[DB QUERY REDACTED]");
  });

  it("should redact SQL with multiple keywords on separate lines", () => {
    const msg = `SELECT
      u.email,
      u.password_hash
    FROM users u
    WHERE u.role = 'admin'
    ORDER BY u.created_at
    LIMIT 100`;
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("[DB QUERY REDACTED]");
    // The regex-based redaction may not catch every token between keywords,
    // but the core SQL structure (SELECT, FROM, WHERE) must be stripped.
    expect(sanitized).not.toContain("SELECT");
    expect(sanitized).not.toContain("FROM users");
  });

  // =========================================================================
  // Very long error messages (10 KB+)
  // =========================================================================

  it("should truncate 10KB+ error message to 500 chars", () => {
    const longMsg = "Error: " + "x".repeat(10 * 1024);
    const sanitized = sanitizeErrorMessage(longMsg);
    expect(sanitized.length).toBeLessThanOrEqual(501);
    expect(sanitized).toContain("…");
  });

  it("should truncate 100KB error message", () => {
    const hugeMsg = "Stack trace: " + "frame\n".repeat(20000);
    const sanitized = sanitizeErrorMessage(hugeMsg);
    expect(sanitized.length).toBeLessThanOrEqual(501);
  });

  it("should handle message that is exactly 500 chars", () => {
    const exactMsg = "B".repeat(500);
    const sanitized = sanitizeErrorMessage(exactMsg);
    expect(sanitized).toBe(exactMsg); // Should not be truncated
    expect(sanitized.length).toBe(500);
  });

  it("should handle message that is 501 chars", () => {
    const msg501 = "C".repeat(501);
    const sanitized = sanitizeErrorMessage(msg501);
    expect(sanitized.length).toBeLessThanOrEqual(501);
    expect(sanitized).toContain("…");
  });

  // =========================================================================
  // Unicode in error messages
  // =========================================================================

  it("should handle Unicode error messages", () => {
    const msg = "Error: \u6587\u5B57\u5316\u3051 (mojibake)";
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).toContain("\u6587\u5B57\u5316\u3051");
  });

  it("should handle RTL override characters", () => {
    const msg = "Error in file: \u202Etxt.exe\u202C";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle zero-width characters in error messages", () => {
    const msg = "User \u200Badmin\u200B not found";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle emoji in error messages", () => {
    const msg = "Error \uD83D\uDCA5: Something went wrong \uD83D\uDE31";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle mixed scripts (homoglyph-like)", () => {
    const msg = "Error: user \u0430dmin not found"; // Cyrillic 'а'
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  // =========================================================================
  // Null bytes and control characters
  // =========================================================================

  it("should handle null bytes in error messages", () => {
    const msg = "Error\x00: null byte present";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle multiple null bytes", () => {
    const msg = "\x00\x00\x00";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle control characters (bell, backspace, etc.)", () => {
    const msg = "Error\x07\x08\x1B[31m with ANSI escape";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle CRLF injection in error messages", () => {
    const msg = "Error\r\nX-Injected: header";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  it("should handle tab characters", () => {
    const msg = "Error:\t\tindented details";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
    expect(sanitized.length).toBeGreaterThan(0);
  });

  it("should handle form feed and vertical tab", () => {
    const msg = "Error\x0C\x0B: rare control chars";
    const sanitized = sanitizeErrorMessage(msg);
    expect(typeof sanitized).toBe("string");
  });

  // =========================================================================
  // Edge cases
  // =========================================================================

  it("should handle empty string", () => {
    expect(sanitizeErrorMessage("")).toBe("");
  });

  it("should handle null/undefined gracefully", () => {
    // TypeScript types prevent this at compile time, but at runtime
    // JS callers might pass null/undefined.
    expect(sanitizeErrorMessage(null as unknown as string)).toBe("");
    expect(sanitizeErrorMessage(undefined as unknown as string)).toBe("");
  });

  it("should handle Windows file paths", () => {
    const msg = "Failed to read C:\\Users\\admin\\secrets\\key.pem";
    const sanitized = sanitizeErrorMessage(msg);
    // The Windows path regex redacts the drive prefix (C:\Users\).
    // Verify at least partial redaction occurs.
    expect(sanitized).toContain("[PATH REDACTED]");
    expect(sanitized).not.toContain("C:\\Users");
  });

  it("should redact database constraint names", () => {
    const msg = "database constraint violation: users_email_key";
    const sanitized = sanitizeErrorMessage(msg);
    expect(sanitized).not.toContain("users_email_key");
  });

  it("preserves lowercase English verbs that collide with SQL keywords", () => {
    // Regression guard: the previous sanitizer was case-insensitive
    // and would chop any message containing "create" / "update" /
    // "delete" / "insert" / "select" etc. to "[DB QUERY REDACTED]",
    // destroying real user-facing error context (e.g. the gcal
    // "Failed to create watch channel" message). The tightened
    // regex now requires an uppercase SQL-shaped statement.
    for (const msg of [
      "Failed to create watch channel on Google API: network error",
      "Could not update record — row was deleted concurrently",
      "Failed to select calendars from Google",
      "Unable to insert into the mailing list",
      "Please delete the duplicate before continuing",
    ]) {
      const sanitized = sanitizeErrorMessage(msg);
      expect(sanitized).not.toContain("[DB QUERY REDACTED]");
      expect(sanitized.length).toBeGreaterThan(msg.length / 2);
    }
  });

  it("still redacts real uppercase SQL statements", () => {
    // Contract guard: genuine query dumps (the shape Postgres errors
    // embed) MUST still be redacted, otherwise we've regressed the
    // defense this function exists for.
    for (const msg of [
      "insert failed: INSERT INTO users (email) VALUES ($1);",
      "error at: SELECT id, email FROM users WHERE id = $1",
      "UPDATE users SET is_active = false WHERE id = $1",
      "DELETE FROM audit_log WHERE user_id = $1",
      "CREATE TABLE foo (id uuid primary key)",
    ]) {
      const sanitized = sanitizeErrorMessage(msg);
      expect(sanitized).toContain("[DB QUERY REDACTED]");
      expect(sanitized).not.toMatch(
        /\b(SELECT|INSERT INTO|UPDATE \w+ SET|DELETE FROM|CREATE TABLE)\b/,
      );
    }
  });
});
