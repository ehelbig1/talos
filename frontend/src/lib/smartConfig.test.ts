import { describe, it, expect } from "vitest";
import {
  analyzeURL,
  validateField,
  applySuggestions,
  getTemplateDefaults,
  getSlackSmartDefaults,
} from "./smartConfig";

/**
 * Tests for the smart configuration utilities. They cover URL analysis,
 * field validation, suggestion application and default generation. The goal
 * is to raise the frontend test coverage above the required thresholds.
 */

describe("analyzeURL", () => {
  it("returns invalid for empty string", () => {
    const result = analyzeURL("");
    expect(result.isValid).toBe(false);
    expect(result.suggestions).toHaveLength(0);
  });

  it("detects GraphQL endpoints and adds POST method", () => {
    const result = analyzeURL("https://example.com/graphql");
    expect(result.isValid).toBe(true);
    const methodSug = result.suggestions.find((s) => s.field === "METHOD");
    expect(methodSug?.value).toBe("POST");
    const headersSug = result.suggestions.find((s) => s.field === "HEADERS");
    expect(headersSug?.value).toContainEqual({
      key: "Content-Type",
      value: "application/json",
    });
  });

  it("adds GitHub specific headers and marks as REST", () => {
    const result = analyzeURL("https://api.github.com/users/octocat");
    expect(result.apiType).toBe("rest");
    const headerSug = result.suggestions.find((s) => s.field === "HEADERS");
    expect(headerSug?.value).toContainEqual({
      key: "Accept",
      value: "application/vnd.github+json",
    });
  });

  it("suggests method based based on generic REST patterns", () => {
    // Paths contain '/api/' to trigger generic REST detection.
    const create = analyzeURL("https://api.example.com/api/createItem");
    const update = analyzeURL("https://api.example.com/api/updateItem");
    const del = analyzeURL("https://api.example.com/api/deleteItem");
    const get = analyzeURL("https://api.example.com/api/list");
    expect(create.suggestions.find((s) => s.field === "METHOD")?.value).toBe(
      "POST",
    );
    expect(update.suggestions.find((s) => s.field === "METHOD")?.value).toBe(
      "PUT",
    );
    expect(del.suggestions.find((s) => s.field === "METHOD")?.value).toBe(
      "DELETE",
    );
    expect(get.suggestions.find((s) => s.field === "METHOD")?.value).toBe(
      "GET",
    );
  });
});

describe("validateField", () => {
  it("validates required URL field", () => {
    const res = validateField("URL", "", { format: "uri" });
    expect(res.valid).toBe(false);
    expect(res.message).toContain("required");
  });

  it("rejects malformed URL", () => {
    const res = validateField("URL", "not-a-url", { format: "uri" });
    expect(res.valid).toBe(false);
    expect(res.message).toContain("Invalid URL");
  });

  it("enforces number range", () => {
    const schema = { type: "number", minimum: 5, maximum: 10 } as any;
    expect(validateField("age", 4, schema).valid).toBe(false);
    expect(validateField("age", 11, schema).valid).toBe(false);
    expect(validateField("age", 7, schema).valid).toBe(true);
  });

  it("checks enum values", () => {
    const schema = { enum: ["a", "b", "c"] } as any;
    expect(validateField("choice", "d", schema).valid).toBe(false);
    expect(validateField("choice", "b", schema).valid).toBe(true);
  });

  it("validates array uniqueness and pattern", () => {
    const schema = {
      type: "array",
      uniqueItems: true,
      items: { pattern: "^\\d+$" },
    } as any;
    // duplicate fails
    expect(validateField("ids", ["1", "1"], schema).valid).toBe(false);
    // pattern mismatch fails
    expect(validateField("ids", ["12", "ab"], schema).valid).toBe(false);
    // valid case
    expect(validateField("ids", ["12", "34"], schema).valid).toBe(true);
  });
});

describe("applySuggestions", () => {
  it("applies missing fields and merges headers", () => {
    const config = {
      METHOD: "",
      HEADERS: [{ key: "Accept", value: "text/plain" }],
    } as any;
    const suggestions = [
      { field: "METHOD", value: "POST", reason: "" },
      {
        field: "HEADERS",
        value: [{ key: "Content-Type", value: "application/json" }],
        reason: "",
      },
    ];
    const result = applySuggestions(config, suggestions);
    expect(result.METHOD).toBe("POST");
    expect(result.HEADERS).toContainEqual({
      key: "Accept",
      value: "text/plain",
    });
    expect(result.HEADERS).toContainEqual({
      key: "Content-Type",
      value: "application/json",
    });
  });
});

describe("getTemplateDefaults & getSlackSmartDefaults", () => {
  it("returns http defaults", () => {
    const defaults = getTemplateDefaults("http", "any");
    expect(defaults.METHOD).toBe("GET");
    expect(defaults.TIMEOUT_MS).toBe(5000);
  });

  it("returns llm defaults", () => {
    const defaults = getTemplateDefaults("llm", "any");
    expect(defaults.MAX_TOKENS).toBe(1000);
    expect(defaults.SYSTEM_PROMPT).toContain("assistant");
  });

  it("returns slack defaults via getTemplateDefaults", () => {
    const defaults = getTemplateDefaults("webhook", "slack-notify");
    expect(defaults.EVENT_TYPES).toContain("message.channels");
  });

  it("getSlackSmartDefaults produces expected keys", () => {
    const slack = getSlackSmartDefaults();
    expect(slack).toHaveProperty("EVENT_TYPES");
    expect(slack).toHaveProperty("RATE_LIMIT");
    expect((slack.RATE_LIMIT as any).enabled).toBe(false);
  });
});
