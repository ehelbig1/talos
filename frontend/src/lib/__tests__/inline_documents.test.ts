/**
 * Every GraphQL document written as a BARE template literal in `src/` is
 * validated against `schema.graphql` (package DT, 2026-09-22).
 *
 * Why this exists: graphql-codegen plucks documents from `gql` tags and
 * `.graphql` files and validates those at codegen time, which CI gates
 * (`npm run codegen && git diff --exit-code`). A document in a plain
 * template literal — `auth.ts`'s login / signup / verifyTwoFactor / me /
 * logout, `session.ts`'s refresh — is invisible to it. `verifyTwoFactor`
 * named its input `VerifyTwoFactorInput` while the schema has called it
 * `Verify2FAInput` since at least 2026-05-18: every 2FA login was refused by
 * schema validation before the code reached the verifier, and nothing in
 * the repository could see it until the first enrolled user signed in.
 *
 * The population is DERIVED (every matching literal under `src/`), never a
 * hand-kept list, and the test refuses to pass over an empty or shrunken
 * scan: a scanner that matches nothing is a green tick over nothing.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { buildSchema, parse, validate, type GraphQLSchema } from "graphql";
import { describe, expect, it } from "vitest";

export interface InlineDocument {
  file: string;
  name: string;
  text: string;
}

/** Drop line comments and block comments so a backticked phrase inside
 *  prose ("the `mutation RefreshToken`") is not read as a document. */
export function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^[ \t]*\/\/.*$/gm, "");
}

/** Bare template literals whose content opens with an operation keyword and
 *  a selection. Interpolated literals (`${…}`) are skipped: their text is
 *  not a document until runtime, and none exists in `src/` today. */
export function extractInlineDocuments(
  file: string,
  source: string,
): InlineDocument[] {
  const out: InlineDocument[] = [];
  const re = /`\s*((?:query|mutation|subscription)\b[\s\S]*?)`/g;
  for (const m of stripComments(source).matchAll(re)) {
    const text = m[1];
    if (text.includes("${") || !text.includes("{")) continue;
    const name =
      (text.match(/^(?:query|mutation|subscription)\s+(\w+)/) ?? [])[1] ??
      "(anonymous)";
    out.push({ file, name, text });
  }
  return out;
}

export function validateInline(
  schema: GraphQLSchema,
  doc: InlineDocument,
): string[] {
  try {
    return validate(schema, parse(doc.text)).map((e) => e.message);
  } catch (e) {
    return [e instanceof Error ? e.message : String(e)];
  }
}

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      if (entry !== "generated" && entry !== "__tests__") sourceFiles(p, out);
    } else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.(ts|tsx)$/.test(entry)) {
      out.push(p);
    }
  }
  return out;
}

// vitest runs with the frontend package as its cwd (vite root).
const schema = buildSchema(readFileSync("schema.graphql", "utf8"));

describe("bare inline GraphQL documents validate against the schema", () => {
  it("every bare document under src/ parses and validates", () => {
    const docs = sourceFiles("src").flatMap((f) =>
      extractInlineDocuments(f, readFileSync(f, "utf8")),
    );
    // The floor is the measured population on 2026-09-22 (53); a scanner
    // change that silently drops most of it must fail here, not pass.
    expect(docs.length).toBeGreaterThanOrEqual(40);
    const failures = docs
      .map((d) => ({ d, errors: validateInline(schema, d) }))
      .filter((r) => r.errors.length > 0)
      .map((r) => `${r.d.file}: ${r.d.name}: ${r.errors.join(" | ")}`);
    expect(failures).toEqual([]);
  });

  it("the 2FA verify document names the schema's input type", () => {
    const docs = extractInlineDocuments(
      "src/lib/auth.ts",
      readFileSync("src/lib/auth.ts", "utf8"),
    );
    const verify = docs.find((d) => d.name === "VerifyTwoFactor");
    expect(verify).toBeDefined();
    expect(verify!.text).toContain("Verify2FAInput!");
  });

  it("self-test: the scanner reports the defect this test exists for", () => {
    const fixture = `
      // prose mentioning \`mutation Ghost\` must not be read as a document
      const m = \`
        mutation VerifyTwoFactor($input: VerifyTwoFactorInput!) {
          verifyTwoFactor(input: $input) { user { id } }
        }
      \`;
      const ok = \`query Me { me { id } }\`;
      const interpolated = \`query \${name} { me { id } }\`;
    `;
    const docs = extractInlineDocuments("fixture.ts", fixture);
    expect(docs.map((d) => d.name)).toEqual(["VerifyTwoFactor", "Me"]);
    expect(validateInline(schema, docs[0]).join(" ")).toMatch(
      /Unknown type "VerifyTwoFactorInput"/,
    );
    expect(validateInline(schema, docs[1])).toEqual([]);
  });

  it("self-test: a document that does not parse is a finding, not a skip", () => {
    const doc = { file: "f.ts", name: "Broken", text: "query Broken { me {" };
    expect(validateInline(schema, doc).length).toBe(1);
  });
});
