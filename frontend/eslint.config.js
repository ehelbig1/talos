import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";
import prettierConfig from "eslint-config-prettier";

export default [
    // Global ignores
    {
        ignores: [
            "dist/**",
            "node_modules/**",
            "*.config.js",
            "*.config.ts",
            "*.config.mjs",
            "codegen.yml",
            "mock-server/**",
        ],
    },

    // Base JS recommended rules
    js.configs.recommended,

    // TypeScript files
    {
        files: ["src/**/*.ts", "src/**/*.tsx"],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaVersion: "latest",
                sourceType: "module",
                ecmaFeatures: { jsx: true },
            },
        },
        plugins: {
            "@typescript-eslint": tsPlugin,
            "react-hooks": reactHooks,
        },
        rules: {
            // React hooks correctness — adopting the v7 React-Compiler
            // `recommended` ruleset incrementally (docs/backlog.md). This slice
            // turns on the two baseline rules PLUS every recommended rule that
            // has ZERO current violations — real correctness guards (e.g.
            // set-state-in-render infinite-loop, components-defined-in-render,
            // useMemo misuse, ref-during-render) that are pure upside.
            "react-hooks/rules-of-hooks": "error",
            "react-hooks/exhaustive-deps": "warn",
            "react-hooks/static-components": "error",
            "react-hooks/use-memo": "error",
            "react-hooks/void-use-memo": "error",
            "react-hooks/incompatible-library": "warn",
            "react-hooks/globals": "error",
            "react-hooks/refs": "error",
            "react-hooks/error-boundaries": "error",
            "react-hooks/set-state-in-render": "error",
            "react-hooks/unsupported-syntax": "warn",
            "react-hooks/config": "error",
            "react-hooks/gating": "error",
            // DEFERRED — these have current findings and need per-site human
            // triage (real bug vs. intentional idiom), done one rule per PR so
            // each fix is reviewable rather than a blanket suppression:
            //   - set-state-in-effect (14): cascading-render risk vs. benign sync
            //   - immutability (6): real mutation vs. idiomatic ref-guard
            //   - purity (6): mostly intentional Date.now() (display/fallback)
            //   - preserve-manual-memoization (1): a real memo-dep fix
            // "react-hooks/set-state-in-effect": "error",
            // "react-hooks/immutability": "error",
            // "react-hooks/purity": "error",
            // "react-hooks/preserve-manual-memoization": "error",

            // Use TypeScript-aware rules instead of base ESLint rules
            "no-unused-vars": "off",
            "@typescript-eslint/no-unused-vars": [
                "warn",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
            "no-undef": "off", // TypeScript handles this
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/consistent-type-imports": "warn",

            // Security: prevent XSS vectors
            "no-eval": "error",
            "no-implied-eval": "error",
            "no-new-func": "error",
        },
    },

    // Disable rules that conflict with Prettier
    prettierConfig,
];
