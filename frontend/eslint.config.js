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
            // React hooks correctness — the two battle-tested baseline rules
            // (NOT the full v7 React-Compiler `recommended` set, which is a
            // separate, larger migration tracked in docs/backlog.md).
            // `rules-of-hooks` catches conditional/loop hook calls (real bugs);
            // `exhaustive-deps` is a warning (stale-closure hint, non-blocking).
            "react-hooks/rules-of-hooks": "error",
            "react-hooks/exhaustive-deps": "warn",

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
