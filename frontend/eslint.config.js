import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
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
        },
        rules: {
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
