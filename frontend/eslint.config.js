import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";
import prettierConfig from "eslint-config-prettier";


// A colour means the same thing everywhere: a status is success / warning /
// destructive / info, an accent is primary, a neutral is muted-foreground or
// white/N. A Tailwind palette hue (amber-500, violet-400, …) is allowed only
// in the kind-colour homes below.
const KIND_COLOUR_HOMES = [
    "src/lib/capabilityBadge.tsx",
    "src/lib/capabilityConfig.ts",
    "src/lib/categoryIcons.ts",
    "src/components/nodes/NodeBadges.tsx",
];
const PALETTE_HUES =
    "(indigo|violet|purple|fuchsia|pink|amber|orange|yellow|emerald|green|teal|lime|red|rose|blue|sky|cyan|gray|slate|zinc|neutral|stone)";
const PALETTE_CLASS = `(^|[\\s"'\`:])(text|bg|border(-[trblxyse])?|ring|fill|stroke|shadow|from|to|via|divide|outline|placeholder)-${PALETTE_HUES}-\\d{2,3}\\b`;
const PALETTE_MESSAGE =
    "A palette hue is not a meaning. Use text-/bg-/border- with success, warning, destructive, info, primary or muted-foreground (white/N for a neutral). A kind colour lives in src/lib/capabilityBadge.tsx, capabilityConfig.ts, categoryIcons.ts or nodes/NodeBadges.tsx.";
const PALETTE_COLOUR_SELECTORS = [
    { selector: `Literal[value=/${PALETTE_CLASS}/]`, message: PALETTE_MESSAGE },
    { selector: `TemplateElement[value.raw=/${PALETTE_CLASS}/]`, message: PALETTE_MESSAGE },
];
const UI_FLOOR_SELECTORS = [
                {
                    // An icon-only button (no text anywhere below it) has no
                    // accessible name unless it says aria-label; a title is a
                    // tooltip, not a name. Spread props may carry one.
                    selector:
                        'JSXElement[openingElement.name.name="button"]:not(:has(JSXText[value=/\\S/])):not(:has(JSXElement > JSXExpressionContainer, JSXFragment > JSXExpressionContainer)):not(:has(JSXAttribute[name.name=/^aria-label(ledby)?$/])):not(:has(JSXSpreadAttribute))',
                    message:
                        "An icon-only button names itself: add aria-label (keep title for the tooltip if you want one).",
                },
                {
                    selector:
                        'JSXOpeningElement[name.name="label"] > JSXAttribute[name.name="className"] > Literal[value=/\\buppercase\\b/]',
                    message:
                        "A form label is read, not scanned: sentence case at text-xs font-medium. Caps are for a one-to-three-word section eyebrow or a tiny status badge only.",
                },
                {
                    selector:
                        "Literal[value=/(^|\\s)(font-black|text-\\[(9|10)px\\]|tracking-\\[0\\.[2-4]em\\]|tracking-widest|text-muted-foreground\\/(10|20|40))(\\s|$)/]",
                    message:
                        "Retired type token. Floor: text-2xs, font-semibold, tracking-wider, text-muted-foreground/60. See src/components/ui.",
                },
                {
                    selector:
                        "TemplateElement[value.raw=/(^|\\s)(font-black|text-\\[(9|10)px\\]|tracking-\\[0\\.[2-4]em\\]|tracking-widest|text-muted-foreground\\/(10|20|40))(\\s|$)/]",
                    message:
                        "Retired type token. Floor: text-2xs, font-semibold, tracking-wider, text-muted-foreground/60. See src/components/ui.",
                },
                {
                    selector:
                        "Literal[value=/(^|\\s)(animate-in|animate-out|slide-in-from-[a-z]+(-(\\d+|full))?|zoom-in(-\\d+)?|zoom-out(-\\d+)?|transition-premium|transition-all|active:scale-\\S+|hover:scale-\\S+|hover:-?translate-\\S+|hover:rotate-\\S+|group-hover(\\/[\\w-]+)?:(-?translate|rotate|scale)-\\S+|animate-bounce|animate-ping|duration-(500|700|1000)|delay-\\d+)(\\s|$)/]",
                    message:
                        "Retired motion token. One transition utility (transition-ui), no entrance animations, no press or hover transforms, durations at most 300 ms; a pulse means a run is in progress. See src/index.css.",
                },
                {
                    selector:
                        "TemplateElement[value.raw=/(^|\\s)(animate-in|animate-out|slide-in-from-[a-z]+(-(\\d+|full))?|zoom-in(-\\d+)?|zoom-out(-\\d+)?|transition-premium|transition-all|active:scale-\\S+|hover:scale-\\S+|hover:-?translate-\\S+|hover:rotate-\\S+|group-hover(\\/[\\w-]+)?:(-?translate|rotate|scale)-\\S+|animate-bounce|animate-ping|duration-(500|700|1000)|delay-\\d+)(\\s|$)/]",
                    message:
                        "Retired motion token. One transition utility (transition-ui), no entrance animations, no press or hover transforms, durations at most 300 ms; a pulse means a run is in progress. See src/index.css.",
                },
];

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
            // GraphQL codegen output — regenerated by `npm run codegen`, so
            // hand-lint fixes here drift on the next run. Lint the sources, not
            // the generated artifact.
            "src/generated/**",
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
            // Enabled after per-site triage of their findings:
            //   - immutability (6): 4 use-before-declare fixed (hoisted fn /
            //     reorder), 2 window.location navigations justified-disabled.
            //   - preserve-manual-memoization (1): memo dep corrected.
            "react-hooks/immutability": "error",
            "react-hooks/preserve-manual-memoization": "error",
            // Enabled after properly fixing all 15 findings (no suppressions):
            //   - 1 genuine derived-state bug (AuthContext) removed.
            //   - 8 external→local syncs moved to the React-endorsed
            //     "store information from previous renders" render-phase
            //     pattern (https://react.dev/learn/you-might-not-need-an-effect).
            //   - 6 mount-fetch components migrated to react-query useQuery so
            //     loading/data/error is derived, not mirrored via an effect.
            "react-hooks/set-state-in-effect": "error",
            // Enabled after properly fixing all 6 findings (no suppressions):
            //   - mount-time / fallback timestamps captured via lazy
            //     useState(() => Date.now()) initializers (allowed — run once).
            //   - the schedule "overdue" check uses an interval-ticked `now`.
            //   - the actor-compare queued-at time is captured inside the
            //     setState updater (render keeps idempotent).
            "react-hooks/purity": "error",

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

    // GraphQL data-layer boundary: components and pages must not talk to the
    // transport directly. Add the operation to src/graphql/*.graphql (or a
    // component-local gql`...` tag), run `npm run codegen`, and use the
    // generated react-query hook from @/generated/graphql — or, for genuinely
    // imperative call sites, a typed wrapper in @/lib/graphqlApi.
    {
        files: ["src/components/**/*.{ts,tsx}", "src/pages/**/*.{ts,tsx}"],
        ignores: ["**/*.test.ts", "**/*.test.tsx"],
        rules: {
            "no-restricted-imports": [
                "error",
                {
                    paths: [
                        {
                            name: "@/lib/graphqlClient",
                            importNames: ["graphqlRequest", "graphqlFetcher"],
                            message:
                                "Don't call the GraphQL transport from components/pages. Use the generated react-query hooks from '@/generated/graphql' (add the operation to src/graphql/*.graphql and run `npm run codegen`), or a typed wrapper in '@/lib/graphqlApi'.",
                        },
                    ],
                },
            ],
        },
    },
    // Type scale, motion, naming and colour floor (2026-10-15). The retired
    // tokens made every label a 9 px, black-weight, letter-spaced caption at
    // 30 % opacity; the floor is text-2xs (11 px), font-semibold,
    // tracking-wider, and text-muted-foreground at /60 or more. Fix the
    // primitive in src/components/ui before reaching for a one-off.
    {
        files: ["src/**/*.ts", "src/**/*.tsx"],
        ignores: ["**/*.test.ts", "**/*.test.tsx", "**/__tests__/**", "src/generated/**", ...KIND_COLOUR_HOMES],
        rules: {
            "no-restricted-syntax": ["error", ...UI_FLOOR_SELECTORS, ...PALETTE_COLOUR_SELECTORS],
        },
    },
    // The kind-colour homes: a capability world, a node kind and a catalog
    // category each get a deliberate hue there, and nowhere else.
    {
        files: KIND_COLOUR_HOMES,
        rules: {
            "no-restricted-syntax": ["error", ...UI_FLOOR_SELECTORS],
        },
    },
    // Test files: allow `any`. Test doubles, mock fetch signatures, and
    // fixture payloads are deliberately loosely typed — enforcing precise
    // types on mocks adds churn without protecting production code. The rule
    // stays ON (warn) for all non-test source, so production type safety is
    // unaffected. no-unused-vars stays ON for tests too (dead test imports are
    // still worth catching).
    {
        files: ["**/*.test.{ts,tsx}", "**/__tests__/**/*.{ts,tsx}"],
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
        },
    },
    // Disable rules that conflict with Prettier
    prettierConfig,
];
