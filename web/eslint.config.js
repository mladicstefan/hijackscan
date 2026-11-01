// ESLint with typescript-eslint (the maintained successor of TSLint) and the React hooks rules.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

// An effect without a dependency array runs after every render. This project forbids that outright
// (useEffect, useLayoutEffect, useInsertionEffect, also when called as React.useEffect).
const EFFECT = "/^use(Layout|Insertion)?Effect$/";
const NO_DEPS_MESSAGE = "Effects must have a dependency array; an effect without one runs after every render.";

export default defineConfig(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        project: ["./tsconfig.app.json", "./tsconfig.node.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
      "no-restricted-syntax": [
        "error",
        { selector: `CallExpression[callee.name=${EFFECT}][arguments.length<2]`, message: NO_DEPS_MESSAGE },
        { selector: `CallExpression[callee.property.name=${EFFECT}][arguments.length<2]`, message: NO_DEPS_MESSAGE },
      ],
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
);
