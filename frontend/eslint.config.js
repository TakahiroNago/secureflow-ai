import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import tseslint from 'typescript-eslint'

/*
 * SecureFlow AI — ESLint configuration
 *
 * XSS policy (docs/security-design.md §14): AI output and user-provided strings are
 * rendered as React text only. Rendering HTML is prohibited in principle, so the
 * corresponding APIs are reported as errors here (and by Semgrep in CI, Phase 3).
 */
const xssRestrictedSyntax = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'dangerouslySetInnerHTML is prohibited (render text only; see docs/security-design.md §14).',
  },
  {
    selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
    message: 'innerHTML / outerHTML are prohibited (render text only).',
  },
  {
    selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
    message: 'insertAdjacentHTML is prohibited (render text only).',
  },
  {
    selector: "CallExpression[callee.property.name='createContextualFragment']",
    message: 'createContextualFragment is prohibited (render text only).',
  },
  {
    selector: "MemberExpression[object.name='document'][property.name=/^(write|writeln)$/]",
    message: 'document.write is prohibited.',
  },
  {
    selector: "MemberExpression[property.name=/^(localStorage|sessionStorage)$/]",
    message: 'Browser storage is prohibited: credentials stay in the HttpOnly session cookie (docs/architecture.md §6).',
  },
]

const storageMessage = 'Browser storage is prohibited: credentials stay in the HttpOnly session cookie (docs/architecture.md §6).'

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.strict],
    languageOptions: {
      ecmaVersion: 2023,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-restricted-syntax': ['error', ...xssRestrictedSyntax],
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: storageMessage },
        { name: 'sessionStorage', message: storageMessage },
      ],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
    },
  },
)
