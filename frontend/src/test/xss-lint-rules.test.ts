// @vitest-environment node
import { ESLint } from 'eslint'
import { describe, expect, it } from 'vitest'

/*
 * P0-FE-01: the ESLint configuration must reject HTML-rendering APIs
 * (docs/security-design.md §14). Lints in-memory snippets with the project config.
 */
const eslint = new ESLint({ cwd: process.cwd() })

async function lint(code: string, file = 'src/__lint_probe__.tsx') {
  const [result] = await eslint.lintText(code, { filePath: file })
  return (result?.messages ?? []).filter((m) => m.ruleId === 'no-restricted-syntax' || m.ruleId === 'no-eval')
}

describe('XSS lint rules', () => {
  it('rejects dangerouslySetInnerHTML', async () => {
    const messages = await lint(
      'export const A = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />\n',
    )
    expect(messages.map((m) => m.message).join('\n')).toContain('dangerouslySetInnerHTML is prohibited')
  })

  it('rejects innerHTML / outerHTML assignment', async () => {
    const messages = await lint('export function f(el: HTMLElement, s: string) { el.innerHTML = s; el.outerHTML = s }\n', 'src/__lint_probe__.ts')
    expect(messages).toHaveLength(2)
  })

  it('rejects insertAdjacentHTML and eval', async () => {
    const messages = await lint(
      "export function f(el: HTMLElement, s: string) { el.insertAdjacentHTML('beforeend', s); eval(s) }\n",
      'src/__lint_probe__.ts',
    )
    expect(messages.map((m) => m.ruleId)).toEqual(expect.arrayContaining(['no-restricted-syntax', 'no-eval']))
  })

  it('allows plain text rendering', async () => {
    const messages = await lint('export const A = ({ text }: { text: string }) => <p>{text}</p>\n')
    expect(messages).toHaveLength(0)
  })
})
