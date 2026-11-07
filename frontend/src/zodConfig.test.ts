import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import './zodConfig'

describe('zod configuration', () => {
  it('never compiles its checks, which the CSP would refuse', () => {
    expect(z.config().jitless).toBe(true)
  })
})
