import { z } from 'zod'
import { apiRequest } from '../../api/client'

const userSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string(),
  role: z.enum(['admin', 'member', 'auditor']),
  organization: z.object({ id: z.string(), name: z.string() }),
})

const userResponseSchema = z.object({ data: userSchema }).transform((response) => response.data)

export type CurrentUser = z.infer<typeof userSchema>

export function login(email: string, password: string): Promise<CurrentUser> {
  return apiRequest('POST', '/api/v1/auth/login', userResponseSchema, { email, password })
}

export async function logout(): Promise<void> {
  await apiRequest('POST', '/api/v1/auth/logout', z.undefined())
}

export function fetchCurrentUser(): Promise<CurrentUser> {
  return apiRequest('GET', '/api/v1/auth/me', userResponseSchema)
}
