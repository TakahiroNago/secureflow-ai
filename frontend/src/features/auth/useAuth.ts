import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '../../api/client'
import { fetchCurrentUser, login, logout, type CurrentUser } from './authApi'

const CURRENT_USER_KEY = ['auth', 'me'] as const

/**
 * The server decides who is logged in. null means "not logged in", and any other failure is treated
 * the same way, so protected screens are only shown after the server has confirmed the user.
 */
export function useCurrentUser() {
  return useQuery<CurrentUser | null>({
    queryKey: CURRENT_USER_KEY,
    queryFn: async () => {
      try {
        return await fetchCurrentUser()
      } catch (error) {
        if (error instanceof ApiError) {
          return null
        }
        throw error
      }
    },
    retry: false,
  })
}

export function useLogin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) => login(email, password),
    onSuccess: (user) => {
      queryClient.setQueryData(CURRENT_USER_KEY, user)
    },
  })
}

export function useLogout() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: logout,
    onSettled: () => {
      queryClient.setQueryData(CURRENT_USER_KEY, null)
    },
  })
}
