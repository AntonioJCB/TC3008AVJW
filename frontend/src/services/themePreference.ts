import type { SupabaseClient } from '@supabase/supabase-js'

export type Theme = 'dark' | 'light'

export function getThemePreference(metadata: Record<string, unknown> | undefined): Theme {
  return metadata?.portal_theme === 'light' ? 'light' : 'dark'
}

export async function saveThemePreference(auth: SupabaseClient['auth'], userId: string, theme: Theme): Promise<void> {
  const { data, error } = await auth.updateUser({ data: { portal_theme: theme } })
  if (error || data.user?.id !== userId || getThemePreference(data.user.user_metadata) !== theme) {
    throw new Error('No se pudo guardar el tema de tu cuenta.')
  }
}
