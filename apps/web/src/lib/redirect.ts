/**
 * A `?redirect=` target is only ever an in-app path. Anything that could leave the app (another
 * origin, a protocol-relative `//host`, a backslash that browsers read as a slash, a scheme) or that
 * would loop back into the login flow is dropped, so the login page cannot be turned into an open
 * redirect.
 */
export function safeRedirectPath(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  if (raw.length === 0 || raw.length > 512) return undefined;
  if (!raw.startsWith('/') || raw.startsWith('//')) return undefined;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return undefined;
  if (/^\/(login|register|2fa)(\/|\?|#|$)/.test(raw)) return undefined;
  return raw;
}
