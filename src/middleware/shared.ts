/**
 * Shared helpers for the framework middleware adapters.
 *
 * The public API is identical across frameworks: extract a Bearer token from
 * the Authorization header, verify it with {@link verifyAccessJwt}, attach the
 * payload to the request, and answer 401 without leaking error details.
 */

/** Generic 401 body. Specific failure reasons go to the server log, never the client. */
export const UNAUTHORIZED_BODY = 'Unauthorized'

/** Suggests Bearer authentication per RFC 6750 when the request is rejected. */
export const WWW_AUTHENTICATE = 'Bearer'

/**
 * Extracts the Bearer token from an Authorization header value.
 *
 * Accepts the shapes frameworks pass through (`string` in most, `string[]` in
 * Express for unusual multi-value headers).
 *
 * @returns The token, or `null` when the header is missing or not a Bearer token.
 */
export function extractBearerToken(header: string | string[] | null | undefined): string | null {
  const value = Array.isArray(header) ? header[0] : header
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) return null
  const token = value.slice('Bearer '.length).trim()
  return token.length > 0 ? token : null
}

/**
 * Records a verification failure on the server side.
 *
 * Middleware never sends these details to the client; this keeps them out of
 * application logs only if you override console.error in your runtime.
 */
export function logVerificationError(error: unknown): void {
  console.error('[cloudflare-access-jwt] token verification failed:', error)
}
