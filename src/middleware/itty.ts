import type { ExecutionContext } from '@cloudflare/workers-types'
import { verifyAccessJwt } from '../verify'
import type { JwtPayload, VerifyAccessJwtOptions } from '../verify'
import { UNAUTHORIZED_BODY, WWW_AUTHENTICATE, extractBearerToken, logVerificationError } from './shared'

/** A Workers `Request` carrying the verified payload. */
type RequestWithJwt = Request & { jwt?: JwtPayload }

/**
 * itty-router route handler to verify Cloudflare Access JWTs.
 *
 * On success the decoded payload is attached to the request object as
 * `request.jwt`; on failure the client receives a generic 401 and details are
 * logged server-side.
 *
 * ```ts
 * app.get('/admin', async (request) => {
 *   const jwt = (request as RequestWithJwt).jwt
 *   ...
 * })
 * ```
 */
export function accessJwtMiddleware(options: VerifyAccessJwtOptions) {
  return async (request: Request, _env: unknown, _ctx: ExecutionContext): Promise<Response> => {
    const token = extractBearerToken(request.headers.get('Authorization'))
    if (!token) {
      logVerificationError(new Error('Missing or invalid Authorization header'))
      return new Response(UNAUTHORIZED_BODY, { status: 401, headers: { 'WWW-Authenticate': WWW_AUTHENTICATE } })
    }

    try {
      ;(request as RequestWithJwt).jwt = await verifyAccessJwt(token, options)
    } catch (error) {
      logVerificationError(error)
      return new Response(UNAUTHORIZED_BODY, { status: 401, headers: { 'WWW-Authenticate': WWW_AUTHENTICATE } })
    }
    return new Response(null, { status: 204 })
  }
}
