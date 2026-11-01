import type { Context, Next } from 'hono'
import { verifyAccessJwt } from '../verify'
import type { JwtPayload, VerifyAccessJwtOptions } from '../verify'
import { UNAUTHORIZED_BODY, WWW_AUTHENTICATE, extractBearerToken, logVerificationError } from './shared'

/**
 * Context variables set by {@link accessJwtMiddleware}.
 * Type your app with them to get a typed `c.get('jwt')`:
 *
 * ```ts
 * const app = new Hono<{ Variables: AccessJwtVariables }>()
 * ```
 */
export type AccessJwtVariables = {
  jwt: JwtPayload
}

/** Hono `Env` shape combining the middleware variables with your own. */
export type AccessJwtEnv<V extends object = object> = { Variables: AccessJwtVariables & V }

/**
 * Hono middleware to verify Cloudflare Access JWTs.
 *
 * On success the decoded payload is available via `c.get('jwt')`.
 * On failure the client receives a generic 401; details are logged server-side.
 */
export function accessJwtMiddleware(options: VerifyAccessJwtOptions) {
  return async (c: Context, next: Next): Promise<Response> => {
    const token = extractBearerToken(c.req.header('Authorization'))
    if (!token) {
      logVerificationError(new Error('Missing or invalid Authorization header'))
      c.header('WWW-Authenticate', WWW_AUTHENTICATE)
      return c.text(UNAUTHORIZED_BODY, 401)
    }

    try {
      c.set('jwt', await verifyAccessJwt(token, options))
      await next()
    } catch (error) {
      logVerificationError(error)
      c.header('WWW-Authenticate', WWW_AUTHENTICATE)
      return c.text(UNAUTHORIZED_BODY, 401)
    }
    return c.res
  }
}
