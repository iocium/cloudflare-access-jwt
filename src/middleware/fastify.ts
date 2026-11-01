import type { FastifyReply, FastifyRequest } from 'fastify'
import { verifyAccessJwt } from '../verify'
import type { JwtPayload, VerifyAccessJwtOptions } from '../verify'
import { UNAUTHORIZED_BODY, WWW_AUTHENTICATE, extractBearerToken, logVerificationError } from './shared'

// Exposes a typed `request.jwt` to consumers once they import this module.
declare module 'fastify' {
  interface FastifyRequest {
    /** Set by {@link accessJwtMiddleware} after successful verification. */
    jwt?: JwtPayload
  }
}

/**
 * Fastify hook to verify Cloudflare Access JWTs.
 *
 * Register it as an `onRequest` hook (or use it as a handler). On success the
 * decoded payload is attached as `request.jwt`; on failure the client receives
 * a generic 401 and details are logged server-side.
 *
 * ```ts
 * app.addHook('onRequest', accessJwtMiddleware({ aud, team }))
 * ```
 */
export function accessJwtMiddleware(options: VerifyAccessJwtOptions) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const token = extractBearerToken(request.headers['authorization'])
    if (!token) {
      logVerificationError(new Error('Missing or invalid Authorization header'))
      reply.status(401).header('WWW-Authenticate', WWW_AUTHENTICATE).send(UNAUTHORIZED_BODY)
      return
    }

    try {
      request.jwt = await verifyAccessJwt(token, options)
    } catch (error) {
      logVerificationError(error)
      reply.status(401).header('WWW-Authenticate', WWW_AUTHENTICATE).send(UNAUTHORIZED_BODY)
    }
  }
}
