import type { NextFunction, Request, Response } from 'express'
import { verifyAccessJwt } from '../verify'
import type { JwtPayload, VerifyAccessJwtOptions } from '../verify'
import { UNAUTHORIZED_BODY, WWW_AUTHENTICATE, extractBearerToken, logVerificationError } from './shared'

// Exposes a typed `req.jwt` to consumers once they import this module.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- standard Express augmentation pattern
  namespace Express {
    interface Request {
      /** Set by {@link accessJwtMiddleware} after successful verification. */
      jwt?: JwtPayload
    }
  }
}

/**
 * Express middleware to verify Cloudflare Access JWTs.
 *
 * On success the decoded payload is attached as `req.jwt`.
 * On failure the client receives a generic 401; details are logged server-side.
 */
export function accessJwtMiddleware(options: VerifyAccessJwtOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const token = extractBearerToken(req.headers['authorization'])
    if (!token) {
      logVerificationError(new Error('Missing or invalid Authorization header'))
      res.status(401).set('WWW-Authenticate', WWW_AUTHENTICATE).send(UNAUTHORIZED_BODY)
      return
    }

    try {
      req.jwt = await verifyAccessJwt(token, options)
      next()
    } catch (error) {
      logVerificationError(error)
      res.status(401).set('WWW-Authenticate', WWW_AUTHENTICATE).send(UNAUTHORIZED_BODY)
    }
  }
}
