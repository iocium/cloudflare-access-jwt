/**
 * @iocium/cloudflare-access-jwt
 *
 * Root entry point: Cloudflare Access JWT verification core.
 *
 * Framework adapters are separate entry points so users only pull in the
 * frameworks they actually use:
 *
 * - `@iocium/cloudflare-access-jwt/verify`
 * - `@iocium/cloudflare-access-jwt/middleware/hono`
 * - `@iocium/cloudflare-access-jwt/middleware/itty`
 * - `@iocium/cloudflare-access-jwt/middleware/express`
 * - `@iocium/cloudflare-access-jwt/middleware/fastify`
 */
export * from './verify'
