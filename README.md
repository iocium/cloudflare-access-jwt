# @iocium/cloudflare-access-jwt

> 🔐 JWT verification middleware for [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/), compatible with modern web frameworks.

Validate and extract Cloudflare Access JWTs using a single, consistent library across:

- ☁️ **Cloudflare Workers**
- 🧬 **Node.js APIs**
- 🧱 Frameworks: `hono`, `itty-router`, `express`, `fastify`

---

## 🚀 Installation

```bash
bun add @iocium/cloudflare-access-jwt
```

Framework adapters are separate entry points, so you only ever pull in the frameworks you actually use (`hono`, `express`, `fastify`, and `itty-router` are optional peer dependencies).

---

## ✨ Features

- ✅ Validates JWTs from Cloudflare Access using the public JWKS
- 🔒 Verifies algorithm (`RS256` only), signature (`kid`), audience (`aud`), and expiration (`exp`)
- 🏷️ Typed errors: every failure is a `JwtError` with a stable machine-readable `code`
- 💼 Compatible with serverless and traditional environments
- 🔧 Middlewares for `hono`, `itty-router`, `express`, and `fastify`
- 📄 Fully typed with TypeScript (typed `req.jwt` / `c.get('jwt')` where frameworks allow)

---

## 📦 Usage Example

Verify a token directly:

```ts
import { verifyAccessJwt } from '@iocium/cloudflare-access-jwt/verify'

const payload = await verifyAccessJwt(token, {
  aud: 'your-cloudflare-access-aud-uuid',
  team: 'your-team-name', // e.g. "iocium"
  clockSkewSeconds: 10, // optional tolerance for exp (default 0)
})
```

Or use middleware (each framework has its own entry point):

```ts
import { accessJwtMiddleware } from '@iocium/cloudflare-access-jwt/middleware/express'

app.use(accessJwtMiddleware({ aud: 'your-aud', team: 'your-team' }))
// after this, req.jwt is the verified JwtPayload
```

```ts
// hono
import { accessJwtMiddleware } from '@iocium/cloudflare-access-jwt/middleware/hono'

const app = new Hono()
app.use(accessJwtMiddleware({ aud, team }))
app.get('/me', (c) => c.json({ sub: c.get('jwt')?.sub }))
```

```ts
// fastify
import { accessJwtMiddleware } from '@iocium/cloudflare-access-jwt/middleware/fastify'

app.addHook('onRequest', accessJwtMiddleware({ aud, team }))
```

---

## 🔍 What is verified

In order:

1. Token and options are well-formed
2. The header uses the `RS256` algorithm and carries a `kid` — any other algorithm is rejected (verification is always pinned to RS256, never to the token's claimed algorithm)
3. The signature verifies against the key published at `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
4. The `aud` claim equals the expected audience
5. The `exp` claim has not passed (tolerating `clockSkewSeconds`)

---

## 🧯 Error handling

All failures throw a `JwtError` (an `Error` subclass) with a stable `code` you can branch on:

| Code | Meaning |
| --- | --- |
| `ERR_INVALID_TOKEN` | Token missing or not a string |
| `ERR_INVALID_OPTIONS` | Missing/invalid `aud` or `team` option |
| `ERR_MALFORMED_TOKEN` | Not three segments, or a segment is not base64url JSON, or missing `kid` |
| `ERR_UNSUPPORTED_ALG` | Header algorithm is not `RS256` |
| `ERR_CRYPTO_UNAVAILABLE` | Web Crypto API not available in this environment |
| `ERR_JWKS_FETCH_FAILED` | JWKS endpoint unreachable or returned an unexpected shape |
| `ERR_UNKNOWN_KID` | No published key matches the token's `kid` |
| `ERR_INVALID_SIGNATURE` | Signature did not verify |
| `ERR_INVALID_AUDIENCE` | `aud` does not match the expected audience |
| `ERR_TOKEN_EXPIRED` | `exp` has passed (beyond `clockSkewSeconds`) |

```ts
import { verifyAccessJwt, JwtError } from '@iocium/cloudflare-access-jwt/verify'

try {
  payload = await verifyAccessJwt(token, { aud, team })
} catch (error) {
  if (error instanceof JwtError && error.code === 'ERR_TOKEN_EXPIRED') {
    // redirect to login, ...
  }
  throw error
}
```

Middleware adapters never send these details to the client: rejected requests get a generic `401 Unauthorized` (with `WWW-Authenticate: Bearer`), and the real error is logged server-side via `console.error`.

---

## 📚 Documentation

- **API Docs** (generated with TypeDoc): [https://iocium.github.io/cloudflare-access-jwt](https://iocium.github.io/cloudflare-access-jwt)

---

## 🛡️ Security

This library uses Cloudflare's public JWKS endpoint to validate JWTs using `RS256` signatures. The algorithm is pinned server-side (never read from the token), tokens are never stored or logged, and middleware responses do not leak verification failure details.

---

## 🧑‍💻 Development

```bash
bun install
bun run lint        # eslint (flat config)
bun run typecheck   # tsc --noEmit (src + tests)
bun test            # bun test
bun run build       # tsup → dist/
```

CI (GitHub Actions) runs lint, typecheck, tests, and build using the latest Bun release.

---

## 📄 License

MIT © [iocium](https://github.com/iocium)
