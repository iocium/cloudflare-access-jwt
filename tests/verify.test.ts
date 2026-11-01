import { afterAll, beforeEach, describe, expect, it, mock } from 'bun:test'
import { JwtError, verifyAccessJwt } from '../src/verify'
import {
  base64url,
  catchJwtError,
  createSignedJwt,
  mockJwks,
  realFetch,
  testJwk,
  testKid,
} from './helpers'

const team = 'mockteam'
const aud = 'myaud'
const now = Math.floor(Date.now() / 1000)

describe('verifyAccessJwt', () => {
  // Fresh JWKS mock per test so a test that swaps `global.fetch` never leaks state.
  beforeEach(() => {
    mockJwks([testJwk])
  })

  afterAll(() => {
    globalThis.fetch = realFetch
  })

  describe('input validation', () => {
    it('throws ERR_INVALID_TOKEN on missing token', async () => {
      // @ts-expect-error token is intentionally missing
      const error = await catchJwtError(verifyAccessJwt(undefined, { aud, team }))
      expect(error.code).toBe('ERR_INVALID_TOKEN')
    })

    it('throws ERR_INVALID_OPTIONS on missing options', async () => {
      // @ts-expect-error options are intentionally missing
      const error = await catchJwtError(verifyAccessJwt('abc.def.ghi'))
      expect(error.code).toBe('ERR_INVALID_OPTIONS')
    })

    it('throws ERR_INVALID_OPTIONS on missing aud', async () => {
      // @ts-expect-error aud is intentionally missing
      const error = await catchJwtError(verifyAccessJwt('abc.def.ghi', { team }))
      expect(error.code).toBe('ERR_INVALID_OPTIONS')
      expect(error.message).toMatch(/`aud`/)
    })

    it('throws ERR_INVALID_OPTIONS on missing team', async () => {
      // @ts-expect-error team is intentionally missing
      const error = await catchJwtError(verifyAccessJwt('abc.def.ghi', { aud }))
      expect(error.code).toBe('ERR_INVALID_OPTIONS')
      expect(error.message).toMatch(/`team`/)
    })

    it('throws ERR_MALFORMED_TOKEN on wrong segment count', async () => {
      const error = await catchJwtError(verifyAccessJwt('abc.def', { aud, team }))
      expect(error.code).toBe('ERR_MALFORMED_TOKEN')
    })
  })

  describe('header validation', () => {
    it('accepts an RS256 header', async () => {
      const token = createSignedJwt({ sub: 'user1', aud, iat: now, exp: now + 60 })
      const payload = await verifyAccessJwt(token, { aud, team })
      expect(payload.sub).toBe('user1')
    })

    for (const alg of ['HS256', 'none', 'ES256']) {
      it(`rejects non-RS256 alg ${alg} with ERR_UNSUPPORTED_ALG`, async () => {
        const token = createSignedJwt({ sub: 'user1', aud, iat: now, exp: now + 60 }, undefined, { alg })
        const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
        expect(error.code).toBe('ERR_UNSUPPORTED_ALG')
      })
    }

    it('rejects a missing alg header with ERR_UNSUPPORTED_ALG', async () => {
      // The alg check runs before signature verification, so the signature may be garbage.
      const header = base64url(JSON.stringify({ typ: 'JWT', kid: testKid }))
      const payload = base64url(JSON.stringify({ sub: 'user1', aud, iat: now, exp: now + 60 }))
      const error = await catchJwtError(verifyAccessJwt(`${header}.${payload}.sig`, { aud, team }))
      expect(error.code).toBe('ERR_UNSUPPORTED_ALG')
    })

    it('throws ERR_MALFORMED_TOKEN on missing kid', async () => {
      const header = base64url(JSON.stringify({ alg: 'RS256' }))
      const payload = base64url(JSON.stringify({ aud, exp: now + 60 }))
      const error = await catchJwtError(verifyAccessJwt(`${header}.${payload}.sig`, { aud, team }))
      expect(error.code).toBe('ERR_MALFORMED_TOKEN')
      expect(error.message).toMatch(/kid/)
    })

    it('throws ERR_MALFORMED_TOKEN on a non-base64url header segment', async () => {
      const error = await catchJwtError(verifyAccessJwt('!!!not-base64!!!.abc.sig', { aud, team }))
      expect(error.code).toBe('ERR_MALFORMED_TOKEN')
    })
  })

  describe('signature verification', () => {
    it('throws ERR_JWKS_FETCH_FAILED when the JWKS endpoint is unavailable', async () => {
      globalThis.fetch = mock<() => Promise<Response>>(() =>
        Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) } as Response)
      ) as unknown as typeof fetch

      const token = createSignedJwt({ aud, iat: now, exp: now + 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
      expect(error.code).toBe('ERR_JWKS_FETCH_FAILED')
      expect(error.message).toMatch(/503/)
    })

    it('throws ERR_JWKS_FETCH_FAILED on an unexpected JWKS response shape', async () => {
      globalThis.fetch = mock<() => Promise<Response>>(() =>
        Promise.resolve({ ok: true, json: () => Promise.resolve({ keys: 'nope' }) } as Response)
      ) as unknown as typeof fetch

      const token = createSignedJwt({ aud, iat: now, exp: now + 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
      expect(error.code).toBe('ERR_JWKS_FETCH_FAILED')
    })

    it('throws ERR_UNKNOWN_KID when the JWKS has no matching key', async () => {
      mockJwks([])

      const header = base64url(JSON.stringify({ alg: 'RS256', kid: 'missing' }))
      const payload = base64url(JSON.stringify({ aud, exp: now + 60 }))
      const error = await catchJwtError(verifyAccessJwt(`${header}.${payload}.sig`, { aud, team }))
      expect(error.code).toBe('ERR_UNKNOWN_KID')
    })

    it('throws ERR_INVALID_SIGNATURE when the signature does not verify', async () => {
      const originalCrypto = globalThis.crypto

      globalThis.crypto = {
        subtle: {
          importKey: mock(() => Promise.resolve({})),
          verify: mock(() => Promise.resolve(false)),
        },
      } as unknown as typeof crypto

      const token = createSignedJwt({ sub: 'fail-me', aud, iat: now, exp: now + 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
      expect(error.code).toBe('ERR_INVALID_SIGNATURE')

      globalThis.crypto = originalCrypto
    })

    it('throws ERR_CRYPTO_UNAVAILABLE when Web Crypto is missing', async () => {
      const originalCrypto = globalThis.crypto

      Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })

      const header = base64url(JSON.stringify({ alg: 'RS256', kid: testKid }))
      const payload = base64url(JSON.stringify({ aud, exp: 9999999999 }))
      const error = await catchJwtError(verifyAccessJwt(`${header}.${payload}.sig`, { aud, team }))
      expect(error.code).toBe('ERR_CRYPTO_UNAVAILABLE')

      Object.defineProperty(globalThis, 'crypto', { value: originalCrypto, configurable: true })
    })
  })

  describe('claim validation', () => {
    it('throws ERR_INVALID_AUDIENCE when aud does not match', async () => {
      const token = createSignedJwt({ aud: 'wrong', iat: now, exp: now + 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
      expect(error.code).toBe('ERR_INVALID_AUDIENCE')
    })

    it('throws ERR_TOKEN_EXPIRED for an expired token', async () => {
      const token = createSignedJwt({ aud, iat: now - 120, exp: now - 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team }))
      expect(error.code).toBe('ERR_TOKEN_EXPIRED')
    })

    it('accepts a token expired within clockSkewSeconds', async () => {
      const token = createSignedJwt({ aud, iat: now - 120, exp: now - 10 })
      const payload = await verifyAccessJwt(token, { aud, team, clockSkewSeconds: 30 })
      expect(payload.aud).toBe(aud)
    })

    it('rejects a token expired beyond clockSkewSeconds', async () => {
      const token = createSignedJwt({ aud, iat: now - 120, exp: now - 60 })
      const error = await catchJwtError(verifyAccessJwt(token, { aud, team, clockSkewSeconds: 30 }))
      expect(error.code).toBe('ERR_TOKEN_EXPIRED')
    })
  })

  describe('error shape', () => {
    it('always throws JwtError instances with a stable name and code', async () => {
      const error = await catchJwtError(verifyAccessJwt('not.a.jwt', { aud, team }))
      expect(error).toBeInstanceOf(Error)
      expect(error).toBeInstanceOf(JwtError)
      expect(error.name).toBe('JwtError')
      expect(typeof error.code).toBe('string')
    })
  })
})
