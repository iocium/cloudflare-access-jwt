import { afterAll, beforeAll, beforeEach, describe, expect, it, spyOn } from 'bun:test'
import { Hono } from 'hono'
import fastify, { FastifyInstance } from 'fastify'
import { accessJwtMiddleware as honoMiddleware, AccessJwtVariables } from '../src/middleware/hono'
import { accessJwtMiddleware as expressMiddleware } from '../src/middleware/express'
import { accessJwtMiddleware as fastifyMiddleware } from '../src/middleware/fastify'
import { accessJwtMiddleware as ittyMiddleware } from '../src/middleware/itty'
import { JwtPayload } from '../src/verify'
import { createSignedJwt, mockJwks, realFetch, testJwk } from './helpers'

const options = { aud: 'myaud', team: 'mockteam' }

// The middleware intentionally logs verification failures; keep test output focused.
let consoleErrorSpy: ReturnType<typeof spyOn<typeof console, 'error'>>

beforeAll(() => {
  consoleErrorSpy = spyOn(console, 'error').mockImplementation(() => {})
})

afterAll(() => {
  consoleErrorSpy.mockRestore()
})

/** Corrupts the signature of a valid token so signature verification fails. */
function withCorruptedSignature(token: string): string {
  // Flip the first character of the signature segment — always a meaningful bit
  // (the last character of a 256-byte signature can be padding-only bits).
  const [header, payload, signature] = token.split('.')
  const flipped = signature[0] === 'A' ? 'B' : 'A'
  return `${header}.${payload}.${flipped}${signature.slice(1)}`
}

describe('hono middleware', () => {
  beforeEach(() => {
    mockJwks([testJwk])
  })

  afterAll(() => {
    globalThis.fetch = realFetch
  })

  function buildApp() {
    const app = new Hono<{ Variables: AccessJwtVariables }>()
    app.use(honoMiddleware(options))
    app.get('/me', (c) => c.json({ sub: c.get('jwt')?.sub }))
    return app
  }

  it('returns 401 without an Authorization header', async () => {
    const res = await buildApp().request('/me')
    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('www-authenticate')).toBe('Bearer')
  })

  it('returns 401 for a non-Bearer scheme', async () => {
    const res = await buildApp().request('/me', { headers: { Authorization: 'Basic abc' } })
    expect(res.status).toBe(401)
  })

  it('returns 401 with a generic body when the signature is invalid', async () => {
    const token = withCorruptedSignature(createSignedJwt({ sub: 'user1', aud: options.aud, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 }))
    const res = await buildApp().request('/me', { headers: { Authorization: `Bearer ${token}` } })
    expect(res.status).toBe(401)
    const body = await res.text()
    expect(body).toBe('Unauthorized')
    expect(body).not.toMatch(/signature|JWKS|Invalid/i)
  })

  it('attaches the payload to the context on success', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 })
    const res = await buildApp().request('/me', { headers: { Authorization: `Bearer ${token}` } })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ sub: 'user1' })
  })
})

describe('express middleware', () => {
  beforeEach(() => {
    mockJwks([testJwk])
  })

  afterAll(() => {
    globalThis.fetch = realFetch
  })

  interface Harness {
    status?: number
    body?: string
    headers: Record<string, string>
    nextCalled: boolean
    jwt?: JwtPayload
  }

  async function run(handler: ReturnType<typeof expressMiddleware>, headers: Record<string, string>): Promise<Harness> {
    const result: Harness = { headers: {}, nextCalled: false }
    const req = { headers, jwt: undefined } as { headers: Record<string, string>; jwt?: JwtPayload }
    const res = {
      status(code: number) {
        result.status = code
        return res
      },
      set(name: string, value: string) {
        result.headers[name] = value
        return res
      },
      send(body: string) {
        result.body = body
        return res
      },
    }
    await handler(req as never, res as never, () => {
      result.nextCalled = true
    })
    result.jwt = req.jwt
    return result
  }

  it('returns 401 without an Authorization header', async () => {
    const handler = expressMiddleware(options)
    const result = await run(handler, {})
    expect(result.status).toBe(401)
    expect(result.body).toBe('Unauthorized')
    expect(result.headers['WWW-Authenticate']).toBe('Bearer')
    expect(result.nextCalled).toBe(false)
  })

  it('returns 401 with a generic body when the signature is invalid', async () => {
    const handler = expressMiddleware(options)
    const now = Math.floor(Date.now() / 1000)
    const token = withCorruptedSignature(createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 }))
    const result = await run(handler, { authorization: `Bearer ${token}` })
    expect(result.status).toBe(401)
    expect(result.body).toBe('Unauthorized')
    expect(result.nextCalled).toBe(false)
  })

  it('attaches the payload to the request and calls next on success', async () => {
    const handler = expressMiddleware(options)
    const now = Math.floor(Date.now() / 1000)
    const token = createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 })
    const result = await run(handler, { authorization: `Bearer ${token}` })
    expect(result.nextCalled).toBe(true)
    expect(result.jwt?.sub).toBe('user1')
  })
})

describe('fastify middleware', () => {
  beforeEach(() => {
    mockJwks([testJwk])
  })

  afterAll(async () => {
    globalThis.fetch = realFetch
  })

  function buildApp(): FastifyInstance {
    const app = fastify()
    app.addHook('onRequest', fastifyMiddleware(options))
    app.get('/me', async (req) => ({ sub: req.jwt?.sub }))
    return app
  }

  it('returns 401 without an Authorization header', async () => {
    const app = buildApp()
    const res = await app.inject({ url: '/me' })
    await app.close()
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe('Unauthorized')
    expect(res.headers['www-authenticate']).toBe('Bearer')
  })

  it('returns 401 with a generic body when the signature is invalid', async () => {
    const app = buildApp()
    const now = Math.floor(Date.now() / 1000)
    const token = withCorruptedSignature(createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 }))
    const res = await app.inject({ url: '/me', headers: { authorization: `Bearer ${token}` } })
    await app.close()
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe('Unauthorized')
    expect(res.body).not.toMatch(/signature|JWKS|Invalid/i)
  })

  it('attaches the payload to the request on success', async () => {
    const app = buildApp()
    const now = Math.floor(Date.now() / 1000)
    const token = createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 })
    const res = await app.inject({ url: '/me', headers: { authorization: `Bearer ${token}` } })
    await app.close()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ sub: 'user1' })
  })
})

describe('itty-router middleware', () => {
  beforeEach(() => {
    mockJwks([testJwk])
  })

  afterAll(() => {
    globalThis.fetch = realFetch
  })

  async function run(authorization: string | undefined) {
    const headers: Record<string, string> = {}
    if (authorization) headers.Authorization = authorization
    const request = new Request('https://example.com/admin', { headers })
    const handler = ittyMiddleware(options)
    const response = await handler(request, {}, undefined as never)
    return { request, response }
  }

  it('returns 401 without an Authorization header', async () => {
    const { response } = await run(undefined)
    expect(response.status).toBe(401)
    expect(await response.text()).toBe('Unauthorized')
    expect(response.headers.get('WWW-Authenticate')).toBe('Bearer')
  })

  it('returns 401 with a generic body when the signature is invalid', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = withCorruptedSignature(createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 }))
    const { response } = await run(`Bearer ${token}`)
    expect(response.status).toBe(401)
    expect(await response.text()).toBe('Unauthorized')
  })

  it('attaches the payload to the request on success', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = createSignedJwt({ sub: 'user1', aud: options.aud, iat: now, exp: now + 60 })
    const { request, response } = await run(`Bearer ${token}`)
    expect(response.status).toBe(204)
    expect((request as Request & { jwt?: JwtPayload }).jwt?.sub).toBe('user1')
  })
})
