import * as crypto from 'crypto'
import { describe, expect, it, mock } from 'bun:test'
import { JwtError } from '../src/verify'

/** Test-only RSA private key (PKCS#1 PEM). Never leaves the test suite. */
export const testPrivateKeyPem = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwCUW5iVYsbgMBLCuT69+5sN+AoRAGNJQKs8ungALCrw6w0j9
Ow++6XVvmFfNWzL5w19REwD0NA+XD8c/QGDS3/T4yKVkrfpxNN3HvCjmR5WVtP9P
4hWwmGcSR1yVlJGg6HkQjhGBVtPk63pN74p0GjoAsnN41Y4NX3RDhOlOqK3apDZH
T7nxFoo2iBjm79TE/spmcRF0MSVZ1/gcWInjKEV4s8b5rehhI5sDzIRLst9mUKPM
hU2DkZgH+YtksLhfSc5b0vdoJcEBJozIRyTW40xXVl/GaZ/jonw2C+THuJ3OxL2S
vSNaK/Y9tUajBwI7F2o/JsoBhtRISmCS7emSVwIDAQABAoIBACWEGGB/Uj4A7XfM
93vfjCuKaAQdxlYSWkzBfxyibYV/EwomKitp+6ChqVRZcGMqJNIcvjuzp/qyQJB4
GsV7IjFQJ3Mlt+6wQ4JK+0Cly7CWaFCauQIvsfdPyKXeUeZcOMqrOKxEhrhpTv0b
ODRZGCo2wQQWv7USs1G75aMB2rXcRToXbIUR8iulLk/Re69phlTfAFKf/6h74sKZ
H0hOBkWKwl+DbGqvpBAxrXTnEXkD19Y4tLqVtzWTF/mv5zhBLW6rWbKGTBSzJ1g7
O4/dgwSwNu/jZcf1oCsK8+v983dmgE9nzFq7l9PHpKTo+8mkHE8oaWqg+lp+Eh89
lnFNnQECgYEA8L4sc2v3c1zCfmQYvoC3R9PuU1uYmKoucxMggWMKXTGT+hutXOfx
9egVCCDxdDGuW4IkNVjueZgve5E0k9XhWHS7sxwZDEXVgWyHDehBrUrZVR4/zMck
Zs7n9sLUvjJR5TzizQG1DoQTKDmP5pIny0NVNA+Ps74cSYQ0oRnpTyECgYEAzFJ1
kbL5pL7+qEaTVXhftvpCAKVFRpdMdpqr38B+1OCBezAIFpvyw0NpOJj/TuZ6Fods
4rsqvypB8gYSIuCYA2TxM4UsVMXEXaX27XHU8LvV7VSlqdzVHPFyLWGDSLeh8eUp
XJvSb4UBuZp9qhQGaVxuLgA2cWfhRpw+jooOincCgYAUfIp51AE9vvIKIWh9paRz
J1TLoSrOKwVC46jLeesi3RozmXFaS56qh3Jqu6rwcV3eCagdJhE9Jbc8s7Getv+z
MFPcvRJgmfy+Q8cGZvJX1dvCw404VuYBHbBdrly+RrfzYwgF3BRVROYAcU2OmHds
c7Fneb+H0zDDDM4Ru4vAIQKBgQCcP27DBa/c6WYKvzXKRaxEXCp/HePVMLx7cpp/
GFClcC30S23UBFvoMLPVYULUTnIMqnF9DY6J88HMWBIkc8YrylSdhni5NyeMSe+D
8unZUnss6+9n74VVhdo/k/N2d18zgYBY3pxVRcxk6ByzJG8mwVVMfkMkBEGE4tT/
4dluzwKBgH8raQDI0VLCdQ2sUQECRMeHMssz1UYU5JF0kzVbOWiIwV893veJeYL+
BCNgwSh1TnNy8vmNYtn8H+ExJanX9KO2nbPZYpbCTsY2DpVTosmFm25idtZ4BNNZ
o+YEWMPchT4D6uB5kkOzWDiUHUyk5SMTeAiayNxAB/bnG8mutVCf
-----END RSA PRIVATE KEY-----
`.trim()

/** Public JWK matching {@link testPrivateKeyPem}. */
export const testJwk = {
  kty: 'RSA',
  kid: 'static-key',
  use: 'sig',
  alg: 'RS256',
  n: 'wCUW5iVYsbgMBLCuT69-5sN-AoRAGNJQKs8ungALCrw6w0j9Ow--6XVvmFfNWzL5w19REwD0NA-XD8c_QGDS3_T4yKVkrfpxNN3HvCjmR5WVtP9P4hWwmGcSR1yVlJGg6HkQjhGBVtPk63pN74p0GjoAsnN41Y4NX3RDhOlOqK3apDZHT7nxFoo2iBjm79TE_spmcRF0MSVZ1_gcWInjKEV4s8b5rehhI5sDzIRLst9mUKPMhU2DkZgH-YtksLhfSc5b0vdoJcEBJozIRyTW40xXVl_GaZ_jonw2C-THuJ3OxL2SvSNaK_Y9tUajBwI7F2o_JsoBhtRISmCS7emSVw',
  e: 'AQAB',
} as const

export const testKid = 'static-key'

/** A reference to the runtime's native fetch, captured before any test may overwrite it. */
export const realFetch: typeof fetch = globalThis.fetch

/** Encodes a string or buffer as base64url (no padding). */
export function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

export interface SignedJwtOptions {
  kid?: string
  alg?: string
}

/**
 * Creates an RS256-signed JWT with the given payload using the test key.
 */
export function createSignedJwt(
  payload: object,
  privateKeyPem: string = testPrivateKeyPem,
  { kid = testKid, alg = 'RS256' }: SignedJwtOptions = {}
): string {
  const header = { alg, typ: 'JWT', kid }
  const encodedHeader = base64url(JSON.stringify(header))
  const encodedPayload = base64url(JSON.stringify(payload))
  const toSign = `${encodedHeader}.${encodedPayload}`
  const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs1' })
  const signature = crypto.createSign('RSA-SHA256').update(toSign).sign(privateKey)
  return `${toSign}.${base64url(signature)}`
}

/** Bun mock for {@link fetch}. */
export type FetchMock = ReturnType<typeof mock<() => Promise<Response>>>

/**
 * Installs a `global.fetch` mock serving the given JWKS key set.
 * @returns the fetch mock (inspect call args if needed)
 */
export function mockJwks(keys: unknown[]): FetchMock {
  const m = mock<() => Promise<Response>>(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ keys }),
    } as Response)
  )
  globalThis.fetch = m as unknown as typeof fetch
  return m
}

/**
 * Awaits a promise that must reject with a {@link JwtError} and returns it.
 */
export async function catchJwtError(promise: Promise<unknown>): Promise<JwtError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof JwtError) return error
    throw new Error(`Expected JwtError, got: ${error instanceof Error ? error.message : String(error)}`)
  }
  throw new Error('Expected verification to reject, but it resolved')
}

describe('catchJwtError helper', () => {
  it('re-throws when the promise rejects with a non-JwtError (Error instance)', async () => {
    await expect(catchJwtError(Promise.reject(new Error('boom')))).rejects.toThrow('Expected JwtError')
  })

  it('re-throws when the promise rejects with a non-JwtError primitive', async () => {
    await expect(catchJwtError(Promise.reject('raw string error'))).rejects.toThrow('raw string error')
  })

  it('throws when the promise resolves', async () => {
    await expect(catchJwtError(Promise.resolve('ok'))).rejects.toThrow('Expected verification to reject')
  })
})
