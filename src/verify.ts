/**
 * Machine-readable error codes thrown by {@link verifyAccessJwt}.
 *
 * Use these to branch on the failure reason instead of matching
 * error message strings.
 */
export type JwtErrorCode =
  | 'ERR_INVALID_TOKEN'
  | 'ERR_INVALID_OPTIONS'
  | 'ERR_MALFORMED_TOKEN'
  | 'ERR_UNSUPPORTED_ALG'
  | 'ERR_CRYPTO_UNAVAILABLE'
  | 'ERR_JWKS_FETCH_FAILED'
  | 'ERR_UNKNOWN_KID'
  | 'ERR_INVALID_SIGNATURE'
  | 'ERR_INVALID_AUDIENCE'
  | 'ERR_TOKEN_EXPIRED'

/**
 * Error thrown for any JWT verification failure.
 *
 * Always an instance of {@link Error}; inspect {@link code} for a
 * stable, machine-readable reason.
 */
export class JwtError extends Error {
  /** Stable machine-readable reason for the failure. */
  readonly code: JwtErrorCode

  constructor(code: JwtErrorCode, message: string) {
    super(message)
    this.name = 'JwtError'
    this.code = code
  }
}

/**
 * Options for verifying a Cloudflare Access JWT.
 */
export interface VerifyAccessJwtOptions {
  /** The expected audience (AUD) value of the token */
  aud: string
  /** The Cloudflare Access team domain prefix (e.g., "iocium") */
  team: string
  /** Optional number of seconds to tolerate for clock skew on `exp` (default 0) */
  clockSkewSeconds?: number
}

/**
 * The payload of a successfully verified Cloudflare Access JWT.
 */
export interface JwtPayload {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  email?: string
  [key: string]: unknown
}

/**
 * An RSA signing key as published by the Cloudflare Access JWKS endpoint.
 */
export interface RsaJwk extends JsonWebKey {
  kty: 'RSA'
  /** Key ID, matched against the `kid` in the JWT header */
  kid: string
  use: 'sig'
  alg: 'RS256'
  /** Base64url-encoded modulus */
  n: string
  /** Base64url-encoded public exponent */
  e: string
}

// ---------------------------------------------------------------------------
// base64url helpers — the single decoding path for all JWT segments
// ---------------------------------------------------------------------------

/** Converts a base64url string to padded standard base64. */
function base64UrlToBase64(input: string): string {
  const pad = '='.repeat((4 - (input.length % 4)) % 4)
  return (input + pad).replace(/-/g, '+').replace(/_/g, '/')
}

/** Decodes a base64url string into raw bytes. */
function base64UrlToBytes(input: string): Uint8Array {
  const binary = atob(base64UrlToBase64(input))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

/** Decodes a base64url-encoded JSON segment; throws {@link JwtError} if malformed. */
function base64UrlToJson<T>(input: string): T {
  try {
    return JSON.parse(atob(base64UrlToBase64(input))) as T
  } catch {
    throw new JwtError('ERR_MALFORMED_TOKEN', 'Malformed JWT: segment is not valid base64url-encoded JSON')
  }
}

// ---------------------------------------------------------------------------
// token parsing
// ---------------------------------------------------------------------------

/** Minimal shape of the JWT header fields we rely on. */
interface JwtHeader {
  alg?: unknown
  kid?: unknown
  typ?: unknown
}

/**
 * Splits a JWT into its three base64url segments.
 * @throws {JwtError} `ERR_MALFORMED_TOKEN` if the token does not have exactly three segments.
 */
function parseJwt(token: string): readonly [string, string, string] {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new JwtError('ERR_MALFORMED_TOKEN', 'Invalid JWT format: expected three dot-separated segments')
  }
  return [parts[0], parts[1], parts[2]] as const
}

// ---------------------------------------------------------------------------
// JWKS + signature verification
// ---------------------------------------------------------------------------

/**
 * Returns the Web Crypto API instance.
 * @throws {JwtError} `ERR_CRYPTO_UNAVAILABLE` if Web Crypto is not available.
 */
function getCrypto(): Crypto {
  if (typeof crypto !== 'undefined' && crypto.subtle) return crypto
  throw new JwtError('ERR_CRYPTO_UNAVAILABLE', 'Web Crypto API not available')
}

/**
 * Fetches the JWKS for a Cloudflare Access team.
 * @throws {JwtError} `ERR_JWKS_FETCH_FAILED` if the request fails.
 */
async function fetchJwks(team: string): Promise<RsaJwk[]> {
  const res = await fetch(`https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`)
  if (!res.ok) {
    throw new JwtError('ERR_JWKS_FETCH_FAILED', `Failed to fetch JWKS: HTTP ${res.status}`)
  }
  const json = (await res.json()) as { keys?: unknown }
  if (!Array.isArray(json.keys)) {
    throw new JwtError('ERR_JWKS_FETCH_FAILED', 'Failed to fetch JWKS: unexpected response shape')
  }
  return json.keys as RsaJwk[]
}

/**
 * Verifies the token signature against the JWK matching `kid`.
 *
 * The algorithm is intentionally fixed to RS256 (RSASSA-PKCS1-v1_5 + SHA-256)
 * and never taken from the token header, which prevents algorithm-confusion
 * attacks.
 *
 * @throws {JwtError} `ERR_UNKNOWN_KID` if no published key matches `kid`.
 * @throws {JwtError} `ERR_INVALID_SIGNATURE` if the signature does not verify.
 */
async function verifySignature(
  headerB64: string,
  payloadB64: string,
  signatureB64: string,
  team: string,
  kid: string
): Promise<void> {
  const crypto = getCrypto()
  const keys = await fetchJwks(team)
  const jwk = keys.find((k) => k.kid === kid)
  if (!jwk) {
    throw new JwtError('ERR_UNKNOWN_KID', `No matching JWK found for KID "${kid}"`)
  }

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'verify',
  ])
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64UrlToBytes(signatureB64) as Uint8Array<ArrayBuffer>,
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  )
  if (!valid) {
    throw new JwtError('ERR_INVALID_SIGNATURE', 'Invalid JWT signature')
  }
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/**
 * Verifies a Cloudflare Access JWT.
 *
 * Performs the following checks, in order:
 * 1. Token and options are well-formed
 * 2. The token header uses the `RS256` algorithm and carries a `kid`
 * 3. The signature verifies against the key published by
 *    `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
 * 4. The `aud` claim equals the expected audience
 * 5. The `exp` claim has not passed (tolerating `clockSkewSeconds`)
 *
 * @param token - The JWT string to verify
 * @param options - Verification options including team and expected AUD
 * @returns The decoded payload if the token is valid
 * @throws {JwtError} with a stable {@link JwtErrorCode} on any failure
 */
export async function verifyAccessJwt(
  token: string,
  options: VerifyAccessJwtOptions
): Promise<JwtPayload> {
  // -- input validation -----------------------------------------------------
  if (!token || typeof token !== 'string') {
    throw new JwtError('ERR_INVALID_TOKEN', 'Missing or invalid JWT token')
  }
  if (!options || typeof options !== 'object') {
    throw new JwtError('ERR_INVALID_OPTIONS', 'Missing verification options')
  }

  const { aud, team, clockSkewSeconds = 0 } = options

  if (!aud || typeof aud !== 'string') {
    throw new JwtError('ERR_INVALID_OPTIONS', 'Missing required `aud` parameter')
  }
  if (!team || typeof team !== 'string') {
    throw new JwtError('ERR_INVALID_OPTIONS', 'Missing required `team` parameter')
  }

  // -- header ----------------------------------------------------------------
  const [headerB64, payloadB64, signatureB64] = parseJwt(token)
  const header = base64UrlToJson<JwtHeader>(headerB64)

  if (header.alg !== 'RS256') {
    throw new JwtError('ERR_UNSUPPORTED_ALG', `Unsupported JWT algorithm: ${String(header.alg)} (only RS256 is accepted)`)
  }
  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new JwtError('ERR_MALFORMED_TOKEN', 'Missing or invalid `kid` in JWT header')
  }

  // -- signature ---------------------------------------------------------------
  await verifySignature(headerB64, payloadB64, signatureB64, team, header.kid)

  // -- claims -------------------------------------------------------------------
  const payload = base64UrlToJson<JwtPayload>(payloadB64)

  if (payload.aud !== aud) {
    throw new JwtError('ERR_INVALID_AUDIENCE', 'Invalid audience')
  }

  const now = Math.floor(Date.now() / 1000)
  if (typeof payload.exp === 'number' && payload.exp < now - clockSkewSeconds) {
    throw new JwtError('ERR_TOKEN_EXPIRED', 'JWT has expired')
  }

  return payload
}
