import { describe, expect, it } from 'bun:test'
import { extractBearerToken, UNAUTHORIZED_BODY, WWW_AUTHENTICATE } from '../src/middleware/shared'

describe('extractBearerToken', () => {
  it('returns null for missing input', () => {
    expect(extractBearerToken(undefined)).toBeNull()
    expect(extractBearerToken(null)).toBeNull()
  })

  it('returns null for non-Bearer values', () => {
    expect(extractBearerToken('Basic abc')).toBeNull()
    expect(extractBearerToken('')).toBeNull()
  })

  it('extracts the token from a Bearer string', () => {
    expect(extractBearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi')
  })

  it('extracts the first value when passed an array', () => {
    const headers = ['Bearer first', 'Bearer second', 'Other']
    expect(extractBearerToken(headers)).toBe('first')
  })

  it('returns null for an array whose first element is not a Bearer string', () => {
    expect(extractBearerToken(['Basic abc', 'Bearer def'])).toBeNull()
  })

  it('returns null when the token is only whitespace', () => {
    expect(extractBearerToken('Bearer   ')).toBeNull()
  })

  it('trims accidental whitespace from the token', () => {
    expect(extractBearerToken('Bearer   abc   ')).toBe('abc')
  })
})

describe('middleware response constants', () => {
  it('keeps the expected generic 401 body', () => {
    expect(UNAUTHORIZED_BODY).toBe('Unauthorized')
  })

  it('keeps the expected WWW-Authenticate scheme', () => {
    expect(WWW_AUTHENTICATE).toBe('Bearer')
  })
})
