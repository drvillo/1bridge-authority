import { describe, expect, it, vi } from 'vitest'
import * as authority from '../src/index.js'

describe('canonical base64url codec', () => {
  it('exports the requested codecs', () => {
    expect(authority).toHaveProperty('encodeBase64Url')
    expect(authority).toHaveProperty('decodeBase64Url')
  })

  it.each([['', ''], ['f', 'Zg'], ['fo', 'Zm8'], ['foo', 'Zm9v'], ['foob', 'Zm9vYg'], ['fooba', 'Zm9vYmE'], ['foobar', 'Zm9vYmFy']])('encodes literal vector %s', (plain, encoded) => {
    const bytes = new TextEncoder().encode(plain)
    expect(authority.encodeBase64Url(bytes)).toBe(encoded)
    expect(authority.decodeBase64Url(encoded)).toEqual(bytes)
  })

  it('uses the URL alphabet for binary bytes', () => {
    expect(authority.encodeBase64Url(Uint8Array.of(255, 239, 0, 128))).toBe('_-8AgA')
    expect(authority.decodeBase64Url('_-8AgA')).toEqual(Uint8Array.of(255, 239, 0, 128))
    expect(authority.encodeBase64Url(Uint8Array.of(0, 1, 2, 253, 254, 255))).toBe('AAEC_f7_')
  })

  it('roundtrips a large binary buffer without argument spreading limits', () => {
    const bytes = Uint8Array.from({ length: 1024 * 1024 }, (_, index) => index % 256)
    expect(authority.decodeBase64Url(authority.encodeBase64Url(bytes))).toEqual(bytes)
  })

  it.each(['Zg=', 'Zg==', '+w', '/w', 'Z g', 'Zg\n', 'Zg\r', 'Zg\r\n', 'é', 'A', 'AAAAA', 'Zh', 'Zm9', '__', '_-8AgB'])('rejects malformed or ambiguous encoding %s', (encoded) => {
    expect(() => authority.decodeBase64Url(encoded)).toThrow()
  })

  it('rejects malformed encoder and decoder runtime types', () => {
    for (const value of [null, undefined, '', 1, {}, [], new Uint16Array([1]), new Uint8ClampedArray([1])]) {
      expect(() => authority.encodeBase64Url(value as Uint8Array)).toThrow()
    }
    for (const value of [null, undefined, 1, {}, [], new Uint8Array()]) {
      expect(() => authority.decodeBase64Url(value as string)).toThrow()
    }
  })

  it('accepts exact decoded-size limits and empty at zero', () => {
    expect(authority.decodeBase64Url('', 0)).toEqual(new Uint8Array())
    expect(authority.decodeBase64Url('AA', 1)).toEqual(Uint8Array.of(0))
    expect(authority.decodeBase64Url('AAA', 2)).toEqual(Uint8Array.of(0, 0))
    expect(authority.decodeBase64Url('AAAA', 3)).toEqual(Uint8Array.of(0, 0, 0))
    for (const [encoded, limit] of [['AA', 0], ['AAA', 1], ['AAAA', 2]] as const) {
      expect(() => authority.decodeBase64Url(encoded, limit)).toThrow()
    }
  })

  it.each([-1, -0.5, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1, null, '1', undefined])('rejects explicitly supplied invalid maximum %s', (limit) => {
    expect(() => authority.decodeBase64Url('', limit as number)).toThrow()
  })

  it('prebounds oversized input before native decoding or alphabet checks', () => {
    const decode = vi.spyOn(globalThis, 'atob')
    const alphabet = vi.spyOn(RegExp.prototype, 'test')
    try {
      expect(() => authority.decodeBase64Url('A'.repeat(1024 * 1024 * 2))).toThrow()
      expect(() => authority.decodeBase64Url('AA', 0)).toThrow()
      expect(decode).not.toHaveBeenCalled()
      expect(alphabet).not.toHaveBeenCalled()
    } finally {
      decode.mockRestore()
      alphabet.mockRestore()
    }
  })

  it('does not consume a caller-provided byte iterator', () => {
    const bytes = Uint8Array.of(255)
    const iterator = vi.fn(function* () { yield 0 })
    Object.defineProperty(bytes, Symbol.iterator, { value: iterator })
    expect(authority.encodeBase64Url(bytes)).toBe('_w')
    expect(iterator).not.toHaveBeenCalled()
  })
})
