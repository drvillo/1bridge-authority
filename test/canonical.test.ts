import { describe, expect, it, vi } from 'vitest'
import * as authority from '../src/index.js'

const MAX_BYTES = 1024 * 1024

function nestedArray(count: number): unknown {
  let value: unknown = null
  for (let index = 0; index < count; index += 1) value = [value]
  return value
}

describe('canonical JSON profile', () => {
  it('exports the canonical record functions', () => {
    for (const name of ['canonicalJson', 'canonicalBytes', 'parseCanonical']) expect(authority).toHaveProperty(name)
  })

  it('sorts keys into the literal canonical fixture', () => {
    expect(authority.canonicalJson({ b: 2, a: 'x' })).toBe('{"a":"x","b":2}')
    expect(authority.canonicalBytes({ b: 2, a: 'x' })).toEqual(new TextEncoder().encode('{"a":"x","b":2}'))
  })

  it('sorts keys by UTF-16 code units rather than code points', () => {
    expect(authority.canonicalJson({ '\ue000': 1, '🙂': 2, 'a': 3 })).toBe('{"a":3,"🙂":2,"\ue000":1}')
  })

  it('uses exact JSON string escaping and UTF-8', () => {
    const value = 'ñ🙂\u0000\b\t\n\f\r"\\'
    const expected = '"ñ🙂\\u0000\\b\\t\\n\\f\\r\\"\\\\"'
    expect(authority.canonicalJson(value)).toBe(expected)
    expect(authority.canonicalBytes(value)).toEqual(new TextEncoder().encode(expected))
  })

  it('encodes arrays, null, booleans and safe integer boundaries', () => {
    expect(authority.canonicalJson([null, true, false, 0, -1, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER])).toBe('[null,true,false,0,-1,-9007199254740991,9007199254740991]')
  })

  it.each([undefined, 1n, Symbol('x'), () => 1, NaN, Infinity, -Infinity, -0, 1.25, Number.MAX_SAFE_INTEGER + 1])('rejects unsupported primitive %s', (value) => {
    expect(() => authority.canonicalJson(value)).toThrow()
    expect(() => authority.canonicalJson({ value })).toThrow()
    expect(() => authority.canonicalJson([value])).toThrow()
  })

  it.each(['\ud800', '\udfff', 'a\ud800b', '\ud800\ud800', '\udc00\ud800'])('rejects lone UTF-16 surrogate %s', (value) => {
    expect(() => authority.canonicalJson(value)).toThrow()
    expect(() => authority.canonicalJson({ [value]: 1 })).toThrow()
  })

  it('accepts null-prototype objects and repeated noncyclic references', () => {
    const shared = Object.assign(Object.create(null), { x: 1 })
    expect(authority.canonicalJson({ b: shared, a: shared })).toBe('{"a":{"x":1},"b":{"x":1}}')
  })

  it('encodes own nonenumerable data properties without losing their values', () => {
    expect(authority.canonicalJson(Object.defineProperty({}, 'x', { value: 1 }))).toBe('{"x":1}')
  })

  it('rejects cyclic arrays and objects', () => {
    const object: { self?: unknown } = {}
    object.self = object
    const array: unknown[] = []
    array.push(array)
    for (const value of [object, array]) expect(() => authority.canonicalJson(value)).toThrow()
  })

  it('rejects custom object prototypes', () => {
    for (const value of [new Date(), new Map(), new Set(), new Number(1), new Uint8Array(), Object.create({ x: 1 })]) {
      expect(() => authority.canonicalJson(value)).toThrow()
    }
  })

  it('rejects accessors without calling a getter or toJSON', () => {
    const getter = vi.fn(() => 1)
    const toJSON = vi.fn(() => ({}))
    for (const value of [Object.defineProperty({}, 'x', { get: getter }), Object.defineProperty([1], '0', { get: getter }), { toJSON }]) {
      expect(() => authority.canonicalJson(value)).toThrow()
    }
    expect(getter).not.toHaveBeenCalled()
    expect(toJSON).not.toHaveBeenCalled()
  })

  it('rejects symbol keys on arrays and objects', () => {
    for (const value of [Object.assign({}, { [Symbol('hidden')]: 1 }), Object.assign([1], { [Symbol('hidden')]: 1 })]) {
      expect(() => authority.canonicalJson(value)).toThrow()
    }
  })

  it('rejects holes, extra properties and array custom iterators', () => {
    const iterator = vi.fn(function* () { yield 1 })
    const disguised = [undefined]
    Object.defineProperty(disguised, Symbol.iterator, { value: iterator })
    for (const value of [Array(1), Object.assign([1], { x: 2 }), Object.defineProperty([1], 'hidden', { value: 2 }), disguised, Object.setPrototypeOf([1], null)]) {
      expect(() => authority.canonicalJson(value)).toThrow()
    }
    expect(iterator).not.toHaveBeenCalled()
  })

  it('allows 32 nested containers and rejects the 33rd', () => {
    expect(authority.canonicalJson(nestedArray(32))).toBe('['.repeat(32) + 'null' + ']'.repeat(32))
    expect(() => authority.canonicalJson(nestedArray(33))).toThrow()
  })

  it('bounds the full UTF-8 serialization at exactly 1 MiB', () => {
    expect(authority.canonicalBytes('x'.repeat(MAX_BYTES - 2))).toHaveLength(MAX_BYTES)
    expect(() => authority.canonicalJson('x'.repeat(MAX_BYTES - 1))).toThrow()
    expect(() => authority.canonicalJson('ñ'.repeat(MAX_BYTES / 2))).toThrow()
    expect(() => authority.canonicalJson(['x'.repeat(MAX_BYTES / 2), 'x'.repeat(MAX_BYTES / 2)])).toThrow()
  })
})

describe('canonical parser', () => {
  it('accepts canonical strings and exact UTF-8 bytes', () => {
    const serialized = '{"a":"ñ🙂","b":[null,true,2]}'
    expect(authority.parseCanonical(serialized)).toEqual({ a: 'ñ🙂', b: [null, true, 2] })
    expect(authority.parseCanonical(new TextEncoder().encode(serialized))).toEqual({ a: 'ñ🙂', b: [null, true, 2] })
  })

  it.each(['{"b":2,"a":"x"}', '{"a":1,"a":1}', '{"a":1,"a":2}', 'null ', ' null', '\nnull', '"\\u0061"', '"\\/"', '1e0', '1.0', '-0', '1.5', '9007199254740992', '"\\ud800"', '\ufeffnull', '', '{'])('rejects noncanonical serialization %s', (serialized) => {
    expect(() => authority.parseCanonical(serialized)).toThrow()
    expect(() => authority.parseCanonical(new TextEncoder().encode(serialized))).toThrow()
  })

  it('rejects invalid UTF-8 and byte-order marks', () => {
    for (const bytes of [Uint8Array.of(0xc0, 0xaf), Uint8Array.of(0xff), Uint8Array.of(0x22, 0xed, 0xa0, 0x80, 0x22), Uint8Array.of(0xef, 0xbb, 0xbf, 0x6e, 0x75, 0x6c, 0x6c)]) {
      expect(() => authority.parseCanonical(bytes)).toThrow()
    }
  })

  it('rejects malformed runtime input types', () => {
    for (const value of [null, undefined, {}, 1, [], new Uint16Array([1])]) {
      expect(() => authority.parseCanonical(value as string)).toThrow()
    }
  })

  it('applies nesting and byte bounds to parsed input', () => {
    expect(() => authority.parseCanonical('['.repeat(33) + 'null' + ']'.repeat(33))).toThrow()
    expect(() => authority.parseCanonical('"' + 'x'.repeat(MAX_BYTES - 1) + '"')).toThrow()
    expect(() => authority.parseCanonical(new Uint8Array(MAX_BYTES + 1))).toThrow()
  })

  it('retains a literal __proto__ data key', () => {
    const value = authority.parseCanonical('{"__proto__":{"x":1}}')
    expect(Object.hasOwn(value as object, '__proto__')).toBe(true)
    expect(authority.canonicalJson(value)).toBe('{"__proto__":{"x":1}}')
  })
})
