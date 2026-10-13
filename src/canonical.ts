export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

const MAX_BYTES = 1024 * 1024
const MAX_DEPTH = 32
const encoder = new TextEncoder()

interface EncodingState {
  chunks: string[]
  bytes: number
  ancestors: Set<object>
}

function assertString(value: string): void {
  if (value.length > MAX_BYTES) throw new RangeError('Canonical JSON exceeds 1 MiB')
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('Lone UTF-16 surrogate')
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError('Lone UTF-16 surrogate')
    }
  }
}

function appendEncoded(fragment: string, state: EncodingState): void {
  state.bytes += encoder.encode(fragment).length
  if (state.bytes > MAX_BYTES) throw new RangeError('Canonical JSON exceeds 1 MiB')
  state.chunks.push(fragment)
}

function encodeArray(value: unknown[], depth: number, state: EncodingState): void {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError('Expected an ordinary array')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== value.length + 1) throw new TypeError('Expected dense array without extra properties')
  appendEncoded('[', state)
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected array data entries')
    if (index > 0) appendEncoded(',', state)
    encodeValue(descriptor.value, depth + 1, state)
  }
  appendEncoded(']', state)
}

function encodeObject(value: object, depth: number, state: EncodingState): void {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected a plain object')
  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key !== 'string')) throw new TypeError('Symbol keys are unsupported')
  const names = (keys as string[]).sort()
  appendEncoded('{', state)
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index]!
    assertString(name)
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected object data properties')
    if (index > 0) appendEncoded(',', state)
    appendEncoded(JSON.stringify(name) + ':', state)
    encodeValue(descriptor.value, depth + 1, state)
  }
  appendEncoded('}', state)
}

function encodeValue(value: unknown, depth: number, state: EncodingState): void {
  if (value === null || typeof value === 'boolean') {
    appendEncoded(String(value), state)
    return
  }
  if (typeof value === 'string') {
    assertString(value)
    appendEncoded(JSON.stringify(value), state)
    return
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError('Expected safe integer without negative zero')
    appendEncoded(String(value), state)
    return
  }
  if (typeof value !== 'object') throw new TypeError('Unsupported JSON value')
  if (depth >= MAX_DEPTH) throw new RangeError('Canonical JSON exceeds 32 nested containers')
  if (state.ancestors.has(value)) throw new TypeError('Cyclic JSON value')
  state.ancestors.add(value)
  if (Array.isArray(value)) encodeArray(value, depth, state)
  else encodeObject(value, depth, state)
  state.ancestors.delete(value)
}

export function canonicalJson(value: unknown): string {
  const state: EncodingState = { chunks: [], bytes: 0, ancestors: new Set() }
  encodeValue(value, 0, state)
  return state.chunks.join('')
}

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalJson(value))
}

function parseValue(serialized: string): JsonValue {
  assertString(serialized)
  if (encoder.encode(serialized).length > MAX_BYTES) throw new RangeError('Canonical JSON exceeds 1 MiB')
  const value: unknown = JSON.parse(serialized)
  if (canonicalJson(value) !== serialized) throw new TypeError('Expected exact canonical JSON')
  return value as JsonValue
}

export function parseCanonical(serialized: string | Uint8Array): JsonValue {
  if (typeof serialized === 'string') return parseValue(serialized)
  if (!(serialized instanceof Uint8Array)) throw new TypeError('Expected string or Uint8Array')
  if (serialized.length > MAX_BYTES) throw new RangeError('Canonical JSON exceeds 1 MiB')
  const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(serialized)
  const value = parseValue(decoded)
  const bytes = canonicalBytes(value)
  if (bytes.length !== serialized.length) throw new TypeError('Expected exact canonical UTF-8')
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== serialized[index]) throw new TypeError('Expected exact canonical UTF-8')
  }
  return value
}
