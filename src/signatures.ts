import { canonicalBytes } from './canonical.js'
import { decodeBase64Url, encodeBase64Url } from './encoding.js'
import { sha256 } from './hash.js'

const KEY_MAX_BYTES = 1024
const SIGNATURE_BYTES = 64
const keyAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' }
const signatureAlgorithm = { name: 'ECDSA', hash: 'SHA-256' }
const purposePattern = /^[a-z][a-z0-9._-]{0,63}$/
const encoder = new TextEncoder()

function assertSigningKey(key: CryptoKey, type: 'public' | 'private'): void {
  if (!(key instanceof CryptoKey)) throw new TypeError('Expected native CryptoKey')
  const algorithm = key.algorithm as EcKeyAlgorithm
  const usage = type === 'public' ? 'verify' : 'sign'
  if (key.type !== type || algorithm.name !== 'ECDSA' || algorithm.namedCurve !== 'P-256') throw new TypeError('Expected ECDSA P-256 key profile')
  if (key.usages.length !== 1 || key.usages[0] !== usage) throw new TypeError('Expected signing key usage')
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(left.length + right.length)
  bytes.set(left)
  bytes.set(right, left.length)
  return bytes
}

function recordBytes(purpose: string, record: unknown): Uint8Array<ArrayBuffer> {
  if (typeof purpose !== 'string' || purpose.length > 64 || purposePattern.exec(purpose)?.[0] !== purpose) throw new TypeError('Expected ASCII signature purpose')
  return concatBytes(encoder.encode('1bridge.authority/v1\n' + purpose + '\n'), canonicalBytes(record))
}

function keyBytes(encoded: string): Uint8Array<ArrayBuffer> {
  const bytes = decodeBase64Url(encoded, KEY_MAX_BYTES)
  if (bytes.length === 0) throw new TypeError('Expected nonempty key encoding')
  return new Uint8Array(bytes)
}

export async function generateSigningKey(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify'])
}

export async function exportSigningPublicKey(key: CryptoKey): Promise<string> {
  assertSigningKey(key, 'public')
  const bytes = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', key))
  if (bytes.length > KEY_MAX_BYTES) throw new RangeError('Key exceeds byte limit')
  return encodeBase64Url(bytes)
}

export async function importSigningPublicKey(encoded: string): Promise<CryptoKey> {
  const bytes = keyBytes(encoded)
  const key = await globalThis.crypto.subtle.importKey('spki', bytes, keyAlgorithm, true, ['verify'])
  assertSigningKey(key, 'public')
  if (await exportSigningPublicKey(key) !== encoded) throw new TypeError('Expected canonical native SPKI')
  return key
}

export async function exportSigningPrivateKey(key: CryptoKey): Promise<string> {
  assertSigningKey(key, 'private')
  const bytes = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', key))
  if (bytes.length > KEY_MAX_BYTES) throw new RangeError('Key exceeds byte limit')
  return encodeBase64Url(bytes)
}

export async function importSigningPrivateKey(encoded: string): Promise<CryptoKey> {
  const bytes = keyBytes(encoded)
  const key = await globalThis.crypto.subtle.importKey('pkcs8', bytes, keyAlgorithm, true, ['sign'])
  assertSigningKey(key, 'private')
  return key
}

export async function signingKeyId(publicKey: CryptoKey): Promise<string> {
  const encoded = await exportSigningPublicKey(publicKey)
  return sha256(concatBytes(encoder.encode('1bridge.authority/v1/public-key\n'), keyBytes(encoded)))
}

export async function signRecord(purpose: string, record: unknown, privateKey: CryptoKey): Promise<string> {
  assertSigningKey(privateKey, 'private')
  const bytes = recordBytes(purpose, record)
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign(signatureAlgorithm, privateKey, bytes))
  if (signature.length !== SIGNATURE_BYTES) throw new TypeError('Expected fixed-width IEEE-P1363 signature')
  return encodeBase64Url(signature)
}

export async function verifyRecord(purpose: string, record: unknown, signature: string, publicKey: CryptoKey): Promise<boolean> {
  try {
    assertSigningKey(publicKey, 'public')
    const bytes = recordBytes(purpose, record)
    const decoded = decodeBase64Url(signature, SIGNATURE_BYTES)
    if (decoded.length !== SIGNATURE_BYTES) return false
    return await globalThis.crypto.subtle.verify(signatureAlgorithm, publicKey, new Uint8Array(decoded), bytes)
  } catch {
    return false
  }
}
