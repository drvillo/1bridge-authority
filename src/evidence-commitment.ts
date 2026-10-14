import { canonicalBytes } from './canonical.js'
import { decodeBase64Url, encodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'

declare const evidenceSaltBrand: unique symbol

export interface EvidenceSalt {
  readonly [evidenceSaltBrand]: true
}

const saltBytesByHandle = new WeakMap<EvidenceSalt, Uint8Array>()

function preimage(audienceId: string, valueBytes: Uint8Array, saltBytes: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(69 + valueBytes.length)
  bytes[0] = 0x04
  for (let index = 0; index < 32; index += 1) {
    bytes[index + 1] = Number.parseInt(audienceId.slice(index * 2, index * 2 + 2), 16)
  }
  bytes.set(saltBytes, 33)
  new DataView(bytes.buffer).setUint32(65, valueBytes.length, false)
  bytes.set(valueBytes, 69)
  return bytes
}

export function createEvidenceSalt(): EvidenceSalt {
  const saltBytes = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const handle = Object.freeze({}) as EvidenceSalt
  saltBytesByHandle.set(handle, saltBytes)
  return handle
}

export function exportEvidenceSalt(handle: EvidenceSalt): string {
  const saltBytes = saltBytesByHandle.get(handle)
  if (!saltBytes) throw new TypeError('Expected a live evidence salt handle')
  return encodeBase64Url(saltBytes)
}

export async function commitEvidence(audienceId: string, value: unknown, handle: EvidenceSalt): Promise<Hash> {
  if (!validHash(audienceId)) throw new TypeError('Expected 64 lowercase hexadecimal audience characters')
  const valueBytes = canonicalBytes(value)
  const saltBytes = saltBytesByHandle.get(handle)
  if (!saltBytes) throw new TypeError('Expected a live evidence salt handle')
  const bytes = preimage(audienceId, valueBytes, saltBytes)
  saltBytesByHandle.delete(handle)
  return sha256(bytes)
}

export async function verifyEvidenceOpening(
  audienceId: string, value: unknown, salt: string, commitment: Hash,
): Promise<boolean> {
  try {
    if (!validHash(audienceId) || !validHash(commitment)) return false
    const saltBytes = decodeBase64Url(salt, 32)
    if (saltBytes.length !== 32) return false
    const valueBytes = canonicalBytes(value)
    const bytes = preimage(audienceId, valueBytes, saltBytes)
    return await sha256(bytes) === commitment
  } catch {
    return false
  }
}
