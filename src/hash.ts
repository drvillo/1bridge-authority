export type Hash = string

export function validHash(value: unknown): value is Hash {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

function encodeHash(bytes: Uint8Array): Hash {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function decodeHash(hash: Hash): Uint8Array {
  if (!validHash(hash)) throw new TypeError('Expected 64 lowercase hexadecimal characters')
  const bytes = new Uint8Array(32)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hash.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

export async function sha256(bytes: Uint8Array): Promise<Hash> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(bytes))
  return encodeHash(new Uint8Array(digest))
}

export async function hashLeaf(leaf: Uint8Array): Promise<Hash> {
  if (!(leaf instanceof Uint8Array)) throw new TypeError('Expected Uint8Array leaf bytes')
  const bytes = new Uint8Array(leaf.length + 1)
  bytes[0] = 0x00
  bytes.set(leaf, 1)
  return sha256(bytes)
}

export async function hashNode(left: Hash, right: Hash): Promise<Hash> {
  const bytes = new Uint8Array(65)
  bytes[0] = 0x01
  bytes.set(decodeHash(left), 1)
  bytes.set(decodeHash(right), 33)
  return sha256(bytes)
}
