import { canonicalBytes } from './canonical.js'
import { decodeBase64Url, encodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'

const PREFIX = new TextEncoder().encode('1bridge.authority/v1/recipient-key\n')
const PUBLIC_KEY_PREFIX = 'v3.x25519.'
const CLAIM_FIELDS = ['version', 'workspaceId', 'membershipId', 'membershipKeyRowId', 'membershipKeyVersion', 'keySuite', 'keyId', 'publicKey']

export interface RecipientKeyClaim {
  version: 1
  workspaceId: Hash
  membershipId: Hash
  membershipKeyRowId: Hash
  membershipKeyVersion: number
  keySuite: 'x25519'
  keyId: string
  publicKey: string
}

function snapshotClaim(value: unknown): RecipientKeyClaim {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected recipient key claim')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain recipient key claim')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== CLAIM_FIELDS.length || keys.some(key => typeof key !== 'string' || !CLAIM_FIELDS.includes(key))) throw new TypeError('Expected exact recipient key claim fields')
  const snapshot: Record<string, unknown> = {}
  for (const name of CLAIM_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected recipient key claim data fields')
    snapshot[name] = descriptor.value
  }
  if (snapshot.version !== 1 || !validHash(snapshot.workspaceId) || !validHash(snapshot.membershipId)
    || !validHash(snapshot.membershipKeyRowId) || typeof snapshot.membershipKeyVersion !== 'number'
    || !Number.isSafeInteger(snapshot.membershipKeyVersion) || snapshot.membershipKeyVersion < 1
    || snapshot.keySuite !== 'x25519' || typeof snapshot.keyId !== 'string'
    || typeof snapshot.publicKey !== 'string' || !snapshot.publicKey.startsWith(PUBLIC_KEY_PREFIX)) throw new TypeError('Invalid recipient key claim')
  const raw = decodeBase64Url(snapshot.publicKey.slice(PUBLIC_KEY_PREFIX.length), 32)
  if (raw.length !== 32 || raw.every(byte => byte === 0)) throw new TypeError('Invalid X25519 public key')
  if (decodeBase64Url(snapshot.keyId, 32).length !== 32) throw new TypeError('Invalid X25519 fingerprint')
  return snapshot as unknown as RecipientKeyClaim
}

export async function recipientKeyClaimHash(claim: RecipientKeyClaim): Promise<Hash> {
  const snapshot = snapshotClaim(claim)
  const raw = decodeBase64Url(snapshot.publicKey.slice(PUBLIC_KEY_PREFIX.length), 32)
  const fingerprint = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(raw)))
  if (snapshot.keyId !== encodeBase64Url(fingerprint)) throw new TypeError('X25519 fingerprint mismatch')
  const body = canonicalBytes(snapshot)
  const bytes = new Uint8Array(PREFIX.length + body.length)
  bytes.set(PREFIX)
  bytes.set(body, PREFIX.length)
  return sha256(bytes)
}
