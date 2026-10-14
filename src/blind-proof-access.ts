import { decodeBase64Url, encodeBase64Url } from './encoding.js'
import { sha256, type Hash } from './hash.js'
import { blindRsa, i2osp, os2ip } from './blind-rsa.js'

declare const proofAccessBlindStateBrand: unique symbol

export interface ProofAccessBlindState {
  readonly [proofAccessBlindStateBrand]: true
}

export interface ProofAccessToken {
  readonly preparedMessage: string
  readonly signature: string
}

const MODULUS_BYTES = 512
const RANDOM_BYTES = 32
const PSS_SALT_BYTES = 48
const MESSAGE_PREFIX = new TextEncoder().encode('1bridge.authority/v1/proof-access\n')
const NULLIFIER_PREFIX = new TextEncoder().encode('1bridge.authority/v1/proof-access-nullifier\n')
const PREPARED_BYTES = RANDOM_BYTES + MESSAGE_PREFIX.length + RANDOM_BYTES

interface PublicSnapshot {
  modulus: bigint
  exponent: bigint
}

interface BlindSnapshot extends PublicSnapshot {
  publicKey: CryptoKey
  inverse: bigint
  preparedMessage: Uint8Array
}

const publicKeys = new WeakMap<CryptoKey, PublicSnapshot>()
const blindStates = new WeakMap<ProofAccessBlindState, BlindSnapshot>()

function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

function snapshotKey(publicKey: CryptoKey): PublicSnapshot {
  const snapshot = publicKeys.get(publicKey)
  if (!snapshot || publicKey.type !== 'public' || !publicKey.extractable || publicKey.usages.length !== 1 || publicKey.usages[0] !== 'verify') {
    throw new TypeError('Expected imported proof-access public key')
  }
  const algorithm = publicKey.algorithm as RsaHashedKeyAlgorithm
  if (algorithm.name !== 'RSA-PSS' || algorithm.modulusLength !== 4096 || algorithm.hash.name !== 'SHA-384') {
    throw new TypeError('Expected RSA-PSS/SHA-384 key')
  }
  return snapshot
}

function snapshotToken(token: unknown): { preparedMessage: Uint8Array; signature: Uint8Array } {
  if (typeof token !== 'object' || token === null || Array.isArray(token)) throw new TypeError('Expected proof-access token')
  const descriptors = Object.getOwnPropertyDescriptors(token)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== 2 || !keys.includes('preparedMessage') || !keys.includes('signature')) throw new TypeError('Expected exact proof-access fields')
  const preparedText = descriptors.preparedMessage?.value
  const signatureText = descriptors.signature?.value
  const preparedMessage = decodeBase64Url(preparedText, PREPARED_BYTES)
  const signature = decodeBase64Url(signatureText, MODULUS_BYTES)
  if (preparedMessage.length !== PREPARED_BYTES || signature.length !== MODULUS_BYTES) throw new TypeError('Expected fixed-width proof-access fields')
  for (let index = 0; index < MESSAGE_PREFIX.length; index += 1) {
    if (preparedMessage[RANDOM_BYTES + index] !== MESSAGE_PREFIX[index]) throw new TypeError('Expected proof-access message profile')
  }
  return { preparedMessage, signature }
}

export async function importProofAccessPublicKey(spkiBase64url: string): Promise<CryptoKey> {
  const spki = decodeBase64Url(spkiBase64url, 1024)
  if (spki.length === 0) throw new TypeError('Expected public SPKI')
  const key = await globalThis.crypto.subtle.importKey('spki', new Uint8Array(spki), { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'])
  if (key.type !== 'public' || !key.extractable || key.usages.length !== 1 || key.usages[0] !== 'verify') throw new TypeError('Expected verify-only public key')
  const algorithm = key.algorithm as RsaHashedKeyAlgorithm
  if (algorithm.name !== 'RSA-PSS' || algorithm.modulusLength !== 4096 || algorithm.hash.name !== 'SHA-384') throw new TypeError('Expected RSA-4096/PSS/SHA-384 key')
  const exportedSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', key))
  if (encodeBase64Url(exportedSpki) !== spkiBase64url) throw new TypeError('Expected canonical SPKI')
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', key)
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') throw new TypeError('Expected RSA public parameters')
  const nBytes = decodeBase64Url(jwk.n, MODULUS_BYTES)
  const eBytes = decodeBase64Url(jwk.e, 3)
  if (nBytes.length !== MODULUS_BYTES || os2ip(nBytes).toString(2).length !== 4096 || os2ip(eBytes) !== 65537n) throw new TypeError('Expected RSA-4096/65537 key')
  publicKeys.set(key, { modulus: os2ip(nBytes), exponent: 65537n })
  return key
}

export async function blindProofAccess(publicKey: CryptoKey): Promise<{ blindedMessage: string; state: ProofAccessBlindState }> {
  const { modulus, exponent } = snapshotKey(publicKey)
  const prepared = new Uint8Array(PREPARED_BYTES)
  prepared.set(randomBytes(RANDOM_BYTES))
  prepared.set(MESSAGE_PREFIX, RANDOM_BYTES)
  prepared.set(randomBytes(RANDOM_BYTES), RANDOM_BYTES + MESSAGE_PREFIX.length)
  const salt = randomBytes(PSS_SALT_BYTES)
  const { blindedMessage, inverse } = await blindRsa(modulus, exponent, prepared, salt, () => randomBytes(MODULUS_BYTES))
  const state = Object.freeze({}) as ProofAccessBlindState
  blindStates.set(state, { publicKey, modulus, exponent, inverse, preparedMessage: prepared })
  return { blindedMessage: encodeBase64Url(blindedMessage), state }
}

export async function finalizeProofAccess(state: ProofAccessBlindState, blindSignature: string): Promise<ProofAccessToken> {
  const snapshot = blindStates.get(state)
  if (!snapshot) throw new TypeError('Expected live proof-access state')
  blindStates.delete(state)
  const bytes = decodeBase64Url(blindSignature, MODULUS_BYTES)
  if (bytes.length !== MODULUS_BYTES) throw new TypeError('Expected fixed-width blind signature')
  const representative = os2ip(bytes)
  if (representative === 0n || representative >= snapshot.modulus) throw new RangeError('Blind signature out of range')
  const unblinded = representative * snapshot.inverse % snapshot.modulus
  const token = Object.freeze({ preparedMessage: encodeBase64Url(snapshot.preparedMessage), signature: encodeBase64Url(i2osp(unblinded, MODULUS_BYTES)) })
  if (!await verifyProofAccess(token, snapshot.publicKey)) throw new TypeError('Invalid blind signature')
  return token
}

export async function verifyProofAccess(token: ProofAccessToken, publicKey: CryptoKey): Promise<boolean> {
  try {
    const { modulus } = snapshotKey(publicKey)
    const { preparedMessage, signature } = snapshotToken(token)
    if (os2ip(signature) >= modulus) return false
    return await globalThis.crypto.subtle.verify({ name: 'RSA-PSS', saltLength: PSS_SALT_BYTES }, publicKey, new Uint8Array(signature), new Uint8Array(preparedMessage))
  } catch {
    return false
  }
}

export async function proofAccessNullifier(token: ProofAccessToken): Promise<Hash> {
  const { preparedMessage } = snapshotToken(token)
  const preimage = new Uint8Array(NULLIFIER_PREFIX.length + preparedMessage.length)
  preimage.set(NULLIFIER_PREFIX)
  preimage.set(preparedMessage, NULLIFIER_PREFIX.length)
  return sha256(preimage)
}
