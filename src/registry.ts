import { canonicalBytes, parseCanonical } from './canonical.js'
import type { SignedAuthorityAnchor } from './authority-lifecycle.js'
import type { SignedCheckpoint } from './checkpoint.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import { verifyConsistency } from './history.js'
import { signRecord, signingKeyId, verifyRecord } from './signatures.js'

const PURPOSE = 'registry.checkpoint'
const ID_PREFIX = new TextEncoder().encode('1bridge.authority/v1/registry-checkpoint-id\n')
const EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

export type RegistryEntry =
  | { version: 1; kind: 'feed_anchor'; index: number; feedId: Hash; anchorPin: Hash;
      signedAnchor: SignedAuthorityAnchor }
  | { version: 1; kind: 'feed_head'; index: number; feedId: Hash;
      signedCheckpoint: SignedCheckpoint }

export interface RegistryCheckpoint {
  version: 1
  size: number
  root: Hash
  signerKeyId: Hash
  previous: Hash | null
}

export interface SignedRegistryCheckpoint {
  statement: RegistryCheckpoint
  signature: string
}

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected registry record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain registry record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError('Expected exact registry fields')
  }
  const copy: Record<string, unknown> = {}
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected registry data fields')
    copy[field] = descriptor.value
  }
  return copy
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}

function signature(value: unknown): string {
  if (typeof value !== 'string' || decodeBase64Url(value, 64).length !== 64) {
    throw new TypeError('Expected registry signature')
  }
  return value
}

function entry(value: unknown): RegistryEntry {
  const kind = exact(value, ['version', 'kind', 'index', 'feedId',
    ...(value !== null && typeof value === 'object' && !Array.isArray(value)
      && Object.getOwnPropertyDescriptor(value, 'kind')?.value === 'feed_anchor'
      ? ['anchorPin', 'signedAnchor'] : ['signedCheckpoint'])])
  if (kind.version !== 1 || !count(kind.index) || !validHash(kind.feedId)) {
    throw new TypeError('Invalid registry entry identity')
  }
  if (kind.kind === 'feed_anchor') {
    if (!validHash(kind.anchorPin)) throw new TypeError('Invalid registry anchor pin')
    const signed = exact(kind.signedAnchor, ['anchor', 'rootSignature', 'recoverySignature'])
    const anchor = exact(signed.anchor, ['version', 'feedId', 'workspaceId', 'rootKeySpki', 'rootKeyId',
      'recoveryKeySpki', 'recoveryKeyId', 'checkpointKeySpki', 'checkpointKeyId', 'authorityRoot',
      'policyEpoch', 'observerPolicyHash'])
    if (anchor.feedId !== kind.feedId) throw new TypeError('Registry anchor feed mismatch')
    signature(signed.rootSignature)
    signature(signed.recoverySignature)
  } else if (kind.kind === 'feed_head') {
    const signed = exact(kind.signedCheckpoint, ['statement', 'signature'])
    const statement = exact(signed.statement, ['version', 'feedId', 'size', 'historyRoot', 'authorityRoot',
      'policyEpoch', 'signerKeyId', 'previous'])
    if (statement.feedId !== kind.feedId) throw new TypeError('Registry head feed mismatch')
    signature(signed.signature)
  } else throw new TypeError('Invalid registry entry kind')
  return parseCanonical(canonicalBytes(kind)) as unknown as RegistryEntry
}

export function registryEntryBytes(value: RegistryEntry): Uint8Array {
  return canonicalBytes(entry(value))
}

function checkpoint(value: unknown): RegistryCheckpoint {
  const fields = exact(value, ['version', 'size', 'root', 'signerKeyId', 'previous'])
  if (fields.version !== 1 || !count(fields.size) || !validHash(fields.root)
    || !validHash(fields.signerKeyId)) throw new TypeError('Invalid registry checkpoint')
  if (fields.size === 0) {
    if (fields.root !== EMPTY_ROOT || fields.previous !== null) throw new TypeError('Invalid empty registry checkpoint')
  } else if (!validHash(fields.previous)) throw new TypeError('Expected registry predecessor')
  return fields as unknown as RegistryCheckpoint
}

function signedCheckpoint(value: unknown): SignedRegistryCheckpoint {
  const fields = exact(value, ['statement', 'signature'])
  return { statement: checkpoint(fields.statement), signature: signature(fields.signature) }
}

export async function registryCheckpointHash(value: RegistryCheckpoint): Promise<Hash> {
  const body = canonicalBytes(checkpoint(value))
  const bytes = new Uint8Array(ID_PREFIX.length + body.length)
  bytes.set(ID_PREFIX)
  bytes.set(body, ID_PREFIX.length)
  return sha256(bytes)
}

export async function signRegistryCheckpoint(value: RegistryCheckpoint,
  pair: CryptoKeyPair): Promise<SignedRegistryCheckpoint> {
  const statement = checkpoint(value)
  const keys = exact(pair, ['publicKey', 'privateKey'])
  if (statement.signerKeyId !== await signingKeyId(keys.publicKey as CryptoKey)) {
    throw new TypeError('Registry signer key mismatch')
  }
  const signed = { statement, signature: await signRecord(PURPOSE, statement, keys.privateKey as CryptoKey) }
  if (!await verifyRecord(PURPOSE, statement, signed.signature, keys.publicKey as CryptoKey)) {
    throw new TypeError('Registry signing pair mismatch')
  }
  return signed
}

export async function verifyRegistryCheckpoint(value: SignedRegistryCheckpoint,
  trustedKey: CryptoKey): Promise<boolean> {
  try {
    const signed = signedCheckpoint(value)
    return signed.statement.signerKeyId === await signingKeyId(trustedKey)
      && await verifyRecord(PURPOSE, signed.statement, signed.signature, trustedKey)
  } catch { return false }
}

export async function verifyRegistryExtension(oldValue: SignedRegistryCheckpoint,
  newValue: SignedRegistryCheckpoint, proof: readonly Hash[], trustedKey: CryptoKey): Promise<boolean> {
  try {
    const oldHead = signedCheckpoint(oldValue)
    const newHead = signedCheckpoint(newValue)
    if (newHead.statement.size <= oldHead.statement.size
      || newHead.statement.signerKeyId !== oldHead.statement.signerKeyId
      || newHead.statement.previous !== await registryCheckpointHash(oldHead.statement)
      || !await verifyRegistryCheckpoint(oldHead, trustedKey)
      || !await verifyRegistryCheckpoint(newHead, trustedKey)) return false
    return await verifyConsistency(oldHead.statement.size, newHead.statement.size,
      oldHead.statement.root, newHead.statement.root, proof)
  } catch { return false }
}
