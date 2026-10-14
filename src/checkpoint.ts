import { canonicalBytes } from './canonical.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import { verifyConsistency } from './history.js'
import { signRecord, signingKeyId, verifyRecord } from './signatures.js'

const PURPOSE = 'history.checkpoint'
const ID_PREFIX = new TextEncoder().encode('1bridge.authority/v1/checkpoint-id\n')
const EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const STATEMENT_FIELDS = ['version', 'feedId', 'size', 'historyRoot', 'authorityRoot', 'policyEpoch', 'signerKeyId', 'previous'] as const
const SIGNED_FIELDS = ['statement', 'signature'] as const

export interface GovernanceCheckpoint {
  version: 1
  feedId: Hash
  size: number
  historyRoot: Hash
  authorityRoot: Hash
  policyEpoch: number
  signerKeyId: Hash
  previous: Hash | null
}

export interface SignedCheckpoint {
  statement: GovernanceCheckpoint
  signature: string
}

function dataFields(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected checkpoint object')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain checkpoint object')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError('Expected exact checkpoint fields')
  }
  const snapshot: Record<string, unknown> = {}
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected checkpoint data fields')
    snapshot[field] = descriptor.value
  }
  return snapshot
}

function validCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}

function snapshotStatement(value: unknown): GovernanceCheckpoint {
  const fields = dataFields(value, STATEMENT_FIELDS)
  if (fields.version !== 1 || !validHash(fields.feedId) || !validCount(fields.size)
    || !validHash(fields.historyRoot) || !validHash(fields.authorityRoot)
    || !validCount(fields.policyEpoch) || !validHash(fields.signerKeyId)) {
    throw new TypeError('Invalid checkpoint statement')
  }
  if (fields.size === 0) {
    if (fields.historyRoot !== EMPTY_ROOT || fields.previous !== null) throw new TypeError('Invalid empty checkpoint')
  } else if (!validHash(fields.previous)) {
    throw new TypeError('Expected predecessor hash')
  }
  return fields as unknown as GovernanceCheckpoint
}

function snapshotSignedCheckpoint(value: unknown): SignedCheckpoint {
  const fields = dataFields(value, SIGNED_FIELDS)
  const statement = snapshotStatement(fields.statement)
  const signature = fields.signature
  if (typeof signature !== 'string' || decodeBase64Url(signature, 64).length !== 64) {
    throw new TypeError('Expected canonical P-256 signature')
  }
  return { statement, signature }
}

function snapshotSigningPair(value: unknown): CryptoKeyPair {
  const fields = dataFields(value, ['publicKey', 'privateKey'])
  return fields as unknown as CryptoKeyPair
}

function snapshotProof(value: unknown): Hash[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > 54) {
    throw new TypeError('Expected bounded consistency proof')
  }
  if (Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError('Expected dense consistency proof')
  const proof: Hash[] = []
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !validHash(descriptor.value)) {
      throw new TypeError('Expected hash proof node')
    }
    proof.push(descriptor.value)
  }
  return proof
}

async function hashStatement(statement: GovernanceCheckpoint): Promise<Hash> {
  const body = canonicalBytes(statement)
  const bytes = new Uint8Array(ID_PREFIX.length + body.length)
  bytes.set(ID_PREFIX)
  bytes.set(body, ID_PREFIX.length)
  return sha256(bytes)
}

export async function checkpointHash(statement: GovernanceCheckpoint): Promise<Hash> {
  return hashStatement(snapshotStatement(statement))
}

export async function signCheckpoint(statement: GovernanceCheckpoint, keyPair: CryptoKeyPair): Promise<SignedCheckpoint> {
  const snapshot = snapshotStatement(statement)
  const keys = snapshotSigningPair(keyPair)
  if (snapshot.signerKeyId !== await signingKeyId(keys.publicKey)) throw new TypeError('Signer key ID does not match public key')
  const signature = await signRecord(PURPOSE, snapshot, keys.privateKey)
  if (!await verifyRecord(PURPOSE, snapshot, signature, keys.publicKey)) throw new TypeError('Signing key pair does not match')
  return { statement: snapshot, signature }
}

async function verifySnapshot(signed: SignedCheckpoint, trustedPublicKey: CryptoKey): Promise<boolean> {
  return signed.statement.signerKeyId === await signingKeyId(trustedPublicKey)
    && await verifyRecord(PURPOSE, signed.statement, signed.signature, trustedPublicKey)
}

export async function verifyCheckpoint(signed: SignedCheckpoint, trustedPublicKey: CryptoKey): Promise<boolean> {
  try {
    return await verifySnapshot(snapshotSignedCheckpoint(signed), trustedPublicKey)
  } catch {
    return false
  }
}

export async function verifyCheckpointExtension(
  oldSigned: SignedCheckpoint, newSigned: SignedCheckpoint, proof: readonly Hash[], trustedPublicKey: CryptoKey,
): Promise<boolean> {
  try {
    const oldHead = snapshotSignedCheckpoint(oldSigned)
    const newHead = snapshotSignedCheckpoint(newSigned)
    const path = snapshotProof(proof)
    const oldState = oldHead.statement
    const newState = newHead.statement
    if (oldState.feedId !== newState.feedId || oldState.signerKeyId !== newState.signerKeyId
      || newState.size <= oldState.size || newState.policyEpoch < oldState.policyEpoch) return false
    if (!await verifySnapshot(oldHead, trustedPublicKey) || !await verifySnapshot(newHead, trustedPublicKey)) return false
    if (newState.previous !== await hashStatement(oldState)) return false
    return await verifyConsistency(oldState.size, newState.size, oldState.historyRoot, newState.historyRoot, path)
  } catch {
    return false
  }
}
