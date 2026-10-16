import { canonicalBytes, parseCanonical } from './canonical.js'
import { decodeBase64Url } from './encoding.js'
import { validHash, type Hash } from './hash.js'
import { verifyConsistency } from './history.js'
import { observerEvidenceSetDigest } from './observer-report.js'
import { registryCheckpointHash, verifyRegistryCheckpoint,
  type SignedRegistryCheckpoint } from './registry.js'
import { signRecord, signingKeyId, verifyRecord } from './signatures.js'

const PURPOSE = 'observer.registry-witness.v2'

export interface RegistryWitnessStatement {
  version: 2
  coverageScope: 'registry_append_only'
  registryCheckpointHash: Hash
  registryCheckpoint: SignedRegistryCheckpoint
  observerKeyId: Hash
  checkedAt: string
  unresolvedFindings: { count: number; digest: Hash | null }
}

export interface SignedRegistryWitness {
  statement: RegistryWitnessStatement
  signature: string
}

function exact(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Invalid witness record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Invalid witness record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) {
    throw new TypeError('Invalid witness fields')
  }
  const result: Record<string, unknown> = {}
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Invalid witness field')
    result[name] = descriptor.value
  }
  return result
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value
}

function statement(value: unknown): RegistryWitnessStatement {
  const fields = exact(value, ['version', 'coverageScope', 'registryCheckpointHash',
    'registryCheckpoint', 'observerKeyId', 'checkedAt', 'unresolvedFindings'])
  const findings = exact(fields.unresolvedFindings, ['count', 'digest'])
  const signed = exact(fields.registryCheckpoint, ['statement', 'signature'])
  if (fields.version !== 2 || fields.coverageScope !== 'registry_append_only'
    || !validHash(fields.registryCheckpointHash) || !validHash(fields.observerKeyId)
    || !timestamp(fields.checkedAt)
    || !Number.isSafeInteger(findings.count) || (findings.count as number) < 0
    || (findings.count === 0 ? findings.digest !== null : !validHash(findings.digest))
    || typeof signed.signature !== 'string'
    || decodeBase64Url(signed.signature, 64).length !== 64) {
    throw new TypeError('Invalid witness statement')
  }
  return { version: 2, coverageScope: 'registry_append_only',
    registryCheckpointHash: fields.registryCheckpointHash as Hash,
    registryCheckpoint: fields.registryCheckpoint as SignedRegistryCheckpoint,
    observerKeyId: fields.observerKeyId as Hash, checkedAt: fields.checkedAt,
    unresolvedFindings: findings as { count: number; digest: Hash | null } }
}

function snapshot<T>(value: T): T {
  const bytes = canonicalBytes(value)
  if (bytes.length > 16_384) throw new RangeError('Registry witness record exceeds byte limit')
  return parseCanonical(bytes) as T
}

function proofHashes(value: readonly Hash[]): Hash[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > 64 || Reflect.ownKeys(value).length !== value.length + 1) {
    throw new TypeError('Invalid registry consistency proof')
  }
  const copied: Hash[] = []
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')
      || !validHash(descriptor.value)) throw new TypeError('Invalid registry consistency proof')
    copied.push(descriptor.value)
  }
  return copied
}

async function extendsPrefix(oldHead: SignedRegistryCheckpoint, newHead: SignedRegistryCheckpoint,
  proof: readonly Hash[], publisherKey: CryptoKey): Promise<boolean> {
  if (!await verifyRegistryCheckpoint(oldHead, publisherKey)
    || !await verifyRegistryCheckpoint(newHead, publisherKey)) return false
  const oldSize = oldHead.statement.size
  const newSize = newHead.statement.size
  if (newSize < oldSize) return false
  if (newSize === oldSize) {
    const oldBytes = canonicalBytes(oldHead)
    const newBytes = canonicalBytes(newHead)
    return proof.length === 0 && oldBytes.length === newBytes.length
      && oldBytes.every((byte, index) => byte === newBytes[index])
  }
  return verifyConsistency(oldSize, newSize, oldHead.statement.root, newHead.statement.root, proof)
}

function findingHashes(value: readonly Hash[]): Hash[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > 10_000 || Reflect.ownKeys(value).length !== value.length + 1) {
    throw new TypeError('Invalid witness findings')
  }
  const copied: Hash[] = []
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    const hash = descriptor?.value
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') || !validHash(hash)
      || index > 0 && hash <= copied[index - 1]!) throw new TypeError('Invalid witness findings')
    copied.push(hash)
  }
  return copied
}

/** Sign only a publisher-authenticated registry prefix or an exact time refresh. */
export async function signRegistryWitness(oldHead: SignedRegistryCheckpoint,
  newHead: SignedRegistryCheckpoint, proof: readonly Hash[], findings: readonly Hash[],
  checkedAt: string, signer: CryptoKeyPair, publisherKey: CryptoKey): Promise<SignedRegistryWitness> {
  const oldCopy = snapshot(oldHead)
  const newCopy = snapshot(newHead)
  const path = proofHashes(proof)
  const hashes = findingHashes(findings)
  const observerPublicKey = signer.publicKey
  const observerPrivateKey = signer.privateKey
  const observerKeyId = await signingKeyId(observerPublicKey)
  if (!timestamp(checkedAt) || observerKeyId === await signingKeyId(publisherKey)
    || !await extendsPrefix(oldCopy, newCopy, path, publisherKey)) {
    throw new TypeError('Invalid registry witness target')
  }
  const body = statement({ version: 2, coverageScope: 'registry_append_only',
    registryCheckpointHash: await registryCheckpointHash(newCopy.statement),
    registryCheckpoint: newCopy, observerKeyId, checkedAt,
    unresolvedFindings: { count: hashes.length,
      digest: hashes.length === 0 ? null : await observerEvidenceSetDigest(hashes) } })
  const signature = await signRecord(PURPOSE, body, observerPrivateKey)
  if (!await verifyRecord(PURPOSE, body, signature, observerPublicKey)) {
    throw new TypeError('Observer signing pair does not match')
  }
  return { statement: body, signature }
}

/** Verify one exact witnessed target against a separately trusted earlier publisher head. */
export async function verifyRegistryWitness(value: SignedRegistryWitness,
  trustedOldHead: SignedRegistryCheckpoint, proof: readonly Hash[],
  observerKey: CryptoKey, publisherKey: CryptoKey): Promise<boolean> {
  try {
    const signed = exact(snapshot(value), ['statement', 'signature'])
    const oldCopy = snapshot(trustedOldHead)
    const path = proofHashes(proof)
    const body = statement(signed.statement)
    if (typeof signed.signature !== 'string' || decodeBase64Url(signed.signature, 64).length !== 64
      || body.observerKeyId !== await signingKeyId(observerKey)
      || body.observerKeyId === await signingKeyId(publisherKey)
      || body.registryCheckpointHash !== await registryCheckpointHash(body.registryCheckpoint.statement)
      || !await verifyRecord(PURPOSE, body, signed.signature, observerKey)) return false
    return await extendsPrefix(oldCopy, body.registryCheckpoint, path, publisherKey)
  } catch { return false }
}
