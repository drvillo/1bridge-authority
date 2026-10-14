import { canonicalBytes, parseCanonical } from './canonical.js'
import { checkpointHash, type SignedCheckpoint } from './checkpoint.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import type { GovernanceReplaySnapshot } from './replay.js'
import { signRecord, signingKeyId, verifyRecord } from './signatures.js'

const PURPOSE = 'observer.coverage'
const SET_PREFIX = new TextEncoder().encode('1bridge.authority/v1/observer-evidence-set\n')
const FINDING_PREFIX = new TextEncoder().encode('1bridge.authority/v1/observer-finding-id\n')
const STATEMENT_FIELDS = ['version', 'coverageScope', 'feedId', 'anchorPin', 'observerKeyId',
  'coveredCheckpointHash', 'coveredCheckpoint', 'authorityRevision', 'authorityRevisionHash',
  'observerPolicyHash', 'checkedAt', 'knownReceipts', 'unresolvedFindings'] as const

export interface ObserverReportScope {
  anchorPin: Hash
  checkedAt: string
  knownReceipts: { kind: 'none' | 'known_archive'; count: number; digest: Hash | null }
  unresolvedFindings: { count: number; digest: Hash | null }
}

export interface ObserverReportStatement extends ObserverReportScope {
  version: 1
  coverageScope: 'verified_prefix'
  feedId: Hash
  observerKeyId: Hash
  coveredCheckpointHash: Hash
  coveredCheckpoint: SignedCheckpoint
  authorityRevision: number
  authorityRevisionHash: Hash
  observerPolicyHash: Hash | null
}

export interface SignedObserverReport {
  statement: ObserverReportStatement
  signature: string
}

function prefixed(prefix: Uint8Array, body: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(prefix.length + body.length)
  bytes.set(prefix)
  bytes.set(body, prefix.length)
  return bytes
}

/** Commits one nonempty sorted, duplicate-free set of independently known evidence IDs. */
export async function observerEvidenceSetDigest(hashes: readonly Hash[]): Promise<Hash> {
  if (!Array.isArray(hashes) || Object.getPrototypeOf(hashes) !== Array.prototype
    || hashes.length === 0 || hashes.length > 20_000
    || Reflect.ownKeys(hashes).length !== hashes.length + 1) {
    throw new TypeError('Expected nonempty sorted unique evidence hashes')
  }
  // Fixed-width ASCII hashes permit the same canonical JSON bytes beyond the general 1 MiB record limit.
  const body = new Uint8Array(hashes.length * 67 + 1)
  body[0] = 0x5b
  let offset = 1
  let previous: string | null = null
  for (let index = 0; index < hashes.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(hashes, String(index))
    const hash = descriptor?.value
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !validHash(hash)
      || (previous !== null && hash <= previous)) {
      throw new TypeError('Expected nonempty sorted unique evidence hashes')
    }
    if (index > 0) body[offset++] = 0x2c
    body[offset++] = 0x22
    for (let character = 0; character < 64; character++) body[offset++] = hash.charCodeAt(character)
    body[offset++] = 0x22
    previous = hash
  }
  body[offset++] = 0x5d
  if (offset !== body.length) throw new TypeError('Invalid evidence-set encoding')
  return sha256(prefixed(SET_PREFIX, body))
}

/** Identifies exact retained canonical finding evidence without trusting a database row ID. */
export async function observerFindingHash(evidence: Uint8Array): Promise<Hash> {
  if (!(evidence instanceof Uint8Array) || evidence.length === 0 || evidence.length > 16_384) {
    throw new TypeError('Expected bounded finding evidence')
  }
  const copied = new Uint8Array(evidence)
  const canonical = canonicalBytes(parseCanonical(copied))
  if (canonical.length !== copied.length || canonical.some((byte, index) => byte !== copied[index])) {
    throw new TypeError('Expected canonical finding evidence')
  }
  return sha256(prefixed(FINDING_PREFIX, copied))
}

function exact(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected plain report record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain report record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) {
    throw new TypeError('Expected exact report fields')
  }
  const copied: Record<string, unknown> = {}
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected report data fields')
    copied[name] = descriptor.value
  }
  return copied
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value
}

function scope(value: unknown): ObserverReportScope {
  const fields = exact(value, ['anchorPin', 'checkedAt', 'knownReceipts', 'unresolvedFindings'])
  if (!validHash(fields.anchorPin) || !timestamp(fields.checkedAt)) throw new TypeError('Invalid report scope')
  const receipts = exact(fields.knownReceipts, ['kind', 'count', 'digest'])
  const findings = exact(fields.unresolvedFindings, ['count', 'digest'])
  if (!count(receipts.count) || !count(findings.count)
    || (receipts.kind !== 'none' && receipts.kind !== 'known_archive')
    || (receipts.count === 0 ? receipts.digest !== null : !validHash(receipts.digest))
    || (findings.count === 0 ? findings.digest !== null : !validHash(findings.digest))
    || (receipts.kind === 'none' && receipts.count !== 0)) throw new TypeError('Invalid report evidence scope')
  return { anchorPin: fields.anchorPin, checkedAt: fields.checkedAt,
    knownReceipts: { kind: receipts.kind, count: receipts.count, digest: receipts.digest as Hash | null },
    unresolvedFindings: { count: findings.count, digest: findings.digest as Hash | null } }
}

function signedHead(value: unknown): SignedCheckpoint {
  const fields = exact(value, ['statement', 'signature'])
  if (typeof fields.signature !== 'string' || decodeBase64Url(fields.signature, 64).length !== 64) {
    throw new TypeError('Invalid signed report checkpoint')
  }
  const statement = parseCanonical(canonicalBytes(fields.statement)) as unknown as SignedCheckpoint['statement']
  return { statement, signature: fields.signature }
}

function statement(value: unknown): ObserverReportStatement {
  const fields = exact(value, STATEMENT_FIELDS)
  if (fields.version !== 1 || fields.coverageScope !== 'verified_prefix'
    || !validHash(fields.feedId) || !validHash(fields.observerKeyId)
    || !validHash(fields.coveredCheckpointHash) || !count(fields.authorityRevision)
    || !validHash(fields.authorityRevisionHash)
    || (fields.observerPolicyHash !== null && !validHash(fields.observerPolicyHash))) {
    throw new TypeError('Invalid observer report statement')
  }
  const reportScope = scope({ anchorPin: fields.anchorPin, checkedAt: fields.checkedAt,
    knownReceipts: fields.knownReceipts, unresolvedFindings: fields.unresolvedFindings })
  const coveredCheckpoint = signedHead(fields.coveredCheckpoint)
  if (coveredCheckpoint.statement.feedId !== fields.feedId) throw new TypeError('Report feed differs from checkpoint')
  return { version: 1, coverageScope: 'verified_prefix', feedId: fields.feedId,
    ...reportScope, observerKeyId: fields.observerKeyId,
    coveredCheckpointHash: fields.coveredCheckpointHash, coveredCheckpoint,
    authorityRevision: fields.authorityRevision, authorityRevisionHash: fields.authorityRevisionHash,
    observerPolicyHash: fields.observerPolicyHash } as ObserverReportStatement
}

/** Signs the exact replayed prefix; the observer's independent key must be pinned by each verifier. */
export async function signObserverReport(snapshot: GovernanceReplaySnapshot, head: SignedCheckpoint,
  evidenceScope: ObserverReportScope, signer: CryptoKeyPair): Promise<SignedObserverReport> {
  const replay = exact(snapshot, ['feedId', 'anchorPin', 'size', 'checkpointHash', 'authorityRoot', 'authorityRevision',
    'authorityRevisionHash', 'policyEpoch', 'observerPolicyHash', 'actorHeads'])
  const coveredCheckpoint = signedHead(head)
  const reportScope = scope(evidenceScope)
  const pair = exact(signer, ['publicKey', 'privateKey'])
  const hash = await checkpointHash(coveredCheckpoint.statement)
  if (hash !== replay.checkpointHash || coveredCheckpoint.statement.feedId !== replay.feedId
    || !validHash(replay.anchorPin) || reportScope.anchorPin !== replay.anchorPin
    || coveredCheckpoint.statement.size !== replay.size
    || coveredCheckpoint.statement.authorityRoot !== replay.authorityRoot
    || coveredCheckpoint.statement.policyEpoch !== replay.policyEpoch
    || !count(replay.authorityRevision) || !validHash(replay.authorityRevisionHash)
    || (replay.observerPolicyHash !== null && !validHash(replay.observerPolicyHash))) {
    throw new TypeError('Report checkpoint disagrees with replayed prefix')
  }
  const observerKeyId = await signingKeyId(pair.publicKey as CryptoKey)
  const body = statement({ version: 1, coverageScope: 'verified_prefix', feedId: replay.feedId,
    ...reportScope, observerKeyId, coveredCheckpointHash: hash, coveredCheckpoint,
    authorityRevision: replay.authorityRevision, authorityRevisionHash: replay.authorityRevisionHash,
    observerPolicyHash: replay.observerPolicyHash })
  const signature = await signRecord(PURPOSE, body, pair.privateKey as CryptoKey)
  if (!await verifyRecord(PURPOSE, body, signature, pair.publicKey as CryptoKey)) {
    throw new TypeError('Observer signing pair does not match')
  }
  return { statement: body, signature }
}

/** Verifies observer attribution and exact report syntax, not the underlying retained source history. */
export async function verifyObserverReport(signed: SignedObserverReport, trustedObserverKey: CryptoKey,
  expected: { feedId: Hash; anchorPin: Hash }): Promise<boolean> {
  try {
    const fields = exact(signed, ['statement', 'signature'])
    const body = statement(fields.statement)
    if (typeof fields.signature !== 'string' || decodeBase64Url(fields.signature, 64).length !== 64
      || !validHash(expected.feedId) || !validHash(expected.anchorPin)
      || body.feedId !== expected.feedId || body.anchorPin !== expected.anchorPin
      || body.coveredCheckpointHash !== await checkpointHash(body.coveredCheckpoint.statement)
      || body.observerKeyId !== await signingKeyId(trustedObserverKey)) return false
    return await verifyRecord(PURPOSE, body, fields.signature, trustedObserverKey)
  } catch { return false }
}
