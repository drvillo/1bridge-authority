import { canonicalBytes, parseCanonical } from './canonical.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import { inclusionProof, merkleRoot, verifyInclusion } from './history.js'
import { registryCheckpointHash, verifyRegistryCheckpoint, type SignedRegistryCheckpoint } from './registry.js'
import type { RegistryReplaySnapshot } from './registry-replay.js'
import type { GovernanceReplaySnapshot } from './replay.js'
import { signRecord, signingKeyId, verifyRecord } from './signatures.js'

const PURPOSE = 'observer.aggregate'
const STATUS_PREFIX = new TextEncoder().encode('1bridge.authority/v1/aggregate-feed-status\n')

interface SetSummary { count: number; root: Hash | null }

export interface AggregateFeedStatus {
  feedId: Hash
  anchorPin: Hash
  checkpointHash: Hash | null
  status: 'verified' | 'pending'
}

export interface AggregateFeedStatusProof {
  status: AggregateFeedStatus
  index: number
  proof: Hash[]
}

export interface AggregateReportStatement {
  version: 1
  coverageScope: 'shared_registry'
  registryCheckpointHash: Hash
  registryCheckpoint: SignedRegistryCheckpoint
  observerKeyId: Hash
  checkedAt: string
  verifiedFeeds: SetSummary
  pendingFeeds: SetSummary
  unresolvedFindings: SetSummary
}

export interface SignedAggregateReport {
  statement: AggregateReportStatement
  signature: string
}

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected aggregate record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain aggregate record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError('Expected exact aggregate fields')
  }
  const copy: Record<string, unknown> = {}
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected aggregate data fields')
    copy[field] = descriptor.value
  }
  return copy
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}

function denseArray<T>(value: readonly T[], label: string): T[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || Reflect.ownKeys(value).length !== value.length + 1) {
    throw new TypeError(`Expected bounded dense ${label} array`)
  }
  const copied: T[] = []
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`Expected ${label} data entry`)
    }
    copied.push(descriptor.value)
  }
  return copied
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const date = new Date(value)
  return !Number.isNaN(date.getTime()) && date.toISOString() === value
}

function summary(value: unknown): SetSummary {
  const fields = exact(value, ['count', 'root'])
  if (!count(fields.count) || (fields.count === 0 ? fields.root !== null : !validHash(fields.root))) {
    throw new TypeError('Invalid aggregate set summary')
  }
  return fields as unknown as SetSummary
}

function signedHead(value: unknown): SignedRegistryCheckpoint {
  const fields = exact(value, ['statement', 'signature'])
  if (typeof fields.signature !== 'string' || decodeBase64Url(fields.signature, 64).length !== 64) {
    throw new TypeError('Invalid aggregate registry signature')
  }
  return parseCanonical(canonicalBytes(fields)) as unknown as SignedRegistryCheckpoint
}

function statement(value: unknown): AggregateReportStatement {
  const fields = exact(value, ['version', 'coverageScope', 'registryCheckpointHash', 'registryCheckpoint',
    'observerKeyId', 'checkedAt', 'verifiedFeeds', 'pendingFeeds', 'unresolvedFindings'])
  if (fields.version !== 1 || fields.coverageScope !== 'shared_registry'
    || !validHash(fields.registryCheckpointHash) || !validHash(fields.observerKeyId)
    || !timestamp(fields.checkedAt)) throw new TypeError('Invalid aggregate statement')
  return { version: 1, coverageScope: 'shared_registry', registryCheckpointHash: fields.registryCheckpointHash,
    registryCheckpoint: signedHead(fields.registryCheckpoint), observerKeyId: fields.observerKeyId,
    checkedAt: fields.checkedAt, verifiedFeeds: summary(fields.verifiedFeeds),
    pendingFeeds: summary(fields.pendingFeeds), unresolvedFindings: summary(fields.unresolvedFindings) }
}

async function statusHash(feedId: Hash, anchorPin: Hash,
  checkpointHash: Hash | null, status: 'verified' | 'pending'): Promise<Hash> {
  const body = canonicalBytes({ version: 1, status, feedId, anchorPin, checkpointHash })
  const bytes = new Uint8Array(STATUS_PREFIX.length + body.length)
  bytes.set(STATUS_PREFIX)
  bytes.set(body, STATUS_PREFIX.length)
  return sha256(bytes)
}

function hashBytes(hash: Hash): Uint8Array {
  if (!validHash(hash)) throw new TypeError('Invalid aggregate hash')
  return Uint8Array.from(hash.match(/../g)!, byte => Number.parseInt(byte, 16))
}

async function setSummary(hashes: readonly Hash[]): Promise<SetSummary> {
  if (hashes.length === 0) return { count: 0, root: null }
  return { count: hashes.length, root: await merkleRoot(hashes.map(hashBytes)) }
}

function feedStatus(value: unknown): AggregateFeedStatus {
  const fields = exact(value, ['feedId', 'anchorPin', 'checkpointHash', 'status'])
  if (!validHash(fields.feedId) || !validHash(fields.anchorPin)
    || (fields.checkpointHash !== null && !validHash(fields.checkpointHash))
    || (fields.status !== 'verified' && fields.status !== 'pending')
    || (fields.status === 'verified' && fields.checkpointHash === null)) {
    throw new TypeError('Invalid aggregate feed status')
  }
  return fields as unknown as AggregateFeedStatus
}

function coverageRows(registry: RegistryReplaySnapshot, verified: readonly GovernanceReplaySnapshot[]): {
  verifiedRows: AggregateFeedStatus[]; pendingRows: AggregateFeedStatus[]
} {
  const replay = exact(registry, ['size', 'checkpointHash', 'feeds'])
  if (!count(replay.size) || !validHash(replay.checkpointHash)) throw new TypeError('Invalid registry snapshot')
  const feeds = denseArray(replay.feeds as RegistryReplaySnapshot['feeds'], 'registry feed')
  const verifiedSnapshots = denseArray(verified, 'verified feed')
  const byId = new Map<Hash, RegistryReplaySnapshot['feeds'][number]>()
  for (const value of feeds) {
    const feed = exact(value, ['feedId', 'anchorPin', 'advertisedCheckpointHash', 'advertisedSize'])
    if (!validHash(feed.feedId) || !validHash(feed.anchorPin) || byId.has(feed.feedId)
      || (feed.advertisedCheckpointHash === null ? feed.advertisedSize !== null
        : !validHash(feed.advertisedCheckpointHash) || !count(feed.advertisedSize))) {
      throw new TypeError('Invalid aggregate registry feed')
    }
    byId.set(feed.feedId, feed as unknown as RegistryReplaySnapshot['feeds'][number])
  }
  const verifiedIds = new Set<Hash>()
  for (const value of verifiedSnapshots) {
    const snapshot = exact(value, ['feedId', 'anchorPin', 'size', 'checkpointHash', 'authorityRoot',
      'authorityRevision', 'authorityRevisionHash', 'policyEpoch', 'observerPolicyHash', 'actorHeads'])
    const feed = byId.get(snapshot.feedId as Hash)
    if (!feed || verifiedIds.has(snapshot.feedId as Hash)
      || feed.anchorPin !== snapshot.anchorPin || feed.advertisedCheckpointHash !== snapshot.checkpointHash
      || feed.advertisedSize !== snapshot.size) throw new TypeError('Verified feed differs from advertised head')
    verifiedIds.add(snapshot.feedId as Hash)
  }
  const verifiedRows: AggregateFeedStatus[] = []
  const pendingRows: AggregateFeedStatus[] = []
  for (const feed of [...byId.values()].sort((left, right) => left.feedId < right.feedId ? -1 : 1)) {
    const row = feedStatus({ feedId: feed.feedId, anchorPin: feed.anchorPin,
      checkpointHash: feed.advertisedCheckpointHash,
      status: verifiedIds.has(feed.feedId) ? 'verified' : 'pending' })
    if (row.status === 'verified') verifiedRows.push(row)
    else pendingRows.push(row)
  }
  return { verifiedRows, pendingRows }
}

async function statusLeaves(rows: readonly AggregateFeedStatus[]): Promise<Uint8Array[]> {
  const hashes = await Promise.all(rows.map(row => statusHash(row.feedId, row.anchorPin,
    row.checkpointHash, row.status)))
  return hashes.map(hashBytes)
}

/** Signs the observer's claimed verified subset; callers must supply real replay snapshots. */
export async function signAggregateReport(registry: RegistryReplaySnapshot,
  head: SignedRegistryCheckpoint, verified: readonly GovernanceReplaySnapshot[],
  findings: readonly Hash[], checkedAt: string, signer: CryptoKeyPair): Promise<SignedAggregateReport> {
  const replay = exact(registry, ['size', 'checkpointHash', 'feeds'])
  const signed = signedHead(head)
  const keys = exact(signer, ['publicKey', 'privateKey'])
  if (!count(replay.size) || !validHash(replay.checkpointHash)
    || replay.size !== signed.statement.size
    || replay.checkpointHash !== await registryCheckpointHash(signed.statement)
    || !timestamp(checkedAt) || !Array.isArray(replay.feeds)
    || !Array.isArray(verified) || !Array.isArray(findings)) {
    throw new TypeError('Aggregate input differs from registry checkpoint')
  }
  const findingHashes = denseArray(findings, 'finding')
  const { verifiedRows, pendingRows } = coverageRows(registry, verified)
  const sortedFindings = [...findingHashes].sort()
  if (sortedFindings.some((hash, index) => !validHash(hash)
    || (index > 0 && hash === sortedFindings[index - 1]))) {
    throw new TypeError('Expected unique aggregate findings')
  }
  const observerKeyId = await signingKeyId(keys.publicKey as CryptoKey)
  const body = statement({ version: 1, coverageScope: 'shared_registry',
    registryCheckpointHash: replay.checkpointHash, registryCheckpoint: signed, observerKeyId,
    checkedAt, verifiedFeeds: { count: verifiedRows.length, root: verifiedRows.length
      ? await merkleRoot(await statusLeaves(verifiedRows)) : null },
    pendingFeeds: { count: pendingRows.length, root: pendingRows.length
      ? await merkleRoot(await statusLeaves(pendingRows)) : null },
    unresolvedFindings: await setSummary(sortedFindings) })
  const signature = await signRecord(PURPOSE, body, keys.privateKey as CryptoKey)
  if (!await verifyRecord(PURPOSE, body, signature, keys.publicKey as CryptoKey)) {
    throw new TypeError('Aggregate signing pair mismatch')
  }
  return { statement: body, signature }
}

/** Builds a compact inclusion proof for one explicit status in the aggregate report. */
export async function aggregateFeedStatusProof(registry: RegistryReplaySnapshot,
  verified: readonly GovernanceReplaySnapshot[], feedId: Hash): Promise<AggregateFeedStatusProof> {
  if (!validHash(feedId)) throw new TypeError('Invalid feed ID')
  const { verifiedRows, pendingRows } = coverageRows(registry, verified)
  const rows = verifiedRows.some(row => row.feedId === feedId) ? verifiedRows : pendingRows
  const index = rows.findIndex(row => row.feedId === feedId)
  if (index < 0) throw new TypeError('Feed is absent from aggregate coverage')
  return { status: rows[index]!, index, proof: await inclusionProof(await statusLeaves(rows), index) }
}

/** Checks one report-committed feed status; registry membership still requires registry evidence. */
export async function verifyAggregateFeedStatus(report: SignedAggregateReport,
  statusProof: AggregateFeedStatusProof, observerKey: CryptoKey, publisherKey: CryptoKey,
  expectedRegistryHash: Hash, expectedFeedId: Hash, expectedAnchorPin: Hash): Promise<boolean> {
  try {
    if (!await verifyAggregateReport(report, observerKey, publisherKey, expectedRegistryHash)) return false
    const body = statement(report.statement)
    const proof = exact(statusProof, ['status', 'index', 'proof'])
    const row = feedStatus(proof.status)
    if (!validHash(expectedFeedId) || !validHash(expectedAnchorPin)
      || row.feedId !== expectedFeedId || row.anchorPin !== expectedAnchorPin) return false
    const set = row.status === 'verified' ? body.verifiedFeeds : body.pendingFeeds
    if (!count(proof.index) || proof.index >= set.count || !set.root) return false
    const leaf = hashBytes(await statusHash(row.feedId, row.anchorPin, row.checkpointHash, row.status))
    return verifyInclusion(leaf, proof.index, set.count, proof.proof as Hash[], set.root)
  } catch { return false }
}

/** Verifies attribution and exact scope; underlying feed replay requires the published evidence. */
export async function verifyAggregateReport(value: SignedAggregateReport, observerKey: CryptoKey,
  publisherKey: CryptoKey, expectedRegistryHash: Hash): Promise<boolean> {
  try {
    const signed = exact(value, ['statement', 'signature'])
    const body = statement(signed.statement)
    if (typeof signed.signature !== 'string' || decodeBase64Url(signed.signature, 64).length !== 64
      || !validHash(expectedRegistryHash) || body.registryCheckpointHash !== expectedRegistryHash
      || body.registryCheckpointHash !== await registryCheckpointHash(body.registryCheckpoint.statement)
      || body.observerKeyId !== await signingKeyId(observerKey)
      || !await verifyRegistryCheckpoint(body.registryCheckpoint, publisherKey)) return false
    return await verifyRecord(PURPOSE, body, signed.signature, observerKey)
  } catch { return false }
}
