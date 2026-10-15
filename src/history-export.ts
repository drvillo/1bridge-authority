import { type SignedAuthorityAnchor } from './authority-lifecycle.js'
import { parseCanonical } from './canonical.js'
import { checkpointHash, type SignedCheckpoint } from './checkpoint.js'
import { decodeBase64Url } from './encoding.js'
import { validHash, type Hash } from './hash.js'
import { createGovernanceReplaySession, type GovernanceReplaySnapshot } from './replay.js'

const MAX_LEAVES = 50_000
const MAX_ENCODED_BYTES = 64 * 1024 * 1024
const PAGE_LEAVES = 10

export interface GovernanceHistoryExport {
  version: 1
  signedAnchor: string
  leaves: readonly string[]
  checkpoints: readonly string[]
  advertisedCheckpointHash: Hash
}

export interface RetainedGovernanceCheckpoint {
  anchorPin: Hash
  signedCheckpoint: string
}

export interface VerifiedGovernanceHistoryExport extends GovernanceReplaySnapshot {
  retainedCheckpointHash: Hash
  signedCheckpoint: string
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('Expected plain history export record')
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some((key) => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError('Unexpected history export fields')
  }
  return value as Record<string, unknown>
}

function stringArray(value: unknown, maximum: number): string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) {
    throw new TypeError('Expected bounded dense history array')
  }
  const result: string[] = []
  for (let index = 0; index < value.length; index++) {
    const item = Object.getOwnPropertyDescriptor(value, String(index))?.value
    if (typeof item !== 'string') throw new TypeError('Expected encoded history item')
    result.push(item)
  }
  return result
}

/** Authenticate an exported prefix against a checkpoint the customer retained independently. */
export async function verifyGovernanceHistoryExport(
  independentlyRetained: unknown, exported: unknown,
): Promise<VerifiedGovernanceHistoryExport> {
  const trusted = exactRecord(independentlyRetained, ['anchorPin', 'signedCheckpoint'])
  const candidate = exactRecord(exported,
    ['version', 'signedAnchor', 'leaves', 'checkpoints', 'advertisedCheckpointHash'])
  if (candidate.version !== 1 || !validHash(trusted.anchorPin)
    || typeof trusted.signedCheckpoint !== 'string'
    || !validHash(candidate.advertisedCheckpointHash)
    || typeof candidate.signedAnchor !== 'string') {
    throw new TypeError('Invalid signed-history export header')
  }
  const leaves = stringArray(candidate.leaves, MAX_LEAVES)
  const checkpoints = stringArray(candidate.checkpoints, leaves.length + 1)
  if (checkpoints.length === 0) throw new TypeError('Signed genesis checkpoint is required')
  let encodedBytes = candidate.signedAnchor.length + trusted.signedCheckpoint.length
  for (const item of [...leaves, ...checkpoints]) {
    encodedBytes += item.length
    if (encodedBytes > MAX_ENCODED_BYTES) throw new RangeError('Signed-history export exceeds byte budget')
  }
  const anchor = parseCanonical(decodeBase64Url(candidate.signedAnchor, 32 * 1024)) as unknown as SignedAuthorityAnchor
  const retained = parseCanonical(decodeBase64Url(trusted.signedCheckpoint, 1024)) as unknown as SignedCheckpoint
  const heads = checkpoints.map((item) =>
    parseCanonical(decodeBase64Url(item, 1024)) as unknown as SignedCheckpoint)
  const session = await createGovernanceReplaySession(anchor, trusted.anchorPin as Hash, heads[0]!)
  let offset = 0
  for (const head of heads.slice(1)) {
    if (head.statement.size <= offset || head.statement.size > leaves.length) {
      throw new TypeError('Checkpoint skips or exceeds signed history')
    }
    while (offset < head.statement.size) {
      const next = Math.min(offset + PAGE_LEAVES, head.statement.size)
      await session.appendLeaves(leaves.slice(offset, next).map((item) => decodeBase64Url(item, 24 * 1024)), head)
      offset = next
    }
    await session.sealCheckpoint(head)
  }
  if (offset !== leaves.length) throw new TypeError('Unsealed signed-history tail')
  const snapshot = session.snapshot()
  if (snapshot.checkpointHash !== candidate.advertisedCheckpointHash) {
    throw new TypeError('Advertised head differs from verified history')
  }
  if (retained.statement.size > snapshot.size) throw new TypeError('Candidate is stale before retained checkpoint')
  if (!checkpoints.includes(trusted.signedCheckpoint)) {
    throw new TypeError('Independently retained checkpoint is missing from history')
  }
  return Object.freeze({ ...snapshot,
    retainedCheckpointHash: await checkpointHash(retained.statement),
    signedCheckpoint: checkpoints.at(-1)!,
  })
}
