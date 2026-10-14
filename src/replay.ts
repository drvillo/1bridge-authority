import { governanceActionHash, governanceCompletionLeaf, snapshotSignedAction, verifyGovernanceAction } from './action.js'
import { applyAuthorityRevision, authorityRevisionLeaf, authorityStateSnapshot, verifyAuthorityAnchor,
  type SignedAuthorityAnchor, type SignedAuthorityRevision } from './authority-lifecycle.js'
import { canonicalBytes, parseCanonical } from './canonical.js'
import { checkpointHash, verifyCheckpoint, type SignedCheckpoint } from './checkpoint.js'
import { snapshotCompletionReceipt, verifyReceiptInclusion, type CompletionReceipt } from './completion-receipt.js'
import { validHash, type Hash } from './hash.js'
import { appendHistory, emptyHistoryFrontier, historyFrontierRoot } from './history-frontier.js'
import { importSigningPublicKey } from './signatures.js'

const MAX_LEAVES = 10_000
const MAX_TOTAL_BYTES = 32 * 1024 * 1024
const MAX_LEAF_BYTES = 24 * 1024
const MAX_CHECKPOINT_BYTES = 1024
const MAX_PAGE_LEAVES = 64
const MAX_PAGE_BYTES = 256 * 1024

export interface GovernanceReplaySnapshot {
  feedId: Hash
  anchorPin: Hash
  size: number
  checkpointHash: Hash
  authorityRoot: Hash
  authorityRevision: number
  authorityRevisionHash: Hash
  policyEpoch: number
  observerPolicyHash: Hash | null
  actorHeads: ReadonlyArray<Readonly<{ actorKeyId: Hash; actionHash: Hash }>>
}

interface AcceptedAction { actionHash: Hash; leafIndex: number; operationId: Hash; effectCommitment: Hash; leaf: Uint8Array }
interface AcceptedCheckpoint { signed: SignedCheckpoint; position: number }
type AcceptedMeta = Omit<GovernanceReplaySnapshot, 'actorHeads'>

export interface GovernanceReplaySession {
  appendLeaves(leaves: readonly Uint8Array[], nextCheckpoint: SignedCheckpoint): Promise<void>
  sealCheckpoint(nextCheckpoint: SignedCheckpoint): Promise<void>
  verifyReceipt(receipt: CompletionReceipt, leafBytes: Uint8Array): Promise<boolean>
  snapshot(): GovernanceReplaySnapshot
}

function denseArray(value: unknown, limit: number, label: string): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > limit
    || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError(`Expected bounded dense ${label} array`)
  const entries: unknown[] = []
  for (let index = 0; index < value.length; index++) {
    const field = Object.getOwnPropertyDescriptor(value, String(index))
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) throw new TypeError(`Expected ${label} data entry ${index}`)
    entries.push(field.value)
  }
  return entries
}

function snapshotInput(anchor: SignedAuthorityAnchor, leaves: readonly Uint8Array[], checkpoints: readonly SignedCheckpoint[]) {
  const anchorBytes = canonicalBytes(anchor)
  if (anchorBytes.length > 32 * 1024) throw new RangeError('Anchor exceeds 32 KiB')
  const signedAnchor = parseCanonical(anchorBytes) as unknown as SignedAuthorityAnchor
  const sourceLeaves = denseArray(leaves, MAX_LEAVES, 'leaf')
  const sourceHeads = denseArray(checkpoints, MAX_LEAVES + 1, 'checkpoint')
  if (sourceHeads.length === 0) throw new TypeError('Signed genesis checkpoint is required')
  let totalBytes = anchorBytes.length
  const retainedLeaves = sourceLeaves.map((entry, index) => {
    if (!(entry instanceof Uint8Array) || Object.getPrototypeOf(entry) !== Uint8Array.prototype
      || entry.length > MAX_LEAF_BYTES) throw new TypeError(`Invalid leaf ${index}`)
    totalBytes += entry.length
    if (totalBytes > MAX_TOTAL_BYTES) throw new RangeError('Replay input exceeds 32 MiB')
    return new Uint8Array(entry)
  })
  const signedCheckpoints = sourceHeads.map((entry, index) => {
    const bytes = canonicalBytes(entry)
    if (bytes.length > MAX_CHECKPOINT_BYTES) throw new RangeError(`Checkpoint ${index} exceeds 1 KiB`)
    totalBytes += bytes.length
    if (totalBytes > MAX_TOTAL_BYTES) throw new RangeError('Replay input exceeds 32 MiB')
    return parseCanonical(bytes) as unknown as SignedCheckpoint
  })
  return { signedAnchor, retainedLeaves, signedCheckpoints }
}

function exactLeaf(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('Expected canonical leaf record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError('Unexpected governance leaf fields')
  }
  return value as Record<string, unknown>
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

async function snapshotCheckpoint(value: SignedCheckpoint): Promise<{ signed: SignedCheckpoint; bytes: Uint8Array; hash: Hash }> {
  const bytes = canonicalBytes(value)
  if (bytes.length > MAX_CHECKPOINT_BYTES) throw new RangeError('Checkpoint exceeds 1 KiB')
  const signed = parseCanonical(bytes) as unknown as SignedCheckpoint
  return { signed, bytes, hash: await checkpointHash(signed.statement) }
}

function acceptedMeta(authority: Awaited<ReturnType<typeof verifyAuthorityAnchor>>,
  size: number, headHash: Hash, anchorPin: Hash): AcceptedMeta {
  const final = authorityStateSnapshot(authority)
  return Object.freeze({ feedId: final.feedId, anchorPin, size,
    checkpointHash: headHash, authorityRoot: final.authorityRoot,
    authorityRevision: final.revision, authorityRevisionHash: final.revisionHash,
    policyEpoch: final.policyEpoch, observerPolicyHash: final.observerPolicyHash })
}

class ReplaySession implements GovernanceReplaySession {
  #authority: Awaited<ReturnType<typeof verifyAuthorityAnchor>>
  #frontier = emptyHistoryFrontier()
  #acceptedHeads: Map<Hash, AcceptedCheckpoint>
  #actors = new Map<Hash, AcceptedAction>()
  #tentativeActors = new Map<Hash, AcceptedAction>()
  #operations = new Set<Hash>()
  #accepted: AcceptedMeta
  #snapshotCache: GovernanceReplaySnapshot | null = null
  #target: { signed: SignedCheckpoint; bytes: Uint8Array; hash: Hash } | null = null
  #failed = false
  #busy = false

  constructor(authority: Awaited<ReturnType<typeof verifyAuthorityAnchor>>, genesis: SignedCheckpoint,
    genesisHash: Hash, initial: AcceptedMeta) {
    this.#authority = authority
    this.#acceptedHeads = new Map([[genesisHash, { signed: genesis, position: 0 }]])
    this.#accepted = initial
  }

  snapshot(): GovernanceReplaySnapshot {
    if (this.#failed) throw new TypeError('Cannot read failed session')
    if (!this.#snapshotCache) {
      const actorHeads = [...this.#actors.entries()]
        .map(([actorKeyId, value]) => Object.freeze({ actorKeyId, actionHash: value.actionHash }))
        .sort((a, b) => a.actorKeyId < b.actorKeyId ? -1 : a.actorKeyId > b.actorKeyId ? 1 : 0)
      this.#snapshotCache = Object.freeze({ ...this.#accepted, actorHeads: Object.freeze(actorHeads) })
    }
    return this.#snapshotCache
  }

  /** Checks an externally supplied receipt against this session's already authenticated chain. */
  async verifyReceipt(value: CompletionReceipt, leafBytes: Uint8Array): Promise<boolean> {
    return this.#exclusive(async () => {
      try {
        const receipt = snapshotCompletionReceipt(value)
        if (!(leafBytes instanceof Uint8Array) || leafBytes.length === 0 || leafBytes.length > MAX_LEAF_BYTES) {
          return false
        }
        const leaf = new Uint8Array(leafBytes)
        const acceptedSize = this.#accepted.size
        if (receipt.leafIndex >= acceptedSize) return false
        const headHash = await checkpointHash(receipt.checkpoint.statement)
        const acceptedHead = this.#acceptedHeads.get(headHash)
        if (!acceptedHead || acceptedHead.signed.statement.size > acceptedSize) return false
        return verifyReceiptInclusion(receipt, leaf, acceptedHead.signed)
      } catch { return false }
    })
  }

  async #exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (this.#failed || this.#busy) {
      this.#failed = true
      throw new TypeError('Cannot use failed session')
    }
    this.#busy = true
    try {
      const result = await work()
      if (this.#failed) throw new TypeError('Cannot use failed session')
      return result
    } catch (error) { this.#failed = true; throw error } finally { this.#busy = false }
  }

  async #targetCheckpoint(next: SignedCheckpoint) {
    const proposed = await snapshotCheckpoint(next)
    if (this.#target) {
      if (!equalBytes(this.#target.bytes, proposed.bytes)) throw new TypeError('Checkpoint target changed within tentative span')
      return this.#target
    }
    if (proposed.signed.statement.feedId !== this.#accepted.feedId
      || proposed.signed.statement.size <= this.#accepted.size
      || proposed.signed.statement.previous !== this.#accepted.checkpointHash) {
      throw new TypeError('Checkpoint skips or forks the accepted chain')
    }
    this.#target = proposed
    return proposed
  }

  async appendLeaves(leaves: readonly Uint8Array[], nextCheckpoint: SignedCheckpoint): Promise<void> {
    return this.#exclusive(async () => {
      const entries = denseArray(leaves, MAX_PAGE_LEAVES, 'page leaf')
      if (entries.length === 0) throw new TypeError('Expected nonempty governance leaf page')
      let bytes = 0
      const copied = entries.map((entry, index) => {
        if (!(entry instanceof Uint8Array) || Object.getPrototypeOf(entry) !== Uint8Array.prototype
          || entry.length > MAX_LEAF_BYTES) throw new TypeError(`Invalid page leaf ${index}`)
        bytes += entry.length
        if (bytes > MAX_PAGE_BYTES) throw new RangeError('Leaf page exceeds 256 KiB')
        return new Uint8Array(entry)
      })
      const target = await this.#targetCheckpoint(nextCheckpoint)
      if (this.#frontier.size + copied.length > target.signed.statement.size) {
        throw new TypeError('Leaf page crosses checkpoint boundary')
      }
      for (const leaf of copied) await this.#appendLeaf(leaf)
    })
  }

  async #appendLeaf(leaf: Uint8Array): Promise<void> {
    const leafIndex = this.#frontier.size
    const parsed = parseCanonical(leaf)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError(`Invalid leaf ${leafIndex}`)
    const kind = Object.getOwnPropertyDescriptor(parsed, 'kind')?.value
    if (kind === 'authority.revision') {
      const record = exactLeaf(parsed, ['version', 'kind', 'revision'])
      if (record.version !== 1 || !equalBytes(authorityRevisionLeaf(record.revision as SignedAuthorityRevision), leaf)) {
        throw new TypeError(`Noncanonical authority revision leaf ${leafIndex}`)
      }
      this.#authority = await applyAuthorityRevision(this.#authority, record.revision as SignedAuthorityRevision)
    } else if (kind === 'governance.completion') {
      const record = exactLeaf(parsed, ['version', 'kind', 'action', 'effectCommitment'])
      const signed = snapshotSignedAction(record.action)
      if (record.version !== 1 || record.effectCommitment !== signed.statement.effectCommitment
        || !equalBytes(governanceCompletionLeaf(signed), leaf)) throw new TypeError(`Noncanonical completion leaf ${leafIndex}`)
      const action = signed.statement
      if (!await verifyGovernanceAction(signed, this.#authority)) throw new TypeError(`Unauthorized action at leaf ${leafIndex}`)
      const observed = this.#acceptedHeads.get(action.observedCheckpointHash)
      if (!observed) throw new TypeError(`Action at leaf ${leafIndex} observes an unauthenticated checkpoint`)
      if (this.#operations.has(action.operationId)) throw new TypeError(`Duplicate operation ID at leaf ${leafIndex}`)
      const prior = this.#tentativeActors.get(action.actorKeyId) ?? this.#actors.get(action.actorKeyId)
      if (!prior) {
        if (action.previousActionHash !== null || action.previousReceipt !== null) {
          throw new TypeError(`First action at leaf ${leafIndex} names a predecessor`)
        }
      } else {
        if (action.previousActionHash !== prior.actionHash || action.previousReceipt === null) {
          throw new TypeError(`Actor stream predecessor mismatch at leaf ${leafIndex}`)
        }
        const receipt = action.previousReceipt
        const receiptHash = await checkpointHash(receipt.checkpoint.statement)
        const receiptHead = this.#acceptedHeads.get(receiptHash)
        if (!receiptHead || receiptHead.position > observed.position
          || !equalBytes(canonicalBytes(receiptHead.signed), canonicalBytes(receipt.checkpoint))
          || receipt.leafIndex !== prior.leafIndex || receipt.operationId !== prior.operationId
          || receipt.effectCommitment !== prior.effectCommitment || receipt.actionHash !== prior.actionHash
          || !await verifyReceiptInclusion(receipt, prior.leaf, receiptHead.signed)) {
          throw new TypeError(`Actor stream receipt mismatch at leaf ${leafIndex}`)
        }
      }
      const actionHash = await governanceActionHash(action)
      this.#tentativeActors.set(action.actorKeyId, { actionHash, leafIndex, operationId: action.operationId,
        effectCommitment: action.effectCommitment, leaf })
      this.#operations.add(action.operationId)
    } else {
      throw new TypeError(`Unknown governance leaf kind at ${leafIndex}`)
    }
    this.#frontier = await appendHistory(this.#frontier, leaf)
  }

  async sealCheckpoint(nextCheckpoint: SignedCheckpoint): Promise<void> {
    return this.#exclusive(async () => {
      const target = await this.#targetCheckpoint(nextCheckpoint)
      const head = target.signed
      const headIndex = this.#acceptedHeads.size
      if (this.#frontier.size !== head.statement.size) throw new TypeError('Tentative size differs from checkpoint size')
      const state = authorityStateSnapshot(this.#authority)
      const signer = await importSigningPublicKey(state.checkpointKeySpki)
      if (head.statement.historyRoot !== await historyFrontierRoot(this.#frontier)
        || head.statement.authorityRoot !== state.authorityRoot || head.statement.policyEpoch !== state.policyEpoch
        || head.statement.signerKeyId !== state.checkpointKeyId || !await verifyCheckpoint(head, signer)) {
        throw new TypeError(`Checkpoint ${headIndex} disagrees with replayed authority or history`)
      }
      this.#acceptedHeads.set(target.hash, { signed: head, position: headIndex })
      for (const [actorKeyId, action] of this.#tentativeActors) this.#actors.set(actorKeyId, action)
      this.#tentativeActors.clear()
      this.#accepted = acceptedMeta(this.#authority, this.#frontier.size, target.hash, this.#accepted.anchorPin)
      this.#snapshotCache = null
      this.#target = null
    })
  }
}

/** Starts an opaque, process-local replay from an independently pinned authority and signed size-zero checkpoint. */
export async function createGovernanceReplaySession(signedAnchor: SignedAuthorityAnchor,
  expectedPin: Hash, signedGenesis: SignedCheckpoint): Promise<GovernanceReplaySession> {
  if (!validHash(expectedPin)) throw new TypeError('An independent authority pin is required')
  const anchorBytes = canonicalBytes(signedAnchor)
  if (anchorBytes.length > 32 * 1024) throw new RangeError('Anchor exceeds 32 KiB')
  const anchor = parseCanonical(anchorBytes) as unknown as SignedAuthorityAnchor
  const genesis = await snapshotCheckpoint(signedGenesis)
  const authority = await verifyAuthorityAnchor(anchor, expectedPin)
  const identity = authorityStateSnapshot(authority)
  const genesisKey = await importSigningPublicKey(identity.checkpointKeySpki)
  if (genesis.signed.statement.feedId !== identity.feedId || genesis.signed.statement.size !== 0
    || genesis.signed.statement.previous !== null
    || genesis.signed.statement.historyRoot !== await historyFrontierRoot(emptyHistoryFrontier())
    || genesis.signed.statement.authorityRoot !== identity.authorityRoot
    || genesis.signed.statement.policyEpoch !== identity.policyEpoch
    || genesis.signed.statement.signerKeyId !== identity.checkpointKeyId
    || !await verifyCheckpoint(genesis.signed, genesisKey)) {
    throw new TypeError('Invalid signed genesis checkpoint')
  }
  const initial = acceptedMeta(authority, 0, genesis.hash, expectedPin)
  return new ReplaySession(authority, genesis.signed, genesis.hash, initial)
}

/** Verifies one complete retained prefix against an independently authenticated customer pin. */
export async function replayGovernanceHistory(
  signedAnchor: SignedAuthorityAnchor, expectedPin: Hash, leaves: readonly Uint8Array[],
  checkpoints: readonly SignedCheckpoint[],
): Promise<GovernanceReplaySnapshot> {
  if (!validHash(expectedPin)) throw new TypeError('An independent authority pin is required')
  const { signedAnchor: anchor, retainedLeaves, signedCheckpoints } = snapshotInput(signedAnchor, leaves, checkpoints)
  const session = await createGovernanceReplaySession(anchor, expectedPin, signedCheckpoints[0]!)
  let offset = 0
  for (let index = 1; index < signedCheckpoints.length; index++) {
    const head = signedCheckpoints[index]!
    if (head.statement.size <= offset || head.statement.size > retainedLeaves.length) {
      throw new TypeError(`Checkpoint ${index} skips or forks the accepted chain`)
    }
    while (offset < head.statement.size) {
      const next = Math.min(offset + MAX_PAGE_LEAVES, head.statement.size)
      await session.appendLeaves(retainedLeaves.slice(offset, next), head)
      offset = next
    }
    await session.sealCheckpoint(head)
  }
  if (offset !== retainedLeaves.length) throw new TypeError('Unsealed governance leaf tail')
  return session.snapshot()
}
