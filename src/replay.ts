import { governanceActionHash, governanceCompletionLeaf, snapshotSignedAction, verifyGovernanceAction } from './action.js'
import { applyAuthorityRevision, authorityRevisionLeaf, authorityStateSnapshot, verifyAuthorityAnchor,
  type SignedAuthorityAnchor, type SignedAuthorityRevision } from './authority-lifecycle.js'
import { canonicalBytes, parseCanonical } from './canonical.js'
import { checkpointHash, verifyCheckpoint, type SignedCheckpoint } from './checkpoint.js'
import { verifyReceiptInclusion } from './completion-receipt.js'
import { validHash, type Hash } from './hash.js'
import { appendHistory, emptyHistoryFrontier, historyFrontierRoot } from './history-frontier.js'
import { importSigningPublicKey } from './signatures.js'

const MAX_LEAVES = 10_000
const MAX_TOTAL_BYTES = 32 * 1024 * 1024
const MAX_LEAF_BYTES = 24 * 1024
const MAX_CHECKPOINT_BYTES = 1024

export interface GovernanceReplaySnapshot {
  feedId: Hash
  size: number
  checkpointHash: Hash
  authorityRoot: Hash
  authorityRevision: number
  authorityRevisionHash: Hash
  policyEpoch: number
  observerPolicyHash: Hash | null
  actorHeads: ReadonlyArray<Readonly<{ actorKeyId: Hash; actionHash: Hash }>>
}

interface AcceptedAction { actionHash: Hash; leafIndex: number; operationId: Hash; effectCommitment: Hash }
interface AcceptedCheckpoint { signed: SignedCheckpoint; position: number }

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

/** Verifies one complete retained prefix against an independently authenticated customer pin. */
export async function replayGovernanceHistory(
  signedAnchor: SignedAuthorityAnchor, expectedPin: Hash, leaves: readonly Uint8Array[],
  checkpoints: readonly SignedCheckpoint[],
): Promise<GovernanceReplaySnapshot> {
  if (!validHash(expectedPin)) throw new TypeError('An independent authority pin is required')
  const { signedAnchor: anchor, retainedLeaves, signedCheckpoints } = snapshotInput(signedAnchor, leaves, checkpoints)
  let authority = await verifyAuthorityAnchor(anchor, expectedPin)
  const identity = authorityStateSnapshot(authority)
  const genesis = signedCheckpoints[0]!
  const genesisKey = await importSigningPublicKey(identity.checkpointKeySpki)
  if (genesis.statement.feedId !== identity.feedId || genesis.statement.size !== 0 || genesis.statement.previous !== null
    || genesis.statement.historyRoot !== await historyFrontierRoot(emptyHistoryFrontier())
    || genesis.statement.authorityRoot !== identity.authorityRoot || genesis.statement.policyEpoch !== identity.policyEpoch
    || genesis.statement.signerKeyId !== identity.checkpointKeyId || !await verifyCheckpoint(genesis, genesisKey)) {
    throw new TypeError('Invalid signed genesis checkpoint')
  }

  let frontier = emptyHistoryFrontier()
  let previous = genesis
  const acceptedHeads = new Map<Hash, AcceptedCheckpoint>([[await checkpointHash(genesis.statement), { signed: genesis, position: 0 }]])
  const actors = new Map<Hash, AcceptedAction>()
  const operations = new Set<Hash>()
  const actionLeaves = new Map<number, Uint8Array>()

  for (let headIndex = 1; headIndex < signedCheckpoints.length; headIndex++) {
    const head = signedCheckpoints[headIndex]!
    if (head.statement.feedId !== identity.feedId || head.statement.size <= frontier.size
      || head.statement.size > retainedLeaves.length
      || head.statement.previous !== await checkpointHash(previous.statement)) {
      throw new TypeError(`Checkpoint ${headIndex} skips or forks the accepted chain`)
    }
    while (frontier.size < head.statement.size) {
      const leafIndex = frontier.size
      const leaf = retainedLeaves[leafIndex]!
      const parsed = parseCanonical(leaf)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError(`Invalid leaf ${leafIndex}`)
      const kind = Object.getOwnPropertyDescriptor(parsed, 'kind')?.value
      if (kind === 'authority.revision') {
        const record = exactLeaf(parsed, ['version', 'kind', 'revision'])
        if (record.version !== 1 || !equalBytes(authorityRevisionLeaf(record.revision as SignedAuthorityRevision), leaf)) {
          throw new TypeError(`Noncanonical authority revision leaf ${leafIndex}`)
        }
        authority = await applyAuthorityRevision(authority, record.revision as SignedAuthorityRevision)
      } else if (kind === 'governance.completion') {
        const record = exactLeaf(parsed, ['version', 'kind', 'action', 'effectCommitment'])
        const signed = snapshotSignedAction(record.action)
        if (record.version !== 1 || record.effectCommitment !== signed.statement.effectCommitment
          || !equalBytes(governanceCompletionLeaf(signed), leaf)) throw new TypeError(`Noncanonical completion leaf ${leafIndex}`)
        const action = signed.statement
        if (!await verifyGovernanceAction(signed, authority)) throw new TypeError(`Unauthorized action at leaf ${leafIndex}`)
        const observed = acceptedHeads.get(action.observedCheckpointHash)
        if (!observed) throw new TypeError(`Action at leaf ${leafIndex} observes an unauthenticated checkpoint`)
        if (operations.has(action.operationId)) throw new TypeError(`Duplicate operation ID at leaf ${leafIndex}`)
        const prior = actors.get(action.actorKeyId)
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
          const receiptHead = acceptedHeads.get(receiptHash)
          const predecessorLeaf = actionLeaves.get(prior.leafIndex)
          if (!receiptHead || receiptHead.position > observed.position
            || !equalBytes(canonicalBytes(receiptHead.signed), canonicalBytes(receipt.checkpoint))
            || receipt.leafIndex !== prior.leafIndex || receipt.operationId !== prior.operationId
            || receipt.effectCommitment !== prior.effectCommitment || receipt.actionHash !== prior.actionHash
            || !predecessorLeaf || !await verifyReceiptInclusion(receipt, predecessorLeaf, receiptHead.signed)) {
            throw new TypeError(`Actor stream receipt mismatch at leaf ${leafIndex}`)
          }
        }
        const actionHash = await governanceActionHash(action)
        actors.set(action.actorKeyId, { actionHash, leafIndex, operationId: action.operationId,
          effectCommitment: action.effectCommitment })
        operations.add(action.operationId)
        actionLeaves.set(leafIndex, leaf)
      } else {
        throw new TypeError(`Unknown governance leaf kind at ${leafIndex}`)
      }
      frontier = await appendHistory(frontier, leaf)
    }
    const state = authorityStateSnapshot(authority)
    const signer = await importSigningPublicKey(state.checkpointKeySpki)
    if (head.statement.historyRoot !== await historyFrontierRoot(frontier)
      || head.statement.authorityRoot !== state.authorityRoot || head.statement.policyEpoch !== state.policyEpoch
      || head.statement.signerKeyId !== state.checkpointKeyId || !await verifyCheckpoint(head, signer)) {
      throw new TypeError(`Checkpoint ${headIndex} disagrees with replayed authority or history`)
    }
    previous = head
    acceptedHeads.set(await checkpointHash(head.statement), { signed: head, position: headIndex })
  }
  if (frontier.size !== retainedLeaves.length) throw new TypeError('Unsealed governance leaf tail')
  const final = authorityStateSnapshot(authority)
  const actorHeads = [...actors.entries()].map(([actorKeyId, value]) => Object.freeze({ actorKeyId, actionHash: value.actionHash }))
    .sort((a, b) => a.actorKeyId < b.actorKeyId ? -1 : a.actorKeyId > b.actorKeyId ? 1 : 0)
  return Object.freeze({ feedId: final.feedId, size: frontier.size,
    checkpointHash: await checkpointHash(previous.statement), authorityRoot: final.authorityRoot,
    authorityRevision: final.revision, authorityRevisionHash: final.revisionHash,
    policyEpoch: final.policyEpoch, observerPolicyHash: final.observerPolicyHash, actorHeads: Object.freeze(actorHeads) })
}
