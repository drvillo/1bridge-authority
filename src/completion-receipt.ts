import { canonicalBytes, parseCanonical } from './canonical.js'
import { decodeBase64Url } from './encoding.js'
import { hashLeaf, sha256, validHash, type Hash } from './hash.js'
import { verifyInclusion } from './history.js'
import { governanceActionHash, governanceCompletionLeaf, snapshotSignedAction } from './action.js'
import type { SignedCheckpoint } from './checkpoint.js'

const encoder = new TextEncoder()
const ID_PREFIX = encoder.encode('1bridge.authority/v1/completion-receipt-id\n')
const RECEIPT_FIELDS = ['version', 'status', 'feedId', 'operationId', 'actionHash', 'effectCommitment', 'leafIndex', 'leafHash', 'checkpoint', 'inclusionProof']
const CHECKPOINT_FIELDS = ['version', 'feedId', 'size', 'historyRoot', 'authorityRoot', 'policyEpoch', 'signerKeyId', 'previous']
const MAX_RECEIPT_BYTES = 8192
const MAX_PROOF_NODES = 54

export interface CompletionReceipt {
  version: 1
  status: 'integrated'
  feedId: Hash
  operationId: Hash
  actionHash: Hash
  effectCommitment: Hash
  leafIndex: number
  leafHash: Hash
  checkpoint: SignedCheckpoint
  inclusionProof: Hash[]
}

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected plain record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) throw new TypeError('Expected exact record fields')
  const result: Record<string, unknown> = {}
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected enumerable data field')
    result[field] = descriptor.value
  }
  return result
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)
}

function signature(value: unknown): string {
  if (typeof value !== 'string' || decodeBase64Url(value, 64).length !== 64) throw new TypeError('Expected canonical P-256 signature')
  return value
}

function checkpoint(value: unknown): SignedCheckpoint {
  const signed = exact(value, ['statement', 'signature'])
  const head = exact(signed.statement, CHECKPOINT_FIELDS)
  if (head.version !== 1 || !validHash(head.feedId) || !count(head.size) || !validHash(head.historyRoot)
    || !validHash(head.authorityRoot) || !count(head.policyEpoch) || !validHash(head.signerKeyId)
    || (head.size === 0 ? head.previous !== null : !validHash(head.previous))) throw new TypeError('Invalid checkpoint')
  return { statement: head as unknown as SignedCheckpoint['statement'], signature: signature(signed.signature) }
}

function proof(value: unknown): Hash[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > MAX_PROOF_NODES
    || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError('Expected bounded dense proof')
  const result: Hash[] = []
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') || !validHash(descriptor.value)) throw new TypeError('Expected hash proof node')
    result.push(descriptor.value)
  }
  return result
}

export function snapshotCompletionReceipt(value: unknown): CompletionReceipt {
  const record = exact(value, RECEIPT_FIELDS)
  if (record.version !== 1 || record.status !== 'integrated' || !validHash(record.feedId) || !validHash(record.operationId)
    || !validHash(record.actionHash) || !validHash(record.effectCommitment) || !count(record.leafIndex) || !validHash(record.leafHash)) {
    throw new TypeError('Invalid integrated receipt')
  }
  const signedHead = checkpoint(record.checkpoint)
  if (record.feedId !== signedHead.statement.feedId || record.leafIndex >= signedHead.statement.size) throw new TypeError('Receipt head mismatch')
  const receipt = { ...record, checkpoint: signedHead, inclusionProof: proof(record.inclusionProof) } as CompletionReceipt
  if (canonicalBytes(receipt).length > MAX_RECEIPT_BYTES) throw new RangeError('Receipt exceeds 8 KiB')
  return receipt
}

export async function completionReceiptHash(receipt: CompletionReceipt): Promise<Hash> {
  const body = canonicalBytes(snapshotCompletionReceipt(receipt))
  const bytes = new Uint8Array(ID_PREFIX.length + body.length)
  bytes.set(ID_PREFIX)
  bytes.set(body, ID_PREFIX.length)
  return sha256(bytes)
}

/** Verifies receipt identity and RFC inclusion against a supplied head; it does not authenticate that head. */
export async function verifyReceiptInclusion(receipt: CompletionReceipt, leafBytes: Uint8Array, suppliedHead: SignedCheckpoint): Promise<boolean> {
  try {
    const record = snapshotCompletionReceipt(receipt)
    const head = checkpoint(suppliedHead)
    if (!(leafBytes instanceof Uint8Array) || leafBytes.length > 24576
      || !equalBytes(canonicalBytes(head), canonicalBytes(record.checkpoint))) return false
    const leaf = new Uint8Array(leafBytes)
    const parsed = parseCanonical(leaf)
    const completed = exact(parsed, ['version', 'kind', 'action', 'effectCommitment'])
    if (completed.version !== 1 || completed.kind !== 'governance.completion' || !validHash(completed.effectCommitment)) return false
    const action = snapshotSignedAction(completed.action)
    if (action.statement.effectCommitment !== completed.effectCommitment
      || !equalBytes(governanceCompletionLeaf(action), leaf)) return false
    if (record.feedId !== action.statement.feedId || record.operationId !== action.statement.operationId
      || record.effectCommitment !== completed.effectCommitment || record.actionHash !== await governanceActionHash(action.statement)
      || record.leafHash !== await hashLeaf(leaf)) return false
    return verifyInclusion(leaf, record.leafIndex, head.statement.size, record.inclusionProof, head.statement.historyRoot)
  } catch {
    return false
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}
