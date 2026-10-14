import { authorityStateSnapshot, type AuthorityScope, type AuthorityState } from './authority-lifecycle.js'
import { canonicalBytes } from './canonical.js'
import { snapshotCompletionReceipt, type CompletionReceipt } from './completion-receipt.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import { importSigningPublicKey, signRecord, signingKeyId, verifyRecord } from './signatures.js'

const encoder = new TextEncoder()
const ID_PREFIX = encoder.encode('1bridge.authority/v1/action-id\n')
const ACTION_FIELDS = ['version', 'feedId', 'workspaceId', 'operationId', 'actorSubjectId', 'actorKeyId', 'actorVersion',
  'scope', 'actionClass', 'authorityRevision', 'authorityRevisionHash', 'authorityRoot', 'policyEpoch',
  'observerPolicyHash', 'intentCommitment', 'effectCommitment', 'observedCheckpointHash', 'previousActionHash', 'previousReceipt']
const CLASS_PATTERN = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){1,3}$/
const PURPOSE = 'governance.action'
const MAX_ACTION_BYTES = 16384
const MAX_LEAF_BYTES = 24576

export interface GovernanceAction {
  version: 1
  feedId: Hash
  workspaceId: Hash
  operationId: Hash
  actorSubjectId: Hash
  actorKeyId: Hash
  actorVersion: number
  scope: AuthorityScope
  actionClass: string
  authorityRevision: number
  authorityRevisionHash: Hash
  authorityRoot: Hash
  policyEpoch: number
  observerPolicyHash: Hash | null
  intentCommitment: Hash
  effectCommitment: Hash
  observedCheckpointHash: Hash
  previousActionHash: Hash | null
  previousReceipt: CompletionReceipt | null
}

export interface SignedAction { statement: GovernanceAction; signature: string }

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

function positive(value: unknown): value is number { return count(value) && value > 0 }

function scope(value: unknown): AuthorityScope {
  if (value === null || typeof value !== 'object') throw new TypeError('Expected authority scope')
  const kind = Object.getOwnPropertyDescriptor(value, 'kind')
  const declared = kind && Object.hasOwn(kind, 'value') ? kind.value : undefined
  const record = exact(value, declared === 'vault' ? ['kind', 'workspaceId', 'vaultId'] : ['kind', 'workspaceId'])
  if (!validHash(record.workspaceId) || (record.kind !== 'workspace' && record.kind !== 'vault')
    || (record.kind === 'vault' && !validHash(record.vaultId))) throw new TypeError('Invalid authority scope')
  return record as AuthorityScope
}

function signature(value: unknown): string {
  if (typeof value !== 'string' || decodeBase64Url(value, 64).length !== 64) throw new TypeError('Expected canonical P-256 signature')
  return value
}

function snapshotStatement(value: unknown): GovernanceAction {
  const record = exact(value, ACTION_FIELDS)
  if (record.version !== 1 || !validHash(record.feedId) || !validHash(record.workspaceId) || !validHash(record.operationId)
    || !validHash(record.actorSubjectId) || !validHash(record.actorKeyId) || !positive(record.actorVersion)
    || typeof record.actionClass !== 'string' || record.actionClass.length > 64 || !CLASS_PATTERN.test(record.actionClass)
    || !count(record.authorityRevision) || !validHash(record.authorityRevisionHash) || !validHash(record.authorityRoot)
    || !count(record.policyEpoch) || (record.observerPolicyHash !== null && !validHash(record.observerPolicyHash))
    || !validHash(record.intentCommitment) || !validHash(record.effectCommitment) || !validHash(record.observedCheckpointHash)) {
    throw new TypeError('Invalid governance action statement')
  }
  const actionScope = scope(record.scope)
  if (actionScope.workspaceId !== record.workspaceId) throw new TypeError('Action scope workspace mismatch')
  if (record.previousActionHash === null && record.previousReceipt === null) {
    return { ...record, scope: actionScope } as GovernanceAction
  }
  if (!validHash(record.previousActionHash) || record.previousReceipt === null) throw new TypeError('Invalid action predecessor')
  const previousReceipt = snapshotCompletionReceipt(record.previousReceipt)
  if (previousReceipt.actionHash !== record.previousActionHash || previousReceipt.feedId !== record.feedId) throw new TypeError('Predecessor receipt mismatch')
  return { ...record, scope: actionScope, previousReceipt } as GovernanceAction
}

export function snapshotSignedAction(value: unknown): SignedAction {
  const record = exact(value, ['statement', 'signature'])
  const signed = { statement: snapshotStatement(record.statement), signature: signature(record.signature) }
  if (canonicalBytes(signed).length > MAX_ACTION_BYTES) throw new RangeError('Signed action exceeds 16 KiB')
  return signed
}

function pair(value: unknown): CryptoKeyPair {
  return exact(value, ['publicKey', 'privateKey']) as unknown as CryptoKeyPair
}

export async function governanceActionHash(statement: GovernanceAction): Promise<Hash> {
  const body = canonicalBytes(snapshotStatement(statement))
  const bytes = new Uint8Array(ID_PREFIX.length + body.length)
  bytes.set(ID_PREFIX)
  bytes.set(body, ID_PREFIX.length)
  return sha256(bytes)
}

export async function signGovernanceAction(statement: GovernanceAction, signer: CryptoKeyPair): Promise<SignedAction> {
  const snapshot = snapshotStatement(statement)
  const keys = pair(signer)
  if (snapshot.actorKeyId !== await signingKeyId(keys.publicKey)) throw new TypeError('Actor key ID mismatch')
  const signed = snapshotSignedAction({ statement: snapshot, signature: await signRecord(PURPOSE, snapshot, keys.privateKey) })
  if (!await verifyRecord(PURPOSE, snapshot, signed.signature, keys.publicKey)) throw new TypeError('Actor signing key pair mismatch')
  return signed
}

/** Checks the actor signature and active customer binding at the supplied historical authority state. */
export async function verifyGovernanceAction(action: SignedAction, historicalState: AuthorityState): Promise<boolean> {
  try {
    const signed = snapshotSignedAction(action)
    const statement = signed.statement
    const state = authorityStateSnapshot(historicalState)
    if (statement.feedId !== state.feedId || statement.workspaceId !== state.workspaceId
      || statement.authorityRevision !== state.revision || statement.authorityRevisionHash !== state.revisionHash
      || statement.authorityRoot !== state.authorityRoot || statement.policyEpoch !== state.policyEpoch
      || statement.observerPolicyHash !== state.observerPolicyHash) return false
    const binding = state.bindings.find(entry => entry.subjectId === statement.actorSubjectId)
    if (!binding || binding.status !== 'active' || binding.keyId !== statement.actorKeyId || binding.version !== statement.actorVersion
      || !binding.actionClasses.includes(statement.actionClass) || binding.scope.workspaceId !== statement.scope.workspaceId
      || (binding.scope.kind === 'vault' && (statement.scope.kind !== 'vault' || binding.scope.vaultId !== statement.scope.vaultId))) return false
    const publicKey = await importSigningPublicKey(binding.keySpki)
    return verifyRecord(PURPOSE, statement, signed.signature, publicKey)
  } catch {
    return false
  }
}

/** Encodes a completed event. Syntax alone does not establish actor signature, authority or database effect. */
export function governanceCompletionLeaf(action: SignedAction): Uint8Array {
  const signed = snapshotSignedAction(action)
  const leaf = canonicalBytes({ version: 1, kind: 'governance.completion', action: signed,
    effectCommitment: signed.statement.effectCommitment })
  if (leaf.length > MAX_LEAF_BYTES) throw new RangeError('Completion leaf exceeds 24 KiB')
  return leaf
}
